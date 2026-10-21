//go:build unix

package runner

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// TmpfsMount is a tmpfs the container is allowed to have and the job may
// write: a mount point, whether programs may be executed from it, and the
// mount must carry a size limit.
type TmpfsMount struct {
	Path string
	// Exec says the mount allows executing programs; otherwise it must be
	// noexec. Every mount must be nosuid and nodev.
	Exec bool
}

// SelfCheckConfig holds the rules of the check of the container's filesystem.
type SelfCheckConfig struct {
	// Root is the directory the walk starts at ("/").
	Root string
	// MountInfo is the file listing the mounts ("/proc/self/mountinfo").
	MountInfo string
	// UID is the user the job runs as: nothing may be owned by it.
	UID uint32
	// Tmpfs are the tmpfs mounts the job may write.
	Tmpfs []TmpfsMount
	// MaxEntries and MaxTime bound the walk.
	MaxEntries int
	MaxTime    time.Duration
	// FS is how the filesystem is read; nil means the real one.
	FS SelfCheckFS
	// Kubernetes, when set, replaces the rules about mounts with the ones of a
	// work Pod and adds the active checks of KubernetesCheck.
	Kubernetes *KubernetesCheck
}

// SelfCheckFS is the part of the filesystem the check reads.
type SelfCheckFS interface {
	Lstat(path string) (fs.FileInfo, error)
	ReadDir(path string) ([]fs.DirEntry, error)
	// Access reports whether the process may do mode (4 read, 2 write, 1
	// search or execute) on path, with the ids it runs as.
	Access(path string, mode uint32) error
}

type osFS struct{}

func (osFS) Lstat(p string) (fs.FileInfo, error)     { return os.Lstat(p) }
func (osFS) ReadDir(p string) ([]fs.DirEntry, error) { return os.ReadDir(p) }
func (osFS) Access(p string, mode uint32) error      { return syscall.Access(p, mode) }

// Limits of the check: the images the program runs in hold about 6,000 entries
// and the walk takes well under a second.
const (
	selfCheckMaxEntries = 50000
	selfCheckMaxTime    = 5 * time.Second
)

// systemMounts are the mounts the container engine makes, whose contents the
// walk leaves out; the files of /etc that it binds are allowed by name.
var (
	systemMountPrefixes = []string{"/proc", "/sys", "/dev"}
	systemFileMounts    = []string{"/etc/resolv.conf", "/etc/hostname", "/etc/hosts"}
)

func underPrefix(p, prefix string) bool { return p == prefix || strings.HasPrefix(p, prefix+"/") }

type mountEntry struct {
	point   string
	options []string
	fstype  string
	super   []string
}

// parseMountInfo reads the lines of /proc/self/mountinfo.
func parseMountInfo(data string) ([]mountEntry, error) {
	var out []mountEntry
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		sep := -1
		for i, x := range f {
			if x == "-" {
				sep = i
				break
			}
		}
		if sep < 6 || len(f) < sep+4 {
			return nil, fmt.Errorf("mountinfo line %q is malformed", line)
		}
		point, err := unescapeMount(f[4])
		if err != nil {
			return nil, err
		}
		out = append(out, mountEntry{
			point: point, options: strings.Split(f[5], ","),
			fstype: f[sep+1], super: strings.Split(f[sep+3], ","),
		})
	}
	if len(out) == 0 {
		return nil, errors.New("mountinfo lists no mounts")
	}
	return out, nil
}

// unescapeMount decodes the octal escapes (\040 for a space) of a mount point.
func unescapeMount(s string) (string, error) {
	if !strings.Contains(s, `\`) {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+3 >= len(s) {
			return "", fmt.Errorf("mount point %q has a bad escape", s)
		}
		n, err := strconv.ParseUint(s[i+1:i+4], 8, 8)
		if err != nil {
			return "", fmt.Errorf("mount point %q has a bad escape", s)
		}
		b.WriteByte(byte(n))
		i += 3
	}
	return b.String(), nil
}

func hasOpt(opts []string, want string) bool {
	for _, o := range opts {
		if o == want {
			return true
		}
	}
	return false
}

func hasOptPrefix(opts []string, prefix string) bool {
	for _, o := range opts {
		if strings.HasPrefix(o, prefix) {
			return true
		}
	}
	return false
}

// checkMounts requires every mount to be the root, one of the engine's, or a
// tmpfs the job may write with the options asked for, and returns the mount
// points of the tmpfs mounts, which the walk leaves out.
func (c *SelfCheckConfig) checkMounts(mounts []mountEntry) (map[string]bool, error) {
	allowed := map[string]TmpfsMount{}
	for _, t := range c.Tmpfs {
		allowed[t.Path] = t
	}
	skip := map[string]bool{}
	for _, m := range mounts {
		switch {
		case m.point == c.Root:
		case underPrefixAny(m.point, systemMountPrefixes):
		case containsString(systemFileMounts, m.point):
		default:
			t, ok := allowed[m.point]
			if !ok {
				return nil, fmt.Errorf("the container has an unexpected mount at %s", m.point)
			}
			if m.fstype != "tmpfs" {
				return nil, fmt.Errorf("%s is a %s mount, not a tmpfs", m.point, m.fstype)
			}
			if !hasOpt(m.options, "rw") || !hasOpt(m.options, "nosuid") || !hasOpt(m.options, "nodev") {
				return nil, fmt.Errorf("the tmpfs at %s is not rw, nosuid and nodev", m.point)
			}
			if t.Exec == hasOpt(m.options, "noexec") {
				return nil, fmt.Errorf("the tmpfs at %s has the wrong exec setting", m.point)
			}
			if !hasOptPrefix(m.super, "size=") {
				return nil, fmt.Errorf("the tmpfs at %s has no size limit", m.point)
			}
			skip[m.point] = true
		}
	}
	return skip, nil
}

func underPrefixAny(p string, prefixes []string) bool {
	for _, x := range prefixes {
		if underPrefix(p, x) {
			return true
		}
	}
	return false
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// selfCheck verifies the container before the job is read: no mount other
// than the allowed ones, and outside the allowed tmpfs mounts and the
// engine's own mounts nothing the job user owns or can write. The job may
// therefore write only into size-limited tmpfs.
func (c *SelfCheckConfig) selfCheck() error {
	fsys := c.FS
	if fsys == nil {
		fsys = osFS{}
	}
	data, err := os.ReadFile(c.MountInfo)
	if err != nil {
		return fmt.Errorf("read the mounts of the container: %w", err)
	}
	mounts, err := parseMountInfo(string(data))
	if err != nil {
		return err
	}
	check := c.checkMounts
	if c.Kubernetes != nil {
		check = c.checkKubernetesMounts
	}
	skip, err := check(mounts)
	if err != nil {
		return err
	}
	w := &walker{c: c, fs: fsys, skip: skip, deadline: time.Now().Add(c.MaxTime)}
	if err := w.walk(c.Root); err != nil {
		return err
	}
	if c.Kubernetes != nil {
		return c.Kubernetes.activeChecks(fsys)
	}
	return nil
}

type walker struct {
	c        *SelfCheckConfig
	fs       SelfCheckFS
	skip     map[string]bool
	deadline time.Time
	n        int
}

func (w *walker) owner(fi fs.FileInfo) (uid uint32, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

func (w *walker) walk(p string) error {
	if w.skip[p] || (p != w.c.Root && underPrefixAny(p, systemMountPrefixes)) {
		return nil
	}
	w.n++
	if w.n > w.c.MaxEntries {
		return fmt.Errorf("the container holds more than %d entries", w.c.MaxEntries)
	}
	if time.Now().After(w.deadline) {
		return fmt.Errorf("the check of the container took longer than %s", w.c.MaxTime)
	}
	fi, err := w.fs.Lstat(p)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", p, err)
	}
	uid, ok := w.owner(fi)
	if !ok {
		return fmt.Errorf("the owner of %s cannot be read", p)
	}
	if uid == w.c.UID {
		return fmt.Errorf("%s is owned by the job user", p)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return nil
	}
	if err := w.fs.Access(p, 2); err == nil {
		return fmt.Errorf("%s is writable by the job user", p)
	}
	if !fi.IsDir() {
		return nil
	}
	entries, err := w.fs.ReadDir(p)
	if err != nil {
		if !errors.Is(err, fs.ErrPermission) {
			return fmt.Errorf("list %s: %w", p, err)
		}
		// A directory the job user does not own, cannot write (checked
		// above) and cannot search holds nothing it can reach. One it can
		// search but not list could still be entered by name.
		if w.fs.Access(p, 1) == nil {
			return fmt.Errorf("%s can be searched but not listed", p)
		}
		return nil
	}
	for _, e := range entries {
		if err := w.walk(filepath.Join(p, e.Name())); err != nil {
			return err
		}
	}
	return nil
}
