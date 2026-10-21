//go:build unix

package runner

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// KubernetesCheck holds the rules a work Pod's container is checked by in
// place of the Docker ones. The layout differs: the root filesystem is read
// only, /work is a read-only mount of a memory volume that another container
// (uid WorkUID) filled, the scratch directories are memory volumes whose mount
// options the Pod cannot set (they carry no nosuid, nodev or noexec), and the
// kubelet bind-mounts the termination message file. The check is not looser
// where it can be strict: it opens the paths that must not be reachable and
// tries the writes that must fail.
type KubernetesCheck struct {
	// WorkPath is the mount the input was unpacked to, and WorkUID the owner
	// every entry in it must have.
	WorkPath string
	WorkUID  uint32
	// TerminationPaths are the paths the kubelet mounts the termination message
	// file at. They may be mounts, and the job user must not be able to open
	// them.
	TerminationPaths []string
	// DefaultTerminationPath is the kubelet's default, which must not exist.
	DefaultTerminationPath string
	// TokenDir is where a service account token would be; it must not exist.
	TokenDir string
	// WriteProbes are paths where creating a file must fail: the root
	// filesystem and the read-only input.
	WriteProbes []string
	// Probe performs the active checks; nil means the real filesystem.
	Probe KubernetesProbe
}

// KubernetesProbe is the part of the filesystem the active checks touch.
type KubernetesProbe interface {
	// CanOpen reports whether path can be opened for reading or writing.
	CanOpen(path string) bool
	// Exists reports whether path exists at all (without following links).
	Exists(path string) bool
	// CanCreate reports whether a file can be created at path.
	CanCreate(path string) bool
}

type osProbe struct{}

func (osProbe) CanOpen(p string) bool {
	for _, flag := range []int{os.O_RDONLY, os.O_WRONLY} {
		if f, err := os.OpenFile(p, flag, 0); err == nil {
			f.Close()
			return true
		}
	}
	return false
}

func (osProbe) Exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil || !errors.Is(err, fs.ErrNotExist)
}

func (osProbe) CanCreate(p string) bool {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(p)
	return true
}

// DefaultKubernetesCheck is the layout inside a work Pod's work container.
func DefaultKubernetesCheck() *KubernetesCheck {
	return &KubernetesCheck{
		WorkPath: worker.WorkDir, WorkUID: worker.ReceiverUID,
		TerminationPaths:       []string{worker.TerminationDir + "/work"},
		DefaultTerminationPath: "/dev/termination-log",
		TokenDir:               "/var/run/secrets/kubernetes.io",
		WriteProbes:            []string{"/.kestrelynx-selfcheck", worker.WorkDir + "/.kestrelynx-selfcheck"},
	}
}

// checkKubernetesMounts is checkMounts for a work Pod: the root filesystem is
// read only; the only other mounts are the engine's, the read-only input, the
// scratch memory volumes and the termination message file. It returns the
// mount points the walk leaves out.
func (c *SelfCheckConfig) checkKubernetesMounts(mounts []mountEntry) (map[string]bool, error) {
	k := c.Kubernetes
	allowed := map[string]TmpfsMount{}
	for _, t := range c.Tmpfs {
		allowed[t.Path] = t
	}
	skip := map[string]bool{}
	sawRoot := false
	for _, m := range mounts {
		switch {
		case m.point == c.Root:
			sawRoot = true
			if !hasOpt(m.options, "ro") {
				return nil, errors.New("the root filesystem is not read only")
			}
		case underPrefixAny(m.point, systemMountPrefixes):
		case containsString(systemFileMounts, m.point):
		case m.point == k.WorkPath:
			if m.fstype != "tmpfs" || !hasOpt(m.options, "ro") || !hasOptPrefix(m.super, "size=") {
				return nil, fmt.Errorf("%s is not a read-only memory volume with a size limit", m.point)
			}
			skip[m.point] = true
		case containsString(k.TerminationPaths, m.point):
			skip[m.point] = true
		default:
			t, ok := allowed[m.point]
			if !ok {
				return nil, fmt.Errorf("the container has an unexpected mount at %s", m.point)
			}
			if m.fstype != "tmpfs" || !hasOpt(m.options, "rw") || !hasOptPrefix(m.super, "size=") {
				return nil, fmt.Errorf("%s is not a writable memory volume with a size limit", t.Path)
			}
			skip[m.point] = true
		}
	}
	if !sawRoot {
		return nil, errors.New("the root filesystem is not in the mount table")
	}
	return skip, nil
}

// activeChecks tries what must not work and looks for what must not be there.
func (k *KubernetesCheck) activeChecks(fsys SelfCheckFS) error {
	probe := k.Probe
	if probe == nil {
		probe = osProbe{}
	}
	for _, p := range k.TerminationPaths {
		if probe.CanOpen(p) {
			return fmt.Errorf("the termination message file %s can be opened", p)
		}
	}
	if probe.Exists(k.DefaultTerminationPath) {
		return fmt.Errorf("%s exists", k.DefaultTerminationPath)
	}
	if k.TokenDir != "" && probe.Exists(k.TokenDir) {
		return fmt.Errorf("%s exists: a service account token is mounted", k.TokenDir)
	}
	for _, p := range k.WriteProbes {
		if probe.CanCreate(p) {
			return fmt.Errorf("a file can be created at %s", p)
		}
	}
	return k.checkWorkOwners(fsys)
}

// checkWorkOwners requires every entry below the input mount to belong to the
// receiving container's user, not to the job user, and none to be writable by
// the job user.
func (k *KubernetesCheck) checkWorkOwners(fsys SelfCheckFS) error {
	var walk func(p string, top bool) error
	walk = func(p string, top bool) error {
		fi, err := fsys.Lstat(p)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", p, err)
		}
		if !top {
			st, ok := fi.Sys().(*syscall.Stat_t)
			if !ok {
				return fmt.Errorf("the owner of %s cannot be read", p)
			}
			if st.Uid != k.WorkUID {
				return fmt.Errorf("%s is owned by uid %d, not %d", p, st.Uid, k.WorkUID)
			}
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s is a link", p)
		}
		if err := fsys.Access(p, 2); err == nil {
			return fmt.Errorf("%s is writable by the job user", p)
		}
		if !fi.IsDir() {
			return nil
		}
		entries, err := fsys.ReadDir(p)
		if err != nil {
			return fmt.Errorf("list %s: %w", p, err)
		}
		for _, e := range entries {
			if err := walk(filepath.Join(p, e.Name()), false); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(k.WorkPath, true)
}
