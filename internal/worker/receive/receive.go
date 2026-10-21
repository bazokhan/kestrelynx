//go:build unix

// Package receive is the program of the init container of a work Pod. It reads
// the job's input as a tar on its standard input, checks it strictly and
// unpacks it into /work, an empty memory volume the work container later
// mounts read only. It prints nothing about the input: it writes a status line
// made of two fixed words, so that neither a path name nor any content reaches
// the log of the container.
package receive

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// Limits bound what the receiver reads and writes. They are the main process's
// limits on the input, so a tar the main process built always fits.
type Limits struct {
	// MaxTarBytes bounds the whole archive read from standard input.
	MaxTarBytes int64
	// MaxFileBytes bounds one file and MaxTotalBytes all file contents.
	MaxFileBytes  int64
	MaxTotalBytes int64
	// MaxEntries bounds files and directories together, MaxPathBytes one path.
	MaxEntries   int
	MaxPathBytes int
}

// DefaultLimits are the limits matching the input the main process builds: the
// project's files, one package manager archive, the work program and the job
// files.
func DefaultLimits() Limits {
	const programBytes = 16 << 20
	total := int64(worker.MaxInputTotalBytes + worker.MaxToolArchiveBytes + programBytes)
	return Limits{
		MaxTarBytes:   total + 1<<20,
		MaxFileBytes:  worker.MaxToolArchiveBytes,
		MaxTotalBytes: total,
		MaxEntries:    4 * (worker.MaxInputs + 8),
		MaxPathBytes:  256,
	}
}

// Config is where the receiver unpacks and what it refuses to be able to reach.
type Config struct {
	// Dest is the directory to unpack into (/work).
	Dest string
	// TerminationPath is the path of this container's termination message file,
	// which it must not be able to open.
	TerminationPath string
	Limits          Limits
}

// DefaultConfig is the layout inside the init container.
func DefaultConfig() Config {
	return Config{Dest: worker.WorkDir, TerminationPath: worker.TerminationDir + "/receive", Limits: DefaultLimits()}
}

// Status codes the receiver prints; each is a fixed word.
const (
	CodeOK            = "ok"
	CodeTermination   = "termination_open"
	CodeRead          = "read_failed"
	CodeTooLarge      = "too_large"
	CodeMalformed     = "malformed"
	CodeUnsafe        = "unsafe_entry"
	CodeWrite         = "write_failed"
	CodeDestination   = "bad_destination"
	CodeUnexpectedEnd = "cut_short"
)

// Error carries the code the receiver prints.
type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string { return e.Code + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func fail(code, format string, args ...any) error {
	return &Error{Code: code, Err: fmt.Errorf(format, args...)}
}

// Run unpacks the tar read from in. The container's termination message file
// must not be openable by this user, the destination must be an empty
// directory, and the archive must hold only regular files and directories with
// clean relative names.
func Run(in io.Reader, cfg Config) error {
	if cfg.TerminationPath != "" {
		for _, flag := range []int{os.O_RDONLY, os.O_WRONLY} {
			if f, err := os.OpenFile(cfg.TerminationPath, flag, 0); err == nil {
				f.Close()
				return fail(CodeTermination, "the termination message file can be opened")
			}
		}
	}
	entries, err := os.ReadDir(cfg.Dest)
	if err != nil {
		return fail(CodeDestination, "the destination cannot be read")
	}
	if len(entries) != 0 {
		return fail(CodeDestination, "the destination is not empty")
	}
	lim := cfg.Limits
	data, err := io.ReadAll(io.LimitReader(in, lim.MaxTarBytes+1))
	if err != nil {
		return fail(CodeRead, "the input cannot be read")
	}
	if int64(len(data)) > lim.MaxTarBytes {
		return fail(CodeTooLarge, "the input is over %d bytes", lim.MaxTarBytes)
	}
	return unpack(data, cfg)
}

func unpack(data []byte, cfg Config) error {
	lim := cfg.Limits
	tr := tar.NewReader(bytes.NewReader(data))
	seen := map[string]bool{}
	isDir := map[string]bool{}
	var total int64
	count := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fail(CodeUnexpectedEnd, "the archive cannot be read")
		}
		count++
		if count > lim.MaxEntries {
			return fail(CodeTooLarge, "more than %d entries", lim.MaxEntries)
		}
		name := strings.TrimSuffix(h.Name, "/")
		if err := checkName(name, lim.MaxPathBytes); err != nil {
			return fail(CodeUnsafe, "an entry has an unusable name")
		}
		if seen[name] {
			return fail(CodeMalformed, "an entry is repeated")
		}
		seen[name] = true
		target := filepath.Join(cfg.Dest, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			isDir[name] = true
			if err := mkdirAll(cfg.Dest, path.Dir(name), isDir); err != nil {
				return err
			}
			if err := os.Mkdir(target, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
				return fail(CodeWrite, "a directory cannot be made")
			}
			isDir[name] = true
		case tar.TypeReg:
			if h.Size < 0 || h.Size > lim.MaxFileBytes {
				return fail(CodeTooLarge, "a file is over %d bytes", lim.MaxFileBytes)
			}
			total += h.Size
			if total > lim.MaxTotalBytes {
				return fail(CodeTooLarge, "the files are over %d bytes", lim.MaxTotalBytes)
			}
			mode := os.FileMode(0o644)
			if h.Mode&0o111 != 0 {
				mode = 0o755
			}
			if err := mkdirAll(cfg.Dest, path.Dir(name), isDir); err != nil {
				return err
			}
			if err := writeFile(target, tr, h.Size, mode); err != nil {
				return err
			}
		default:
			return fail(CodeUnsafe, "an entry is not a file or a directory")
		}
	}
}

// checkName requires a clean relative path of plain elements.
func checkName(name string, max int) error {
	if name == "" || len(name) > max || strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\\\x00") || path.Clean(name) != name {
		return errors.New("bad name")
	}
	for _, e := range strings.Split(name, "/") {
		if e == "" || e == "." || e == ".." {
			return errors.New("bad name")
		}
	}
	return nil
}

// mkdirAll makes the directories above a path that the archive did not list.
func mkdirAll(dest, dir string, made map[string]bool) error {
	if dir == "." || made[dir] {
		return nil
	}
	if err := mkdirAll(dest, path.Dir(dir), made); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(dest, filepath.FromSlash(dir)), 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return fail(CodeWrite, "a directory cannot be made")
	}
	made[dir] = true
	return nil
}

// writeFile creates a new file and copies exactly size bytes into it. A link
// at the path, or a file that exists, is refused.
func writeFile(target string, r io.Reader, size int64, mode os.FileMode) error {
	fd, err := syscall.Open(target, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, uint32(mode))
	if err != nil {
		return fail(CodeWrite, "a file cannot be created")
	}
	f := os.NewFile(uintptr(fd), "input")
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(r, size+1))
	if err != nil || n != size {
		return fail(CodeUnexpectedEnd, "a file is cut short")
	}
	if err := f.Chmod(mode); err != nil {
		return fail(CodeWrite, "a file cannot be set up")
	}
	return nil
}
