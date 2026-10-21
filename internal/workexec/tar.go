package workexec

import (
	"archive/tar"
	"bytes"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// Input entries are owned by root and not writable by the job user (uid
// 10001), so a job can read /work but cannot grow it: the host's disk is only
// consumed through the capped log and the tmpfs mounts.
var (
	modeFile int64 = 0o644
	modeDir  int64 = 0o755
	modeExec int64 = 0o755
	TarMtime       = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
)

// capWriter accumulates bytes and fails as soon as the total would exceed
// max, so an oversized archive is refused while it is being built.
type capWriter struct {
	buf bytes.Buffer
	max int64
}

func (w *capWriter) Write(p []byte) (int, error) {
	if int64(w.buf.Len())+int64(len(p)) > w.max {
		return 0, fmt.Errorf("input archive is over the %d byte limit", w.max)
	}
	return w.buf.Write(p)
}

// ValidRelPath checks a path that must stay inside its base directory:
// non-empty, relative, clean, no "." or ".." elements, no backslash or NUL.
func ValidRelPath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\\x00") {
		return fmt.Errorf("path %q is empty, absolute or contains a forbidden character", p)
	}
	if path.Clean(p) != p {
		return fmt.Errorf("path %q is not clean", p)
	}
	for _, e := range strings.Split(p, "/") {
		if e == "." || e == ".." || e == "" {
			return fmt.Errorf("path %q has an invalid element", p)
		}
	}
	return nil
}

// BuildInputTar builds the archive of a job's input files: the files below
// root (a "root/" directory entry first; with an empty root the paths are
// relative and there is no directory entry for it), every entry owned by root
// with a fixed mode and mtime. Intermediate directories are added automatically.
// Duplicate or conflicting paths are rejected.
func BuildInputTar(inputs []InputFile, lim TransferLimits, root string) ([]byte, error) {
	// Input files, tool archives and the program count against separate
	// limits; the whole archive is bounded below.
	var count, size [3]int64
	maxFiles := [3]int64{int64(lim.MaxInputFiles), 2, 1}
	maxBytes := [3]int64{lim.MaxInputBytes, lim.MaxToolBytes, lim.MaxProgramBytes}
	what := [3]string{"input", "tool archive", "program"}
	if len(inputs) > lim.MaxInputFiles+int(maxFiles[1]+maxFiles[2]) {
		return nil, fmt.Errorf("input has %d files, over the %d file limit", len(inputs), lim.MaxInputFiles)
	}
	files := map[string][]byte{}
	exec := map[string]bool{}
	dirs := map[string]bool{}
	for _, in := range inputs {
		if in.Kind < KindInput || in.Kind > KindProgram {
			return nil, fmt.Errorf("input %q has an unknown kind", in.Path)
		}
		if in.Executable && in.Kind != KindProgram {
			return nil, fmt.Errorf("input %q: only the program may be executable", in.Path)
		}
		if err := ValidRelPath(in.Path); err != nil {
			return nil, fmt.Errorf("input: %w", err)
		}
		if len(in.Path) > lim.MaxInputPathBytes {
			return nil, fmt.Errorf("input path of %d bytes is over the %d byte limit", len(in.Path), lim.MaxInputPathBytes)
		}
		if _, dup := files[in.Path]; dup {
			return nil, fmt.Errorf("input: duplicate path %q", in.Path)
		}
		k := in.Kind
		count[k]++
		size[k] += int64(len(in.Content))
		if count[k] > maxFiles[k] {
			return nil, fmt.Errorf("%s: %d files are over the %d file limit", what[k], count[k], maxFiles[k])
		}
		if size[k] > maxBytes[k] {
			return nil, fmt.Errorf("%s exceeds %d bytes", what[k], maxBytes[k])
		}
		files[in.Path] = in.Content
		exec[in.Path] = in.Executable
		for d := path.Dir(in.Path); d != "."; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	for f := range files {
		if dirs[f] {
			return nil, fmt.Errorf("input: %q is both a file and a directory", f)
		}
	}
	var names []string
	for d := range dirs {
		names = append(names, d)
	}
	for f := range files {
		names = append(names, f)
	}
	sort.Strings(names)

	prefix := ""
	if root != "" {
		prefix = root + "/"
	}
	buf := &capWriter{max: lim.MaxInputTarBytes}
	tw := tar.NewWriter(buf)
	put := func(name string, dir bool, content []byte) error {
		h := &tar.Header{Name: name, Uid: 0, Gid: 0, ModTime: TarMtime, Format: tar.FormatPAX}
		if dir {
			h.Typeflag, h.Mode, h.Name = tar.TypeDir, modeDir, name+"/"
		} else {
			h.Typeflag, h.Mode, h.Size = tar.TypeReg, modeFile, int64(len(content))
			if exec[strings.TrimPrefix(name, prefix)] {
				h.Mode = modeExec
			}
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		_, err := tw.Write(content)
		return err
	}
	if root != "" {
		if err := put(root, true, nil); err != nil {
			return nil, err
		}
	}
	for _, n := range names {
		var err error
		if dirs[n] {
			err = put(prefix+n, true, nil)
		} else {
			err = put(prefix+n, false, files[n])
		}
		if err != nil {
			return nil, fmt.Errorf("write input tar: %w", err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("write input tar: %w", err)
	}
	return buf.buf.Bytes(), nil
}
