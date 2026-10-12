//go:build unix

package runner

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// unpackLimits bound what an archive may unpack to: the number of files and
// directories together, and the bytes of all file contents.
type unpackLimits struct {
	Files int
	Bytes int64
}

const (
	unpackedFileMode  fs.FileMode = 0o644
	unpackedEntryMode fs.FileMode = 0o755
	unpackedDirMode   fs.FileMode = 0o755
)

// unpacker writes the entries of an archive below root. Only regular files and
// directories are written, with fixed modes; a name that is absolute, leaves
// the root, is repeated, or is both a file and a directory fails the whole
// unpack, as does going over a limit.
type unpacker struct {
	root     string
	entry    string
	limits   unpackLimits
	files    map[string]bool
	dirs     map[string]bool // directories, made by an entry or implied
	explicit map[string]bool // directories listed as entries
	count    int
	bytes    int64
}

func newUnpacker(root, entry string, limits unpackLimits) *unpacker {
	return &unpacker{root: root, entry: entry, limits: limits,
		files: map[string]bool{}, dirs: map[string]bool{}, explicit: map[string]bool{}}
}

func (u *unpacker) count1() error {
	u.count++
	if u.count > u.limits.Files {
		return fmt.Errorf("the archive holds more than %d entries", u.limits.Files)
	}
	return nil
}

// mkdirs makes the directories above name, refusing one that is a file.
func (u *unpacker) mkdirs(name string) error {
	dir := path.Dir(name)
	if dir == "." {
		return nil
	}
	if u.files[dir] {
		return fmt.Errorf("%q is both a file and a directory", dir)
	}
	if u.dirs[dir] {
		return nil
	}
	if err := u.mkdirs(dir); err != nil {
		return err
	}
	if err := u.count1(); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(u.root, filepath.FromSlash(dir)), unpackedDirMode); err != nil {
		return err
	}
	u.dirs[dir] = true
	return nil
}

func (u *unpacker) addDir(name string) error {
	if err := worker.ValidEntry(name); err != nil {
		return err
	}
	if u.files[name] {
		return fmt.Errorf("%q is both a file and a directory", name)
	}
	if u.explicit[name] {
		return fmt.Errorf("%q is listed twice", name)
	}
	if err := u.mkdirs(name); err != nil {
		return err
	}
	u.explicit[name] = true
	if u.dirs[name] {
		return nil
	}
	if err := u.count1(); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(u.root, filepath.FromSlash(name)), unpackedDirMode); err != nil {
		return err
	}
	u.dirs[name] = true
	return nil
}

// addFile writes one regular file of the declared size read from r, and fails
// if the reader holds a different number of bytes.
func (u *unpacker) addFile(name string, size int64, r io.Reader) error {
	if err := worker.ValidEntry(name); err != nil {
		return err
	}
	if size < 0 || size > u.limits.Bytes-u.bytes {
		return fmt.Errorf("the archive unpacks to more than %d bytes", u.limits.Bytes)
	}
	if u.files[name] || u.dirs[name] {
		return fmt.Errorf("%q is listed twice or is both a file and a directory", name)
	}
	if err := u.mkdirs(name); err != nil {
		return err
	}
	if err := u.count1(); err != nil {
		return err
	}
	mode := unpackedFileMode
	if name == u.entry {
		mode = unpackedEntryMode
	}
	dst := filepath.Join(u.root, filepath.FromSlash(name))
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(r, size+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n != size {
		return fmt.Errorf("%q does not hold the %d bytes its header declares", name, size)
	}
	// The mode the file was created with is cut by the umask; set it as is.
	if err := os.Chmod(dst, mode); err != nil {
		return err
	}
	u.bytes += n
	u.files[name] = true
	return nil
}

// finish requires the entry to be one of the files written.
func (u *unpacker) finish() error {
	if !u.files[u.entry] {
		return fmt.Errorf("the archive has no file %q", u.entry)
	}
	return nil
}

// unpackNpmTgz unpacks an npm package archive, dropping the leading
// "package/" of every name.
func unpackNpmTgz(archive, root, entry string, limits unpackLimits) error {
	f, _, err := regularFile(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	// The compressed stream is bounded by the file; the unpacked one by the
	// limit, with the headers' share.
	tr := tar.NewReader(io.LimitReader(gz, limits.Bytes+int64(limits.Files)*2048+1<<20))
	u := newUnpacker(root, entry, limits)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeXGlobalHeader:
			continue
		case tar.TypeReg, tar.TypeDir:
		default:
			return fmt.Errorf("%q is not a regular file or directory", h.Name)
		}
		name := strings.TrimSuffix(h.Name, "/")
		rest, ok := strings.CutPrefix(name, "package/")
		if !ok {
			if name == "package" && h.Typeflag == tar.TypeDir {
				continue
			}
			return fmt.Errorf("%q is not under package/", h.Name)
		}
		if h.Typeflag == tar.TypeDir {
			err = u.addDir(rest)
		} else {
			err = u.addFile(rest, h.Size, tr)
		}
		if err != nil {
			return err
		}
	}
	return u.finish()
}

// unpackWheel unpacks a wheel, which is a zip archive.
func unpackWheel(archive, root, entry string, limits unpackLimits) error {
	f, fi, err := regularFile(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := zip.NewReader(f, fi.Size())
	if err != nil {
		return err
	}
	if len(zr.File) > limits.Files {
		return fmt.Errorf("the archive holds more than %d entries", limits.Files)
	}
	var total uint64
	for _, zf := range zr.File {
		total += zf.UncompressedSize64
		if total > uint64(limits.Bytes) {
			return fmt.Errorf("the archive unpacks to more than %d bytes", limits.Bytes)
		}
	}
	u := newUnpacker(root, entry, limits)
	for _, zf := range zr.File {
		mode := zf.Mode()
		name := strings.TrimSuffix(zf.Name, "/")
		switch {
		case mode&fs.ModeSymlink != 0, mode&fs.ModeType&^fs.ModeDir != 0:
			return fmt.Errorf("%q is not a regular file or directory", zf.Name)
		case mode.IsDir() || strings.HasSuffix(zf.Name, "/"):
			if err := u.addDir(name); err != nil {
				return err
			}
		default:
			rc, err := zf.Open()
			if err != nil {
				return err
			}
			err = u.addFile(name, int64(zf.UncompressedSize64), rc)
			rc.Close()
			if err != nil {
				return err
			}
		}
	}
	return u.finish()
}
