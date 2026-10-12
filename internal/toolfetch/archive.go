package toolfetch

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

// countLimit reads at most n bytes and then fails, so a stream that expands
// past its limit stops instead of being read to the end.
type countLimit struct {
	r io.Reader
	n int64
}

func (c *countLimit) Read(p []byte) (int, error) {
	if c.n <= 0 {
		return 0, errTooLarge
	}
	if int64(len(p)) > c.n {
		p = p[:c.n]
	}
	k, err := c.r.Read(p)
	c.n -= int64(k)
	return k, err
}

// archiveInfo is what listing an archive found.
type archiveInfo struct {
	expanded int64
	files    int
}

// inspectTgz lists an npm tarball without writing anything out: it checks
// that the stream expands within the limits, holds only files and
// directories under a leading package/ directory, and has the entry as a
// regular file. entry is the name with package/ removed.
func inspectTgz(file, entry string) (archiveInfo, error) {
	var info archiveInfo
	f, err := os.Open(file)
	if err != nil {
		return info, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return info, fmt.Errorf("not a gzip stream: %w", err)
	}
	defer zr.Close()
	lr := &countLimit{r: zr, n: maxExpanded}
	tr := tar.NewReader(lr)
	found := false
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, errTooLarge) {
			return info, fmt.Errorf("expands to more than %d bytes", int64(maxExpanded))
		}
		if err != nil {
			return info, fmt.Errorf("not a tar stream: %w", err)
		}
		if info.files++; info.files > maxArchiveFile {
			return info, fmt.Errorf("holds more than %d files", maxArchiveFile)
		}
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeDir:
		case tar.TypeXGlobalHeader:
			continue
		default:
			return info, fmt.Errorf("%q is neither a file nor a directory", h.Name)
		}
		rel, ok := strings.CutPrefix(h.Name, "package/")
		if !ok && strings.TrimSuffix(h.Name, "/") != "package" {
			return info, fmt.Errorf("%q is outside the package/ directory", h.Name)
		}
		if rel != "" && (path.Clean(rel) != strings.TrimSuffix(rel, "/") || path.IsAbs(rel) || strings.HasPrefix(rel, "../")) {
			return info, fmt.Errorf("%q is not a clean relative path", h.Name)
		}
		if h.Size < 0 {
			return info, fmt.Errorf("%q has a negative size", h.Name)
		}
		info.expanded += h.Size
		if info.expanded > maxExpanded {
			return info, fmt.Errorf("expands to more than %d bytes", int64(maxExpanded))
		}
		if h.Typeflag == tar.TypeReg && rel == entry {
			if found {
				return info, fmt.Errorf("%q appears twice", entry)
			}
			found = true
		}
	}
	if !found {
		return info, fmt.Errorf("has no %q", entry)
	}
	return info, nil
}

// inspectWheel lists a wheel the same way: the declared sizes of its members
// stay within the limits and entry is a regular file.
func inspectWheel(file, entry string) (archiveInfo, error) {
	var info archiveInfo
	zr, err := zip.OpenReader(file)
	if err != nil {
		return info, fmt.Errorf("not a zip file: %w", err)
	}
	defer zr.Close()
	if len(zr.File) > maxArchiveFile {
		return info, fmt.Errorf("holds %d files, over %d", len(zr.File), maxArchiveFile)
	}
	found := false
	for _, m := range zr.File {
		info.files++
		if info.expanded += int64(m.UncompressedSize64); info.expanded > maxExpanded || m.UncompressedSize64 > maxExpanded {
			return info, fmt.Errorf("expands to more than %d bytes", int64(maxExpanded))
		}
		if m.Name == entry {
			if found {
				return info, fmt.Errorf("%q appears twice", entry)
			}
			if !m.Mode().IsRegular() {
				return info, fmt.Errorf("%q is not a regular file", entry)
			}
			found = true
		}
	}
	if !found {
		return info, fmt.Errorf("has no %q", entry)
	}
	return info, nil
}
