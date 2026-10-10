package worker

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The program in the work container does not write the result to disk. It
// packs it as a tar in memory and prints it on its standard output as one
// text block, which the main process reads back from the container's log:
//
//	KESTRELYNX-WORKER-RESULT <version> <tar bytes> <tar sha256, lowercase hex>\n
//	<tar in standard base64, 76 characters per line>\n
//	KESTRELYNX-WORKER-END\n
//
// Base64 and short lines keep the block intact through a log driver that
// mangles non-UTF-8 bytes and splits long lines. Nothing else is written to
// standard output; diagnostics go to standard error.
const (
	ResultBlockStart = "KESTRELYNX-WORKER-RESULT"
	ResultBlockEnd   = "KESTRELYNX-WORKER-END"
	resultLineWidth  = 76
)

// ResultLimits bound what DecodeResult accepts from an untrusted block.
type ResultLimits struct {
	// MaxTarBytes is the largest tar, before base64.
	MaxTarBytes int64
	// MaxFileBytes and MaxTotalBytes bound one file and the sum of all files.
	MaxFileBytes  int64
	MaxTotalBytes int64
	// MaxEntries bounds files and directories together.
	MaxEntries int
}

// MaxResultEntries is the most files and directories a result may hold.
const MaxResultEntries = 1024

// DefaultResultLimits are the limits the main process applies. The total
// covers result.json and every collected copy.
func DefaultResultLimits() ResultLimits {
	total := int64(MaxOutTotalBytes + MaxResultBytes)
	return ResultLimits{
		MaxTarBytes:   total + MaxResultEntries*2048,
		MaxFileBytes:  MaxOutputFileBytes,
		MaxTotalBytes: total,
		MaxEntries:    MaxResultEntries,
	}
}

// validResultPath reports why name is not an acceptable relative path.
func validResultPath(name string) error {
	switch {
	case name == "" || name == "." || len(name) > 255:
		return fmt.Errorf("path %q has a bad length", name)
	case strings.HasPrefix(name, "/"):
		return fmt.Errorf("path %q is absolute", name)
	case path.Clean(name) != name:
		return fmt.Errorf("path %q is not clean", name)
	case name == "..", strings.HasPrefix(name, "../"):
		return fmt.Errorf("path %q leaves the result", name)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return fmt.Errorf("path %q has an unusable character", name)
		}
	}
	return nil
}

// EncodeResult packs files (paths relative to the result root) into the
// standard-output block. Directories are added as needed, in a fixed order, so
// equal input gives equal bytes.
func EncodeResult(files map[string][]byte) ([]byte, error) {
	names := make([]string, 0, len(files))
	dirs := map[string]bool{}
	for name := range files {
		if err := validResultPath(name); err != nil {
			return nil, err
		}
		names = append(names, name)
		for d := path.Dir(name); d != "."; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	for name := range files {
		if dirs[name] {
			return nil, fmt.Errorf("path %q is both a file and a directory", name)
		}
	}
	var all []string
	for d := range dirs {
		all = append(all, d)
	}
	all = append(all, names...)
	sort.Strings(all)

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for _, name := range all {
		h := &tar.Header{Name: name, ModTime: time.Unix(0, 0), Format: tar.FormatPAX}
		if dirs[name] {
			h.Typeflag, h.Name, h.Mode = tar.TypeDir, name+"/", 0o755
		} else {
			h.Typeflag, h.Mode, h.Size = tar.TypeReg, 0o644, int64(len(files[name]))
		}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if !dirs[name] {
			if _, err := tw.Write(files[name]); err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(tarBuf.Bytes())
	b64 := base64.StdEncoding.EncodeToString(tarBuf.Bytes())

	var out bytes.Buffer
	fmt.Fprintf(&out, "%s %d %d %s\n", ResultBlockStart, ProtocolVersion, tarBuf.Len(), hex.EncodeToString(sum[:]))
	for len(b64) > 0 {
		n := resultLineWidth
		if len(b64) < n {
			n = len(b64)
		}
		out.WriteString(b64[:n])
		out.WriteByte('\n')
		b64 = b64[n:]
	}
	out.WriteString(ResultBlockEnd + "\n")
	return out.Bytes(), nil
}

// DecodeResult reads the block from a container's standard output, which is
// untrusted. The output must be exactly one block: the header line, the base64
// lines, the end line and nothing before, between or after. The tar must match
// the announced length and hash and hold only regular files and directories.
// The returned map is keyed by relative path.
func DecodeResult(stdout []byte, lim ResultLimits) (map[string][]byte, error) {
	nl := bytes.IndexByte(stdout, '\n')
	if nl < 0 {
		return nil, errors.New("result block has no header line")
	}
	fields := strings.Split(string(stdout[:nl]), " ")
	if len(fields) != 4 || fields[0] != ResultBlockStart {
		return nil, errors.New("result block header is malformed")
	}
	if fields[1] != strconv.Itoa(ProtocolVersion) {
		return nil, fmt.Errorf("result block version %q is not %d", fields[1], ProtocolVersion)
	}
	tarLen, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || strconv.FormatInt(tarLen, 10) != fields[2] || tarLen <= 0 || tarLen > lim.MaxTarBytes {
		return nil, errors.New("result block length is invalid or over the limit")
	}
	wantSum := fields[3]
	if len(wantSum) != 64 || strings.ToLower(wantSum) != wantSum {
		return nil, errors.New("result block hash is malformed")
	}
	if _, err := hex.DecodeString(wantSum); err != nil {
		return nil, errors.New("result block hash is malformed")
	}

	// The whole block length follows from the tar length, so a block with
	// extra or missing bytes is refused before it is decoded.
	b64Len := (tarLen + 2) / 3 * 4
	lines := (b64Len + resultLineWidth - 1) / resultLineWidth
	want := int64(nl+1) + b64Len + lines + int64(len(ResultBlockEnd)+1)
	if int64(len(stdout)) != want {
		return nil, errors.New("result block has the wrong size")
	}
	body := stdout[nl+1:]
	if !bytes.HasSuffix(body, []byte(ResultBlockEnd+"\n")) {
		return nil, errors.New("result block has no end line")
	}
	body = body[:len(body)-len(ResultBlockEnd)-1]
	var b64 bytes.Buffer
	for i := int64(0); i < lines; i++ {
		end := bytes.IndexByte(body, '\n')
		if end < 0 {
			return nil, errors.New("result block line is unterminated")
		}
		line := body[:end]
		if i < lines-1 && len(line) != resultLineWidth || len(line) == 0 || len(line) > resultLineWidth {
			return nil, errors.New("result block line has the wrong width")
		}
		b64.Write(line)
		body = body[end+1:]
	}
	if len(body) != 0 || int64(b64.Len()) != b64Len {
		return nil, errors.New("result block body is malformed")
	}
	tarBytes, err := base64.StdEncoding.Strict().DecodeString(b64.String())
	if err != nil {
		return nil, fmt.Errorf("result block is not valid base64: %w", err)
	}
	if int64(len(tarBytes)) != tarLen {
		return nil, errors.New("result block tar length does not match its header")
	}
	if sum := sha256.Sum256(tarBytes); hex.EncodeToString(sum[:]) != wantSum {
		return nil, errors.New("result block tar hash does not match its header")
	}
	return readResultTar(tarBytes, lim)
}

// readResultTar reads the tar strictly: regular files and directories only,
// relative clean unique paths, no file below another file, the limits held,
// and nothing but zero padding after the end of the archive.
func readResultTar(data []byte, lim ResultLimits) (map[string][]byte, error) {
	r := bytes.NewReader(data)
	tr := tar.NewReader(r)
	files := map[string][]byte{}
	dirs := map[string]bool{}
	seen := map[string]bool{}
	var total int64
	entries := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read result tar: %w", err)
		}
		entries++
		if entries > lim.MaxEntries {
			return nil, fmt.Errorf("result has more than %d entries", lim.MaxEntries)
		}
		isDir := h.Typeflag == tar.TypeDir
		if h.Typeflag != tar.TypeReg && !isDir {
			return nil, fmt.Errorf("result entry %q has unsupported type %q", h.Name, string(h.Typeflag))
		}
		name := h.Name
		if isDir {
			name = strings.TrimSuffix(name, "/")
		}
		if err := validResultPath(name); err != nil {
			return nil, fmt.Errorf("result entry: %w", err)
		}
		if seen[name] {
			return nil, fmt.Errorf("result entry %q is duplicated", name)
		}
		seen[name] = true
		if isDir {
			dirs[name] = true
			continue
		}
		if h.Size < 0 || h.Size > lim.MaxFileBytes {
			return nil, fmt.Errorf("result file %q is %d bytes, over the %d byte limit", name, h.Size, lim.MaxFileBytes)
		}
		total += h.Size
		if total > lim.MaxTotalBytes {
			return nil, fmt.Errorf("result exceeds %d bytes", lim.MaxTotalBytes)
		}
		content, err := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if err != nil {
			return nil, fmt.Errorf("read result file %q: %w", name, err)
		}
		if int64(len(content)) != h.Size {
			return nil, fmt.Errorf("result file %q length does not match its header", name)
		}
		files[name] = content
	}
	rest, _ := io.ReadAll(r)
	for _, b := range rest {
		if b != 0 {
			return nil, errors.New("result tar has data after its end")
		}
	}
	// Checked after the whole archive is read, so the order of the entries
	// does not matter: no path is both a file and a directory, and no file or
	// directory sits below a file.
	for f := range files {
		if dirs[f] {
			return nil, fmt.Errorf("result path %q is both a file and a directory", f)
		}
		for d := path.Dir(f); d != "."; d = path.Dir(d) {
			if _, isFile := files[d]; isFile {
				return nil, fmt.Errorf("result file %q is below file %q", f, d)
			}
		}
	}
	for dir := range dirs {
		for d := path.Dir(dir); d != "."; d = path.Dir(d) {
			if _, isFile := files[d]; isFile {
				return nil, fmt.Errorf("result directory %q is below file %q", dir, d)
			}
		}
	}
	return files, nil
}
