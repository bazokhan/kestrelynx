package worker

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func sampleFiles() map[string][]byte {
	return map[string][]byte{
		"result.json":               []byte(`{"status":"completed"}` + "\n"),
		"steps/relock/package.json": []byte(`{"name":"x"}`),
		"steps/relock/empty":        {},
		"final/package-lock.json":   bytes.Repeat([]byte{0, 1, 2, 255, '\n'}, 5000), // not UTF-8, not line-shaped
		"final/package.json":        []byte(`{"name":"x"}`),
	}
}

func TestResultRoundTrip(t *testing.T) {
	files := sampleFiles()
	block, err := EncodeResult(files)
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(strings.TrimSuffix(string(block), "\n"), "\n") {
		if len(line) > 76 && i > 0 {
			t.Fatalf("line %d is %d characters", i, len(line))
		}
	}
	got, err := DecodeResult(block, DefaultResultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(files) {
		t.Fatalf("got %d files, want %d", len(got), len(files))
	}
	for k, v := range files {
		if !bytes.Equal(got[k], v) {
			t.Errorf("%s differs", k)
		}
	}
	again, _ := EncodeResult(files)
	if !bytes.Equal(block, again) {
		t.Error("encoding is not deterministic")
	}
}

// forge builds a block around arbitrary tar bytes, with the header and lines
// as the format requires, so a test can vary one thing at a time.
func forge(tarBytes []byte, mutate func(header *string, lines *[]string)) []byte {
	sum := sha256.Sum256(tarBytes)
	header := fmt.Sprintf("%s %d %d %s", ResultBlockStart, ProtocolVersion, len(tarBytes), hex.EncodeToString(sum[:]))
	b64 := base64.StdEncoding.EncodeToString(tarBytes)
	var lines []string
	for len(b64) > 0 {
		n := 76
		if len(b64) < n {
			n = len(b64)
		}
		lines = append(lines, b64[:n])
		b64 = b64[n:]
	}
	if mutate != nil {
		mutate(&header, &lines)
	}
	return []byte(header + "\n" + strings.Join(lines, "\n") + "\n" + ResultBlockEnd + "\n")
}

func makeTar(entries ...tar.Header) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range entries {
		h := h
		if h.Typeflag == tar.TypeReg {
			h.Size = 3
		}
		tw.WriteHeader(&h)
		if h.Typeflag == tar.TypeReg {
			tw.Write([]byte("abc"))
		}
	}
	tw.Close()
	return buf.Bytes()
}

func TestDecodeResultRefusals(t *testing.T) {
	good, err := EncodeResult(sampleFiles())
	if err != nil {
		t.Fatal(err)
	}
	s := string(good)
	lim := DefaultResultLimits()
	goodTar := makeTar(tar.Header{Name: "a", Typeflag: tar.TypeReg, Mode: 0o644})

	cases := map[string][]byte{
		"empty":              nil,
		"leading byte":       []byte("x" + s),
		"leading newline":    []byte("\n" + s),
		"trailing byte":      []byte(s + "x"),
		"trailing newline":   []byte(s + "\n"),
		"two blocks":         []byte(s + s),
		"no end line":        []byte(strings.TrimSuffix(s, ResultBlockEnd+"\n")),
		"end line altered":   []byte(strings.Replace(s, ResultBlockEnd, "KESTRELYNX-WORKER-ENDX", 1)),
		"no final newline":   []byte(strings.TrimSuffix(s, "\n")),
		"crlf":               []byte(strings.ReplaceAll(s, "\n", "\r\n")),
		"wrong magic":        []byte(strings.Replace(s, ResultBlockStart, "KESTRELYNX-WORKER-RESULTS", 1)),
		"wrong version":      []byte(strings.Replace(s, fmt.Sprintf("%s %d ", ResultBlockStart, ProtocolVersion), fmt.Sprintf("%s %d ", ResultBlockStart, ProtocolVersion+1), 1)),
		"extra header field": []byte(strings.Replace(s, "\n", " extra\n", 1)),
		"length plus sign": forge(goodTar, func(h *string, _ *[]string) {
			*h = strings.Replace(*h, fmt.Sprintf(" %d ", len(goodTar)), fmt.Sprintf(" +%d ", len(goodTar)), 1)
		}),
		"length leading zero": forge(goodTar, func(h *string, _ *[]string) {
			*h = strings.Replace(*h, fmt.Sprintf(" %d ", len(goodTar)), fmt.Sprintf(" 0%d ", len(goodTar)), 1)
		}),
		"length too small": forge(goodTar, func(h *string, _ *[]string) {
			*h = strings.Replace(*h, fmt.Sprintf(" %d ", len(goodTar)), fmt.Sprintf(" %d ", len(goodTar)-1), 1)
		}),
		"length too large": forge(goodTar, func(h *string, _ *[]string) {
			*h = strings.Replace(*h, fmt.Sprintf(" %d ", len(goodTar)), fmt.Sprintf(" %d ", len(goodTar)+3), 1)
		}),
		"length over limit": forge(goodTar, func(h *string, _ *[]string) {
			*h = strings.Replace(*h, fmt.Sprintf(" %d ", len(goodTar)), fmt.Sprintf(" %d ", lim.MaxTarBytes+1), 1)
		}),
		"hash uppercase": forge(goodTar, func(h *string, _ *[]string) {
			f := strings.Split(*h, " ")
			f[3] = strings.ToUpper(f[3])
			*h = strings.Join(f, " ")
		}),
		"hash wrong": forge(goodTar, func(h *string, _ *[]string) {
			f := strings.Split(*h, " ")
			f[3] = strings.Repeat("0", 64)
			*h = strings.Join(f, " ")
		}),
		"hash short": forge(goodTar, func(h *string, _ *[]string) { f := strings.Split(*h, " "); f[3] = f[3][:60]; *h = strings.Join(f, " ") }),
		"hash not hex": forge(goodTar, func(h *string, _ *[]string) {
			f := strings.Split(*h, " ")
			f[3] = strings.Repeat("g", 64)
			*h = strings.Join(f, " ")
		}),
		"broken base64": forge(goodTar, func(_ *string, l *[]string) { (*l)[0] = "!" + (*l)[0][1:] }),
		"padding bits set": forge(append(append([]byte(nil), goodTar...), make([]byte, 512)...), func(_ *string, l *[]string) {
			last := (*l)[len(*l)-1]
			(*l)[len(*l)-1] = last[:len(last)-2] + "B="
		}),
		"short middle line": forge(sampleTar(), func(_ *string, l *[]string) { (*l)[0] = (*l)[0][:70]; (*l)[1] = (*l)[0][:0] + (*l)[1] }),
		"empty line":        forge(sampleTar(), func(_ *string, l *[]string) { *l = append((*l)[:1], append([]string{""}, (*l)[1:]...)...) }),
		"space in line":     forge(goodTar, func(_ *string, l *[]string) { (*l)[0] = " " + (*l)[0][1:] }),
	}
	for name, in := range cases {
		if _, err := DecodeResult(in, lim); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := DecodeResult(good, lim); err != nil {
		t.Errorf("control block refused: %v", err)
	}
}

func sampleTar() []byte {
	block, _ := EncodeResult(sampleFiles())
	lines := strings.Split(strings.TrimSuffix(string(block), "\n"), "\n")
	raw, _ := base64.StdEncoding.DecodeString(strings.Join(lines[1:len(lines)-1], ""))
	return raw
}

func TestDecodeResultTarRefusals(t *testing.T) {
	lim := DefaultResultLimits()
	reg := func(name string) tar.Header { return tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644} }
	dir := func(name string) tar.Header { return tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0o755} }
	cases := map[string][]byte{
		"symlink":                makeTar(tar.Header{Name: "l", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}),
		"hard link":              makeTar(reg("a"), tar.Header{Name: "b", Typeflag: tar.TypeLink, Linkname: "a"}),
		"fifo":                   makeTar(tar.Header{Name: "f", Typeflag: tar.TypeFifo}),
		"char device":            makeTar(tar.Header{Name: "c", Typeflag: tar.TypeChar}),
		"absolute path":          makeTar(reg("/etc/passwd")),
		"parent path":            makeTar(reg("../a")),
		"nested parent":          makeTar(reg("a/../../b")),
		"dot path":               makeTar(reg("./a")),
		"double slash":           makeTar(reg("a//b")),
		"backslash":              makeTar(reg("a\\b")),
		"control char":           makeTar(reg("a\x01b")),
		"empty name":             makeTar(reg("")),
		"dot file":               makeTar(reg(".")),
		"dot directory":          makeTar(dir(".")),
		"file then dir below it": makeTar(reg("a"), dir("a/b")),
		"dir below it then file": makeTar(dir("a/b"), reg("a")),
		"deep dir below file":    makeTar(reg("a"), dir("a/b/c")),
		"duplicate":              makeTar(reg("a"), reg("a")),
		"file then dir":          makeTar(reg("a"), dir("a")),
		"dir then file":          makeTar(dir("a"), reg("a")),
		"file below file":        makeTar(reg("a"), reg("a/b")),
		"global header":          makeTar(tar.Header{Name: "g", Typeflag: tar.TypeXGlobalHeader, PAXRecords: map[string]string{"comment": "x"}}),
	}
	for name, tb := range cases {
		if _, err := DecodeResult(forge(tb, nil), lim); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// data after the end of the archive
	trailing := append(makeTar(reg("a")), []byte("not zero")...)
	if _, err := DecodeResult(forge(trailing, nil), lim); err == nil {
		t.Error("data after the tar accepted")
	}
	zeros := append(makeTar(reg("a")), make([]byte, 2048)...)
	if _, err := DecodeResult(forge(zeros, nil), lim); err != nil {
		t.Errorf("zero padding refused: %v", err)
	}

	// limits
	small := ResultLimits{MaxTarBytes: lim.MaxTarBytes, MaxFileBytes: 2, MaxTotalBytes: 1000, MaxEntries: 10}
	if _, err := DecodeResult(forge(makeTar(reg("a")), nil), small); err == nil {
		t.Error("file over the per-file limit accepted")
	}
	small = ResultLimits{MaxTarBytes: lim.MaxTarBytes, MaxFileBytes: 10, MaxTotalBytes: 5, MaxEntries: 10}
	if _, err := DecodeResult(forge(makeTar(reg("a"), reg("b")), nil), small); err == nil {
		t.Error("total over the limit accepted")
	}
	small = ResultLimits{MaxTarBytes: lim.MaxTarBytes, MaxFileBytes: 10, MaxTotalBytes: 1000, MaxEntries: 2}
	if _, err := DecodeResult(forge(makeTar(reg("a"), reg("b"), reg("c")), nil), small); err == nil {
		t.Error("too many entries accepted")
	}
	if _, err := DecodeResult(forge(makeTar(reg("a")), nil), ResultLimits{MaxTarBytes: 100, MaxFileBytes: 10, MaxTotalBytes: 10, MaxEntries: 10}); err == nil {
		t.Error("tar over the size limit accepted")
	}
}

func TestEncodeResultRefusesBadPaths(t *testing.T) {
	for _, name := range []string{"", ".", "/a", "../a", "a/../b", "a//b", "./a", "a\\b", strings.Repeat("a", 256)} {
		if _, err := EncodeResult(map[string][]byte{name: []byte("x")}); err == nil {
			t.Errorf("%q accepted", name)
		}
	}
	if _, err := EncodeResult(map[string][]byte{"a": nil, "a/b": nil}); err == nil {
		t.Error("file and directory of the same name accepted")
	}
}
