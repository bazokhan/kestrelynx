//go:build unix

package receive

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type entry struct {
	name, body string
	typ        byte
	mode       int64
	link       string
}

func makeTar(t *testing.T, es ...entry) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range es {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		h := &tar.Header{Name: e.name, Typeflag: typ, Mode: mode, Linkname: e.link}
		if typ == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	return b.Bytes()
}

func testConfig(t *testing.T) Config {
	t.Helper()
	c := DefaultConfig()
	c.Dest = t.TempDir()
	c.TerminationPath = ""
	c.Limits = Limits{MaxTarBytes: 1 << 20, MaxFileBytes: 1 << 16, MaxTotalBytes: 1 << 17, MaxEntries: 8, MaxPathBytes: 64}
	return c
}

func codeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestUnpacksFilesAndDirectories(t *testing.T) {
	c := testConfig(t)
	in := makeTar(t,
		entry{name: "job.json", body: `{}`},
		entry{name: "bin/", typ: tar.TypeDir},
		entry{name: "bin/prog", body: "elf", mode: 0o755},
		entry{name: "src/deep/lock.json", body: "lock"},
	)
	if err := Run(bytes.NewReader(in), c); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{"job.json": "{}", "bin/prog": "elf", "src/deep/lock.json": "lock"} {
		got, err := os.ReadFile(filepath.Join(c.Dest, path))
		if err != nil || string(got) != want {
			t.Errorf("%s: %q %v", path, got, err)
		}
	}
	if st, _ := os.Stat(filepath.Join(c.Dest, "bin/prog")); st.Mode().Perm() != 0o755 {
		t.Errorf("program mode %v", st.Mode())
	}
	if st, _ := os.Stat(filepath.Join(c.Dest, "job.json")); st.Mode().Perm() != 0o644 {
		t.Errorf("file mode %v", st.Mode())
	}
}

func TestRefusesUnsafeInput(t *testing.T) {
	cases := map[string]struct {
		in   []byte
		code string
	}{
		"parent path":    {makeTar(t, entry{name: "../x", body: "a"}), CodeUnsafe},
		"absolute path":  {makeTar(t, entry{name: "/etc/x", body: "a"}), CodeUnsafe},
		"dot element":    {makeTar(t, entry{name: "a/./b", body: "a"}), CodeUnsafe},
		"unclean":        {makeTar(t, entry{name: "a//b", body: "a"}), CodeUnsafe},
		"backslash":      {makeTar(t, entry{name: `a\b`, body: "a"}), CodeUnsafe},
		"symlink":        {makeTar(t, entry{name: "l", typ: tar.TypeSymlink, link: "/etc"}), CodeUnsafe},
		"hardlink":       {makeTar(t, entry{name: "l", typ: tar.TypeLink, link: "x"}), CodeUnsafe},
		"device":         {makeTar(t, entry{name: "d", typ: tar.TypeChar}), CodeUnsafe},
		"fifo":           {makeTar(t, entry{name: "f", typ: tar.TypeFifo}), CodeUnsafe},
		"repeated":       {makeTar(t, entry{name: "a", body: "1"}, entry{name: "a", body: "2"}), CodeMalformed},
		"file over file": {makeTar(t, entry{name: "a", body: "1"}, entry{name: "a/b", body: "2"}), CodeWrite},
		"long path":      {makeTar(t, entry{name: strings.Repeat("a", 65), body: "1"}), CodeUnsafe},
		"big file":       {makeTar(t, entry{name: "a", body: strings.Repeat("x", 1<<16+1)}), CodeTooLarge},
		"big total": {makeTar(t, entry{name: "a", body: strings.Repeat("x", 1<<16)}, entry{name: "b", body: strings.Repeat("x", 1<<16)},
			entry{name: "c", body: "x"}), CodeTooLarge},
		"many entries": {makeTar(t, entry{name: "1"}, entry{name: "2"}, entry{name: "3"}, entry{name: "4"}, entry{name: "5"},
			entry{name: "6"}, entry{name: "7"}, entry{name: "8"}, entry{name: "9"}), CodeTooLarge},
		"cut short":  {makeTar(t, entry{name: "a", body: strings.Repeat("x", 4000)})[:1000], CodeUnexpectedEnd},
		"over limit": {bytes.Repeat([]byte{0}, 1<<20+1), CodeTooLarge},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := testConfig(t)
			err := Run(bytes.NewReader(tc.in), c)
			if err == nil {
				t.Fatal("accepted")
			}
			if got := codeOf(err); got != tc.code {
				t.Errorf("code %q (%v), want %q", got, err, tc.code)
			}
		})
	}
}

func TestStatusCodesAreFixedWords(t *testing.T) {
	// A refusal never carries a name or content from the input.
	c := testConfig(t)
	err := Run(bytes.NewReader(makeTar(t, entry{name: "../secret-name", body: "secret-content"})), c)
	if err == nil {
		t.Fatal("accepted")
	}
	if strings.Contains(codeOf(err), "secret") {
		t.Errorf("the code %q holds input", codeOf(err))
	}
}

func TestRefusesANonEmptyOrMissingDestination(t *testing.T) {
	c := testConfig(t)
	os.WriteFile(filepath.Join(c.Dest, "old"), []byte("x"), 0o600)
	if err := Run(bytes.NewReader(makeTar(t)), c); codeOf(err) != CodeDestination {
		t.Errorf("non-empty: %v", err)
	}
	c.Dest = filepath.Join(c.Dest, "missing")
	if err := Run(bytes.NewReader(makeTar(t)), c); codeOf(err) != CodeDestination {
		t.Errorf("missing: %v", err)
	}
}

func TestRefusesWhenTheTerminationFileCanBeOpened(t *testing.T) {
	c := testConfig(t)
	c.TerminationPath = filepath.Join(t.TempDir(), "receive")
	if err := os.WriteFile(c.TerminationPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(bytes.NewReader(makeTar(t)), c); codeOf(err) != CodeTermination {
		t.Errorf("openable: %v", err)
	}
	c.TerminationPath = filepath.Join(t.TempDir(), "absent", "receive")
	if err := Run(bytes.NewReader(makeTar(t)), c); err != nil {
		t.Errorf("unreachable: %v", err)
	}
}
