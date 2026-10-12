//go:build unix

package runner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// ---- the check of the container ----

type fakeEntry struct {
	mode     fs.FileMode
	uid      uint32
	children []string
	writable bool // Access(W_OK) succeeds
	search   bool // Access(X_OK) succeeds
	listErr  error
}

type fakeInfo struct {
	name string
	e    *fakeEntry
}

func (f fakeInfo) Name() string       { return f.name }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.e.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.e.mode.IsDir() }
func (f fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: f.e.uid} }

type fakeDirEntry struct{ fakeInfo }

func (d fakeDirEntry) Type() fs.FileMode          { return d.e.mode.Type() }
func (d fakeDirEntry) Info() (fs.FileInfo, error) { return d.fakeInfo, nil }

type fakeFS map[string]*fakeEntry

func (f fakeFS) Lstat(p string) (fs.FileInfo, error) {
	e, ok := f[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return fakeInfo{filepath.Base(p), e}, nil
}

func (f fakeFS) ReadDir(p string) ([]fs.DirEntry, error) {
	e := f[p]
	if e.listErr != nil {
		return nil, e.listErr
	}
	var out []fs.DirEntry
	for _, c := range e.children {
		out = append(out, fakeDirEntry{fakeInfo{c, f[filepath.Join(p, c)]}})
	}
	return out, nil
}

func (f fakeFS) Access(p string, mode uint32) error {
	e := f[p]
	if (mode == 2 && e.writable) || (mode == 1 && e.search) {
		return nil
	}
	return syscall.EACCES
}

func dir(children ...string) *fakeEntry {
	return &fakeEntry{mode: fs.ModeDir | 0o755, children: children}
}

// cleanImage is a small image: nothing in it is owned or writable by the job
// user, apart from the paths a tmpfs will cover.
func cleanImage() fakeFS {
	return fakeFS{
		"/":            dir("etc", "tmp", "proc", "root", "home"),
		"/etc":         dir("hosts"),
		"/etc/hosts":   {mode: 0o644},
		"/tmp":         {mode: fs.ModeDir | 0o1777, writable: true},
		"/proc":        {mode: fs.ModeDir | 0o555, writable: true},
		"/root":        {mode: fs.ModeDir | 0o700, listErr: fs.ErrPermission},
		"/home":        dir("worker"),
		"/home/worker": {mode: fs.ModeDir | 0o700, uid: 10001, writable: true},
	}
}

const goodMountInfo = `1 0 8:1 / / rw,relatime - overlay overlay rw,lowerdir=x
2 1 0:5 / /proc rw,nosuid,nodev,noexec - proc proc rw
3 1 0:6 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
4 3 0:7 / /dev/shm rw,nosuid,nodev,noexec - tmpfs shm rw,size=65536k
5 1 8:1 /etc/hosts /etc/hosts rw,relatime - ext4 /dev/sda1 rw
6 1 0:20 / /tmp rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=524288k,mode=1777
7 1 0:21 / /home/worker rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=524288k,uid=10001,gid=10001,mode=700
8 1 0:22 / /opt/kestrelynx-tools rw,nosuid,nodev,relatime - tmpfs tmpfs rw,size=262144k,uid=10001,gid=10001,mode=755
`

func checkCfg(t *testing.T, mountinfo string, fsys SelfCheckFS) *SelfCheckConfig {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(p, []byte(mountinfo), 0o600); err != nil {
		t.Fatal(err)
	}
	return &SelfCheckConfig{
		Root: "/", MountInfo: p, UID: 10001, MaxEntries: 1000, MaxTime: time.Minute, FS: fsys,
		Tmpfs: []TmpfsMount{{Path: "/tmp"}, {Path: "/home/worker"}, {Path: "/opt/kestrelynx-tools", Exec: true}},
	}
}

func TestSelfCheckAcceptsACleanContainer(t *testing.T) {
	// The unreadable 0700 directory of root, the writable tmpfs mounts and the
	// engine's mounts are all fine.
	if err := checkCfg(t, goodMountInfo, cleanImage()).selfCheck(); err != nil {
		t.Fatal(err)
	}
}

func TestSelfCheckRefuses(t *testing.T) {
	mod := func(f func(fakeFS)) fakeFS { i := cleanImage(); f(i); return i }
	cases := map[string]struct {
		mounts string
		fsys   fakeFS
		want   string
	}{
		"writable directory":        {goodMountInfo, mod(func(f fakeFS) { f["/etc"].writable = true }), "writable"},
		"owned by the job user":     {goodMountInfo, mod(func(f fakeFS) { f["/etc/hosts"].uid = 10001 }), "owned"},
		"unreadable but searchable": {goodMountInfo, mod(func(f fakeFS) { f["/root"].search = true }), "searched"},
		"unreadable and writable":   {goodMountInfo, mod(func(f fakeFS) { f["/root"].writable = true }), "writable"},
		"list failure":              {goodMountInfo, mod(func(f fakeFS) { f["/home"].listErr = errors.New("io") }), "list"},
		"too many entries":          {goodMountInfo, nil, "more than"},
		"unexpected mount":          {goodMountInfo + "9 1 0:30 / /var/lib/x rw - ext4 /dev/sdb rw\n", nil, "unexpected mount"},
		"a volume":                  {goodMountInfo + "9 1 0:30 / /data rw - ext4 /dev/sdb rw\n", nil, "unexpected mount"},
		"tmpfs without a size":      {strings.Replace(goodMountInfo, "rw,size=524288k,mode=1777", "rw,mode=1777", 1), nil, "size"},
		"tmp may execute":           {strings.Replace(goodMountInfo, "nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=524288k,mode=1777", "nosuid,nodev,relatime - tmpfs tmpfs rw,size=524288k,mode=1777", 1), nil, "exec"},
		"tools cannot execute":      {strings.Replace(goodMountInfo, "rw,nosuid,nodev,relatime - tmpfs tmpfs rw,size=262144k", "rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=262144k", 1), nil, "exec"},
		"tmpfs allowed but a bind":  {strings.Replace(goodMountInfo, "- tmpfs tmpfs rw,size=524288k,mode=1777", "- ext4 /dev/sdb rw", 1), nil, "not a tmpfs"},
		"no mountinfo lines":        {"\n", nil, "no mounts"},
		"malformed line":            {"1 0 8:1 /\n", nil, "malformed"},
	}
	for name, c := range cases {
		fsys := c.fsys
		if fsys == nil {
			fsys = cleanImage()
		}
		cfg := checkCfg(t, c.mounts, fsys)
		if name == "too many entries" {
			cfg.MaxEntries = 3
		}
		err := cfg.selfCheck()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, c.want)
		}
	}
}

func TestSelfCheckUnwritableTmpfsPathsAreWalkedWhenNotMounted(t *testing.T) {
	// /tmp is writable in the image; without a tmpfs over it the walk finds it.
	mounts := strings.Join(strings.Split(goodMountInfo, "\n")[:5], "\n") + "\n"
	err := checkCfg(t, mounts, cleanImage()).selfCheck()
	if err == nil || !strings.Contains(err.Error(), "/tmp") {
		t.Errorf("err = %v", err)
	}
}

func TestSelfCheckTimeLimit(t *testing.T) {
	cfg := checkCfg(t, goodMountInfo, cleanImage())
	cfg.MaxTime = -time.Second
	if err := cfg.selfCheck(); err == nil || !strings.Contains(err.Error(), "took longer") {
		t.Errorf("err = %v", err)
	}
}

func TestSelfCheckOnTheRealFilesystem(t *testing.T) {
	// A directory the test user owns and can write is refused, whoever runs
	// the test.
	root := t.TempDir()
	cfg := &SelfCheckConfig{Root: root, MountInfo: "/proc/self/mountinfo", UID: uint32(os.Getuid()), MaxEntries: 1000, MaxTime: time.Minute}
	w := &walker{c: cfg, fs: osFS{}, skip: map[string]bool{}, deadline: time.Now().Add(time.Minute)}
	if err := w.walk(root); err == nil {
		t.Error("an owned directory was accepted")
	}
}

func TestParseMountInfoEscapes(t *testing.T) {
	m, err := parseMountInfo(`1 0 8:1 / /mnt/with\040space rw - tmpfs tmpfs rw,size=1k` + "\n")
	if err != nil || m[0].point != "/mnt/with space" {
		t.Errorf("%v %v", m, err)
	}
	if _, err := parseMountInfo(`1 0 8:1 / /bad\9 rw - tmpfs tmpfs rw` + "\n"); err == nil {
		t.Error("bad escape accepted")
	}
}

// ---- unpacking ----

type tarEntry struct {
	name, link string
	typ        byte
	body       string
}

func makeTgz(t *testing.T, entries []tarEntry) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Typeflag: typ, Mode: 0o777, Linkname: e.link}
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
	gz.Close()
	p := filepath.Join(t.TempDir(), "a.tgz")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func makeWheel(t *testing.T, files map[string]string, symlink string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	if symlink != "" {
		h := &zip.FileHeader{Name: symlink}
		h.SetMode(fs.ModeSymlink | 0o777)
		w, _ := zw.CreateHeader(h)
		w.Write([]byte("/etc/passwd"))
	}
	zw.Close()
	p := filepath.Join(t.TempDir(), "a.whl")
	os.WriteFile(p, buf.Bytes(), 0o644)
	return p
}

var smallLimits = unpackLimits{Files: 10, Bytes: 1 << 10}

func TestUnpackNpmTgz(t *testing.T) {
	root := t.TempDir()
	p := makeTgz(t, []tarEntry{
		{name: "package/", typ: tar.TypeDir},
		{name: "package/bin/", typ: tar.TypeDir},
		{name: "package/bin/tool.js", body: "#!/usr/bin/env node\n"},
		{name: "package/lib/x.js", body: "x"},
	})
	if err := unpackNpmTgz(p, root, "bin/tool.js", smallLimits); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]fs.FileMode{"bin/tool.js": 0o755, "lib/x.js": 0o644, "lib": fs.ModeDir | 0o755} {
		st, err := os.Stat(filepath.Join(root, path))
		if err != nil || st.Mode() != mode {
			t.Errorf("%s: %v %v, want %v", path, st, err, mode)
		}
	}
}

func TestUnpackNpmTgzRefuses(t *testing.T) {
	file := func(n, b string) tarEntry { return tarEntry{name: n, body: b} }
	cases := map[string]struct {
		entries []tarEntry
		limits  unpackLimits
		want    string
	}{
		"symlink":           {[]tarEntry{file("package/bin/t", ""), {name: "package/l", typ: tar.TypeSymlink, link: "/etc/passwd"}}, smallLimits, "not a regular"},
		"hard link":         {[]tarEntry{file("package/bin/t", ""), {name: "package/l", typ: tar.TypeLink, link: "package/bin/t"}}, smallLimits, "not a regular"},
		"fifo":              {[]tarEntry{file("package/bin/t", ""), {name: "package/f", typ: tar.TypeFifo}}, smallLimits, "not a regular"},
		"no package prefix": {[]tarEntry{file("bin/t", "")}, smallLimits, "not under package/"},
		"dotdot":            {[]tarEntry{file("package/../x", "")}, smallLimits, "invalid element"},
		"absolute":          {[]tarEntry{file("package//etc/x", "")}, smallLimits, "absolute"},
		"duplicate":         {[]tarEntry{file("package/bin/t", "a"), file("package/bin/t", "b")}, smallLimits, "twice"},
		"file then dir":     {[]tarEntry{file("package/bin/t", ""), file("package/bin", "")}, smallLimits, "file and a directory"},
		"dir under a file":  {[]tarEntry{file("package/a", ""), file("package/a/b", ""), file("package/bin/t", "")}, smallLimits, "file and a directory"},
		"too many files":    {[]tarEntry{file("package/bin/t", ""), file("package/a", ""), file("package/b", "")}, unpackLimits{Files: 2, Bytes: 100}, "more than 2 entries"},
		"too many bytes":    {[]tarEntry{file("package/bin/t", strings.Repeat("a", 60)), file("package/b", strings.Repeat("a", 60))}, unpackLimits{Files: 10, Bytes: 100}, "more than 100 bytes"},
		"no entry":          {[]tarEntry{file("package/other", "")}, smallLimits, "no file"},
		"entry is a dir":    {[]tarEntry{{name: "package/bin/t", typ: tar.TypeDir}}, smallLimits, "no file"},
	}
	for name, c := range cases {
		err := unpackNpmTgz(makeTgz(t, c.entries), t.TempDir(), "bin/t", c.limits)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}

func TestUnpackWheel(t *testing.T) {
	root := t.TempDir()
	p := makeWheel(t, map[string]string{"uv-1.0.data/scripts/uv": "binary", "uv/__init__.py": ""}, "")
	if err := unpackWheel(p, root, "uv-1.0.data/scripts/uv", smallLimits); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(root, "uv-1.0.data/scripts/uv")); err != nil || st.Mode() != 0o755 {
		t.Errorf("entry: %v %v", st, err)
	}
	for name, c := range map[string]struct {
		files   map[string]string
		symlink string
		limits  unpackLimits
		want    string
	}{
		"symlink":  {map[string]string{"e": ""}, "l", smallLimits, "not a regular"},
		"dotdot":   {map[string]string{"e": "", "../x": ""}, "", smallLimits, "invalid element"},
		"too big":  {map[string]string{"e": strings.Repeat("a", 200)}, "", unpackLimits{Files: 10, Bytes: 100}, "more than 100 bytes"},
		"too many": {map[string]string{"e": "", "a": "", "b": ""}, "", unpackLimits{Files: 2, Bytes: 100}, "more than 2"},
		"no entry": {map[string]string{"a": ""}, "", smallLimits, "no file"},
	} {
		err := unpackWheel(makeWheel(t, c.files, c.symlink), t.TempDir(), "e", c.limits)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}

// ---- preparing the runtime and the tool ----

// envFixture is a work directory with an archive as the main process places
// it, and fake interpreters.
type envFixture struct {
	e   *env
	job *worker.Job
	tgz string
}

func newEnvFixture(t *testing.T, script string) *envFixture {
	t.Helper()
	e := newEnv(t)
	e.cfg.BinDir = filepath.Join(e.cfg.TmpDir, "tools", "bin")
	e.cfg.Path = e.cfg.BinDir + ":/usr/bin:/bin"
	node := filepath.Join(t.TempDir(), "node")
	n24, _ := worker.LookupRuntime("node24")
	e.write(node, "#!/bin/sh\necho v"+n24.Version+"\n")
	os.Chmod(node, 0o755)
	e.cfg.Environment = &EnvironmentConfig{
		SkipSelfCheck: true, ToolsRoot: filepath.Join(e.cfg.TmpDir, "tools"), ArchiveUID: uint32(os.Getuid()), VersionTimeout: 10 * time.Second,
		Interpreter: func(worker.RuntimeSpec) string { return node },
	}
	if err := os.MkdirAll(e.cfg.Environment.ToolsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	p := makeTgz(t, []tarEntry{{name: "package/bin/npm-cli.js", body: script}})
	data, _ := os.ReadFile(p)
	job := e.npmJob()
	h256, h512 := sha256.Sum256(data), sha512.Sum512(data)
	tool := testTool(worker.ManagerNpm, "11.21.0")
	tool.Entry, tool.Size, tool.SHA256, tool.SHA512 = "bin/npm-cli.js", int64(len(data)), hex.EncodeToString(h256[:]), hex.EncodeToString(h512[:])
	job.Tool = tool
	job.Runtime = testRuntime("node24")
	job.Steps = []worker.Step{{ID: "relock", Op: worker.OpNpmRelock}}
	if err := os.MkdirAll(filepath.Join(e.cfg.WorkDir, "tools"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.cfg.WorkDir, tool.Path), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return &envFixture{e: e, job: job, tgz: filepath.Join(e.cfg.WorkDir, tool.Path)}
}

const toolScript = `#!/bin/sh
case "$1" in --version) echo 11.21.0 ;; *) echo '{"v":"relocked"}' > package-lock.json ;; esac
`

func TestEnvironmentRunsTheUnpackedTool(t *testing.T) {
	f := newEnvFixture(t, toolScript)
	res, err := f.e.run(f.job)
	if err != nil || res.Status != worker.StatusCompleted {
		t.Fatalf("status %v err %v: %+v", res.Status, err, res)
	}
	if got := f.e.read("final", "package-lock.json"); got != "{\"v\":\"relocked\"}\n" {
		t.Errorf("lock = %q", got)
	}
}

func TestEnvironmentRefuses(t *testing.T) {
	cases := map[string]struct {
		change func(*envFixture)
		status worker.Status
		want   string
	}{
		"tool reports another version": {func(f *envFixture) {
			*f = *newEnvFixture(t, strings.Replace(toolScript, "echo 11.21.0", "echo 11.20.0", 1))
		}, worker.StatusInputRejected, "reports"},
		"archive size differs": {func(f *envFixture) { f.job.Tool.Size++ }, worker.StatusInputRejected, "bytes"},
		"archive hash differs": {func(f *envFixture) { f.job.Tool.SHA256 = strings.Repeat("0", 64) }, worker.StatusInputRejected, "hashes"},
		"sha512 differs":       {func(f *envFixture) { f.job.Tool.SHA512 = strings.Repeat("0", 128) }, worker.StatusInputRejected, "hashes"},
		"archive altered": {func(f *envFixture) {
			os.WriteFile(f.tgz, []byte("changed"), 0o644)
		}, worker.StatusInputRejected, "bytes"},
		"archive missing": {func(f *envFixture) { os.Remove(f.tgz) }, worker.StatusInputRejected, "no such file"},
		"entry missing":   {func(f *envFixture) { f.job.Tool.Entry = "bin/other.js" }, worker.StatusInputRejected, "no file"},
		"runtime reports another version": {func(f *envFixture) {
			f.job.Runtime.Version = "24.0.0" // a version no table row pins
		}, worker.StatusEnvironmentRejected, "reports"},
		"interpreter missing": {func(f *envFixture) {
			f.e.cfg.Environment.Interpreter = func(worker.RuntimeSpec) string { return "/nonexistent/node" }
		}, worker.StatusEnvironmentRejected, "not there"},
	}
	for name, c := range cases {
		f := newEnvFixture(t, toolScript)
		c.change(f)
		res, _ := f.e.run(f.job)
		if res == nil || res.Status != c.status || !strings.Contains(res.Error, c.want) {
			t.Errorf("%s: %+v, want %s containing %q", name, res, c.status, c.want)
		}
		if res != nil && len(res.Steps) != 0 {
			t.Errorf("%s: a step ran", name)
		}
	}
}

func TestEnvironmentSelfCheckFailureStopsBeforeTheJobIsRead(t *testing.T) {
	f := newEnvFixture(t, toolScript)
	f.e.cfg.Environment.SkipSelfCheck = false
	f.e.cfg.Environment.SelfCheck = SelfCheckConfig{Root: t.TempDir(), MountInfo: "/nonexistent", UID: 10001, MaxEntries: 10, MaxTime: time.Second}
	res, _ := f.e.run([]byte("not json at all"))
	if res == nil || res.Status != worker.StatusEnvironmentRejected {
		t.Errorf("%+v", res)
	}
}

func TestEnvironmentPipJobNeedsNoTool(t *testing.T) {
	f := newEnvFixture(t, toolScript)
	py := filepath.Join(t.TempDir(), "python3.13")
	p13, _ := worker.LookupRuntime("python3.13")
	f.e.write(py, "#!/bin/sh\ncase \"$1\" in --version) echo Python "+p13.Version+" ;; -m) echo 'pip "+p13.Pip+" from /x (python 3.13)' ;; esac\n")
	os.Chmod(py, 0o755)
	f.e.cfg.Environment.Interpreter = func(worker.RuntimeSpec) string { return py }
	cfg := f.e.cfg
	cfg.Environment = f.e.cfg.Environment
	spec, _ := worker.LookupRuntime("python3.13")
	// Wrong pip.
	job := f.pipJob(spec)
	job.Runtime.Pip = "1.0.0"
	res, _ := f.e.run(job)
	if res == nil || res.Status != worker.StatusEnvironmentRejected || !strings.Contains(res.Error, "pip reports") {
		t.Errorf("%+v", res)
	}
}

func (f *envFixture) pipJob(spec worker.RuntimeSpec) *worker.Job {
	os.Remove(filepath.Join(f.e.cfg.WorkDir, "src", "package.json"))
	os.Remove(filepath.Join(f.e.cfg.WorkDir, "src", "package-lock.json"))
	f.e.write(filepath.Join(f.e.cfg.WorkDir, "src", "requirements.txt"), "urllib3==1.26.4\n")
	return &worker.Job{
		Protocol: worker.ProtocolVersion, Manager: worker.ManagerPip, Runtime: spec.JobRuntime(),
		Inputs:  []worker.Input{{Path: "requirements.txt", Size: 16, SHA256: sum("urllib3==1.26.4\n")}},
		Steps:   []worker.Step{{ID: "d", Op: worker.OpPipDryRun, Scratch: true}},
		Outputs: []string{"requirements.txt", worker.PipReportName}, DeadlineSeconds: 30,
	}
}

func TestToolVersionMatches(t *testing.T) {
	npm := &worker.Tool{Name: worker.ManagerNpm, Version: "11.21.0"}
	uv := &worker.Tool{Name: worker.ManagerUv, Version: "0.13.0"}
	for _, c := range []struct {
		t    *worker.Tool
		out  string
		want bool
	}{
		{npm, "11.21.0\n", true}, {npm, "11.21.1", false}, {npm, "v11.21.0", false}, {npm, "", false},
		{uv, "uv 0.13.0 (abc 2026-01-01)", true}, {uv, "uv 0.13.1", false}, {uv, "0.13.0", false},
	} {
		if got := toolVersionMatches(c.t, c.out); got != c.want {
			t.Errorf("%s %q = %v", c.t.Name, c.out, got)
		}
	}
}

func TestLookPathOnlyUsesTheDirectoryOfTheTools(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "npm"), []byte("#!/bin/sh\n"), 0o755)
	os.WriteFile(filepath.Join(dir, "plain"), []byte("x"), 0o644)
	if p, err := lookPath(dir, "npm"); err != nil || p != filepath.Join(dir, "npm") {
		t.Errorf("%q %v", p, err)
	}
	for _, c := range [][2]string{{dir, "plain"}, {dir, "../npm"}, {dir, ""}, {"relative", "npm"}, {"", "npm"}, {dir, "sh"}} {
		if _, err := lookPath(c[0], c[1]); err == nil {
			t.Errorf("lookPath(%q, %q) succeeded", c[0], c[1])
		}
	}
}
