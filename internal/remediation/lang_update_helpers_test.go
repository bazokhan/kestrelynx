package remediation

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// fakeGH serves files by path at the test commit.
type fakeGH struct {
	mu    sync.Mutex
	files map[string][]byte
	err   error
	reads int
}

func (g *fakeGH) ResolveBranch(context.Context, string, string) (string, error) {
	return testCommit, nil
}
func (g *fakeGH) ListDirectory(context.Context, string, string, string) ([]github.Entry, error) {
	return nil, fmt.Errorf("unused")
}
func (g *fakeGH) ReadFile(_ context.Context, repo, sha, p string) (github.File, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reads++
	if g.err != nil {
		return github.File{}, g.err
	}
	c, ok := g.files[p]
	if !ok || sha != testCommit {
		return github.File{}, github.ErrNotFound
	}
	return github.File{Path: p, SHA: gitBlobSHA(c), Content: c, Mode: "100644"}, nil
}

// fakeWork stands in for the work container: it answers RunJob with a result
// block in the real format, made from the job it was given and a script of
// what the steps do.
type fakeWork struct {
	mu   sync.Mutex
	jobs []worker.Job
	srcs []map[string][]byte
	// repls are the replacement files each job was given, by name.
	repls []map[string][]byte
	ids   []string
	calls int
	// script returns the outcome of the n-th call (0-based).
	script func(n int, job worker.Job, src map[string][]byte) fakeOutcome
}

type fakeOutcome struct {
	// err is returned by RunJob as is.
	err error
	// exit is the container's exit code.
	exit int
	// cleanupErr is returned together with a good result.
	cleanupErr error
	// raw replaces the whole stdout when set.
	raw []byte
	// status is the job status; completed when empty.
	status worker.Status
	// failStep makes that step fail; failReason and unexpected are its
	// machine-readable cause.
	failStep   string
	failReason string
	unexpected []string
	stderr     map[string]string
	// edit changes the files of the step with that id (and, for a step that
	// is not scratch, the working tree from then on).
	edit map[string]map[string][]byte
	// mangle changes the files map before it is packed.
	mangle func(files map[string][]byte)
	// mangleResult changes result.json before it is packed.
	mangleResult func(r *worker.Result)
}

func (f *fakeWork) RunJob(_ context.Context, spec docker.JobSpec) (docker.JobResult, error) {
	var job worker.Job
	src := map[string][]byte{}
	repl := map[string][]byte{}
	for _, in := range spec.Inputs {
		switch {
		case in.Path == "job.json":
			if err := json.Unmarshal(in.Content, &job); err != nil {
				return docker.JobResult{}, err
			}
		case strings.HasPrefix(in.Path, "src/"):
			src[strings.TrimPrefix(in.Path, "src/")] = in.Content
		case strings.HasPrefix(in.Path, worker.ReplaceDirName+"/"):
			repl[strings.TrimPrefix(in.Path, worker.ReplaceDirName+"/")] = in.Content
		}
	}
	f.mu.Lock()
	n := f.calls
	f.calls++
	f.jobs = append(f.jobs, job)
	f.srcs = append(f.srcs, src)
	f.repls = append(f.repls, repl)
	f.ids = append(f.ids, spec.JobID)
	f.mu.Unlock()
	o := f.script(n, job, withReplacements(src, repl))
	if o.err != nil {
		return docker.JobResult{}, o.err
	}
	if o.raw != nil {
		return docker.JobResult{ExitCode: o.exit, Stdout: o.raw}, nil
	}
	if o.exit != 0 {
		return docker.JobResult{ExitCode: o.exit}, nil
	}
	return docker.JobResult{Stdout: buildResult(job, src, repl, o)}, o.cleanupErr
}

func copyFiles(m map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// buildResult makes the stdout block the work program would print.
func buildResult(job worker.Job, src, repl map[string][]byte, o fakeOutcome) []byte {
	files := map[string][]byte{}
	res := worker.Result{Protocol: worker.ProtocolVersion, Status: o.status, Manager: job.Manager}
	if res.Status == "" {
		res.Status = worker.StatusCompleted
	}
	tree := copyFiles(src)
	outputs := func(prefix string, t map[string][]byte) []worker.OutputFile {
		var list []worker.OutputFile
		for _, name := range job.Outputs {
			c, ok := t[name]
			if !ok {
				continue
			}
			files[prefix+"/"+name] = c
			list = append(list, worker.OutputFile{Path: name, Size: int64(len(c)), SHA256: sha256Hex(c)})
		}
		return list
	}
	steps := job.Steps
	if res.Status == worker.StatusInputRejected || res.Status == worker.StatusEnvironmentRejected {
		steps = nil
	}
	replacing := job.FirstReplacingStep()
	for si, s := range steps {
		if si == replacing {
			for name, c := range repl {
				tree[name] = c
			}
		}
		argv, _ := worker.Argv(job, s)
		sr := worker.StepResult{ID: s.ID, Op: s.Op, Scratch: s.Scratch, Argv: argv, Stderr: o.stderr[s.ID]}
		res.Steps = append(res.Steps, sr)
		last := &res.Steps[len(res.Steps)-1]
		if s.ID == o.failStep {
			last.ExitCode = 1
			last.Reason = o.failReason
			if o.failReason == worker.ReasonUnexpectedFiles {
				last.UnexpectedPaths, last.UnexpectedCount = o.unexpected, len(o.unexpected)
			}
			switch res.Status {
			case worker.StatusCompleted:
				res.Status = worker.StatusStepFailed
				res.Error = fmt.Sprintf("step %q failed", s.ID)
			case worker.StatusTimedOut:
				last.TimedOut = true
				last.ExitCode = -1
			}
			break
		}
		stepTree := tree
		if s.Scratch {
			stepTree = copyFiles(tree)
		}
		for name, c := range o.edit[s.ID] {
			stepTree[name] = c
		}
		last.Outputs = outputs(worker.StepsDir+"/"+s.ID, stepTree)
	}
	if res.Status == worker.StatusCompleted {
		res.Final = outputs(worker.FinalDir, tree)
	}
	if res.Steps == nil {
		res.Steps = []worker.StepResult{}
	}
	if o.mangleResult != nil {
		o.mangleResult(&res)
	}
	raw, _ := json.MarshalIndent(res, "", "  ")
	files[worker.ResultName] = raw
	if o.mangle != nil {
		o.mangle(files)
	}
	block, err := worker.EncodeResult(files)
	if err != nil {
		panic(err)
	}
	return block
}

// fakeFS answers ScanFS from a function of the files.
type fakeFS struct {
	mu    sync.Mutex
	calls int
	fn    func(n int, files map[string][]byte) (scanner.FSScan, error)
}

func (f *fakeFS) ScanFS(_ context.Context, files map[string][]byte, _ scanner.ScanConditions) (scanner.FSScan, error) {
	f.mu.Lock()
	n := f.calls
	f.calls++
	f.mu.Unlock()
	return f.fn(n, files)
}

// fakePyPI serves release files by name==version; with auto set, a release
// that is not listed has one wheel made from the name and version.
type fakePyPI struct {
	releases map[string][]PyPIFile
	err      error
	lookups  []string
	auto     bool
	// missing lists the releases (name==version) the index does not know.
	missing map[string]bool
	// requires are the requirements a release declares (requires_dist), and
	// requiresPython the requires-python of a release.
	requires       map[string][]string
	requiresPython map[string]string
	// uploaded are upload times by name==version that replace the ancient one
	// every file of a release the fake serves has.
	uploaded map[string]time.Time
}

// fakeWheelURL and fakeWheelSHA are the wheel the fake index and the fake pip
// report agree on for a release.
func fakeWheelURL(name, ver string) string {
	return "https://files.pythonhosted.org/packages/x/" + strings.ReplaceAll(name, "-", "_") + "-" + ver + "-py3-none-any.whl"
}

func fakeWheelSHA(name, ver string) string {
	switch name + "==" + ver {
	case "urllib3==1.26.4":
		return "2f4da4594db7e1e110a944bb1b551fdf4e6c136ad42e4234131391e21eb5b0df"
	case "urllib3==1.26.17":
		return urllibWheelSHA
	}
	return sha256Hex([]byte(name + "==" + ver))
}

func fakeWheel(name, ver string) PyPIFile {
	return PyPIFile{Filename: strings.ReplaceAll(name, "-", "_") + "-" + ver + "-py3-none-any.whl", URL: fakeWheelURL(name, ver), Wheel: true, SHA256: fakeWheelSHA(name, ver)}
}

// npmDist is what the fake npm registry publishes for minimist 1.2.8.
var minimist128 = NpmDist{
	Tarball:   "https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz",
	Integrity: "sha512-2yyAR8qBkN3YuheJanUpWC5U3bb5osDywNB8RzDVlDwDHbocAJveqqj1u8+SVD7jkWT4yvsHCpWqqWqAxb0zCA==",
}

// fakeNpm serves version documents by name@version.
type fakeNpm struct {
	dists   map[string]NpmDist
	err     error
	lookups []string
	// times are publication times by name and version that replace the ones
	// the fake gives, and timesErr is returned by the lookup of them.
	times    map[string]map[string]time.Time
	timesErr error
}

func (f *fakeNpm) VersionDist(_ context.Context, name, version string) (NpmDist, error) {
	f.lookups = append(f.lookups, name+"@"+version)
	if f.err != nil {
		return NpmDist{}, f.err
	}
	d, ok := f.dists[name+"@"+version]
	if !ok {
		return NpmDist{}, ErrReleaseNotFound
	}
	return d, nil
}

// PublishTimes answers from times (by name, then version); a version of a
// release the fake serves that is not listed there was published long ago.
func (f *fakeNpm) PublishTimes(_ context.Context, name string) (map[string]time.Time, int64, error) {
	out := map[string]time.Time{}
	for k := range f.dists {
		at := strings.LastIndex(k, "@")
		if k[:at] == name {
			out[k[at+1:]] = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		}
	}
	for v, t := range f.times[name] {
		out[v] = t
	}
	return out, 0, f.timesErr
}

func (f *fakePyPI) Release(_ context.Context, name, version string) (PyPIRelease, error) {
	key := name + "==" + version
	f.lookups = append(f.lookups, key)
	if f.err != nil {
		return PyPIRelease{}, f.err
	}
	if f.missing[key] {
		return PyPIRelease{}, ErrReleaseNotFound
	}
	r, ok := f.releases[key]
	if !ok {
		if !f.auto {
			return PyPIRelease{}, ErrReleaseNotFound
		}
		r = []PyPIFile{fakeWheel(name, version)}
	}
	files := make([]PyPIFile, len(r))
	for i, file := range r {
		file.UploadTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		if at, ok := f.uploaded[key]; ok {
			file.UploadTime = at
		}
		files[i] = file
	}
	return PyPIRelease{Files: files, RequiresDist: f.requires[key], RequiresPython: f.requiresPython[key]}, nil
}

var fsConds = func() scanner.ScanConditions {
	c := testConds("db1")
	c.AnalysisSettings = "fs;test"
	return c
}()

// fsReport builds the parsed report of a filesystem scan: packages as
// name, version pairs and vulnerabilities as package, version, id triples.
func fsReport(typ string, pkgsList [][2]string, vulns [][3]string) scanner.FSScan {
	rp := scanner.ResultPackages{Target: "lock", Class: inventory.ClassLang, Type: typ}
	for _, p := range pkgsList {
		rp.Packages = append(rp.Packages, scanner.Package{Name: p[0], Version: p[1]})
	}
	scan := scanner.ImageScan{Packages: []scanner.ResultPackages{rp}, TrivyVersion: "0.71.2"}
	for _, v := range vulns {
		scan.Findings = append(scan.Findings, scanner.Finding{
			Class: inventory.ClassLang, Type: typ, Package: v[0], InstalledVer: v[1], VulnID: v[2],
			Status: scanner.StatusFixed, Severity: scanner.SeverityHigh,
		})
	}
	return scanner.FSScan{Conditions: fsConds, Report: scan}
}

// itemFor builds a plan item for a manager from its files the way the
// planner does: parse, match each group of findings, reconcile and classify.
func itemFor(t *testing.T, m DependencyManager, files map[string]string, groups ...*findingGroup) LanguageItem {
	t.Helper()
	var lf *lockfile
	var err error
	switch m {
	case ManagerNpm:
		lf, err = parseNpm([]byte(files["package.json"]), []byte(files["package-lock.json"]))
	case ManagerPnpm:
		lf, err = parsePnpm([]byte(files["package.json"]), []byte(files["pnpm-lock.yaml"]))
	case ManagerUv:
		lf, err = parseUv([]byte(files["pyproject.toml"]), []byte(files["uv.lock"]))
	default:
		lf, err = parseRequirements([]byte(files["requirements.txt"]))
	}
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	it := LanguageItem{
		Key: "deps:o/r@main:.#" + string(m), Workloads: []string{"compose/p/web"}, Manager: m,
		Source: SourceRecord{Repository: "o/r", BaseBranch: "main", Directory: ".", CommitSHA: testCommit, Origin: OriginConfig, Confidence: ConfidenceAsserted},
	}
	var names []string
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		it.Source.Files = append(it.Source.Files, SourceFile{Path: n, BlobSHA: gitBlobSHA([]byte(files[n]))})
	}
	var pkgs []LanguagePackage
	for _, g := range groups {
		pkgs = append(pkgs, matchPackage(lf, g))
	}
	reconcileVersions(lf, pkgs)
	it.Packages = pkgs
	classify(&it)
	return it
}

func ghFor(files map[string]string) *fakeGH {
	g := &fakeGH{files: map[string][]byte{}}
	for n, c := range files {
		g.files[n] = []byte(c)
	}
	return g
}

func group(typ, name, installed string, origin FindingOrigin, cves ...CVERef) *findingGroup {
	origin.Name, origin.Version = name, installed
	return &findingGroup{Type: typ, Name: name, Installed: installed, cves: cves, origins: []FindingOrigin{origin}}
}

func readTestdata(t *testing.T, dir string, names ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join("testdata", "update", dir, n))
		if err != nil {
			t.Fatal(err)
		}
		out[n] = string(b)
	}
	return out
}

// fakeTools hands out a small archive file for every request and records the
// requests.
type fakeTools struct {
	mu       sync.Mutex
	dir      string
	reqs     []ToolRequest
	err      error
	released []string
}

// Release records that the file of an artifact was let go.
func (f *fakeTools) Release(a ToolArtifact) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released = append(f.released, a.SHA256)
}

func (f *fakeTools) Provide(_ context.Context, req ToolRequest) (ToolArtifact, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, req)
	if f.err != nil {
		return ToolArtifact{}, f.err
	}
	content := []byte("archive of " + string(req.Manager) + " " + req.Version)
	path := filepath.Join(f.dir, string(req.Manager)+"-"+req.Version+".bin")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return ToolArtifact{}, err
	}
	h256, h512 := sha256.Sum256(content), sha512.Sum512(content)
	art := ToolArtifact{Manager: req.Manager, Version: req.Version, Format: "npm-tgz", Path: path, Size: int64(len(content)),
		SHA256: hex.EncodeToString(h256[:]), SHA512: hex.EncodeToString(h512[:]), Entry: "bin/" + string(req.Manager) + ".cjs", RunWithNode: true}
	if req.Manager == ManagerUv {
		art.Format, art.RunWithNode, art.Entry = "wheel", false, "uv-"+req.Version+".data/scripts/uv"
	}
	if req.Manager == ManagerPnpm && strings.HasPrefix(req.Version, "12.") {
		// pnpm 12 is an executable, not a script for node.
		art.RunWithNode, art.Entry = false, "pnpm"
	}
	return art, nil
}

// testDefaultToolVersion are the versions the tests run the managers at.
func testDefaultToolVersion(m DependencyManager, _ string) string {
	switch m {
	case ManagerNpm:
		return "11.19.0"
	case ManagerPnpm:
		return "11.28.2"
	case ManagerUv:
		return "0.13.0"
	}
	return ""
}

// withTestTools gives a configuration the package manager provider, the
// default versions, the platform and the work program a job needs.
func withTestTools(t testing.TB, cfg LangUpdateConfig) LangUpdateConfig {
	t.Helper()
	cfg.Tools = &fakeTools{dir: t.TempDir()}
	cfg.DefaultToolVersion = testDefaultToolVersion
	cfg.Platform = "linux/amd64"
	cfg.Program = func() ([]byte, error) { return []byte("work program"), nil }
	return cfg
}

// withReplacements returns the input files of a job with its replacement files
// added under replace/, which is what a script can look at to see what the job
// took out of the lockfile.
func withReplacements(src, repl map[string][]byte) map[string][]byte {
	out := copyFiles(src)
	for name, c := range repl {
		out[worker.ReplaceDirName+"/"+name] = c
	}
	return out
}

// namesIn returns the packages the n-th job names: those of its uv.upgrade
// steps, and those whose entries its replacement lockfile lacks.
func (f *fakeWork) namesIn(n int) []string {
	return namesInUpdate(f.jobs[n], withReplacements(f.srcs[n], f.repls[n]))
}

// namesInUpdate lists the packages an update job names: the ones in the steps
// that name packages, and the ones the lockfile that replaces the original
// does not have.
func namesInUpdate(job worker.Job, src map[string][]byte) []string {
	var out []string
	for _, s := range job.Steps {
		for _, p := range s.Packages {
			out = append(out, p.Name)
		}
	}
	lock := worker.LockfileName(job.Manager)
	repl, replaced := src[worker.ReplaceDirName+"/"+lock]
	if !replaced {
		return out
	}
	had, now := lockPackageNames(job.Manager, src[lock]), lockPackageNames(job.Manager, repl)
	for name := range had {
		if !now[name] {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// lockPackageNames are the names of the packages a lockfile has entries for.
func lockPackageNames(m worker.Manager, lock []byte) map[string]bool {
	names := map[string]bool{}
	switch m {
	case worker.ManagerNpm:
		doc, err := readNpmLock(lock)
		if err != nil {
			panic(err)
		}
		for k := range doc.entries {
			if k != "" {
				names[npmPathName(k)] = true
			}
		}
	case worker.ManagerPnpm:
		doc, err := readPnpmLock(lock)
		if err != nil {
			panic(err)
		}
		for k := range gmap(doc.top["packages"]) {
			if name, _, ok := splitPnpmKey(pnpmBase(k)); ok {
				names[name] = true
			}
		}
	}
	return names
}
