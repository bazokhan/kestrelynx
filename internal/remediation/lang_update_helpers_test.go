package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

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
	mu    sync.Mutex
	jobs  []worker.Job
	srcs  []map[string][]byte
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
	for _, in := range spec.Inputs {
		switch {
		case in.Path == "job.json":
			if err := json.Unmarshal(in.Content, &job); err != nil {
				return docker.JobResult{}, err
			}
		case strings.HasPrefix(in.Path, "src/"):
			src[strings.TrimPrefix(in.Path, "src/")] = in.Content
		}
	}
	f.mu.Lock()
	n := f.calls
	f.calls++
	f.jobs = append(f.jobs, job)
	f.srcs = append(f.srcs, src)
	f.ids = append(f.ids, spec.JobID)
	f.mu.Unlock()
	o := f.script(n, job, src)
	if o.err != nil {
		return docker.JobResult{}, o.err
	}
	if o.raw != nil {
		return docker.JobResult{ExitCode: o.exit, Stdout: o.raw}, nil
	}
	if o.exit != 0 {
		return docker.JobResult{ExitCode: o.exit}, nil
	}
	return docker.JobResult{Stdout: buildResult(job, src, o)}, o.cleanupErr
}

func copyFiles(m map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// buildResult makes the stdout block the work program would print.
func buildResult(job worker.Job, src map[string][]byte, o fakeOutcome) []byte {
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
	if res.Status == worker.StatusInputRejected {
		steps = nil
	}
	for _, s := range steps {
		argv, _ := worker.Argv(job.Manager, s)
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
	return PyPIRelease{Files: r, RequiresDist: f.requires[key], RequiresPython: f.requiresPython[key]}, nil
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
