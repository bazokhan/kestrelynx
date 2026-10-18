package remediation

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

func TestClassifyPyEdge(t *testing.T) {
	// t is fixed in 1.2.0 and in 2.1.0.
	cves := []CVERef{{VulnID: "CVE-1", FixedVers: []string{"1.2.0", "2.1.0"}}}
	cases := []struct {
		spec string
		want edgeClass
		name string
	}{
		{"==1.0.0", edgePinning, "an exact version below the fix"},
		{"==1.1.9", edgePinning, "an exact version in the line the fix is above"},
		{"<1.2.0", edgePinning, "an upper bound at the lowest fixed version"},
		{">=1.0,<1.2", edgePinning, "a set of clauses with an upper bound below the lowest fixed version"},
		{"<=1.1.9", edgePinning, "an inclusive upper bound below the lowest fixed version"},
		{"~=1.0", edgeAllowsFix, "a compatible release whose range reaches the fix"},
		{"~=1.0.2", edgePinning, "a compatible release whose upper bound is below the fix"},
		{">=1.0, <1.1", edgePinning, "spaces in the specifier"},
		{"<=1.2.0", edgeAllowsFix, "an inclusive upper bound at the lowest fixed version allows it"},
		{">=1.0,<2", edgeAllowsFix, "a range that allows the lowest fixed version"},
		{">=1,!=1.2.0,<1.2.1", edgeUnevaluable, "a set with != is not used to prove a pin, and does not allow the fix"},
		{">=1.0,!=1.0.5", edgeAllowsFix, "a set with != that allows the fix"},
		{"==1.*", edgeAllowsFix, "a wildcard that allows the fix"},
		{"==1.0.*", edgeUnevaluable, "a wildcard is not used to prove a pin"},
		{"===1.0.0", edgeUnevaluable, "arbitrary equality"},
		{"", edgeAllowsFix, "no specifier"},
		{"not a specifier", edgeUnevaluable, "a specifier that cannot be read"},
		{"==2.1.0", edgeAllowsFix, "an exact fixed version, the first fix of its line"},
		{"==2.5.0", edgeUnevaluable, "an exact version that is fixed but not a version the fix is first made in"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, _ := classifyPyEdge(c.spec, "1.2.0", cves); got != c.want {
				t.Errorf("classifyPyEdge(%q) = %v, want %v", c.spec, got, c.want)
			}
		})
	}
	// Versions with an epoch, a pre-release, a post-release or a local label.
	epochCases := []struct {
		spec, lower string
		fixed       []string
		want        edgeClass
		name        string
	}{
		{"~=1!1.0", "1!1.5", []string{"1!1.5"}, edgeAllowsFix, "a compatible release keeps its epoch: it reaches a fix of the same epoch"},
		{"~=1!1.0", "1!2.0", []string{"1!2.0"}, edgePinning, "a compatible release of an epoch ends at the next release of that epoch"},
		{"~=1!1.0", "2.0", []string{"2.0"}, edgeUnevaluable, "a fix of epoch 0 is below every version of epoch 1"},
		{"<1!2", "1!1.5", []string{"1!1.5"}, edgeAllowsFix, "an upper bound with an epoch above the fix"},
		{"<1!1.5", "1!1.5", []string{"1!1.5"}, edgePinning, "an upper bound with an epoch at the fix"},
		{"==1!1.0", "1!1.5", []string{"1!1.5"}, edgePinning, "an exact version with an epoch below the fix"},
		{"<1.2.0rc1", "1.2.0", []string{"1.2.0"}, edgePinning, "a bound at a pre-release of the fix"},
		{"<=1.2.0.post1", "1.2.0", []string{"1.2.0"}, edgeAllowsFix, "an inclusive bound at a post-release of the fix"},
		{"<=1.2.0.dev1", "1.2.0", []string{"1.2.0"}, edgePinning, "an inclusive bound at a development release of the fix"},
		{"==1.2.0+local", "1.2.0", []string{"1.2.0"}, edgeUnevaluable, "an exact version with a local label is not below the fix"},
		{">=1.0", "1!1.0", []string{"1!1.0"}, edgeAllowsFix, "a lower bound of epoch 0 is met by a version of epoch 1"},
		{"<2", "1!1.0", []string{"1!1.0"}, edgePinning, "an upper bound of epoch 0 is below a fix of epoch 1"},
	}
	for _, c := range epochCases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := classifyPyEdge(c.spec, c.lower, []CVERef{{VulnID: "CVE-E", FixedVers: c.fixed}})
			if got != c.want {
				t.Errorf("classifyPyEdge(%q, fixed %v) = %v, want %v", c.spec, c.fixed, got, c.want)
			}
		})
	}
	if _, p := classifyPyEdge("==1.0.0", "1.2.0", cves); p != proofExact {
		t.Errorf("proof = %q", p)
	}
	if _, p := classifyPyEdge("<1.2", "1.2.0", cves); p != proofUpperBound {
		t.Errorf("proof = %q", p)
	}
}

// uvEntry is a package of a generated uv.lock.
type uvEntry struct {
	name, ver string
	deps      []string
}

// genUvLock makes a uv.lock whose packages are published by the fake index:
// each has a wheel the fake serves.
func genUvLock(rootSpecs map[string]string, entries []uvEntry) string {
	var b strings.Builder
	b.WriteString("version = 1\nrevision = 5\nrequires-python = \">=3.9\"\n\n[[package]]\nname = \"fixture-uv\"\nversion = \"1.0.0\"\nsource = { virtual = \".\" }\ndependencies = [\n")
	var names, reqs []string
	for n := range rootSpecs {
		names = append(names, n)
	}
	sortStrings(names)
	for _, n := range names {
		fmt.Fprintf(&b, "    { name = %q },\n", n)
		reqs = append(reqs, fmt.Sprintf("{ name = %q, specifier = %q }", n, rootSpecs[n]))
	}
	fmt.Fprintf(&b, "]\n\n[package.metadata]\nrequires-dist = [%s]\n", strings.Join(reqs, ", "))
	for _, e := range entries {
		fmt.Fprintf(&b, "\n[[package]]\nname = %q\nversion = %q\nsource = { registry = \"https://pypi.org/simple\" }\n", e.name, e.ver)
		if len(e.deps) > 0 {
			b.WriteString("dependencies = [\n")
			for _, d := range e.deps {
				fmt.Fprintf(&b, "    { name = %q },\n", d)
			}
			b.WriteString("]\n")
		}
		fmt.Fprintf(&b, "wheels = [\n    { url = %q, hash = \"sha256:%s\", size = 1, upload-time = \"2020-01-01T00:00:00Z\" },\n]\n",
			fakeWheelURL(e.name, e.ver), fakeWheelSHA(e.name, e.ver))
	}
	return b.String()
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

var uvEntryRE = regexp.MustCompile(`(?m)^name = "([^"]+)"\nversion = "([^"]+)"\nsource = \{ registry`)

// uvChainHarness is a harness for a uv project in which a (>=1,<2) requires t
// exactly at 1.0.0, and t is fixed in 1.2.0. a 1.1.0 requires t >=1.2.
func uvChainHarness(t *testing.T, script func(n int, job worker.Job, src map[string][]byte) fakeOutcome) (*harness, string, string) {
	return uvChainHarnessWith(t, false, script)
}

// uvChainHarnessWith is uvChainHarness; withB adds a second direct dependency b,
// which the lockfile after the update moves from 1.0.0 to 1.0.1 although
// nothing asks for it.
func uvChainHarnessWith(t *testing.T, withB bool, script func(n int, job worker.Job, src map[string][]byte) fakeOutcome) (*harness, string, string) {
	t.Helper()
	deps, roots := `"a>=1,<2"`, map[string]string{"a": ">=1,<2"}
	beforeEntries := []uvEntry{{"a", "1.0.0", []string{"t"}}, {"t", "1.0.0", nil}}
	afterEntries := []uvEntry{{"a", "1.1.0", []string{"t"}}, {"t", "1.2.0", nil}}
	if withB {
		deps, roots["b"] = `"a>=1,<2", "b>=1,<2"`, ">=1,<2"
		beforeEntries = append(beforeEntries, uvEntry{"b", "1.0.0", nil})
		afterEntries = append(afterEntries, uvEntry{"b", "1.0.1", nil})
	}
	pyproject := "[project]\nname = \"fixture-uv\"\nversion = \"1.0.0\"\nrequires-python = \">=3.9\"\ndependencies = [" + deps + "]\n\n[tool.uv]\npackage = false\n"
	before := genUvLock(roots, beforeEntries)
	after := genUvLock(roots, afterEntries)
	files := map[string]string{"pyproject.toml": pyproject, "uv.lock": before}
	h := &harness{t: t, fx: fixtureFor("uv"), files: files}
	h.item = itemFor(t, ManagerUv, files, group(typePythonPkg, "t", "1.0.0",
		FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "usr/local/lib/python3.12/site-packages/t-1.0.0.dist-info/METADATA", Target: "Python"},
		CVERef{VulnID: "CVE-T", FixedVers: []string{"1.2.0"}}))
	if h.item.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("the project is not an update candidate: %s %s", h.item.Category, h.item.Detail)
	}
	h.gh = ghFor(files)
	h.npm = &fakeNpm{}
	h.pypi = &fakePyPI{auto: true, requires: map[string][]string{
		"a==1.0.0": {"t==1.0.0"}, "a==1.1.0": {"t>=1.2"},
	}}
	h.work = &fakeWork{script: script}
	h.fs = &fakeFS{fn: func(n int, in map[string][]byte) (scanner.FSScan, error) {
		var pkgs [][2]string
		var vulns [][3]string
		for _, m := range uvEntryRE.FindAllStringSubmatch(string(in["uv.lock"]), -1) {
			pkgs = append(pkgs, [2]string{m[1], m[2]})
			if m[1] == "t" && m[2] == "1.0.0" {
				vulns = append(vulns, [3]string{"t", "1.0.0", "CVE-T"})
			}
		}
		return fsReport("uv", pkgs, vulns), nil
	}}
	h.cfg = LangUpdateConfig{
		Scanner: h.fs, Work: h.work, PyPI: h.pypi, Npm: h.npm, GitHub: h.gh,
		Prepared: fsConds, Images: map[string]ImageEnv{"img": debianAmd64}, MaxJobs: 5,
	}
	h.cfg = withTestTools(t, h.cfg)
	return h, before, after
}

func (h *harness) runUv() LanguageItem {
	h.t.Helper()
	it, _ := h.run()
	return it
}

func TestUvChainJobMovesThePackagesThatRequireTheHeldBackOne(t *testing.T) {
	var after string
	h, _, a := uvChainHarness(t, func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		if n == 0 {
			// uv cannot make a lockfile with t fixed: the update step fails.
			return fakeOutcome{failStep: "update", failReason: "exit"}
		}
		return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"uv.lock": []byte(after)}}}
	})
	after = a
	it := h.runUv()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if h.work.calls != 2 {
		t.Fatalf("containers = %d: the first update and the chain job", h.work.calls)
	}
	job := h.work.jobs[1]
	if len(job.Steps) != 2 || job.Steps[0].Op != worker.OpUvUpgradeChain || job.Steps[1].Op != worker.OpUvCheck || !job.Steps[1].Scratch {
		t.Fatalf("steps = %+v: the update and the check, and no check of the original", job.Steps)
	}
	if got := fmt.Sprint(job.Steps[0].Packages); got != "[{t  1.2.0} {a  }]" {
		t.Errorf("packages = %s: t from its lowest fixed version, a free", got)
	}
	tp := packageOf(t, it, "t")
	if tp.AdoptedVersion != "1.2.0" || strings.Join(tp.Through, ",") != "a" {
		t.Errorf("t = %+v", tp)
	}
	c := it.Update.Chain
	if c == nil || c.Outcome != ChainAdopted || c.Source != "chain_job" || len(c.Tops) != 1 || c.Tops[0] != (ChainMove{Name: "a", From: "1.0.0", To: "1.1.0", Kind: "top"}) ||
		len(c.Blocked) != 1 || c.Blocked[0].Range != "==1.0.0" || c.Blocked[0].Proof != "exact" {
		t.Errorf("chain = %+v", c)
	}
	if string(it.Artifacts[0].Content) != after {
		t.Error("the artifact is not the chain's lockfile")
	}
	if it.SourceCheck == nil || !it.SourceCheck.Passed || it.SourceCheck.Basis != "package_version_vuln_edges_positions" {
		t.Errorf("source check = %+v", it.SourceCheck)
	}
}

func TestUvChainJudgesTheFirstUpdatesLockfileAgain(t *testing.T) {
	var after string
	h, _, a := uvChainHarness(t, func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		// uv makes the lockfile with t fixed, moving a on its own: the ordinary
		// difference check refuses it.
		return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"uv.lock": []byte(after)}}}
	})
	after = a
	it := h.runUv()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if h.work.calls != 1 {
		t.Fatalf("containers = %d: the lockfile is judged again and nothing is run", h.work.calls)
	}
	c := it.Update.Chain
	if c == nil || c.Outcome != ChainAdopted || c.Source != "first_run" || c.Usage.Containers != 1 {
		t.Fatalf("chain = %+v", c)
	}
	if it.Update.Runtime == nil || it.Update.Tool == nil || len(it.Update.Steps) == 0 {
		t.Errorf("the record of the first update's run is lost: %+v", it.Update)
	}
	if strings.Join(packageOf(t, it, "t").Through, ",") != "a" || string(it.Artifacts[0].Content) != after {
		t.Errorf("t = %+v", packageOf(t, it, "t"))
	}
	// The same lockfile with another vulnerable version of a package brought in
	// is refused by the stricter comparison.
	h2, _, _ := uvChainHarness(t, func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"uv.lock": []byte(after)}}}
	})
	h2.fs.fn = func(n int, in map[string][]byte) (scanner.FSScan, error) {
		lock := string(in["uv.lock"])
		pkgs := [][2]string{{"a", "1.0.0"}, {"t", "1.0.0"}}
		vulns := [][3]string{{"t", "1.0.0", "CVE-T"}}
		if strings.Contains(lock, `version = "1.1.0"`) {
			pkgs = [][2]string{{"a", "1.1.0"}, {"t", "1.2.0"}, {"u", "1.0.0"}}
			vulns = [][3]string{{"a", "1.1.0", "CVE-A"}}
		}
		return fsReport("uv", pkgs, vulns), nil
	}
	// The lockfile also brings in u, which a 1.1.0 asks for.
	after2 := genUvLock(map[string]string{"a": ">=1,<2"}, []uvEntry{{"a", "1.1.0", []string{"t", "u"}}, {"t", "1.2.0", nil}, {"u", "1.0.0", nil}})
	h2.pypi.requires["a==1.1.0"] = []string{"t>=1.2", "u"}
	h2.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"uv.lock": []byte(after2)}}}
	}
	it = h2.runUv()
	if it.Category == CategoryPRCandidate {
		t.Fatalf("a result with a new finding was proposed")
	}
	c = it.Update.Chain
	if c == nil || c.Outcome != ChainRejected || c.Reason != ReasonSourceIntroduced || c.Source != "first_run" {
		t.Fatalf("chain = %+v", c)
	}
	if len(c.Moves) != 1 || c.Moves[0] != (ChainMove{Name: "u", To: "1.0.0", Kind: "added"}) {
		t.Errorf("moves = %+v: the entries the refused lockfile would have added are listed by name", c.Moves)
	}
	if p := packageOf(t, it, "t"); p.Reason != ReasonDependentsRejected {
		t.Errorf("t = %+v", p)
	}
}

func TestUvChainDoesNotAdoptAChangeNothingExplains(t *testing.T) {
	// uv moved b as well in the first update's lockfile. b is a direct dependency
	// that does not hold t back, so the chain's rules do not explain its change
	// and the first update's refusal stands.
	var after string
	h, _, a := uvChainHarnessWith(t, true, func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"uv.lock": []byte(after)}}}
	})
	after = a
	it := h.runUv()
	wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
	c := it.Update.Chain
	if c == nil || c.Outcome != ChainRejected || c.Reason != ReasonUnexplainedDiff || c.Source != "first_run" || len(it.Artifacts) != 0 {
		t.Errorf("chain = %+v, artifacts = %d", c, len(it.Artifacts))
	}
	if p := packageOf(t, it, "t"); p.Reason != ReasonDependentsRejected || len(p.Through) != 0 {
		t.Errorf("t = %+v", p)
	}
}

func TestUvChainWaitsForAFileThatIsTooNew(t *testing.T) {
	var after string
	h, _, a := uvChainHarness(t, func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"uv.lock": []byte(after)}}}
	})
	after = a
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	h.cfg.Now = func() time.Time { return now }
	h.pypi.uploaded = map[string]time.Time{"a==1.1.0": now.Add(-10 * time.Hour)}
	it := h.runUv()
	wantCategory(t, it, CategoryDeferred, ReasonReleaseTooNew)
	if it.RetryAfter == nil || !it.RetryAfter.Equal(now.Add(-10*time.Hour+72*time.Hour)) {
		t.Errorf("retry after = %v", it.RetryAfter)
	}
	if it.waitIntent == nil || it.waitIntent.Kind != releaseAgeWait || len(it.Artifacts) != 0 {
		t.Errorf("intent = %+v, artifacts = %d", it.waitIntent, len(it.Artifacts))
	}
	// The lockfile judged again is the first update's own.
	if c := it.Update.Chain; c == nil || c.Outcome != ChainDeferred || c.Source != "first_run" {
		t.Errorf("chain = %+v", c)
	}
}

func TestUvChainRefusesAScopeItCannotReduce(t *testing.T) {
	var after string
	h, _, a := uvChainHarness(t, func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"uv.lock": []byte(after)}}}
	})
	after = a
	// a asks for t twice with different specifiers (under different markers).
	h.pypi.requires["a==1.0.0"] = []string{"t==1.0.0; python_version < '3.10'", "t>=1.0; python_version >= '3.10'"}
	it := h.runUv()
	wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
	if p := packageOf(t, it, "t"); p.Reason != ReasonDependentsUnsupported {
		t.Errorf("t = %+v", p)
	}
}

func TestChainUpgradePackages(t *testing.T) {
	r := &updateRun{set: updateSet{display: map[string]string{"t": "T", "u": "u"}}, full: updateSet{target: map[string]string{"t": "1.2.0", "u": "3.0"}}}
	r.set = r.full
	r.set.display = map[string]string{"t": "T", "u": "u"}
	scope := &chainScope{
		Targets: map[string]bool{"t": true, "u": true}, Bn: []string{"t"},
		Names: map[string]bool{"a": true, "mid": true, "t": true},
	}
	got := fmt.Sprint(r.chainUpgradePackages(scope))
	if got != "[{T  1.2.0} {u 3.0 } {a  } {mid  }]" {
		t.Errorf("packages = %s", got)
	}
}

func TestUvChainScopeNamesTheDeclarationOfTheTop(t *testing.T) {
	h, _, _ := uvChainHarness(t, nil)
	set, _ := newUpdateSet(&h.item)
	up, _ := NewLangUpdater(h.cfg)
	r := &updateRun{
		u: up, it: &h.item, set: set, full: set, upd: &LanguageUpdate{}, shared: newItemShared(),
		src:      &sourceFiles{manifest: []byte(h.files["pyproject.toml"]), lock: []byte(h.files["uv.lock"]), manifestName: "pyproject.toml", lockName: "uv.lock"},
		manifest: []byte(h.files["pyproject.toml"]),
	}
	g0, err := buildGraph(bg, ManagerUv, r.src.lock)
	if err != nil {
		t.Fatal(err)
	}
	scope, fail := buildChainScope(bg, r, g0, []string{"t"})
	if fail != nil || scope == nil {
		t.Fatalf("scope = %v, failure = %+v", scope, fail)
	}
	if len(scope.Tops) != 1 || scope.Tops[0] != (chainTop{Name: "a", Group: "project.dependencies", Spec: ">=1,<2", Key: "a==1.0.0"}) {
		t.Errorf("tops = %+v", scope.Tops)
	}
	if len(scope.Blocked) != 1 || scope.Blocked[0].Parent != "a" || scope.Blocked[0].Range != "==1.0.0" || strings.Join(scope.Blocked[0].Via, ",") != "a" {
		t.Errorf("blocked = %+v", scope.Blocked)
	}
	if !scope.Anc["a==1.0.0"] || !scope.Be["t==1.0.0"] || scope.Scheme != schemePEP440 {
		t.Errorf("scope = %+v", scope)
	}
}

func TestPyPIReleaseKeepsUploadTimesAndSize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"info":{"name":"Pkg","version":"1.0.0","requires_dist":null},"urls":[
 {"filename":"pkg-1.0.0.tar.gz","url":"https://files.pythonhosted.org/p.tar.gz","packagetype":"sdist","digests":{"sha256":"`+strings.Repeat("a", 64)+`"},"upload_time_iso_8601":"2023-08-23T14:43:36.178293Z"},
 {"filename":"pkg-1.0.0-py3-none-any.whl","url":"https://files.pythonhosted.org/p.whl","packagetype":"bdist_wheel","digests":{"sha256":"`+strings.Repeat("b", 64)+`"},"upload_time_iso_8601":"not a time"}]}`)
	}))
	defer srv.Close()
	rel, err := (&PyPIClient{BaseURL: srv.URL}).Release(bg, "pkg", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(rel.Files) != 2 || !rel.Files[0].UploadTime.Equal(time.Date(2023, 8, 23, 14, 43, 36, 178293000, time.UTC)) || !rel.Files[1].UploadTime.IsZero() || rel.BodyBytes <= 0 {
		t.Errorf("release = %+v", rel)
	}
}
