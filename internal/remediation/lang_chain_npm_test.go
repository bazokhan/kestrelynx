package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// npmDistFor is what the fake registry publishes for a package version of
// npmLock: the files and the declared requirements.
func npmDistFor(name, ver string, deps map[string]string) NpmDist {
	return NpmDist{
		Tarball:   "https://registry.npmjs.org/" + name + "/-/" + name[strings.LastIndex(name, "/")+1:] + "-" + ver + ".tgz",
		Integrity: "sha512-" + name + ver, Dependencies: deps,
	}
}

// npmPackagesOf lists the (name, version) pairs of a package-lock.json.
func npmPackagesOf(lock []byte) [][2]string {
	var doc struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(lock, &doc); err != nil {
		return nil
	}
	var out [][2]string
	seen := map[string]bool{}
	for path, p := range doc.Packages {
		if path == "" {
			continue
		}
		name := npmPathName(path)
		if k := name + "@" + p.Version; !seen[k] {
			seen[k] = true
			out = append(out, [2]string{name, p.Version})
		}
	}
	return out
}

// mkdirpProject is the npm project of the chain update: mkdirp, which holds
// minimist at exactly 0.0.8, and rc, whose range for minimist allows the fix
// and which has its own copy of 1.2.0. minimist is fixed in 1.2.6.
type mkdirpProject struct {
	manifest string
	lock     func(mkdirp, minimist string, rcNested bool) []byte
	dists    map[string]NpmDist
	findings map[string]string
}

func newMkdirpProject() mkdirpProject {
	root := map[string]string{"mkdirp": "^0.5.1", "rc": "^1.2.0"}
	return mkdirpProject{
		manifest: `{"name":"app","version":"1.0.0","dependencies":{"mkdirp":"^0.5.1","rc":"^1.2.0"}}`,
		lock: func(mkdirp, minimist string, rcNested bool) []byte {
			mkdirpDep := "0.0.8"
			if mkdirp != "0.5.1" {
				mkdirpDep = "^1.2.6"
			}
			pkgs := map[string]npmEntry{
				"node_modules/mkdirp":   {ver: mkdirp, deps: map[string]string{"minimist": mkdirpDep}},
				"node_modules/minimist": {ver: minimist},
				"node_modules/rc":       {ver: "1.2.8", deps: map[string]string{"minimist": "^1.2.0"}},
			}
			if rcNested {
				pkgs["node_modules/rc/node_modules/minimist"] = npmEntry{ver: "1.2.0"}
			}
			return npmLock(root, pkgs)
		},
		dists: map[string]NpmDist{
			"mkdirp@0.5.1":   npmDistFor("mkdirp", "0.5.1", map[string]string{"minimist": "0.0.8"}),
			"mkdirp@0.5.6":   npmDistFor("mkdirp", "0.5.6", map[string]string{"minimist": "^1.2.6"}),
			"minimist@1.2.8": npmDistFor("minimist", "1.2.8", nil),
			"rc@1.2.8":       npmDistFor("rc", "1.2.8", map[string]string{"minimist": "^1.2.0"}),
		},
		findings: map[string]string{"minimist@0.0.8": "CVE-2021-44906", "minimist@1.2.0": "CVE-2021-44906"},
	}
}

// newNpmHarness is a harness for an npm project. The work container leaves the
// lockfile as it is on the first update and returns lockFor(n) on a later job.
func newNpmHarness(t *testing.T, manifest string, lock []byte, groups []*findingGroup, dists map[string]NpmDist, findings map[string]string, lockFor func(n int) []byte) *harness {
	t.Helper()
	files := map[string]string{"package.json": manifest, "package-lock.json": string(lock)}
	h := &harness{t: t, fx: fixtureFor("npm"), files: files}
	h.item = itemFor(t, ManagerNpm, files, groups...)
	if h.item.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("the project is not an update candidate: %s %s", h.item.Category, h.item.Detail)
	}
	h.gh = ghFor(files)
	h.npm = &fakeNpm{dists: dists}
	h.pypi = &fakePyPI{auto: true}
	h.work = &fakeWork{script: func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		out := src["package-lock.json"]
		if lockFor != nil {
			if l := lockFor(n); l != nil {
				out = l
			}
		}
		return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"package-lock.json": out}}}
	}}
	h.fs = &fakeFS{fn: func(n int, in map[string][]byte) (scanner.FSScan, error) {
		pkgs := npmPackagesOf(in["package-lock.json"])
		var vulns [][3]string
		for _, p := range pkgs {
			if id := findings[p[0]+"@"+p[1]]; id != "" {
				vulns = append(vulns, [3]string{p[0], p[1], id})
			}
		}
		return fsReport("npm", pkgs, vulns), nil
	}}
	h.cfg = LangUpdateConfig{
		Scanner: h.fs, Work: h.work, PyPI: h.pypi, Npm: h.npm, GitHub: h.gh,
		Prepared: fsConds, Images: map[string]ImageEnv{"img": debianAmd64}, MaxJobs: 5,
	}
	h.cfg = withTestTools(h.t, h.cfg)
	return h
}

func (h *harness) runNpm(tune func(*LangUpdater, *LanguageItem)) (LanguageItem, *LangUpdater) {
	h.t.Helper()
	up, err := NewLangUpdater(h.cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	item := h.item
	item.Packages = append([]LanguagePackage(nil), h.item.Packages...)
	if tune != nil {
		tune(up, &item)
	}
	plan := &Plan{LanguageItems: []LanguageItem{item}}
	up.Run(context.Background(), plan)
	return plan.LanguageItems[0], up
}

func minimistGroupAt(ver string) *findingGroup {
	return group(typeNodePkg, "minimist", ver, FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "app/node_modules/minimist/package.json"},
		CVERef{VulnID: "CVE-2021-44906", FixedVers: []string{"0.2.4", "1.2.6"}})
}

func mkdirpHarness(t *testing.T) (*harness, mkdirpProject) {
	p := newMkdirpProject()
	h := newNpmHarness(t, p.manifest, p.lock("0.5.1", "0.0.8", true), []*findingGroup{minimistGroupAt("0.0.8")}, p.dists, p.findings, func(n int) []byte {
		if n == 0 {
			return nil
		}
		return p.lock("0.5.6", "1.2.8", false)
	})
	return h, p
}

func TestNpmChainTakesAPinnedPackageThroughItsDirectDependency(t *testing.T) {
	h, p := mkdirpHarness(t)
	it, _ := h.runNpm(nil)
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if h.work.calls != 2 {
		t.Fatalf("containers = %d: the first update and the chain update", h.work.calls)
	}
	min := packageOf(t, it, "minimist")
	if min.AdoptedVersion != "1.2.8" || strings.Join(min.Through, ",") != "mkdirp" {
		t.Errorf("minimist = %+v", min)
	}
	c := it.Update.Chain
	if c == nil || c.Outcome != ChainAdopted || len(c.Tops) != 1 || c.Tops[0] != (ChainMove{Name: "mkdirp", From: "0.5.1", To: "0.5.6", Kind: "top"}) ||
		len(c.Blocked) != 1 || c.Blocked[0].Parent != "mkdirp" || c.Blocked[0].Range != "0.0.8" {
		t.Errorf("chain = %+v", c)
	}
	if len(c.Moves) != 0 {
		t.Errorf("moves = %+v: the top and the updated package are not listed among them", c.Moves)
	}
	if string(it.Artifacts[0].Content) != string(p.lock("0.5.6", "1.2.8", false)) {
		t.Error("the artifact is not the chain's lockfile")
	}
	// The lockfile the chain job was given lacks the entries of mkdirp and of
	// minimist at every path, and keeps rc.
	given := string(h.work.srcs[1]["package-lock.json"])
	if strings.Contains(given, `"node_modules/mkdirp"`) || strings.Contains(given, `"node_modules/minimist"`) || strings.Contains(given, `rc/node_modules/minimist`) || !strings.Contains(given, `"node_modules/rc"`) {
		t.Errorf("the chain job's lockfile: %s", given)
	}
	if got := h.work.jobs[1].Steps; len(got) != 1 || got[0].Op != worker.OpNpmRelock {
		t.Errorf("chain job steps = %+v: the original is not checked again", got)
	}
	if it.SourceCheck == nil || !it.SourceCheck.Passed || it.SourceCheck.Basis != "package_version_vuln_edges_positions" {
		t.Errorf("source check = %+v", it.SourceCheck)
	}
	if !contains2(it.Update.Notes, "mkdirp") {
		t.Errorf("notes = %v", it.Update.Notes)
	}
}

func contains2(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func TestNpmChainWaitsForAVersionThatIsTooNew(t *testing.T) {
	h, _ := mkdirpHarness(t)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	published := now.Add(-10 * time.Hour)
	h.cfg.Now = func() time.Time { return now }
	h.npm.times = map[string]map[string]time.Time{"mkdirp": {"0.5.6": published}, "minimist": {"1.2.8": now.Add(-100 * time.Hour)}}
	it, _ := h.runNpm(nil)
	wantCategory(t, it, CategoryDeferred, ReasonReleaseTooNew)
	if it.RetryAfter == nil || !it.RetryAfter.Equal(published.Add(72*time.Hour)) {
		t.Errorf("retry after = %v", it.RetryAfter)
	}
	if it.waitIntent == nil || it.waitIntent.Kind != releaseAgeWait || len(it.Artifacts) != 0 {
		t.Errorf("intent = %+v, artifacts = %d", it.waitIntent, len(it.Artifacts))
	}
	// A version that was in the original lockfile is not judged.
	h2, _ := mkdirpHarness(t)
	h2.cfg.Now = func() time.Time { return now }
	h2.npm.times = map[string]map[string]time.Time{"mkdirp": {"0.5.6": now.Add(-100 * time.Hour)}, "minimist": {"1.2.8": now.Add(-100 * time.Hour), "0.0.8": now}}
	if it, _ = h2.runNpm(nil); it.Category != CategoryPRCandidate {
		t.Errorf("category = %s %s", it.Category, it.Reason)
	}
	// A registry client that cannot tell fails the chain update, which is not a
	// wait.
	h3, _ := mkdirpHarness(t)
	h3.cfg.Npm = npmFunc(h3.npm.VersionDist)
	it, _ = h3.runNpm(nil)
	if it.Category == CategoryPRCandidate || it.Category == CategoryDeferred {
		t.Errorf("category = %s %s", it.Category, it.Reason)
	}
}

func TestNpmChainDoesNotStartFromADeclaredPackage(t *testing.T) {
	p := newMkdirpProject()
	manifest := `{"name":"app","version":"1.0.0","dependencies":{"mkdirp":"^0.5.1","rc":"^1.2.0","minimist":"^1.2.0"}}`
	root := map[string]string{"mkdirp": "^0.5.1", "rc": "^1.2.0", "minimist": "^1.2.0"}
	lock := npmLock(root, map[string]npmEntry{
		"node_modules/mkdirp":                       {ver: "0.5.1", deps: map[string]string{"minimist": "0.0.8"}},
		"node_modules/mkdirp/node_modules/minimist": {ver: "0.0.8"},
		"node_modules/minimist":                     {ver: "1.2.8"},
		"node_modules/rc":                           {ver: "1.2.8", deps: map[string]string{"minimist": "^1.2.0"}},
	})
	h := newNpmHarness(t, manifest, lock, []*findingGroup{minimistGroupAt("0.0.8")}, p.dists, p.findings, nil)
	it, _ := h.runNpm(nil)
	wantCategory(t, it, CategoryManual, ReasonTargetNotUpdated)
	if it.Update != nil && it.Update.Chain != nil {
		t.Errorf("chain = %+v", it.Update.Chain)
	}
	for _, l := range h.npm.lookups {
		if strings.HasPrefix(l, "mkdirp@") || strings.HasPrefix(l, "rc@") {
			t.Errorf("looked up %s for a package that is excluded", l)
		}
	}
}

func TestNpmChainOfTwoTopsOneStuck(t *testing.T) {
	// optimist holds minimist below the fix by a range with an upper bound
	// (provable) but the chain update still leaves a copy under optimist short of
	// the fix: the item stays manual with dependents_update_not_fixed.
	root := map[string]string{"mkdirp": "^0.5.1", "optimist": "^0.6.1"}
	manifest := `{"name":"app","version":"1.0.0","dependencies":{"mkdirp":"^0.5.1","optimist":"^0.6.1"}}`
	lock := func(mkdirp, nested string) []byte {
		dep := "0.0.8"
		if mkdirp != "0.5.1" {
			dep = "^1.2.6"
		}
		return npmLock(root, map[string]npmEntry{
			"node_modules/mkdirp":                         {ver: mkdirp, deps: map[string]string{"minimist": dep}},
			"node_modules/minimist":                       {ver: map[bool]string{true: "0.0.8", false: "1.2.8"}[mkdirp == "0.5.1"]},
			"node_modules/optimist":                       {ver: "0.6.1", deps: map[string]string{"minimist": "~0.0.1"}},
			"node_modules/optimist/node_modules/minimist": {ver: nested},
		})
	}
	dists := map[string]NpmDist{
		"mkdirp@0.5.1":    npmDistFor("mkdirp", "0.5.1", map[string]string{"minimist": "0.0.8"}),
		"mkdirp@0.5.6":    npmDistFor("mkdirp", "0.5.6", map[string]string{"minimist": "^1.2.6"}),
		"optimist@0.6.1":  npmDistFor("optimist", "0.6.1", map[string]string{"minimist": "~0.0.1"}),
		"minimist@1.2.8":  npmDistFor("minimist", "1.2.8", nil),
		"minimist@0.0.10": npmDistFor("minimist", "0.0.10", nil),
	}
	h := newNpmHarness(t, manifest, lock("0.5.1", "0.0.8"), []*findingGroup{minimistGroupAt("0.0.8")}, dists,
		map[string]string{"minimist@0.0.8": "CVE-2021-44906", "minimist@0.0.10": "CVE-2021-44906"}, func(n int) []byte {
			if n == 0 {
				return nil
			}
			return lock("0.5.6", "0.0.10")
		})
	it, _ := h.runNpm(nil)
	wantCategory(t, it, CategoryManual, ReasonTargetNotUpdated)
	if pin := packageOf(t, it, "minimist"); pin.Reason != ReasonDependentsNotFixed {
		t.Errorf("minimist = %+v", pin)
	}
	if c := it.Update.Chain; c == nil || c.Outcome != ChainNotFixed {
		t.Errorf("chain = %+v", c)
	}
}

func TestRemoveNpmEntriesTakesOutPathsAndWhatIsNestedBelow(t *testing.T) {
	lock := npmLock(map[string]string{"a": "^1", "b": "^1"}, map[string]npmEntry{
		"node_modules/a":                {ver: "1.0.0", deps: map[string]string{"t": "^1"}},
		"node_modules/a/node_modules/n": {ver: "1.0.0"},
		"node_modules/b":                {ver: "1.0.0", deps: map[string]string{"t": "^1"}},
		"node_modules/t":                {ver: "1.0.0"},
		"node_modules/b/node_modules/t": {ver: "1.0.1"},
	})
	got, problem := removeNpmEntries(bg, lock, map[string]bool{"t": true}, map[string]bool{"node_modules/a": true})
	if problem != nil {
		t.Fatal(problem.detail)
	}
	var doc struct {
		Packages map[string]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(got.lock, &doc); err != nil {
		t.Fatal(err)
	}
	var kept []string
	for k := range doc.Packages {
		kept = append(kept, k)
	}
	if len(kept) != 2 || doc.Packages[""] == nil || doc.Packages["node_modules/b"] == nil {
		t.Errorf("kept = %v", kept)
	}
	if len(got.paths) != 5-1 {
		t.Errorf("removed paths = %v", got.paths)
	}
	if _, problem := removeNpmEntries(bg, lock, map[string]bool{"t": true}, map[string]bool{"node_modules/zzz": true}); problem == nil || problem.reason != ReasonTargetNotInLockfile {
		t.Errorf("a path the lockfile lacks: %+v", problem)
	}
	// With no paths it is the removal of the targets alone.
	a, _ := removeNpmTargets(bg, lock, map[string]bool{"t": true})
	b, _ := removeNpmEntries(bg, lock, map[string]bool{"t": true}, nil)
	if !bytes.Equal(a.lock, b.lock) {
		t.Error("removeNpmTargets differs from removeNpmEntries without paths")
	}
}

func TestRemoveNpmEntriesTakesTheEntriesOutOfTheLegacyTreeToo(t *testing.T) {
	lock := []byte(`{"name":"app","version":"1.0.0","lockfileVersion":2,"requires":true,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"a":"^1","t":"^1"}},"node_modules/a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"sha512-a1","dependencies":{"t":"^1"}},"node_modules/t":{"version":"1.0.0","resolved":"https://registry.npmjs.org/t/-/t-1.0.0.tgz","integrity":"sha512-t1"}},"dependencies":{"a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"sha512-a1","requires":{"t":"^1"}},"t":{"version":"1.0.0","resolved":"https://registry.npmjs.org/t/-/t-1.0.0.tgz","integrity":"sha512-t1"}}}`)
	got, problem := removeNpmEntries(bg, lock, map[string]bool{"t": true}, map[string]bool{"node_modules/a": true})
	if problem != nil {
		t.Fatal(problem.detail)
	}
	var doc struct {
		Packages     map[string]json.RawMessage `json:"packages"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if err := json.Unmarshal(got.lock, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Packages) != 1 || len(doc.Dependencies) != 0 {
		t.Errorf("packages = %d, tree = %d", len(doc.Packages), len(doc.Dependencies))
	}
}

func TestNpmClientPublishTimes(t *testing.T) {
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.EscapedPath())
		switch r.URL.EscapedPath() {
		case "/missing":
			w.WriteHeader(http.StatusNotFound)
		case "/huge":
			w.Write([]byte(`{"name":"huge","versions":{"x":{"readme":"`))
			chunk := bytes.Repeat([]byte("a"), 1<<20)
			for i := 0; i < 34; i++ {
				w.Write(chunk)
			}
		case "/notime":
			w.Write([]byte(`{"name":"notime","versions":{}}`))
		default:
			io.WriteString(w, `{"_id":"p","name":"p","dist-tags":{"latest":"1.0.1"},"versions":{"1.0.0":{"a":[1,{"b":null}],"c":"d"},"1.0.1":{}},"time":{"created":"2020-01-01T00:00:00.000Z","modified":"2021-01-01T00:00:00.000Z","1.0.0":"2020-02-03T04:05:06.007Z","1.0.1":"not a time"},"readme":"x"}`)
		}
	}))
	defer srv.Close()
	c := &NpmClient{BaseURL: srv.URL}
	times, n, err := c.PublishTimes(bg, "p")
	if err != nil {
		t.Fatal(err)
	}
	if got := times["1.0.0"]; !got.Equal(time.Date(2020, 2, 3, 4, 5, 6, 7_000_000, time.UTC)) {
		t.Errorf("1.0.0 = %v", got)
	}
	if _, ok := times["1.0.1"]; ok {
		t.Error("a version with no readable time was given one")
	}
	if n <= 0 || n > 400 {
		t.Errorf("read %d bytes", n)
	}
	if _, _, err := c.PublishTimes(bg, "missing"); !strings.Contains(err.Error(), ErrReleaseNotFound.Error()) {
		t.Errorf("missing: %v", err)
	}
	if _, _, err := c.PublishTimes(bg, "notime"); err == nil {
		t.Error("a document with no time member was accepted")
	}
	_, n, err = c.PublishTimes(bg, "huge")
	if err == nil || n <= maxPackumentBytes {
		t.Errorf("huge: n = %d, err = %v", n, err)
	}
	if _, _, err := c.PublishTimes(bg, "../x"); err == nil {
		t.Error("a name that is not a package name was looked up")
	}
}

func TestPublishTimesCountAgainstTheItemsBudget(t *testing.T) {
	npm := &fakeNpm{dists: map[string]NpmDist{"x@1.0.0": {}}}
	r := &updateRun{u: &LangUpdater{cfg: LangUpdateConfig{Npm: &bytesNpm{npm, 40 << 20}}}, shared: newItemShared()}
	r.shared.budget.enforced = true
	if _, err := r.publishTimes(bg, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.publishTimes(bg, "x"); err != nil || r.shared.budget.lookups != 1 {
		t.Errorf("a second look-up of the package: %v, counted %d", err, r.shared.budget.lookups)
	}
	if _, err := r.publishTimes(bg, "y"); err != nil {
		t.Fatal(err)
	}
	_, err := r.publishTimes(bg, "z")
	if isItemBudget(err) != budgetBytesWait {
		t.Errorf("third package: %v (%d bytes counted)", err, r.shared.budget.bytes)
	}
}

// bytesNpm reports that every publication-time lookup read n bytes.
type bytesNpm struct {
	*fakeNpm
	n int64
}

func (b *bytesNpm) PublishTimes(ctx context.Context, name string) (map[string]time.Time, int64, error) {
	t, _, err := b.fakeNpm.PublishTimes(ctx, name)
	return t, b.n, err
}

func TestOrdinaryNpmUpdateIsNotHeldToTheItemsReceivedBytes(t *testing.T) {
	// An update that never goes on to the chain update keeps the limits it had
	// (a document of 2 MiB at most, 256 lookups): what it receives is recorded
	// but a total over the item's 96 MiB does not stop it.
	plain := newHarness(t, "npm")
	want, _ := plain.run()
	wantCategory(t, want, CategoryPRCandidate, ReasonUpdateVerified)

	big := newHarness(t, "npm")
	for k, d := range big.npm.dists {
		d.BodyBytes = 60 << 20
		big.npm.dists[k] = d
	}
	got, _ := big.run()
	wantCategory(t, got, CategoryPRCandidate, ReasonUpdateVerified)
	if got.waitIntent != nil && got.waitIntent.Kind != "" {
		t.Errorf("wait intent = %+v", got.waitIntent)
	}
	a, _ := json.Marshal(want.Packages)
	b, _ := json.Marshal(got.Packages)
	if string(a) != string(b) || big.work.calls != plain.work.calls || len(got.Artifacts) != len(want.Artifacts) {
		t.Errorf("the result differs: calls %d -> %d\n%s\n%s", plain.work.calls, big.work.calls, a, b)
	}
}
