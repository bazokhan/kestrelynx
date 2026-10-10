package remediation

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func TestLanguagePlan_NpmrcAndWorkspaceSettings(t *testing.T) {
	deps := []DependencyMapping{depMapping("compose/shop/api", "ex/app", ".")}
	in := langInput("shop", "api", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"))
	cases := []struct {
		name   string
		setup  func(f *fakeGitHub)
		reason Reason
		cat    Category
	}{
		{"public registry", func(f *fakeGitHub) {
			f.put("ex/app", ".", ".npmrc", "# comment\nregistry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${TOKEN}\n")
		}, ReasonUpdateCandidateInSource, CategoryDependencyUpdateCandidate},
		{"no npmrc", func(f *fakeGitHub) {}, ReasonUpdateCandidateInSource, CategoryDependencyUpdateCandidate},
		{"private registry", func(f *fakeGitHub) {
			f.put("ex/app", ".", ".npmrc", "registry=https://npm.corp.example/\n")
		}, ReasonUnsupportedSource, CategoryManual},
		{"scope registry", func(f *fakeGitHub) {
			f.put("ex/app", ".", ".npmrc", "@corp:registry = \"https://npm.corp.example\"\n")
		}, ReasonUnsupportedSource, CategoryManual},
		{"registry from the environment", func(f *fakeGitHub) {
			f.put("ex/app", ".", ".npmrc", "registry=${NPM_REGISTRY}\n")
		}, ReasonUnsupportedSource, CategoryManual},
		{"npmrc is a symlink", func(f *fakeGitHub) {
			f.putEntry("ex/app", ".", github.Entry{Name: ".npmrc", Type: github.EntrySymlink})
		}, ReasonDependencyFileUnusable, CategoryManual},
	}
	for _, c := range cases {
		for _, mgr := range []string{"npm", "pnpm"} {
			t.Run(c.name+"/"+mgr, func(t *testing.T) {
				gh := newFakeGitHub()
				if mgr == "npm" {
					npmRepo(gh, "ex/app", ".")
				} else {
					gh.put("ex/app", ".", "package.json", pnpmManifest)
					gh.put("ex/app", ".", "pnpm-lock.yaml", pnpmLock)
					in = langInput("shop", "api", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"))
				}
				c.setup(gh)
				it := langPlan(t, gh, deps, nil, in).LanguageItems[0]
				if it.Category != c.cat || it.Reason != c.reason {
					t.Errorf("item = %s / %s (%s)", it.Category, it.Reason, it.Detail)
				}
				if c.cat == CategoryDependencyUpdateCandidate && c.name == "public registry" {
					found := false
					for _, f := range it.Source.Files {
						found = found || f.Path == ".npmrc"
					}
					if !found {
						t.Errorf("the .npmrc that was read is not recorded: %+v", it.Source.Files)
					}
				}
			})
		}
	}
}

func TestLanguagePlan_PnpmWorkspaceFileAndManifestChecks(t *testing.T) {
	deps := []DependencyMapping{depMapping("compose/shop/api", "ex/app", ".")}
	in := langInput("shop", "api", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"))
	run := func(manifest string, extra func(f *fakeGitHub)) LanguageItem {
		gh := newFakeGitHub()
		gh.put("ex/app", ".", "package.json", manifest)
		gh.put("ex/app", ".", "pnpm-lock.yaml", pnpmLock)
		extra(gh)
		return langPlan(t, gh, deps, nil, in).LanguageItems[0]
	}
	if it := run(pnpmManifest, func(f *fakeGitHub) { f.put("ex/app", ".", "pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n") }); it.Reason != ReasonWorkspaceUnsupported {
		t.Errorf("pnpm-workspace.yaml: %s / %s", it.Category, it.Reason)
	}
	for name, manifest := range map[string]string{
		"invalid JSON":       `{"name":`,
		"workspaces":         strings.Replace(pnpmManifest, `"name":"web"`, `"name":"web","workspaces":["a"]`, 1),
		"different range":    strings.Replace(pnpmManifest, `"lodash":"^4.17.20"`, `"lodash":"^4.17.21"`, 1),
		"dependency missing": strings.Replace(pnpmManifest, `"lodash":"^4.17.20",`, ``, 1),
		"extra dependency":   strings.Replace(pnpmManifest, `"dependencies":{`, `"dependencies":{"left-pad":"^1.0.0",`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			it := run(manifest, func(*fakeGitHub) {})
			if it.Category != CategoryManual {
				t.Errorf("item = %s / %s (%s)", it.Category, it.Reason, it.Detail)
			}
		})
	}
	// pnpm-workspace.yaml means nothing to an npm project.
	gh := newFakeGitHub()
	npmRepo(gh, "ex/app", ".")
	gh.put("ex/app", ".", "pnpm-workspace.yaml", "packages: []\n")
	if it := langPlan(t, gh, deps, nil, in).LanguageItems[0]; it.Category != CategoryDependencyUpdateCandidate {
		t.Errorf("npm with a stray pnpm-workspace.yaml: %s / %s", it.Category, it.Reason)
	}
}

func TestLanguagePlan_UnverifiedScansAreNotMatched(t *testing.T) {
	gh := newFakeGitHub()
	npmRepo(gh, "ex/app", ".")
	deps := []DependencyMapping{depMapping("compose/shop/api", "ex/app", ".")}

	unpinned := langInput("shop", "api", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"))
	unpinned.Scan.Pinned = false
	if unpinned.Scan.Err != nil {
		t.Fatal("the fixture scan failed")
	}
	plan := langPlan(t, gh, deps, nil, unpinned)
	if len(plan.LanguageItems) != 1 {
		t.Fatalf("units = %d", len(plan.LanguageItems))
	}
	it := plan.LanguageItems[0]
	if it.Category != CategoryNotComparable || it.Reason != ReasonScanNotPinned || len(it.Packages) != 1 || it.Packages[0].Action != "" {
		t.Errorf("item = %s / %s %+v", it.Category, it.Reason, it.Packages)
	}
	if len(gh.calls) != 0 {
		t.Errorf("an unverified scan started source reading: %v", gh.calls)
	}

	unresolved := langInput("shop", "api", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"))
	unresolved.Scan.Subject.Resolved = false
	if it := langPlan(t, gh, deps, nil, unresolved).LanguageItems[0]; it.Reason != ReasonScanNotPinned {
		t.Errorf("an unresolved subject = %s / %s", it.Category, it.Reason)
	}

	// A verified scan next to an unverified one: the verified findings are
	// planned, the others reported separately.
	good := langInput("shop", "api", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"))
	bad := langInput("shop", "api", nodeFinding("CVE-2", "express", "4.18.2", "4.19.2"))
	bad.Scan.Pinned = false
	plan = langPlan(t, gh, deps, nil, good, bad)
	if len(plan.LanguageItems) != 2 || plan.LanguageItems[0].Category != CategoryDependencyUpdateCandidate || len(plan.LanguageItems[0].Packages) != 1 ||
		plan.LanguageItems[1].Reason != ReasonScanNotPinned || plan.LanguageItems[1].Packages[0].Name != "express" {
		t.Errorf("items = %+v", plan.LanguageItems)
	}
}

func TestParseUvRevisionDynamicAndTypes(t *testing.T) {
	cases := []struct {
		name      string
		pyproject string
		lock      string
		reason    Reason
	}{
		{"revision 3 would be migrated by the work image", uvPyproject, strings.Replace(uvLock, "revision = 5", "revision = 3", 1), ReasonUnsupportedLockfile},
		{"revision 2", uvPyproject, strings.Replace(uvLock, "revision = 5", "revision = 2", 1), ReasonUnsupportedLockfile},
		{"revision 4", uvPyproject, strings.Replace(uvLock, "revision = 5", "revision = 4", 1), ReasonUnsupportedLockfile},
		{"no revision", uvPyproject, strings.Replace(uvLock, "revision = 5\n", "", 1), ReasonUnsupportedLockfile},
		{"revision is a string", uvPyproject, strings.Replace(uvLock, "revision = 5", `revision = "5"`, 1), ReasonUnsupportedLockfile},
		{"dynamic version", strings.Replace(uvPyproject, `version = "0.1.0"`, `dynamic = ["version"]`, 1), uvLock, ReasonDynamicMetadata},
		{"dynamic anything", strings.Replace(uvPyproject, `version = "0.1.0"`, `dynamic = ["readme"]`, 1), uvLock, ReasonDynamicMetadata},
		{"dynamic is not a list", strings.Replace(uvPyproject, `version = "0.1.0"`, `dynamic = "version"`, 1), uvLock, ReasonDynamicMetadata},
		{"package name is a number", uvPyproject, strings.Replace(uvLock, `name = "certifi"`, `name = 5`, 1), ReasonUnparsableSource},
		{"version is a number", uvPyproject, strings.Replace(uvLock, `version = "2024.2.2"`, `version = 2024`, 1), ReasonUnparsableSource},
		{"wheels is a string", uvPyproject, strings.Replace(uvLock, "wheels = [\n    { url = \"https://files.pythonhosted.org/certifi.whl\", hash = \"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\", size = 2 },\n]", `wheels = "none"`, 1), ReasonUnparsableSource},
		{"source is a string", uvPyproject, strings.Replace(uvLock, `source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/certifi.tar.gz"`, `source = "pypi"
sdist = { url = "https://files.pythonhosted.org/certifi.tar.gz"`, 1), ReasonUnparsableSource},
		{"root dependencies is a table", uvPyproject, strings.Replace(uvLock, "dependencies = [\n    { name = \"flask-cors\" },\n    { name = \"requests\" },\n]", `dependencies = { name = "x" }`, 1), ReasonUnparsableSource},
		{"tool is not a table", uvPyproject + "\n", uvLock, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseUv([]byte(c.pyproject), []byte(c.lock))
			if c.reason == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			mustUnsupported(t, err, c.reason)
		})
	}
	if _, err := parseUv([]byte("[project]\nname = \"x\"\n[tool]\nuv = 5\n"), []byte(uvLock)); err == nil {
		t.Error("a tool.uv that is not a table was accepted")
	}
}

func TestReconcile_OnlyUpdatedVersionsAreCovered(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{
	  "":{"dependencies":{"semver":"7"}},
	  "node_modules/semver":{"version":"7.5.1","resolved":"https://registry.npmjs.org/semver/-/semver-7.5.1.tgz"},
	  "node_modules/a/node_modules/semver":{"version":"6.3.0","resolved":"https://registry.npmjs.org/semver/-/semver-6.3.0.tgz"}
	}}`
	l, err := parseNpm([]byte(npmManifest), []byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	// 6.3.0 has a finding but no usable fix: it is not updated, so it does
	// not count as covered and 7.5.1 is not updated alone.
	ps := match(t, l,
		nodeFinding("CVE-1", "semver", "7.5.1", "7.5.2"),
		nodeFinding("CVE-2", "semver", "6.3.0", "not-a-version"),
	)
	for _, p := range ps {
		if p.Action != ActionManual {
			t.Errorf("%s %s = %+v, want manual for the whole package", p.Name, p.Installed, p)
		}
	}
	if p := find(t, ps, "semver", "7.5.1"); p.Reason != ReasonMultipleVersions || len(p.Occurrences) != 2 || p.SelectionLowerBound != "" {
		t.Errorf("7.5.1 = %+v", p)
	}
	if p := find(t, ps, "semver", "6.3.0"); p.Reason != ReasonUnparsableVersion {
		t.Errorf("6.3.0 keeps its own reason: %+v", p)
	}

	// An occurrence from another source makes the whole package manual even
	// when its version is above the target.
	lock2 := `{"lockfileVersion":3,"packages":{
	  "":{"dependencies":{"semver":"7"}},
	  "node_modules/semver":{"version":"7.5.1","resolved":"https://registry.npmjs.org/semver/-/semver-7.5.1.tgz"},
	  "node_modules/a/node_modules/semver":{"version":"9.0.0","resolved":"git+ssh://git@github.com/x/semver.git#abc"}
	}}`
	l2, err := parseNpm([]byte(npmManifest), []byte(lock2))
	if err != nil {
		t.Fatal(err)
	}
	if p := match(t, l2, nodeFinding("CVE-1", "semver", "7.5.1", "7.5.2"))[0]; p.Action != ActionManual || p.Reason != ReasonMultipleVersions {
		t.Errorf("semver next to a git copy = %+v", p)
	}

	// A sibling version without a finding (not vulnerable) at or above the
	// target stays fine.
	lock3 := strings.Replace(lock2, `"resolved":"git+ssh://git@github.com/x/semver.git#abc"`, `"resolved":"https://registry.npmjs.org/semver/-/semver-9.0.0.tgz"`, 1)
	l3, _ := parseNpm([]byte(npmManifest), []byte(lock3))
	if p := match(t, l3, nodeFinding("CVE-1", "semver", "7.5.1", "7.5.2"))[0]; p.Action != ActionUpdate {
		t.Errorf("semver next to a newer registry copy = %+v", p)
	}
}

func TestLanguagePlan_KeepsFindingCorrespondence(t *testing.T) {
	gh := newFakeGitHub()
	npmRepo(gh, "ex/app", ".")
	deps := []DependencyMapping{depMapping("compose/shop/api", "ex/app", "."), depMapping("compose/shop/worker", "ex/app", ".")}
	f1 := nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21")
	f1.PkgPath = "app/node_modules/lodash/package.json"
	f2 := nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21")
	f2.PkgPath = "srv/node_modules/lodash/package.json"
	api := langInput("shop", "api", f1, f2)
	worker := langInput("shop", "worker", f1)
	worker.Scan = configScan("shop-worker:2", 'b', []scanner.Finding{f1}, nil)
	plan := langPlan(t, gh, deps, nil, api, worker)
	p := plan.LanguageItems[0].Packages[0]
	if len(p.Origins) != 3 {
		t.Fatalf("origins = %+v", p.Origins)
	}
	entities := map[string]bool{}
	workloads := map[string]bool{}
	for _, o := range p.Origins {
		entities[o.Entity] = true
		workloads[o.Workload] = true
		if o.Name != "lodash" || o.Version != "4.17.20" || o.VulnID != "CVE-1" || o.Target != "Node.js" || o.PkgPath == "" || o.Ecosystem != "node-pkg" || o.Class != "lang" {
			t.Errorf("origin = %+v", o)
		}
	}
	if len(entities) != 2 || !workloads["compose/shop/api"] || !workloads["compose/shop/worker"] {
		t.Errorf("entities = %v, workloads = %v", entities, workloads)
	}
	for i := 1; i < len(p.Origins); i++ {
		if p.Origins[i-1].key() > p.Origins[i].key() {
			t.Error("origins are not sorted")
		}
	}
}

func TestFingerprint_LanguageOccurrencesAndOrigins(t *testing.T) {
	gh := newFakeGitHub()
	npmRepo(gh, "ex/app", ".")
	mk := func() Plan {
		return langPlan(t, gh, []DependencyMapping{depMapping("compose/shop/api", "ex/app", ".")}, nil,
			langInput("shop", "api", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21")))
	}
	base := mk()
	if len(base.LanguageItems[0].Packages[0].Occurrences) != 1 {
		t.Fatal("fixture")
	}
	for name, mut := range map[string]func(*Plan){
		"occurrence path": func(p *Plan) {
			p.LanguageItems[0].Packages[0].Occurrences[0].Path = "node_modules/x/node_modules/lodash"
		},
		"occurrence version": func(p *Plan) { p.LanguageItems[0].Packages[0].Occurrences[0].Version = "4.17.19" },
		"occurrence direct":  func(p *Plan) { p.LanguageItems[0].Packages[0].Occurrences[0].Direct = false },
		"occurrence marker":  func(p *Plan) { p.LanguageItems[0].Packages[0].Occurrences[0].Marker = "python_version<'3'" },
		"occurrence constraint": func(p *Plan) {
			p.LanguageItems[0].Packages[0].Occurrences[0].Constraint = ">=1"
		},
		"occurrence manual reason": func(p *Plan) {
			p.LanguageItems[0].Packages[0].Occurrences[0].ManualReason = ReasonNonRegistrySource
		},
		"origin entity":   func(p *Plan) { p.LanguageItems[0].Packages[0].Origins[0].Entity = "config:sha256:ff" },
		"origin pkg path": func(p *Plan) { p.LanguageItems[0].Packages[0].Origins[0].PkgPath = "other/package.json" },
		"origin workload": func(p *Plan) { p.LanguageItems[0].Packages[0].Origins[0].Workload = "compose/shop/other" },
		"origin vuln":     func(p *Plan) { p.LanguageItems[0].Packages[0].Origins[0].VulnID = "CVE-9" },
	} {
		c := mk()
		mut(&c)
		if Fingerprint(base) == Fingerprint(c) {
			t.Errorf("a changed %s did not change the fingerprint", name)
		}
	}
	// Occurrence order does not matter; SHAs do not appear.
	two := mk()
	two.LanguageItems[0].Packages[0].Occurrences = append(two.LanguageItems[0].Packages[0].Occurrences, SourceOccurrence{Path: "z", Version: "1.0.0"})
	rev := mk()
	rev.LanguageItems[0].Packages[0].Occurrences = []SourceOccurrence{{Path: "z", Version: "1.0.0"}, rev.LanguageItems[0].Packages[0].Occurrences[0]}
	if Fingerprint(two) != Fingerprint(rev) {
		t.Error("the order of occurrences changed the fingerprint")
	}
	sha := mk()
	sha.LanguageItems[0].Source.Files[0].BlobSHA = strings.Repeat("9", 40)
	if Fingerprint(base) != Fingerprint(sha) {
		t.Error("a blob SHA changed the fingerprint")
	}
}

func TestLanguagePlan_SamePriorityKeepsInputOrder(t *testing.T) {
	gh := newFakeGitHub()
	for _, r := range []string{"ex/a", "ex/b", "ex/c"} {
		npmRepo(gh, r, ".")
	}
	deps := []DependencyMapping{depMapping("compose/shop/a", "ex/a", "."), depMapping("compose/shop/b", "ex/b", "."), depMapping("compose/shop/c", "ex/c", ".")}
	f := func(v string) scanner.Finding { return nodeFinding("CVE-"+v, "lodash", "4.17.20", "4.17.21") }
	intel := func(id string) (VulnIntel, bool) {
		if id == "CVE-c" {
			return VulnIntel{Priority: PriorityActNow}, true
		}
		return VulnIntel{Priority: PriorityWatch}, true
	}
	// The planner is given c, a, b; a and b share a priority and keep their
	// order, whatever the order of the mappings.
	plan := langPlan(t, gh, deps, intel,
		langInput("shop", "b", f("b")), langInput("shop", "a", f("a")), langInput("shop", "c", f("c")))
	var keys []string
	for _, it := range plan.LanguageItems {
		keys = append(keys, strings.TrimSuffix(strings.TrimPrefix(it.Key, "deps:ex/"), "@main:.#npm"))
	}
	if got := strings.Join(keys, ","); got != "c,b,a" {
		t.Errorf("order = %s, want c,b,a (priority, then input order)", got)
	}
}

func TestLanguagePlan_StopsBetweenEcosystemsOfAUnit(t *testing.T) {
	gh := newFakeGitHub()
	npmRepo(gh, "ex/app", ".")
	gh.put("ex/app", ".", "requirements.txt", requirements)
	gh.readErr["ex/app/package-lock.json"] = &github.RateLimitedError{}
	deps := []DependencyMapping{depMapping("compose/shop/api", "ex/app", ".")}
	plan := langPlan(t, gh, deps, nil, langInput("shop", "api",
		nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"),
		pyFinding("CVE-2", "requests", "2.31.0", "2.32.0")))
	if len(plan.LanguageItems) != 2 {
		t.Fatalf("units = %d", len(plan.LanguageItems))
	}
	for _, it := range plan.LanguageItems {
		if it.Category != CategoryDeferred || it.Reason != ReasonRateLimited {
			t.Errorf("%s = %s / %s", it.Key, it.Category, it.Reason)
		}
	}
	if gh.count("read:ex/app/requirements.txt") != 0 {
		t.Errorf("the Python part read a file after the rate limit: %v", gh.calls)
	}
	if plan.LanguageItems[1].Source.CommitSHA != testCommit {
		t.Error("the deferred part lost the resolved commit")
	}
}

// cancelAfterFiles cancels the cycle when the nth file has been read.
type cancelAfterFiles struct {
	*fakeGitHub
	n      int
	cancel context.CancelFunc
}

func (c *cancelAfterFiles) ReadFile(ctx context.Context, repo, sha, p string) (github.File, error) {
	f, err := c.fakeGitHub.ReadFile(ctx, repo, sha, p)
	if c.count("read:") >= c.n {
		c.cancel()
	}
	return f, err
}

func TestLanguagePlan_DeadlineIsCheckedBeforeEachRead(t *testing.T) {
	inner := newFakeGitHub()
	npmRepo(inner, "ex/app", ".")
	inner.put("ex/app", ".", ".npmrc", "registry=https://registry.npmjs.org/\n")
	inner.put("ex/app", ".", "requirements.txt", requirements)
	ctx, cancel := context.WithCancel(context.Background())
	gh := &cancelAfterFiles{fakeGitHub: inner, n: 1, cancel: cancel}
	deps := []DependencyMapping{depMapping("compose/shop/api", "ex/app", ".")}
	plan := langPlanCtx(t, ctx, gh, deps, nil, langInput("shop", "api",
		nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"),
		pyFinding("CVE-2", "requests", "2.31.0", "2.32.0")))
	if n := inner.count("read:"); n != 1 {
		t.Errorf("%d files read after the cycle ended, want the one in flight: %v", n, inner.calls)
	}
	for _, it := range plan.LanguageItems {
		if it.Category != CategoryDeferred || it.Reason != ReasonCycleDeadline {
			t.Errorf("%s = %s / %s", it.Key, it.Category, it.Reason)
		}
	}
}

func TestLanguagePlan_SizeFailuresAreNotBudgetDeferrals(t *testing.T) {
	deps := []DependencyMapping{depMapping("compose/shop/a", "ex/one", "."), depMapping("compose/shop/b", "ex/two", ".")}
	in := func() []ImageInput {
		return []ImageInput{
			langInput("shop", "a", nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21")),
			langInput("shop", "b", nodeFinding("CVE-2", "express", "4.18.2", "4.19.2")),
		}
	}
	wrap := func(e error) error { return fmt.Errorf("%w: reading the file", e) }

	gh := newFakeGitHub()
	npmRepo(gh, "ex/one", ".")
	npmRepo(gh, "ex/two", ".")
	gh.readErr["ex/one/package-lock.json"] = wrap(github.ErrTooLarge)
	plan := langPlan(t, gh, deps, nil, in()...)
	if first := plan.LanguageItems[0]; first.Category != CategoryFailed || first.Reason != ReasonFileTooLarge {
		t.Errorf("a file over its cap = %s / %s", first.Category, first.Reason)
	}
	if second := plan.LanguageItems[1]; second.Category != CategoryDependencyUpdateCandidate {
		t.Errorf("one oversized file stopped the others: %s / %s", second.Category, second.Reason)
	}

	gh = newFakeGitHub()
	npmRepo(gh, "ex/one", ".")
	npmRepo(gh, "ex/two", ".")
	gh.listErr["ex/one/."] = wrap(github.ErrTooLarge)
	if first := langPlan(t, gh, deps, nil, in()...).LanguageItems[0]; first.Category != CategoryFailed || first.Reason != ReasonSourceTooLarge {
		t.Errorf("a directory listing over its cap = %s / %s", first.Category, first.Reason)
	}

	gh = newFakeGitHub()
	npmRepo(gh, "ex/one", ".")
	npmRepo(gh, "ex/two", ".")
	gh.readErr["ex/one/package-lock.json"] = wrap(github.ErrByteBudgetExhausted)
	plan = langPlan(t, gh, deps, nil, in()...)
	for _, it := range plan.LanguageItems {
		if it.Category != CategoryDeferred || it.Reason != ReasonByteBudget {
			t.Errorf("%s = %s / %s, want a deferral for the exhausted byte budget", it.Key, it.Category, it.Reason)
		}
	}
	if gh.count("branch:ex/two") != 0 {
		t.Error("GitHub was asked again after the byte budget ran out")
	}
}
