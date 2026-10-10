package remediation

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// Tests of what an update's result is compared with: every occurrence of an
// updated package, both directions of every requirement an update touches, the
// dependency records of uv packages, the kind of an unresolved requirement,
// the extras that spread through a pip report, and the time scans take.

func TestUntouchedOccurrenceOfAnUpdatedPackageIsComparedWithTheRegistryToo(t *testing.T) {
	root := map[string]string{"a": "^1.0.0", "t": "^1.0.0"}
	// A second copy of t is already at the target version in the original,
	// with the tarball of 1.0.0, and the container returns it untouched.
	nested := npmEntry{ver: "1.0.5", url: npmURL("t", "1.0.0")}
	before := map[string]npmEntry{
		"node_modules/a":                {ver: "1.0.0", deps: map[string]string{"t": "^1.0.0"}},
		"node_modules/a/node_modules/t": nested,
		"node_modules/t":                {ver: "1.0.0"},
	}
	after := map[string]npmEntry{
		"node_modules/a":                before["node_modules/a"],
		"node_modules/a/node_modules/t": nested,
		"node_modules/t":                {ver: "1.0.5"},
	}
	h := newNpmCase(t, root, before, after)
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	if !strings.Contains(it.Detail, "node_modules/a/node_modules/t") {
		t.Errorf("detail = %q", it.Detail)
	}

	// With the right tarball recorded the same project passes.
	good := npmEntry{ver: "1.0.5"}
	before["node_modules/a/node_modules/t"], after["node_modules/a/node_modules/t"] = good, good
	h = newNpmCase(t, root, before, after)
	it, _ = h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
}

func TestRequirementsOfAnEntryThatMovedAreJudgedInBothDirections(t *testing.T) {
	root := map[string]string{"a": "^1.0.0"}
	before := map[string]npmEntry{
		"node_modules/a": {ver: "1.0.0", deps: map[string]string{"t": "^1.0.0"}},
		"node_modules/t": {ver: "1.0.0", deps: map[string]string{"c": "^1.0.0"}},
		"node_modules/c": {ver: "1.0.0"},
	}
	// The update of t makes c, which only t needs, move; t's new version
	// accepts c ^1.0.3.
	mk := func(cVer string) *harness {
		after := map[string]npmEntry{
			"node_modules/a": before["node_modules/a"],
			"node_modules/t": {ver: "1.0.5", deps: map[string]string{"c": "^1.0.3"}},
			"node_modules/c": {ver: cVer},
		}
		return newNpmCase(t, root, before, after)
	}
	it, _ := mk("1.0.4").run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	it, _ = mk("3.0.1").run()
	wantCategory(t, it, CategoryManual, ReasonRangeExcludesFix)
	if !strings.Contains(it.Detail, "t 1.0.5 asks for c") {
		t.Errorf("detail = %q", it.Detail)
	}
	// A range that cannot be judged is left to a person.
	h := mk("1.0.4")
	h.npm.dists["t@1.0.5"] = NpmDist{Tarball: npmURL("t", "1.0.5"), Integrity: "sha512-t1.0.5", Dependencies: map[string]string{"c": "github:x/c"}}
	it, _ = h.run()
	wantCategory(t, it, CategoryManual, ReasonRangeNotEvaluable)
}

func TestPipRequirementOfAnotherPackageOnAnUpdatedOneIsJudged(t *testing.T) {
	h := newHarness(t, "pip")
	useUnhashed(t, h)
	h.pypi.requires = map[string][]string{"urllib3==1.26.17": {"six<1.0"}}
	h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		if n == 0 {
			return fakeOutcome{edit: map[string]map[string][]byte{stepBaseline: {worker.PipReportName: pipReportItems(pipItem{name: "urllib3", ver: "1.26.4"})}}}
		}
		return fakeOutcome{edit: map[string]map[string][]byte{stepCheck: {worker.PipReportName: pipReportItems(pipItem{name: "urllib3", ver: "1.26.17", requires: []string{"six<1.0"}}, pipItem{name: "six", ver: "1.16.0", notReq: true})}}}
	}
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonRangeExcludesFix)
}

// uvWithSix is the uv fixture after the update with a package "six" added
// before urllib3, and extra appended to the file (the last package is
// urllib3, so a table appended to it belongs to it).
func uvWithSix(t *testing.T, h *harness, urllib3Records string) {
	t.Helper()
	six := fmt.Sprintf(`[[package]]
name = "six"
version = "1.16.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = %q, hash = "sha256:%s" },
]

`, fakeWheelURL("six", "1.16.0"), fakeWheelSHA("six", "1.16.0"))
	s := strings.Replace(string(h.after), "[[package]]\nname = \"urllib3\"", six+"[[package]]\nname = \"urllib3\"", 1)
	h.editLock(s + urllib3Records)
}

func TestUvDependencyRecordsMustBeDeclaredByTheIndex(t *testing.T) {
	plain := "\n"
	t.Run("an undeclared dependency edge", func(t *testing.T) {
		h := newHarness(t, "uv")
		uvWithSix(t, h, plain)
		// urllib3 records a dependency on six (added to its dependencies below).
		s := string(h.after)
		s = strings.Replace(s, "[[package]]\nname = \"urllib3\"\nversion = \"1.26.17\"\nsource = { registry = \"https://pypi.org/simple\" }\n", "[[package]]\nname = \"urllib3\"\nversion = \"1.26.17\"\nsource = { registry = \"https://pypi.org/simple\" }\ndependencies = [\n    { name = \"six\" },\n]\n", 1)
		h.after = []byte(s)
		uvWithSix(t, h, "")
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
		if !strings.Contains(it.Detail, "does not declare") {
			t.Errorf("detail = %q", it.Detail)
		}
	})
	extra := func(name string) string {
		return fmt.Sprintf("\n[package.optional-dependencies]\nsocks = [\n    { name = %q },\n]\n", name)
	}
	t.Run("a dependency recorded for an extra the index declares for that extra", func(t *testing.T) {
		h := newHarness(t, "uv")
		h.pypi.requires = map[string][]string{"urllib3==1.26.17": {`six; extra == "socks"`}}
		uvWithSix(t, h, extra("six"))
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("a dependency recorded for another extra than the one the index names", func(t *testing.T) {
		h := newHarness(t, "uv")
		h.pypi.requires = map[string][]string{"urllib3==1.26.17": {`six; extra == "brotli"`}}
		uvWithSix(t, h, extra("six"))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("a dependency recorded for an extra the index declares without one", func(t *testing.T) {
		h := newHarness(t, "uv")
		h.pypi.requires = map[string][]string{"urllib3==1.26.17": {`six`}}
		uvWithSix(t, h, extra("six"))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("a dependency record of a kind a registry package does not have", func(t *testing.T) {
		h := newHarness(t, "uv")
		uvWithSix(t, h, "\n[package.dev-dependencies]\ndev = [\n    { name = \"six\" },\n]\n")
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
}

func TestExtraNamesOfAMarker(t *testing.T) {
	cases := []struct {
		marker string
		names  []string
		ok     bool
	}{
		{``, nil, true},
		{`python_version >= "3.8"`, nil, true},
		{`extra == "socks"`, []string{"socks"}, true},
		{`extra=='Socks_X'`, []string{"socks-x"}, true},
		{`(os_name != "nt") and extra == "brotli"`, []string{"brotli"}, true},
		{`extra == "a" or extra == 'b'`, []string{"a", "b"}, true},
		{`extra != "a"`, []string{"a"}, true},
		{`extra in "ab"`, nil, false},
		{`extra`, nil, false},
		{`extra == `, nil, false},
		{`extra == x`, nil, false},
		{`extra == "x`, nil, false},
	}
	for _, c := range cases {
		got, ok := extraNamesOf(c.marker)
		if ok != c.ok || (ok && strings.Join(got, ",") != strings.Join(c.names, ",")) {
			t.Errorf("extraNamesOf(%q) = %v, %v; want %v, %v", c.marker, got, ok, c.names, c.ok)
		}
	}
}

func TestUnresolvedRequirementKindIsTheRegistrys(t *testing.T) {
	root := map[string]string{"a": "^1.0.0"}
	// Before and after, t lists "o" under optionalDependencies and no entry
	// satisfies it.
	before := map[string]npmEntry{
		"node_modules/a": {ver: "1.0.0", deps: map[string]string{"t": "^1.0.0"}},
		"node_modules/t": {ver: "1.0.0", opt: map[string]string{"o": "^1.0.0"}},
	}
	after := map[string]npmEntry{
		"node_modules/a": before["node_modules/a"],
		"node_modules/t": {ver: "1.0.5", opt: map[string]string{"o": "^1.0.0"}},
	}
	t.Run("the registry declares it optional", func(t *testing.T) {
		h := newNpmCase(t, root, before, after)
		h.npm.dists["t@1.0.5"] = NpmDist{Tarball: npmURL("t", "1.0.5"), Integrity: "sha512-t1.0.5", OptionalDependencies: map[string]string{"o": "^1.0.0"}}
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("the registry declares it required", func(t *testing.T) {
		h := newNpmCase(t, root, before, after)
		h.npm.dists["t@1.0.5"] = NpmDist{Tarball: npmURL("t", "1.0.5"), Integrity: "sha512-t1.0.5", Dependencies: map[string]string{"o": "^1.0.0"}}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
	})
	t.Run("kinds are told apart by the unresolved-edge rule", func(t *testing.T) {
		mk := func(optional bool) *depGraph {
			g := &depGraph{nodes: map[string]*depNode{}}
			g.nodes["node_modules/p"] = &depNode{name: "p", version: "1", deps: []depEdge{{name: "o", optional: optional}}}
			return g
		}
		if got := newUnresolved(mk(true), mk(false)); len(got) != 1 {
			t.Errorf("optional before, required after: %v", got)
		}
		if got := newUnresolved(mk(false), mk(true)); len(got) != 1 {
			t.Errorf("required before, optional after: %v", got)
		}
		if got := newUnresolved(mk(true), mk(true)); len(got) != 0 {
			t.Errorf("the same optional: %v", got)
		}
	})
}

// pipExtrasCase is a project with urllib3 (updated) and an application that
// asks for packages with extras, and a fake index that declares the
// requirements.
func pipExtrasCase(t *testing.T, requires map[string][]string, before, after []pipItem) *harness {
	t.Helper()
	h := newHarness(t, "pip")
	h.files["requirements.txt"] = "urllib3==1.26.4\nselenium==4.0\n"
	h.item = itemFor(t, ManagerPip, h.files, urllibGroup())
	h.gh = ghFor(h.files)
	h.cfg.GitHub = h.gh
	h.pypi.requires = requires
	h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		items := before
		step := stepBaseline
		if n == 1 {
			items, step = after, stepCheck
		}
		return fakeOutcome{edit: map[string]map[string][]byte{step: {worker.PipReportName: pipReportItems(items...)}}}
	}
	return h
}

func TestExtrasAskedForByAParentSpreadToTheChild(t *testing.T) {
	requires := map[string][]string{
		"selenium==4.0":    {"urllib3[socks]>=1.26"},
		"urllib3==1.26.4":  {"pysocks!=1.5.7,<2.0,>=1.5.6; extra == 'socks'"},
		"urllib3==1.26.17": {"pysocks!=1.5.7,<2.0,>=1.5.6; extra == 'socks'"},
	}
	sel := pipItem{name: "selenium", ver: "4.0"}
	t.Run("the package the extra needs is installed", func(t *testing.T) {
		before := []pipItem{{name: "urllib3", ver: "1.26.4"}, sel, {name: "pysocks", ver: "1.7.1", notReq: true}}
		after := []pipItem{{name: "urllib3", ver: "1.26.17"}, sel, {name: "pysocks", ver: "1.7.1", notReq: true}}
		it, _ := pipExtrasCase(t, requires, before, after).run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("the package the extra needs is not installed", func(t *testing.T) {
		both := []pipItem{{name: "urllib3", ver: "1.26.4"}, sel}
		after := []pipItem{{name: "urllib3", ver: "1.26.17"}, sel}
		h := pipExtrasCase(t, requires, both, after)
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
		if !strings.Contains(it.Detail, "pysocks") {
			t.Errorf("detail = %q", it.Detail)
		}
	})
	t.Run("the package the extra needs is outside the range", func(t *testing.T) {
		before := []pipItem{{name: "urllib3", ver: "1.26.4"}, sel, {name: "pysocks", ver: "1.7.1", notReq: true}}
		after := []pipItem{{name: "urllib3", ver: "1.26.17"}, sel, {name: "pysocks", ver: "3.0", notReq: true}}
		it, _ := pipExtrasCase(t, requires, before, after).run()
		wantCategory(t, it, CategoryManual, ReasonRangeExcludesFix)
	})
	t.Run("extra names are PEP 685 names", func(t *testing.T) {
		req := map[string][]string{
			"selenium==4.0":    {"urllib3[So_Cks]>=1.26"},
			"urllib3==1.26.4":  {"pysocks; extra == 'so-cks'"},
			"urllib3==1.26.17": {"pysocks; extra == 'So.cks'"},
		}
		it, _ := pipExtrasCase(t, req, []pipItem{{name: "urllib3", ver: "1.26.4"}, sel}, []pipItem{{name: "urllib3", ver: "1.26.17"}, sel}).run()
		wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
	})
}

func TestExtrasSpreadThroughSeveralPackagesWhateverTheOrder(t *testing.T) {
	// selenium asks for b[x]; b with x asks for c[y]; c with y asks for d. The
	// report lists them in the order that takes the most passes.
	requires := map[string][]string{
		"selenium==4.0":   {"b[x]"},
		"b==1.0":          {"c[y]; extra == 'x'"},
		"c==1.0":          {"d; extra == 'y'"},
		"urllib3==1.26.4": nil,
	}
	order := func(withD bool) []pipItem {
		items := []pipItem{}
		if withD {
			items = append(items, pipItem{name: "d", ver: "1.0", notReq: true})
		}
		items = append(items, pipItem{name: "c", ver: "1.0", notReq: true}, pipItem{name: "b", ver: "1.0", notReq: true}, pipItem{name: "selenium", ver: "4.0"})
		return items
	}
	build := func(withD bool) []pipItem {
		return append(order(withD), pipItem{name: "urllib3", ver: "1.26.17"})
	}
	requires["urllib3==1.26.17"] = nil
	h := pipExtrasCase(t, requires, append(order(false), pipItem{name: "urllib3", ver: "1.26.4"}), build(false))
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonUnexplainedDiff)
	if !strings.Contains(it.Detail, " d ") && !strings.Contains(it.Detail, "requires d") {
		t.Errorf("detail = %q", it.Detail)
	}
	h = pipExtrasCase(t, requires, append(order(true), pipItem{name: "urllib3", ver: "1.26.4"}), build(true))
	it, _ = h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
}

func TestSpreadingOfExtrasIsBoundedAndWatchesTheDeadline(t *testing.T) {
	// A chain of packages each asking for the next with an extra, listed
	// last first so that every pass moves one step.
	n := maxExtraPasses + 8
	requires := map[string][]string{"selenium==4.0": {"p0[x]"}, "urllib3==1.26.4": nil, "urllib3==1.26.17": nil}
	items := []pipItem{}
	for i := n - 1; i >= 0; i-- {
		items = append(items, pipItem{name: fmt.Sprintf("p%d", i), ver: "1.0", notReq: true})
		if i+1 < n {
			requires[fmt.Sprintf("p%d==1.0", i)] = []string{fmt.Sprintf("p%d[x]; extra == 'x'", i+1)}
		}
	}
	items = append(items, pipItem{name: "selenium", ver: "4.0"})
	before := append(append([]pipItem{}, items...), pipItem{name: "urllib3", ver: "1.26.4"})
	after := append(append([]pipItem{}, items...), pipItem{name: "urllib3", ver: "1.26.17"})
	it, _ := pipExtrasCase(t, requires, before, after).run()
	wantCategory(t, it, CategoryManual, ReasonMarkerNotEvaluated)

	h := pipExtrasCase(t, map[string][]string{"selenium==4.0": nil}, []pipItem{{name: "urllib3", ver: "1.26.4"}, {name: "selenium", ver: "4.0"}}, []pipItem{{name: "urllib3", ver: "1.26.17"}, {name: "selenium", ver: "4.0"}})
	ctx, cancel := context.WithCancel(context.Background())
	h.cfg.PyPI = pypiFunc(func(c context.Context, name, version string) (PyPIRelease, error) {
		cancel()
		return PyPIRelease{Files: []PyPIFile{fakeWheel(name, version)}}, nil
	})
	it, _ = h.runCtx(ctx)
	wantCategory(t, it, CategoryDeferred, ReasonCycleDeadline)
}

func TestLongContinuedRequirementIsScannedOnce(t *testing.T) {
	build := func(n int) string {
		var b strings.Builder
		b.WriteString("urllib3==1.26.4 \\\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "    --hash=sha256:%064x \\\n", i)
		}
		b.WriteString("    --hash=sha256:" + h64('f') + "\n")
		return b.String()
	}
	t.Run("within the limit", func(t *testing.T) {
		text := build(maxLogicalLine - 100)
		start := time.Now()
		lf, err := parseRequirements([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		hs := requirementHashes([]byte(text), lf)
		if len(hs["urllib3"]) != maxLogicalLine-100+1 {
			t.Errorf("%d hashes", len(hs["urllib3"]))
		}
		lines := splitReqLines([]byte(text))
		if !requirementHasHashes(lines, 1) {
			t.Error("hashes not found")
		}
		out, err := rewriteLines(bg, []byte(text), lines, []reqEdit{{Name: "urllib3", Line: 1, OldVersion: "1.26.4", NewVersion: "1.26.17", Hashes: []string{h64('1')}}})
		if err != nil || !strings.HasPrefix(string(out), "urllib3==1.26.17 \\\n") {
			t.Fatalf("%v", err)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("took %s", d)
		}
	})
	t.Run("over the limit", func(t *testing.T) {
		text := build(maxLogicalLine + 100)
		lines := splitReqLines([]byte(text))
		if e := reqSpan(lines, 0); e-0+1 != maxLogicalLine {
			t.Errorf("span = %d lines", e+1)
		}
		_, err := rewriteLines(bg, []byte(text), lines, []reqEdit{{Name: "urllib3", Line: 1, OldVersion: "1.26.4", NewVersion: "1.26.17", Hashes: []string{h64('1')}}})
		if err == nil || !strings.Contains(err.Error(), "spans") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("an update of such a file is deferred, not run", func(t *testing.T) {
		h := newHarness(t, "pip")
		h.files["requirements.txt"] = build(maxLogicalLine + 100)
		h.item = itemFor(t, ManagerPip, h.files, urllibGroup())
		h.gh = ghFor(h.files)
		h.cfg.GitHub = h.gh
		it, _ := h.run()
		wantCategory(t, it, CategoryDeferred, ReasonUpdateInputLimit)
		if h.work.calls != 0 {
			t.Error("a job ran")
		}
	})
}

func TestMarkerEvaluationOfExtrasAndOfPatchLevels(t *testing.T) {
	cases := []struct {
		extras []string
		marker string
		want   bool
		err    bool
	}{
		{[]string{"a", "b"}, `extra != "a"`, true, false}, // true for b
		{[]string{"a"}, `extra != "a"`, true, false},      // true with no extra
		{[]string{"a", "b"}, `extra == "a"`, true, false},
		{[]string{"a", "b"}, `extra == "a" and extra == "b"`, false, false}, // one extra at a time
		{[]string{"a", "b"}, `extra == "c"`, false, false},
		{nil, `extra == "a"`, false, false},
		{[]string{"My_Extra"}, `extra == "my-extra"`, true, false},
		{[]string{"a"}, `extra == "a" and platform_release >= "5"`, false, true},
		{[]string{"a", "b"}, `extra == "a" and platform_release >= "5" or extra == "b"`, true, false},
		{nil, `python_full_version in "3.12.1 3.12.2"`, false, true},
		{nil, `python_full_version not in "3.11"`, false, true},
		{nil, `python_full_version === "3.12.0"`, false, true},
		{nil, `implementation_version in "3.12.1"`, false, true},
		{nil, `python_full_version != "3.12.5"`, false, true},
		{nil, `python_full_version ~= "3.12.1"`, false, true},
		{nil, `python_full_version >= "3.12"`, true, false},
		{nil, `python_full_version >= "3.11.4"`, true, false},
		{nil, `python_full_version < "3.12.0"`, false, false},
		{nil, `python_version in "3.11 3.12"`, true, false},
	}
	for _, c := range cases {
		env := markerEnv{pyMinor: "3.12", machine: "x86_64", extras: map[string]bool{}}
		for _, x := range c.extras {
			env.extras[normExtra(x)] = true
		}
		got, err := env.eval(c.marker)
		if (err != nil) != c.err || (err == nil && got != c.want) {
			t.Errorf("extras %v: eval(%s) = %v, %v; want %v, error %v", c.extras, c.marker, got, err, c.want, c.err)
		}
	}
}
