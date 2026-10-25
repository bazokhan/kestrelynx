package remediation

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

const pyRuntime = "Python runtime"

// fakeRuntime is a scanner.RuntimeAdvisor for CPython: the vulnerabilities of
// a version are listed in vulns, a version it has no entry for has none.
type fakeRuntime struct {
	vulns     map[string][]string
	unchecked bool
	// listed makes an unchecked result still list the runtime's package.
	listed bool
}

func (f fakeRuntime) Augment(scan scanner.ImageScan, severities []string) scanner.RuntimeAugment {
	var ver string
	for _, e := range scan.ConfigEnv {
		if v, ok := cutPrefix(e, "PYTHON_VERSION="); ok {
			ver = v
		}
	}
	if ver == "" {
		return scanner.RuntimeAugment{}
	}
	if f.unchecked {
		out := scanner.RuntimeAugment{Unchecked: []string{pyRuntime}}
		if f.listed {
			out.Packages = runtimePkgs(ver)
		}
		return out
	}
	var out scanner.RuntimeAugment
	for _, id := range f.vulns[ver] {
		out.Findings = append(out.Findings, runtimeFinding(id, ver))
	}
	out.Packages = runtimePkgs(ver)
	return out
}

func cutPrefix(s, p string) (string, bool) {
	if len(s) >= len(p) && s[:len(p)] == p {
		return s[len(p):], true
	}
	return "", false
}

func runtimeFinding(id, ver string) scanner.Finding {
	return scanner.Finding{
		Class: inventory.ClassLang, Type: string(inventory.EcosystemPythonRuntime), Target: "usr/local/bin/python3.12", PkgPath: "usr/local/bin/python3.12",
		Package: pyRuntime, InstalledVer: ver, FixedVer: "3.12.99", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: id,
	}
}

func runtimePkgs(ver string) []scanner.ResultPackages {
	return []scanner.ResultPackages{{
		Target: "usr/local/bin/python3.12", Class: inventory.ClassLang, Type: string(inventory.EcosystemPythonRuntime),
		Packages: []scanner.Package{{Name: pyRuntime, Version: ver}},
	}}
}

func withRuntime(in ImageInput, ver string) ImageInput {
	in.Scan.ConfigEnv = []string{"PATH=/usr/local/bin", "PYTHON_VERSION=" + ver}
	return in
}

func withBaseEnv(r registry.Resolution, env ...string) registry.Resolution {
	r.Env = env
	return r
}

func (e *dfEnv) planRuntimes(t *testing.T, prep scanner.ScanConditions, rts []scanner.RuntimeAdvisor, inputs ...ImageInput) Plan {
	t.Helper()
	p, err := NewPlanner(Config{
		Registry: e.reg, Scanner: e.scn, Prepared: prep, Limits: bigLimits, GitHub: e.gh, Runtimes: rts,
		Dockerfiles: []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", ""), dfMapping("compose/p/worker", "Dockerfile", "")},
		Now:         func() time.Time { return time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return p.Plan(context.Background(), inputs)
}

func joinPkgs(a, b []scanner.ResultPackages) []scanner.ResultPackages {
	return append(append([]scanner.ResultPackages(nil), a...), b...)
}

// A pinned base whose image config and the running image's name the same
// runtime version: the runtime findings count as the base's and the
// comparison of the bases resolves them.
func TestDockerfileRuntimeFindingsJoinBase(t *testing.T) {
	setup := func(runEnv, curEnv []string, candPkgs []scanner.ResultPackages) (*dfEnv, ImageInput) {
		e := newDFEnv()
		e.gh.put("ex/app", ".", "Dockerfile", appDockerfile)
		cur := withBaseEnv(baseResolution('1', '2', 'a', 'b'))
		cur.Env = curEnv
		e.reg.res["python:3.12.3-slim"] = cur
		e.candidateScan("python:3.12.3-slim", []scanner.Finding{runtimeFinding("CVE-R", "3.12.3")}, joinPkgs(pkgs("libc", "1"), runtimePkgs("3.12.3")))
		e.base("3.12.5-slim", baseResolution('3', '4', 'x', 'y'), nil, candPkgs)
		in := dfInput("myapp:1", 'a', "app", appLayers, runtimeFinding("CVE-R", "3.12.3"))
		in.Scan.ConfigEnv = runEnv
		return e, in
	}
	same := []string{"PATH=/x", "PYTHON_VERSION=3.12.3"}
	okCand := joinPkgs(pkgs("libc", "2"), runtimePkgs("3.12.5"))

	t.Run("same version: adopted", func(t *testing.T) {
		e, in := setup(same, same, okCand)
		it := onlyDockerfile(t, e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil, in))
		if it.Category != CategoryPRCandidate || it.Reason != ReasonAdopted {
			t.Fatalf("item = %s/%s (%s)", it.Category, it.Reason, it.Detail)
		}
		if it.Counts.Targets != 1 || it.Counts.Resolved != 1 {
			t.Errorf("counts = %+v", it.Counts)
		}
		if got := it.Entities[0].Findings; got != (LayerCounts{Base: 1}) {
			t.Errorf("findings by layer = %+v", got)
		}
	})
	t.Run("last value of a repeated variable is used", func(t *testing.T) {
		e, in := setup([]string{"PYTHON_VERSION=3.11.0", "PYTHON_VERSION=3.12.3"}, same, okCand)
		if it := onlyDockerfile(t, e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil, in)); it.Category != CategoryPRCandidate {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("different version: left unknown", func(t *testing.T) {
		e, in := setup([]string{"PYTHON_VERSION=3.12.2"}, same, okCand)
		it := onlyDockerfile(t, e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil, in))
		if it.Category != CategoryNoCandidate || it.Reason != ReasonNoBaseFindings {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("not set on the running image", func(t *testing.T) {
		e, in := setup(nil, same, okCand)
		if it := onlyDockerfile(t, e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil, in)); it.Reason != ReasonNoBaseFindings {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("not set on the base", func(t *testing.T) {
		e, in := setup(same, []string{"PATH=/x"}, okCand)
		if it := onlyDockerfile(t, e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil, in)); it.Reason != ReasonNoBaseFindings {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
	t.Run("the candidate side was not checked: not adopted", func(t *testing.T) {
		e, in := setup(same, same, pkgs("libc", "2"))
		it := onlyDockerfile(t, e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil, in))
		if it.Category == CategoryPRCandidate {
			t.Fatalf("item = %s/%s", it.Category, it.Reason)
		}
		if it.Category != CategoryNotComparable || it.Reason != ReasonAnalysisIncomplete {
			t.Errorf("item = %s/%s (%s)", it.Category, it.Reason, it.Detail)
		}
	})
	t.Run("the baseline side was not checked: not adopted", func(t *testing.T) {
		// An OS target the candidate resolves keeps the comparison going, so
		// only the unjudged runtime target can stop the adoption.
		e, in := setup(same, same, okCand)
		in.Scan.Findings = append(in.Scan.Findings, layered(finding("CVE-A", "libc", "1", "2", scanner.SeverityHigh), 'b'))
		e.candidateScan("python:3.12.3-slim", []scanner.Finding{finding("CVE-A", "libc", "1", "2", scanner.SeverityHigh)}, pkgs("libc", "1"))
		it := onlyDockerfile(t, e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil, in))
		if it.Category != CategoryNotComparable || it.Reason != ReasonAnalysisIncomplete {
			t.Fatalf("item = %s/%s (%s)", it.Category, it.Reason, it.Detail)
		}
		cmp := it.Entities[0].Comparison
		if cmp == nil {
			t.Fatal("no comparison")
		}
		found := false
		for _, v := range cmp.Verdicts {
			if v.VulnID == "CVE-R" {
				found = true
				if v.Outcome != OutcomeUnknown {
					t.Errorf("runtime verdict = %s", v.Outcome)
				}
			}
		}
		if !found {
			t.Error("no verdict for the runtime target")
		}
	})
	t.Run("an unattributed runtime finding does not stop an OS target", func(t *testing.T) {
		e, in := setup([]string{"PYTHON_VERSION=3.12.2"}, same, okCand)
		in.Scan.Findings = append(in.Scan.Findings, layered(finding("CVE-A", "libc", "1", "2", scanner.SeverityHigh), 'b'))
		e.candidateScan("python:3.12.3-slim", []scanner.Finding{finding("CVE-A", "libc", "1", "2", scanner.SeverityHigh)}, pkgs("libc", "1"))
		it := onlyDockerfile(t, e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil, in))
		if it.Category != CategoryPRCandidate || it.Counts.Targets != 1 {
			t.Errorf("item = %s/%s counts %+v", it.Category, it.Reason, it.Counts)
		}
	})
}

// A floating tag that moved on: the runtime of the current base tells what a
// rebuild would pick up.
func TestDockerfileRuntimeRebuild(t *testing.T) {
	adv := func() []scanner.RuntimeAdvisor {
		return []scanner.RuntimeAdvisor{fakeRuntime{vulns: map[string][]string{
			"3.12.3": {"CVE-R1", "CVE-R2", "CVE-R3"},
			"3.12.9": {"CVE-R3", "CVE-R4"},
		}}}
	}
	setup := func(baseEnv ...string) *dfEnv {
		e := newDFEnv()
		e.gh.put("ex/app", ".", "Dockerfile", "FROM python:3.12-slim\nCOPY . /app\n")
		e.base("3.12-slim", withBaseEnv(baseResolution('1', '2', '9', 'b'), baseEnv...), nil, pkgs("libc", "2"))
		return e
	}
	run := func(h byte, svc string, layers []byte) ImageInput {
		return withRuntime(dfInput("my"+svc+":1", h, svc, layers,
			runtimeFinding("CVE-R3", "3.12.3"), runtimeFinding("CVE-R1", "3.12.3"), runtimeFinding("CVE-R2", "3.12.3")), "3.12.3")
	}
	want := []RuntimeRebuild{{Package: pyRuntime, Installed: "3.12.3", BaseVersion: "3.12.9", Disappearing: []string{"CVE-R1", "CVE-R2"}, Remaining: []string{"CVE-R3"}}}

	t.Run("recorded on the entity and the item", func(t *testing.T) {
		e := setup("PYTHON_VERSION=3.12.9")
		it := onlyDockerfile(t, e.planRuntimes(t, prepared, adv(), run('a', "app", appLayers)))
		if it.Category != CategoryNotComparable || it.Reason != ReasonFloatingBaseUnconfirmed {
			t.Fatalf("item = %s/%s", it.Category, it.Reason)
		}
		if !reflect.DeepEqual(it.Entities[0].RebuildRuntimes, want) || !reflect.DeepEqual(it.RebuildRuntimes, want) {
			t.Errorf("entity %+v item %+v", it.Entities[0].RebuildRuntimes, it.RebuildRuntimes)
		}
	})
	t.Run("images of one item are grouped, the base-only finding is not counted", func(t *testing.T) {
		e := setup("PYTHON_VERSION=3.12.9")
		plan := e.planRuntimes(t, prepared, adv(), run('a', "app", appLayers), run('b', "worker", []byte{'a', 'd', 'c'}))
		it := onlyDockerfile(t, plan)
		if len(it.Entities) != 2 || it.Reason != ReasonFloatingBaseUnconfirmed {
			t.Fatalf("item = %s/%s entities %d", it.Category, it.Reason, len(it.Entities))
		}
		if !reflect.DeepEqual(it.RebuildRuntimes, want) {
			t.Errorf("item = %+v", it.RebuildRuntimes)
		}
	})
	t.Run("an item with mixed outcomes carries none", func(t *testing.T) {
		e := setup("PYTHON_VERSION=3.12.9")
		// The first image still has the base the tag points at.
		plan := e.planRuntimes(t, prepared, adv(), run('a', "app", []byte{'9', 'b', 'c'}), run('b', "worker", appLayers))
		it := onlyDockerfile(t, plan)
		if it.Category != CategoryManual || it.Reason != ReasonDockerfileSetNotAdopted {
			t.Fatalf("item = %s/%s", it.Category, it.Reason)
		}
		if len(it.RebuildRuntimes) != 0 {
			t.Errorf("item = %+v", it.RebuildRuntimes)
		}
		if len(it.Entities[1].RebuildRuntimes) != 1 {
			t.Errorf("the entity keeps its own record: %+v", it.Entities[1].RebuildRuntimes)
		}
	})
	t.Run("no runtime variable on the base", func(t *testing.T) {
		e := setup("PATH=/x")
		it := onlyDockerfile(t, e.planRuntimes(t, prepared, adv(), run('a', "app", appLayers)))
		if len(it.RebuildRuntimes) != 0 || len(it.Entities[0].RebuildRuntimes) != 0 {
			t.Errorf("item = %+v", it.RebuildRuntimes)
		}
	})
	t.Run("the base cannot be checked", func(t *testing.T) {
		for _, listed := range []bool{false, true} {
			e := setup("PYTHON_VERSION=3.12.9")
			it := onlyDockerfile(t, e.planRuntimes(t, prepared, []scanner.RuntimeAdvisor{fakeRuntime{unchecked: true, listed: listed}}, run('a', "app", appLayers)))
			if len(it.RebuildRuntimes) != 0 || len(it.Entities[0].RebuildRuntimes) != 0 {
				t.Errorf("listed %v: entity %+v item %+v", listed, it.Entities[0].RebuildRuntimes, it.RebuildRuntimes)
			}
		}
	})
	t.Run("no severities, no advisors", func(t *testing.T) {
		e := setup("PYTHON_VERSION=3.12.9")
		noSev := prepared
		noSev.Severities = nil
		if it := onlyDockerfile(t, e.planRuntimes(t, noSev, adv(), run('a', "app", appLayers))); len(it.RebuildRuntimes) != 0 {
			t.Errorf("without severities: %+v", it.RebuildRuntimes)
		}
		if it := onlyDockerfile(t, e.planRuntimes(t, prepared, nil, run('a', "app", appLayers))); len(it.RebuildRuntimes) != 0 {
			t.Errorf("without advisors: %+v", it.RebuildRuntimes)
		}
	})
	t.Run("the running image has no runtime finding", func(t *testing.T) {
		e := setup("PYTHON_VERSION=3.12.9")
		in := withRuntime(dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...), "3.12.3")
		if it := onlyDockerfile(t, e.planRuntimes(t, prepared, adv(), in)); len(it.RebuildRuntimes) != 0 {
			t.Errorf("item = %+v", it.RebuildRuntimes)
		}
	})
}

func TestMergeRuntimeRebuilds(t *testing.T) {
	ents := []DockerfileEntity{
		{RebuildRuntimes: []RuntimeRebuild{
			{Package: "Python runtime", Installed: "3.12.3", BaseVersion: "3.12.9", Disappearing: []string{"B", "A"}, Remaining: []string{"C"}},
			{Package: "Node.js", Installed: "22.1.0", BaseVersion: "22.2.0", Disappearing: []string{"N1"}},
		}},
		{RebuildRuntimes: []RuntimeRebuild{
			{Package: "Python runtime", Installed: "3.12.3", BaseVersion: "3.12.9", Disappearing: []string{"A", "D", "C"}},
			{Package: "Python runtime", Installed: "3.11.0", BaseVersion: "3.12.9", Disappearing: []string{"E"}},
		}},
	}
	want := []RuntimeRebuild{
		{Package: "Node.js", Installed: "22.1.0", BaseVersion: "22.2.0", Disappearing: []string{"N1"}},
		{Package: "Python runtime", Installed: "3.11.0", BaseVersion: "3.12.9", Disappearing: []string{"E"}},
		{Package: "Python runtime", Installed: "3.12.3", BaseVersion: "3.12.9", Disappearing: []string{"A", "B", "D"}, Remaining: []string{"C"}},
	}
	if got := mergeRuntimeRebuilds(ents); !reflect.DeepEqual(got, want) {
		t.Errorf("merged = %+v", got)
	}
}

// An image that runs directly from a registry tag: the runtime finding is a
// target of the tag update and the candidate's package list shows it checked.
func TestPlanDirectImageRuntimeFinding(t *testing.T) {
	run := func(candPkgs []scanner.ResultPackages, candFindings ...scanner.Finding) Item {
		e := newEnv()
		e.reg.tags["nginx"] = registry.TagList{Tags: []string{"1.25.3", "1.25.4", "1.25.5"}, Pages: 1}
		e.reg.res["nginx:1.25.5"] = resolution('b', 'c')
		e.candidateScan("nginx:1.25.5", candFindings, candPkgs)
		in := input("nginx:1.25.3", 'a', prepared, fixedA(), runtimeFinding("CVE-R", "3.12.3"))
		in.Scan.Packages = joinPkgs(in.Scan.Packages, runtimePkgs("3.12.3"))
		plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{in})
		return item(t, plan, 0)
	}

	it := run(joinPkgs(pkgs("libc", "2"), runtimePkgs("3.12.5")))
	if it.Category != CategoryPRCandidate || it.Reason != ReasonAdopted {
		t.Fatalf("item = %s/%s (%s)", it.Category, it.Reason, it.Detail)
	}
	if len(it.Targets) != 2 || it.Comparison == nil {
		t.Fatalf("targets = %+v", it.Targets)
	}
	resolved := map[string]bool{}
	for _, v := range it.Comparison.Verdicts {
		if v.Outcome == OutcomeResolved {
			resolved[v.VulnID] = true
		}
	}
	if !resolved["CVE-R"] || !resolved["CVE-A"] {
		t.Errorf("verdicts = %+v", it.Comparison.Verdicts)
	}

	// A candidate scan that did not check the runtime cannot show it resolved.
	if it := run(pkgs("libc", "2")); it.Category == CategoryPRCandidate {
		t.Errorf("item = %s/%s", it.Category, it.Reason)
	}
}
