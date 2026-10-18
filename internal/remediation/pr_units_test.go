package remediation

import (
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

func TestBuildComposeUnitsAdopted(t *testing.T) {
	plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, []string{"CVE-2"}))
	units := buildComposeUnits(plan, testContainers(), testMappings())
	if len(units) != 1 {
		t.Fatalf("units = %d", len(units))
	}
	u := units[0]
	if u.manual || strings.Join(u.services, ",") != "web,worker" || strings.Join(u.locations, ",") != "services.web.image,services.worker.image" ||
		u.candidate == nil || u.candidate.Tag != "1.25.4" || u.repo != testRepo {
		t.Errorf("unit = %+v", u)
	}
	if len(u.also) != 1 || u.also[0] != (ServiceRef{Project: "other", Service: "extra", Container: "other-extra-1"}) {
		t.Errorf("also running = %+v", u.also)
	}
	ft := u.fixTargets()
	if len(ft) != 2 || ft[0].VulnID != "CVE-1" || ft[0].Location != "services.web.image" || ft[1].Location != "services.worker.image" {
		t.Errorf("fix targets = %+v", ft)
	}
	ev := u.evidence(plan)
	if len(ev.Items) != 1 || len(ev.Items[0].Resolved) != 1 || len(ev.Items[0].Remaining) != 1 || ev.TrivyVersion != "0.71.2" || len(ev.Items[0].Locations) != 2 {
		t.Errorf("evidence = %+v", ev)
	}
}

func TestComposeEvidenceSeparatesOtherFindings(t *testing.T) {
	it := nginxItem("1.25.4", '1', []string{"CVE-1"}, []string{"CVE-2"})
	// Findings without a target (no fixed version) are compared too.
	it.Comparison.Verdicts = append(it.Comparison.Verdicts,
		VulnVerdict{VulnID: "CVE-3", Package: pkgCoord("pkg-CVE-3"), Outcome: OutcomeResolved},
		VulnVerdict{VulnID: "CVE-4", Package: pkgCoord("pkg-CVE-4"), Outcome: OutcomeRemaining},
		VulnVerdict{VulnID: "CVE-5", Package: pkgCoord("pkg-CVE-5"), Outcome: OutcomeRemaining},
	)
	plan := testPlan(it)
	units := buildComposeUnits(plan, testContainers(), testMappings())
	if len(units) != 1 {
		t.Fatalf("units = %d", len(units))
	}
	ev := units[0].evidence(plan)
	ids := func(vs []VulnSummary) string {
		var out []string
		for _, v := range vs {
			out = append(out, v.VulnID)
		}
		return strings.Join(out, ",")
	}
	got := ev.Items[0]
	if ids(got.Resolved) != "CVE-1" || ids(got.Remaining) != "CVE-2" || ids(got.OtherResolved) != "CVE-3" || ids(got.OtherRemaining) != "CVE-4,CVE-5" {
		t.Errorf("resolved %q, remaining %q, other resolved %q, other remaining %q",
			ids(got.Resolved), ids(got.Remaining), ids(got.OtherResolved), ids(got.OtherRemaining))
	}
	// Replacement still sees every pair the comparison resolved.
	resolved := resolvedFromEvidence(ev)
	for _, id := range []string{"CVE-1", "CVE-3"} {
		k := FixTarget{Location: "services.web.image", VulnID: id, Package: pkgCoord("pkg-" + id)}.key()
		if !resolved[k] {
			t.Errorf("%s missing from the resolved pairs", id)
		}
	}
}

func TestBuildComposeUnitsWholeSetOrNothing(t *testing.T) {
	t.Run("entity without item", func(t *testing.T) {
		cs := testContainers()
		cs[1].Image.Config = configKey('z').Digest // the worker runs other content the planner skipped
		units := buildComposeUnits(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)), cs, testMappings())
		if len(units) != 1 || !units[0].manual || units[0].manualReason != ReasonComposeSetNotAdopted || len(units[0].services) != 2 {
			t.Errorf("units = %+v", units[0])
		}
	})
	t.Run("item not adopted", func(t *testing.T) {
		cs := testContainers()
		cs[1].Image.Config = configKey('z').Digest
		other := nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)
		other.Key = "nginx:1.25.3|" + entityString(configKey('z'))
		other.Category, other.Candidate = CategoryManual, nil
		units := buildComposeUnits(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil), other), cs, testMappings())
		if len(units) != 1 || !units[0].manual || units[0].manualReason != ReasonComposeSetNotAdopted {
			t.Errorf("units = %+v", units)
		}
	})
	t.Run("different candidates", func(t *testing.T) {
		cs := testContainers()
		cs[1].Image.Config = configKey('z').Digest
		other := nginxItem("1.25.5", '2', []string{"CVE-1"}, nil)
		other.Key = "nginx:1.25.3|" + entityString(configKey('z'))
		units := buildComposeUnits(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil), other), cs, testMappings())
		if len(units) != 1 || !units[0].manual || !strings.Contains(units[0].manualDetail, "different candidates") {
			t.Errorf("units = %+v", units)
		}
	})
	t.Run("nothing to propose", func(t *testing.T) {
		it := nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)
		it.Category = CategoryPullAgain
		if units := buildComposeUnits(testPlan(it), testContainers(), testMappings()); len(units) != 0 {
			t.Errorf("units = %+v", units)
		}
	})
	t.Run("unmapped", func(t *testing.T) {
		if units := buildComposeUnits(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)), testContainers(), nil); len(units) != 0 {
			t.Errorf("units = %+v", units)
		}
	})
}

func TestBuildComposeUnitsGroupsByFileAndReference(t *testing.T) {
	cs := testContainers()
	ms := testMappings()
	ms[1].Path = "worker.yml" // the worker is deployed by another file
	units := buildComposeUnits(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)), cs, ms)
	if len(units) != 2 || units[0].path != "compose.yml" || units[1].path != "worker.yml" {
		t.Fatalf("units = %+v", units)
	}
	// The same image spelled another way is the same unit.
	cs[1].Image.Ref = "docker.io/library/nginx:1.25.3"
	ms[1].Path = "compose.yml"
	it := nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)
	it2 := it
	it2.Key = "docker.io/library/nginx:1.25.3|" + entityString(configKey('a'))
	units = buildComposeUnits(testPlan(it, it2), cs, ms)
	if len(units) != 1 || len(units[0].services) != 2 || units[0].current != "docker.io/library/nginx:1.25.3" {
		t.Errorf("units = %+v", units)
	}
}

func TestFixTargetsAreTheIntersectionPerLocation(t *testing.T) {
	cs := testContainers()
	cs = append(cs, inventory.Container{Name: "app-web-2", Workload: inventory.Workload{Kind: inventory.WorkloadCompose, Group: "app", Name: "web"},
		Image: inventory.RunningImage{Ref: "nginx:1.25.3", Config: configKey('z').Digest}})
	a := nginxItem("1.25.4", '1', []string{"CVE-1", "CVE-2"}, nil)
	b := nginxItem("1.25.4", '1', []string{"CVE-1"}, []string{"CVE-2"})
	b.Key = "nginx:1.25.3|" + entityString(configKey('z'))
	units := buildComposeUnits(testPlan(a, b), cs, testMappings())
	if len(units) != 1 || units[0].manual {
		t.Fatalf("units = %+v", units)
	}
	var web []string
	for _, f := range units[0].fixTargets() {
		if f.Location == "services.web.image" {
			web = append(web, f.VulnID)
		}
	}
	if strings.Join(web, ",") != "CVE-1" {
		t.Errorf("web fix targets = %v, want only what both entities resolve", web)
	}
}

func TestFingerprintCoversPullRequestStage(t *testing.T) {
	base := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
	plain := Fingerprint(base)
	with := func(units []PRUnit, problems []PRStageProblem, ops []OperationEvent) string {
		p := base
		PRStageResult{Units: units, Problems: problems, Operations: ops}.Attach(&p)
		return Fingerprint(p)
	}
	if with(nil, nil, nil) != plain {
		t.Error("an empty stage result changes the fingerprint of a plan")
	}
	created := []PRUnit{{Key: "k", UpdateKey: "u", Status: PRStatusCreated, Number: 1, State: PRStateOpen, Detail: "x"}}
	open := []PRUnit{{Key: "k", UpdateKey: "u", Status: PRStatusOpen, Number: 1, State: PRStateOpen, Detail: "y"}}
	other := []PRUnit{{Key: "k", UpdateKey: "u", Status: PRStatusOpen, Number: 2, State: PRStateOpen}}
	deferred := []PRUnit{{Key: "k", UpdateKey: "u", Status: PRStatusDeferred, Reason: ReasonPRLimit}}
	deferred2 := []PRUnit{{Key: "k", UpdateKey: "u", Status: PRStatusDeferred, Reason: ReasonCandidateChanged}}
	fps := map[string]string{}
	for name, fp := range map[string]string{
		"created": with(created, nil, nil), "open": with(open, nil, nil), "other number": with(other, nil, nil),
		"deferred": with(deferred, nil, nil), "deferred other reason": with(deferred2, nil, nil),
		"problem": with(nil, []PRStageProblem{{Code: PRProblemWriteBlocked, Repo: testRepo}}, nil),
	} {
		if prev, dup := fps[fp]; dup || fp == plain {
			t.Errorf("%s fingerprints like %q", name, prev)
		}
		fps[fp] = name
	}
	// Details, times and operation events are not part of it.
	open2 := []PRUnit{{Key: "k", UpdateKey: "u", Status: PRStatusOpen, Number: 1, State: PRStateOpen, Detail: "other text"}}
	if with(open, nil, nil) != with(open2, nil, []OperationEvent{{Seq: 1, ID: "x"}}) {
		t.Error("detail text or operations change the fingerprint")
	}
	if Fingerprint(Plan{PRProblems: []PRStageProblem{{Code: PRProblemStorageFailed}}}) == "" {
		t.Error("a plan with only a stage problem has the empty fingerprint")
	}
}
