package runner

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/intel"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/notify"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func hex64(c byte) string { return strings.Repeat(string(c), 64) }

var linuxAmd64 = inventory.Platform{OS: "linux", Architecture: "amd64"}

func planConds() scanner.ScanConditions {
	return scanner.ScanConditions{
		TrivyVersion:       "0.71.2",
		VulnerabilityDB:    scanner.DBInfo{Version: 2, UpdatedAt: clock()},
		JavaDB:             scanner.DBInfo{Version: 1, UpdatedAt: clock()},
		Severities:         []string{"CRITICAL", "HIGH"},
		AnalysisSettings:   "image;test",
		VulnerabilityDBSHA: "v", JavaDBSHA: "j", TrivySHA: "t",
	}
}

func osFinding(vuln string) scanner.Finding {
	return scanner.Finding{
		Class: scanner.ClassOS, Type: "debian", Target: "web (debian 12)", Package: "libc",
		InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: vuln,
	}
}

func osPackages(ver string) []scanner.ResultPackages {
	return []scanner.ResultPackages{{
		Target: "web (debian 12)", Class: scanner.ClassOS, Type: "debian",
		Packages: []scanner.Package{{Name: "libc", Version: ver}},
	}}
}

// planScanner is the fake comparison-mode scanner: running images come back
// as the configured scan, candidates (remote targets) as a clean image.
type planScanner struct {
	events     []string
	local      map[string]scanner.ImageScan
	candidate  []scanner.Finding
	prepareErr error
	verifyOK   bool
	verifyErr  error
	prepares   int
	verifies   int
}

func (p *planScanner) Scan(_ context.Context, t scanner.ScanTarget) scanner.ImageScan {
	p.events = append(p.events, "scan:"+t.Subject.Ref)
	if t.Source == scanner.SourceRemote {
		return scanner.ImageScan{
			Image: t.Subject.Ref, Subject: t.Subject, ScannedKey: t.Subject.Key, Pinned: true,
			Source: scanner.SourceRemote, Platform: linuxAmd64, OSFamily: "debian", Findings: p.candidate, Packages: osPackages("2"),
		}
	}
	if s, ok := p.local[t.Subject.Ref]; ok {
		return s
	}
	return scanner.ImageScan{Image: t.Subject.Ref}
}

func (p *planScanner) PrepareDB(context.Context) (scanner.ScanConditions, error) {
	p.prepares++
	p.events = append(p.events, "prepare")
	return planConds(), p.prepareErr
}

func (p *planScanner) VerifyDB(context.Context, scanner.ScanConditions) (bool, error) {
	p.verifies++
	p.events = append(p.events, "verify")
	return p.verifyOK, p.verifyErr
}

// planRegistry serves nginx-like tags: web:1.25.3 is running, 1.25.4 is newer.
type planRegistry struct {
	resolveErr error
	budget     *registry.Budget
}

func (r *planRegistry) ListTagsUpTo(context.Context, string, int) (registry.TagList, error) {
	return registry.TagList{Tags: []string{"1.25.3", "1.25.4"}, Pages: 1}, nil
}

func (r *planRegistry) Resolve(context.Context, string, string, inventory.Platform) (registry.Resolution, error) {
	if r.resolveErr != nil {
		return registry.Resolution{}, r.resolveErr
	}
	return registry.Resolution{
		TopDigest: "sha256:" + hex64('0'), ManifestDigest: "sha256:" + hex64('b'), ConfigDigest: "sha256:" + hex64('c'),
		PlatformVerified: true,
	}, nil
}

type fakePlanStore struct {
	saved []remediation.Plan
	err   error
}

func (f *fakePlanStore) Save(p remediation.Plan) error {
	f.saved = append(f.saved, p)
	return f.err
}

type fakeDelivered struct {
	fp      string
	loadErr error
	saves   []string
}

func (f *fakeDelivered) Load() (string, error) { return f.fp, f.loadErr }
func (f *fakeDelivered) Save(fp string) error {
	f.saves = append(f.saves, fp)
	f.fp = fp
	return nil
}

// planHarness wires a Runner with the plan on over one running image,
// web:1.25.3, that has a fixed finding.
type planHarness struct {
	r         Runner
	scn       *planScanner
	normal    *fakeScanner
	reg       *planRegistry
	plans     *fakePlanStore
	delivered *fakeDelivered
	notif     *fakeNotifier
	store     *fakeStore
}

func newPlanHarness(findings ...scanner.Finding) *planHarness {
	key := mustConfigKey("sha256:" + hex64('a'))
	base := scanner.ImageScan{
		Image: "web:1.25.3", Subject: inventory.ImageSubject{Ref: "web:1.25.3", Key: key, Resolved: true},
		ScannedKey: key, Pinned: true, Source: scanner.SourceLocal, Platform: linuxAmd64, OSFamily: "debian",
		Findings: findings, Packages: osPackages("1"),
	}
	cfg, _ := inventory.ParseDigest(inventory.DigestConfig, "sha256:"+hex64('a'))
	containers := []inventory.Container{{
		ID: "c1", Name: "shop-web-1",
		Workload: inventory.Workload{Kind: inventory.WorkloadCompose, Group: "shop", Name: "web"},
		Image:    inventory.RunningImage{Ref: "web:1.25.3", Config: cfg},
	}}
	h := &planHarness{
		scn:       &planScanner{local: map[string]scanner.ImageScan{"web:1.25.3": base}, verifyOK: true},
		normal:    &fakeScanner{byImage: map[string]scanner.ImageScan{"web:1.25.3": base}},
		reg:       &planRegistry{},
		plans:     &fakePlanStore{},
		delivered: &fakeDelivered{},
		notif:     &fakeNotifier{},
		store:     &fakeStore{},
	}
	h.r = Runner{
		Lister:        fakeLister{containers: containers},
		Scanner:       h.normal,
		Notifier:      h.notif,
		Store:         h.store,
		FullReportDay: NoFullReport,
		Now:           clock,
		Plan: &PlanConfig{
			Scanner: h.scn,
			NewRegistry: func(b *registry.Budget) remediation.Registry {
				h.reg.budget = b
				return h.reg
			},
			Limits:              remediation.Limits{MaxCandidateScans: 5, MaxBaselineRescans: 5, MaxTagPages: 5},
			MaxRegistryRequests: 50,
			Plans:               h.plans,
			Delivered:           h.delivered,
		},
	}
	return h
}

func (h *planHarness) run(t *testing.T) {
	t.Helper()
	if err := h.r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
}

func TestPlan_DisabledChangesNothing(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"))
	h.r.Plan = nil
	h.run(t)
	if !h.notif.called {
		t.Fatal("no notification")
	}
	if h.notif.msg.Plan != nil {
		t.Errorf("Message.Plan = %+v, want nil with the plan off", h.notif.msg.Plan)
	}
	if len(h.normal.calls) != 1 || len(h.scn.events) != 0 {
		t.Errorf("normal scanner calls = %d, plan scanner events = %v; want the normal scanner only", len(h.normal.calls), h.scn.events)
	}
	if len(h.plans.saved) != 0 || len(h.delivered.saves) != 0 {
		t.Error("plan records written with the plan off")
	}
}

func TestPlan_DatabasePreparationFailureStillNotifies(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"))
	h.scn.prepareErr = errors.New("download failed")
	h.run(t)
	if !h.notif.called {
		t.Fatal("the normal notification must still be sent")
	}
	p := h.notif.msg.Plan
	if p == nil || p.Plan != nil || p.Unavailable != notify.PlanDatabasesNotPrepared {
		t.Fatalf("Message.Plan = %+v, want unavailable (databases not prepared)", p)
	}
	if len(h.normal.calls) != 1 {
		t.Errorf("normal scanner calls = %d, want the cycle scanned as usual", len(h.normal.calls))
	}
	for _, ev := range h.scn.events {
		if strings.HasPrefix(ev, "scan:") {
			t.Errorf("comparison scanner scanned (%s) after the preparation failed", ev)
		}
	}
	if len(h.plans.saved) != 0 {
		t.Error("a plan was stored although none was built")
	}
	// The problem itself is what was delivered.
	if want := remediation.StatusFingerprint("", string(notify.PlanDatabasesNotPrepared), false); len(h.delivered.saves) != 1 || h.delivered.saves[0] != want {
		t.Errorf("delivered saves = %v, want the unavailable-status fingerprint", h.delivered.saves)
	}
	if h.store.saved == nil {
		t.Error("state not saved after the notification")
	}
	if len(h.notif.msg.Report.Actionable) == 0 {
		t.Error("the finding is missing from the normal report")
	}
}

func TestPlan_ProducedSavedAndIncluded(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"))
	h.run(t)

	if len(h.scn.events) < 3 || h.scn.events[0] != "prepare" || h.scn.events[1] != "scan:web:1.25.3" || h.scn.events[2] != "verify" {
		t.Errorf("events = %v, want prepare, the image scan, then verify", h.scn.events)
	}
	if len(h.normal.calls) != 0 {
		t.Errorf("the normal scanner ran %d scans in a cycle with prepared databases", len(h.normal.calls))
	}
	p := h.notif.msg.Plan
	if p == nil || p.Plan == nil {
		t.Fatalf("Message.Plan = %+v, want a plan", p)
	}
	if p.NotSaved {
		t.Error("NotSaved set although the save succeeded")
	}
	if len(p.Plan.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(p.Plan.Items))
	}
	it := p.Plan.Items[0]
	if it.Category != remediation.CategoryPRCandidate || it.Candidate == nil || it.Candidate.Tag != "1.25.4" {
		t.Errorf("item = category %s, candidate %+v; want an update candidate 1.25.4 (%s: %s)", it.Category, it.Candidate, it.Reason, it.Detail)
	}
	if len(it.Services) != 1 || it.Services[0].Project != "shop" || it.Services[0].Service != "web" {
		t.Errorf("services = %+v", it.Services)
	}
	if p.Plan.Usage.BaselineRescans != 0 || p.Plan.Usage.CandidateScans != 1 {
		t.Errorf("usage = %+v, want no baseline rescan (verified conditions) and one candidate scan", p.Plan.Usage)
	}
	if len(h.plans.saved) != 1 {
		t.Fatalf("plan saves = %d, want 1", len(h.plans.saved))
	}
	if !p.Changed {
		t.Error("Changed = false for a first plan")
	}
	want := remediation.Fingerprint(*p.Plan)
	if want == "" || len(h.delivered.saves) != 1 || h.delivered.saves[0] != want {
		t.Errorf("delivered saves = %v, want the plan fingerprint %q", h.delivered.saves, want)
	}
	if h.reg.budget == nil || h.reg.budget.Remaining() > 50 {
		t.Error("the registry client was not built with a fresh budget")
	}
}

func TestPlan_UnchangedFingerprintIsNotRecordedAgain(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"))
	h.run(t)
	h.store.st = *h.store.saved
	h.notif.called = false
	h.run(t)
	// Open findings still send the heartbeat; the plan rides along unchanged.
	if !h.notif.called {
		t.Fatal("heartbeat missing")
	}
	if h.notif.msg.Plan == nil || h.notif.msg.Plan.Changed {
		t.Errorf("Plan = %+v, want an unchanged plan", h.notif.msg.Plan)
	}
	if len(h.delivered.saves) != 1 {
		t.Errorf("delivered saves = %d, want only the first", len(h.delivered.saves))
	}
}

func TestPlan_FingerprintChangeSendsWithoutFindings(t *testing.T) {
	for _, mode := range []string{"diff", "full"} {
		t.Run(mode, func(t *testing.T) {
			// A clean cycle: no findings, so the plan is empty. The last
			// delivered plan had items, so the empty plan is a change.
			h := newPlanHarness()
			if mode == "full" {
				h.r.Store = nil
			}
			h.delivered.fp = "previous-plan"
			h.run(t)
			if !h.notif.called {
				t.Fatal("a changed plan must be sent although nothing else is worth a message")
			}
			p := h.notif.msg.Plan
			if p == nil || p.Plan == nil || len(p.Plan.Items) != 0 || !p.Changed {
				t.Fatalf("Plan = %+v, want an empty, changed plan", p)
			}
			if len(h.delivered.saves) != 1 || h.delivered.saves[0] != "" {
				t.Errorf("delivered saves = %v, want the empty fingerprint", h.delivered.saves)
			}
			if mode == "diff" && h.store.saved == nil {
				t.Error("state not saved")
			}

			// The same cycle again: the delivered record matches, so it is quiet.
			h.notif.called = false
			h.run(t)
			if h.notif.called {
				t.Error("an unchanged, empty plan sent a notification")
			}
		})
	}
}

func TestPlan_CleanCycleWithoutPlanChangeStaysQuiet(t *testing.T) {
	h := newPlanHarness()
	h.run(t)
	if h.notif.called {
		t.Error("clean and unchanged cycle notified")
	}
	if h.store.saveCalls != 1 {
		t.Error("state should still be saved when the notification is skipped")
	}
}

func TestPlan_DeliveredRecordedOnlyAfterSuccessfulSend(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"))
	h.notif.err = errors.New("slack down")
	if err := h.r.RunOnce(context.Background()); err == nil {
		t.Fatal("expected the send error")
	}
	if len(h.delivered.saves) != 0 {
		t.Errorf("delivered saves = %v after a failed send", h.delivered.saves)
	}
	if len(h.plans.saved) != 1 {
		t.Error("the plan itself is still stored")
	}
	// The next cycle announces the plan again.
	h.notif.err = nil
	h.run(t)
	if len(h.delivered.saves) != 1 || !h.notif.msg.Plan.Changed {
		t.Errorf("after recovery: saves=%v changed=%v", h.delivered.saves, h.notif.msg.Plan.Changed)
	}
}

func TestPlan_StoreFailureIsSurfacedNotFatal(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"))
	h.plans.err = errors.New("disk full")
	h.run(t)
	if !h.notif.called || h.notif.msg.Plan == nil || !h.notif.msg.Plan.NotSaved {
		t.Fatalf("Plan = %+v, want NotSaved with the notification sent", h.notif.msg.Plan)
	}
	if h.notif.msg.Plan.Plan == nil {
		t.Error("the plan is still shown")
	}
}

func TestPlan_UnreadableDeliveredRecordCountsAsUndelivered(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"))
	h.delivered.loadErr = errors.New("corrupt")
	h.run(t)
	if !h.notif.msg.Plan.Changed {
		t.Error("an unreadable delivered record should make the plan count as changed")
	}
}

func TestPlan_UnverifiedDatabasesRescanBaseline(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"))
	h.scn.verifyOK = false
	h.run(t)
	p := h.notif.msg.Plan
	if p == nil || p.Plan == nil {
		t.Fatalf("Plan = %+v", p)
	}
	if p.Plan.Usage.BaselineRescans != 1 {
		t.Errorf("baseline rescans = %d, want 1 because the scans carry no verified conditions", p.Plan.Usage.BaselineRescans)
	}
}

func TestPlan_VerifyErrorDoesNotStopTheCycle(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"))
	h.scn.verifyErr = errors.New("cannot read database")
	h.run(t)
	if !h.notif.called || h.notif.msg.Plan == nil {
		t.Fatal("the notification must still go out with a plan section")
	}
}

func TestPlan_RegistryFailureNeverStopsTheCycle(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"))
	h.reg.resolveErr = errors.New("registry exploded")
	h.run(t)
	if !h.notif.called {
		t.Fatal("no notification")
	}
	p := h.notif.msg.Plan
	if p == nil || p.Plan == nil || len(p.Plan.Items) != 1 || p.Plan.Items[0].Category != remediation.CategoryFailed {
		t.Fatalf("Plan = %+v, want one failed item", p)
	}
	if len(h.notif.msg.Report.Actionable) == 0 {
		t.Error("the normal report lost its finding")
	}
}

func TestPlan_MissingRegistryFactoryIsUnavailable(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"))
	h.r.Plan.NewRegistry = nil
	h.run(t)
	p := h.notif.msg.Plan
	if p == nil || p.Plan != nil || p.Unavailable != notify.PlanNotBuilt {
		t.Fatalf("Plan = %+v, want unavailable (not built)", p)
	}
}

func TestPlan_InputsFollowThePriorityBuckets(t *testing.T) {
	mk := func(ref, vuln string) scanner.ImageScan {
		f := osFinding(vuln)
		f.Image = ref
		return scanner.ImageScan{Image: ref, Subject: inventory.ImageSubject{Ref: ref}, Findings: []scanner.Finding{f}}
	}
	scans := []scanner.ImageScan{mk("a:1", "CVE-A"), mk("b:1", "CVE-B"), mk("c:1", "CVE-C")}
	targets := make([]scanner.ScanTarget, len(scans))
	tr := analyze.Triage{
		Enabled: true, ActNowEPSS: 0.1, WatchEPSS: 0.01,
		Enrich: map[string]analyze.Enrichment{"CVE-B": {KEV: true}},
		Intel:  analyze.IntelStatus{KEVOK: true, EPSSOK: true},
	}
	report := analyze.Build(scans, nil, tr, clock())

	in := planInputs(report, nil, scans, targets, planConds())
	var got []string
	for _, i := range in {
		got = append(got, i.Scan.Image)
		if !i.Conditions.Equal(planConds()) {
			t.Errorf("%s: conditions not carried", i.Scan.Image)
		}
	}
	// b is act_now and comes first; the others keep their scan order.
	if strings.Join(got, ",") != "b:1,a:1,c:1" {
		t.Errorf("order = %v, want b:1,a:1,c:1", got)
	}

	r := Runner{}
	intel := r.planIntel(context.Background(), report)
	if in, ok := intel("CVE-B"); !ok || !in.KEV || in.Priority != remediation.PriorityActNow {
		t.Errorf("intel(CVE-B) = %+v, %v", in, ok)
	}
	if _, ok := intel("CVE-UNKNOWN"); ok {
		t.Error("intel knows a vulnerability the report does not")
	}
	if r.planIntel(context.Background(), analyze.Build(scans, nil, analyze.Triage{}, clock())) != nil {
		t.Error("intel without triage should be nil")
	}
}

// A plan problem is worth a message of its own: a new one, or the end of one,
// is sent in a cycle with nothing else to say; the same one again is not.
func TestPlan_ProblemsNotifyOnChangeOnly(t *testing.T) {
	for _, mode := range []string{"diff", "full"} {
		t.Run(mode, func(t *testing.T) {
			h := newPlanHarness() // a clean cycle: no findings, NotifyOnClean off
			if mode == "full" {
				h.r.Store = nil
			}
			step := func(name string, wantSend bool) {
				t.Helper()
				h.notif.called = false
				h.run(t)
				if h.notif.called != wantSend {
					t.Fatalf("%s: sent=%v, want %v", name, h.notif.called, wantSend)
				}
			}

			// Databases cannot be prepared: announced once.
			h.scn.prepareErr = errors.New("download failed")
			step("first unavailable cycle", true)
			if p := h.notif.msg.Plan; p == nil || p.Unavailable != notify.PlanDatabasesNotPrepared {
				t.Fatalf("Plan = %+v", p)
			}
			step("same problem again", false)

			// Recovered: the end of the problem is a change too.
			h.scn.prepareErr = nil
			step("recovery", true)
			step("healthy and empty", false)

			// The plan cannot be written: announced once.
			h.plans.err = errors.New("disk full")
			step("first not-saved cycle", true)
			if p := h.notif.msg.Plan; p == nil || !p.NotSaved {
				t.Fatalf("Plan = %+v", p)
			}
			step("not saved again", false)

			// A different problem is a change.
			h.scn.prepareErr = errors.New("download failed")
			step("not saved becomes unavailable", true)
		})
	}
}

type kevIntel struct {
	fakeIntel
	kev map[string]bool
	err error
}

func (k *kevIntel) KEVSet(context.Context) (map[string]bool, error) { return k.kev, k.err }

// A candidate that brings in a KEV-listed vulnerability the cycle never saw
// is a manual item with that reason, and Slack says so.
func TestPlan_IntroducedKEVFromCatalogReachesSlack(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"))
	h.scn.candidate = []scanner.Finding{{
		Class: scanner.ClassOS, Type: "debian", Target: "web (debian 12)", Package: "newlib",
		InstalledVer: "1", Status: scanner.StatusAffected, Severity: scanner.SeverityCritical, VulnID: "CVE-KEV-NEW",
	}}
	h.r.Intel = &kevIntel{
		fakeIntel: fakeIntel{fresh: intel.Freshness{KEVOK: true, EPSSOK: true}},
		kev:       map[string]bool{"CVE-KEV-NEW": true},
	}
	h.r.ActNowEPSS, h.r.WatchEPSS = 0.1, 0.01
	h.run(t)

	it := h.notif.msg.Plan.Plan.Items[0]
	if it.Category != remediation.CategoryManual || it.Reason != remediation.ReasonIntroducedKEV {
		t.Fatalf("item = %s/%s (%s), want manual/introduced_kev", it.Category, it.Reason, it.Detail)
	}
	for _, lang := range []notify.Language{notify.LanguageEN, notify.LanguageJA} {
		var text string
		for _, m := range notify.BuildChannelMessages(h.notif.msg, notify.ChannelFooter{}, lang) {
			for _, b := range m.Blocks {
				text += b.Text + "\n"
			}
		}
		want := "web:1.25.3 to 1.25.4"
		if lang == notify.LanguageJA {
			want = "web:1.25.3 を 1.25.4"
		}
		if !strings.Contains(text, want) || !strings.Contains(text, "KEV") {
			t.Errorf("%s: the KEV warning line is missing in\n%s", lang, text)
		}
	}
}

func TestPlan_KEVCatalogErrorDoesNotStopThePlan(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"))
	h.scn.candidate = []scanner.Finding{{
		Class: scanner.ClassOS, Type: "debian", Target: "web (debian 12)", Package: "newlib",
		InstalledVer: "1", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-NEW",
	}}
	h.r.Intel = &kevIntel{fakeIntel: fakeIntel{fresh: intel.Freshness{KEVOK: true, EPSSOK: true}}, err: errors.New("no catalog")}
	h.run(t)
	// Still manual: anything introduced blocks adoption; only the KEV reason is lost.
	if it := h.notif.msg.Plan.Plan.Items[0]; it.Category != remediation.CategoryManual || it.Reason != remediation.ReasonIntroducedFindings {
		t.Errorf("item = %s/%s", it.Category, it.Reason)
	}
}
