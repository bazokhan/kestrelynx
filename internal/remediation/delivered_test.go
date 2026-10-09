package remediation

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFingerprint_EmptyPlanIsEmpty(t *testing.T) {
	if got := Fingerprint(Plan{}); got != "" {
		t.Errorf("Fingerprint(empty plan) = %q, want empty", got)
	}
}

func TestFingerprint_IgnoresTimesOrderAndErrorText(t *testing.T) {
	a := samplePlan()
	a.Items = append(a.Items, Item{
		Key: "redis:7|config:sha256:bb", Category: CategoryFailed, Reason: ReasonRegistryError, Detail: "timeout at 12:00",
		Current: ImageState{Ref: "redis:7"},
	})
	b := samplePlan()
	b.Items = append(b.Items, a.Items[1])
	b.Items[1].Detail = "timeout at 12:05"
	b.Items[0], b.Items[1] = b.Items[1], b.Items[0] // other order
	b.GeneratedAt = b.GeneratedAt.Add(24 * time.Hour)
	b.Conditions = testConds("db2")
	b.Usage.RegistryRequests = 99
	b.Scans = []ScanExecution{{ID: "s1"}}
	if Fingerprint(a) != Fingerprint(b) {
		t.Error("fingerprint changed with times, order, error text, conditions or usage")
	}
}

func TestFingerprint_ChangesWithVisibleContent(t *testing.T) {
	base := Fingerprint(samplePlan())
	mutations := map[string]func(*Plan){
		"category":      func(p *Plan) { p.Items[0].Category = CategoryManual },
		"reason":        func(p *Plan) { p.Items[0].Reason = ReasonPartialImprovement },
		"candidate tag": func(p *Plan) { p.Items[0].Candidate.Ref = "nginx:1.25.5" },
		"candidate content": func(p *Plan) {
			p.Items[0].Candidate.ConfigDigest = "sha256:" + hex64('c')
		},
		"image content": func(p *Plan) { p.Items[0].Current.Entity = "config:sha256:ff" },
		"service":       func(p *Plan) { p.Items[0].Services = []ServiceRef{{Project: "p", Service: "web"}} },
		"comparison": func(p *Plan) {
			p.Items[0].Comparison = &VerificationResult{Comparable: true, Verdicts: []VulnVerdict{{VulnID: "CVE-1", Outcome: OutcomeResolved}}}
		},
		"extra item": func(p *Plan) { p.Items = append(p.Items, Item{Key: "k", Category: CategoryExcluded}) },
	}
	for name, mutate := range mutations {
		p := samplePlan()
		// samplePlan shares nothing between calls, but its candidate is a
		// pointer; copy it so a mutation never leaks into the next case.
		c := *p.Items[0].Candidate
		p.Items[0].Candidate = &c
		mutate(&p)
		if got := Fingerprint(p); got == base {
			t.Errorf("%s: fingerprint did not change", name)
		}
	}
}

func TestDeliveredStoreRoundTrip(t *testing.T) {
	path := DefaultDeliveredPath(filepath.Join(t.TempDir(), "state"))
	s := DeliveredStore{Path: path}
	if got, err := s.Load(); err != nil || got != "" {
		t.Fatalf("missing file: got %q err %v", got, err)
	}
	if err := s.Save("abc"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Load(); err != nil || got != "abc" {
		t.Fatalf("load: got %q err %v", got, err)
	}
	if err := s.Save("def"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Load(); got != "def" {
		t.Errorf("second save: got %q", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("directory holds %d entries, want only the record", len(entries))
	}
}

func TestDeliveredStoreCorruptIsErrorButSaveRecovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delivered.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := DeliveredStore{Path: path}
	if _, err := s.Load(); err == nil {
		t.Error("Load: want an error for a corrupt file")
	}
	if err := s.Save("abc"); err != nil {
		t.Fatalf("Save over a corrupt file: %v", err)
	}
	if got, err := s.Load(); err != nil || got != "abc" {
		t.Errorf("after recovery: got %q err %v", got, err)
	}
	if err := os.WriteFile(path, []byte(`{"version":99,"fingerprint":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil {
		t.Error("Load: want an error for a foreign version")
	}
}

func TestDeliveredStoreNoPath(t *testing.T) {
	if err := (DeliveredStore{}).Save("x"); err == nil {
		t.Error("Save without a path: want an error")
	}
}

func TestStatusFingerprint(t *testing.T) {
	plan := Fingerprint(samplePlan())
	if got := StatusFingerprint(plan, "", false); got != plan {
		t.Error("a healthy plan's fingerprint must be unchanged")
	}
	if got := StatusFingerprint("", "", false); got != "" {
		t.Errorf("healthy empty plan = %q, want empty", got)
	}
	seen := map[string]string{}
	for name, fp := range map[string]string{
		"unavailable":            StatusFingerprint("", "databases_not_prepared", false),
		"other unavailable":      StatusFingerprint("", "planner_not_built", false),
		"not saved, empty":       StatusFingerprint("", "", true),
		"not saved, with plan":   StatusFingerprint(plan, "", true),
		"unavailable, not saved": StatusFingerprint("", "databases_not_prepared", true),
	} {
		if fp == "" || fp == plan {
			t.Errorf("%s: fingerprint %q is not distinct from a healthy one", name, fp)
		}
		if other, dup := seen[fp]; dup {
			t.Errorf("%s and %s share a fingerprint", name, other)
		}
		seen[fp] = name
	}
	if StatusFingerprint("", "databases_not_prepared", false) != StatusFingerprint("", "databases_not_prepared", false) {
		t.Error("not deterministic")
	}
}
