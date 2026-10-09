package remediation

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func samplePlan() Plan {
	return Plan{
		GeneratedAt: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC),
		Conditions:  testConds("db1"),
		Limits:      Limits{MaxCandidateScans: 3, MaxBaselineRescans: 2, MaxTagPages: 5},
		Usage:       Usage{CandidateScans: 1, TagPages: 2, RegistryRequests: 9},
		Items: []Item{{
			Key: "nginx:1.25.3|config:sha256:aa", Kind: TagPinned, Category: CategoryPRCandidate, Reason: ReasonAdopted,
			Current:   ImageState{Ref: "nginx:1.25.3", Tag: "1.25.3"},
			Candidate: &ImageState{Ref: "nginx:1.25.4", Tag: "1.25.4"},
			Targets:   []Target{{VulnID: "CVE-1", Package: PackageCoord{Name: "libc"}, FixedVers: []string{"2"}}},
			Decision:  &Decision{Kind: DecisionAdopt, Propose: true, Targets: 1, Resolved: 1},
		}},
	}
}

func TestPlanStoreRoundTrip(t *testing.T) {
	path := DefaultPlanPath(filepath.Join(t.TempDir(), "state"))
	s := PlanStore{Path: path}
	if _, found, err := s.Load(); err != nil || found {
		t.Fatalf("missing file: found=%v err=%v", found, err)
	}
	want := samplePlan()
	if err := s.Save(want); err != nil {
		t.Fatal(err)
	}
	got, found, err := s.Load()
	if err != nil || !found {
		t.Fatalf("load: found=%v err=%v", found, err)
	}
	want.Version = PlanVersion
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip differs:\n got %+v\nwant %+v", got, want)
	}
	// Saving again replaces the file and leaves no temporary files.
	want.Usage.TagPages = 7
	if err := s.Save(want); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.Load(); got.Usage.TagPages != 7 {
		t.Error("second save not visible")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("directory holds %d entries, want only the plan", len(entries))
	}
}

func TestPlanStoreRejectsDamagedFiles(t *testing.T) {
	cases := []struct {
		name    string
		content string
		version bool
	}{
		{"corrupt", `{"version": 1, "items": [`, false},
		{"not json", `plan`, false},
		{"empty file", ``, false},
		{"wrong version", `{"version": 99}`, true},
		{"no version", `{"items": []}`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "plan.json")
			if err := os.WriteFile(path, []byte(c.content), 0o644); err != nil {
				t.Fatal(err)
			}
			_, found, err := PlanStore{Path: path}.Load()
			if err == nil || found {
				t.Fatalf("found=%v err=%v, want an error", found, err)
			}
			if c.version != errors.Is(err, ErrPlanVersion) {
				t.Errorf("version error = %v, want %v (%v)", errors.Is(err, ErrPlanVersion), c.version, err)
			}
			// The damaged file is left as it was.
			if b, _ := os.ReadFile(path); string(b) != c.content {
				t.Error("Load modified the file")
			}
		})
	}
}

func TestPlanStoreUnreadable(t *testing.T) {
	dir := t.TempDir()
	// A directory where the file should be is an error, not "no plan".
	if _, found, err := (PlanStore{Path: dir}).Load(); err == nil || found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if err := (PlanStore{}).Save(samplePlan()); err == nil || !strings.Contains(err.Error(), "no path") {
		t.Errorf("save without path: %v", err)
	}
}

func TestPlanStoreSaveRefusesToOverwriteDamagedFile(t *testing.T) {
	for name, content := range map[string]string{
		"corrupt":       `{"version": 1, `,
		"future format": `{"version": 99, "items": []}`,
		"empty":         ``,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "plan.json")
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := (PlanStore{Path: path}).Save(samplePlan()); err == nil {
				t.Fatal("Save replaced a file it cannot read")
			}
			if b, _ := os.ReadFile(path); string(b) != content {
				t.Error("the existing file was modified")
			}
			entries, _ := os.ReadDir(filepath.Dir(path))
			if len(entries) != 1 {
				t.Errorf("stray files left: %d entries", len(entries))
			}
		})
	}
}

func TestPlanStoreSaveReplacesReadablePlan(t *testing.T) {
	s := PlanStore{Path: filepath.Join(t.TempDir(), "plan.json")}
	if err := s.Save(samplePlan()); err != nil {
		t.Fatal(err)
	}
	p := samplePlan()
	p.Usage.CandidateScans = 4
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.Load(); got.Usage.CandidateScans != 4 {
		t.Error("second save lost")
	}
}
