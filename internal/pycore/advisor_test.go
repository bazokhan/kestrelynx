package pycore

import (
	"sync"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

var allSeverities = []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE"}

func pyScan(ver string) scanner.ImageScan {
	return scanner.ImageScan{
		Image:     "app:1",
		ConfigEnv: []string{"PATH=/usr/local/bin", "PYTHON_VERSION=" + ver},
		Platform:  inventory.Platform{OS: "linux", Architecture: "amd64"},
	}
}

func advisorWithFixture(t *testing.T) *Advisor {
	t.Helper()
	a := &Advisor{}
	a.Set(fixtureSnapshot(t))
	return a
}

func TestAugmentFindings(t *testing.T) {
	aug := advisorWithFixture(t).Augment(pyScan("3.12.14"), allSeverities)
	if len(aug.Unchecked) > 0 {
		t.Fatal("Unchecked")
	}
	if len(aug.Findings) != 19 {
		t.Fatalf("findings = %d, want 19", len(aug.Findings))
	}
	var f *scanner.Finding
	for i := range aug.Findings {
		if aug.Findings[i].VulnID == "CVE-2026-115557" {
			f = &aug.Findings[i]
		}
	}
	if f == nil {
		t.Fatal("CVE-2026-115557 missing")
	}
	want := scanner.Finding{
		Image: "app:1", Class: scanner.ClassLang, Package: "Python runtime", InstalledVer: "3.12.14",
		Status: scanner.StatusAffected, Severity: scanner.SeverityCritical,
		VulnID: "CVE-2026-115557", URL: f.URL,
		Title: `Python has added a denylist for known compromised certificates to the "ssl" module to ensure user safety even without certificate revocation configured.`,
		Type:  "python-runtime", Target: "usr/local/bin/python3.12", PkgPath: "usr/local/bin/python3.12",
	}
	if *f != want {
		t.Errorf("finding =\n%+v\nwant\n%+v", *f, want)
	}
	if f.URL != "https://mail.python.org/archives/list/security-announce@python.org/thread/FNAJMZV6XQYLVPABNINDMF3VF66AYLW4/" {
		t.Errorf("URL = %q", f.URL)
	}
	fixed, affected := 0, 0
	for _, fd := range aug.Findings {
		if fd.LayerDiffID != "" || fd.LayerDigest != "" {
			t.Errorf("%s has layer fields", fd.VulnID)
		}
		switch fd.Status {
		case scanner.StatusFixed:
			fixed++
			if fd.FixedVer != "3.12.15" {
				t.Errorf("%s FixedVer = %s", fd.VulnID, fd.FixedVer)
			}
		case scanner.StatusAffected:
			affected++
		}
	}
	if fixed != 8 || affected != 11 {
		t.Errorf("fixed=%d affected=%d, want 8/11", fixed, affected)
	}
	for i := 1; i < len(aug.Findings); i++ {
		if aug.Findings[i-1].VulnID >= aug.Findings[i].VulnID {
			t.Errorf("findings not sorted: %s, %s", aug.Findings[i-1].VulnID, aug.Findings[i].VulnID)
		}
	}

	if len(aug.Packages) != 1 {
		t.Fatalf("Packages = %v", aug.Packages)
	}
	p := aug.Packages[0]
	if p.Target != "usr/local/bin/python3.12" || p.Class != scanner.ClassLang || p.Type != "python-runtime" ||
		len(p.Packages) != 1 || p.Packages[0] != (scanner.Package{Name: "Python runtime", Version: "3.12.14", PkgPath: "usr/local/bin/python3.12"}) {
		t.Errorf("Packages[0] = %+v", p)
	}
}

func TestAugmentSeverityFilter(t *testing.T) {
	a := advisorWithFixture(t)
	aug := a.Augment(pyScan("3.12.14"), []string{"HIGH", "CRITICAL"})
	fixed, affected := 0, 0
	for _, f := range aug.Findings {
		if f.Severity != scanner.SeverityHigh && f.Severity != scanner.SeverityCritical {
			t.Errorf("%s severity %s", f.VulnID, f.Severity)
		}
		if f.Status == scanner.StatusFixed {
			fixed++
		} else {
			affected++
		}
	}
	if len(aug.Findings) != 4 || fixed != 3 || affected != 1 {
		t.Errorf("HIGH+CRITICAL: %d findings (fixed %d, affected %d), want 4 (3, 1)", len(aug.Findings), fixed, affected)
	}
	// Severities are matched ignoring case and surrounding space.
	if got := len(a.Augment(pyScan("3.12.14"), []string{" high ", "critical"}).Findings); got != 4 {
		t.Errorf("lower case severities: %d findings, want 4", got)
	}
	// With nothing matching, the package list is still reported.
	if aug := a.Augment(pyScan("3.12.14"), []string{"LOW"}); len(aug.Packages) != 1 {
		t.Errorf("packages = %d, want the runtime listed", len(aug.Packages))
	}
}

func TestAugmentNoFixAtLatest(t *testing.T) {
	aug := advisorWithFixture(t).Augment(pyScan("3.12.15"), allSeverities)
	if len(aug.Findings) != 11 {
		t.Fatalf("findings = %d, want 11", len(aug.Findings))
	}
	for _, f := range aug.Findings {
		if f.Status != scanner.StatusAffected || f.FixedVer != "" {
			t.Errorf("%s: %s %q", f.VulnID, f.Status, f.FixedVer)
		}
	}
}

func TestAugmentEqualizesFixedVersion(t *testing.T) {
	aug := advisorWithFixture(t).Augment(pyScan("3.13.8"), allSeverities)
	fixed, affected := 0, 0
	perCVE := map[string]bool{}
	for _, f := range aug.Findings {
		switch f.Status {
		case scanner.StatusFixed:
			fixed++
			perCVE[f.FixedVer] = true
			if f.FixedVer != "3.13.16" {
				t.Errorf("%s FixedVer = %s, want 3.13.16", f.VulnID, f.FixedVer)
			}
		case scanner.StatusAffected:
			affected++
			if f.FixedVer != "" {
				t.Errorf("%s affected with FixedVer %s", f.VulnID, f.FixedVer)
			}
		}
	}
	if len(aug.Findings) != 51 || fixed != 45 || affected != 6 {
		t.Errorf("findings=%d fixed=%d affected=%d, want 51/45/6", len(aug.Findings), fixed, affected)
	}
	// The per-CVE fixes differ; only the finding equalizes them.
	if a, ok := find(fixtureSnapshot(t).Match(mustVersion(t, "3.13.8"), "linux"), "CVE-2026-6019"); !ok || a.FixedVer != "3.13.14" {
		t.Errorf("per-CVE fix of CVE-2026-6019 = %+v", a)
	}
}

func TestAugmentEOLHasNoFixedVersion(t *testing.T) {
	aug := advisorWithFixture(t).Augment(pyScan("3.10.22"), allSeverities)
	if len(aug.Findings) != 16 {
		t.Fatalf("findings = %d, want 16", len(aug.Findings))
	}
	for _, f := range aug.Findings {
		if f.Status != scanner.StatusEndOfLife || f.FixedVer != "" {
			t.Errorf("%s: %s %q", f.VulnID, f.Status, f.FixedVer)
		}
		if f.Target != "usr/local/bin/python3.10" {
			t.Errorf("Target = %s", f.Target)
		}
	}
}

func TestAugmentPerCVEFixAtOlderVersion(t *testing.T) {
	aug := advisorWithFixture(t).Augment(pyScan("3.14.4"), allSeverities)
	if len(aug.Findings) != 33 {
		t.Fatalf("findings = %d, want 33", len(aug.Findings))
	}
	for _, f := range aug.Findings {
		if f.Status == scanner.StatusFixed && f.FixedVer != "3.14.9" {
			t.Errorf("%s FixedVer = %s, want the highest fix 3.14.9", f.VulnID, f.FixedVer)
		}
	}
}

func TestAugmentLinuxPlatform(t *testing.T) {
	a := advisorWithFixture(t)
	hasID := func(aug scanner.RuntimeAugment, id string) bool {
		for _, f := range aug.Findings {
			if f.VulnID == id {
				return true
			}
		}
		return false
	}
	aug := a.Augment(pyScan("3.12.0"), allSeverities)
	if !hasID(aug, "CVE-2023-6507") {
		t.Error("CVE-2023-6507 (POSIX) missing for linux")
	}
	if hasID(aug, "CVE-2024-4030") {
		t.Error("CVE-2024-4030 (Windows) reported for linux")
	}
	empty := pyScan("3.12.0")
	empty.Platform.OS = ""
	if got := len(a.Augment(empty, allSeverities).Findings); got != len(aug.Findings) {
		t.Errorf("empty OS gave %d findings, linux %d", got, len(aug.Findings))
	}
}

func TestAugmentPythonVersionDetection(t *testing.T) {
	a := advisorWithFixture(t)
	for _, v := range []string{"3.15.0rc3", "3.12", "v3.12.1", "3.012.1", "3.12.01", "3.12.1 ", "3.12.1-slim", "2.7.18", "4.0.0", "", "3.1234567890.1"} {
		aug := a.Augment(pyScan(v), allSeverities)
		if len(aug.Findings) != 0 || len(aug.Packages) != 0 || len(aug.Unchecked) > 0 {
			t.Errorf("PYTHON_VERSION=%q: got %+v, want empty", v, aug)
		}
	}
	if aug := a.Augment(scanner.ImageScan{Image: "x"}, allSeverities); len(aug.Packages) != 0 || len(aug.Unchecked) > 0 {
		t.Errorf("no env: got %+v", aug)
	}

	// The last occurrence wins, and a similarly named variable is not it.
	scan := pyScan("3.12.14")
	scan.ConfigEnv = []string{"PYTHON_VERSION=3.8.0", "MY_PYTHON_VERSION=3.9.0", "PYTHON_VERSION=3.12.14"}
	aug := a.Augment(scan, allSeverities)
	if len(aug.Packages) != 1 || aug.Packages[0].Packages[0].Version != "3.12.14" {
		t.Errorf("packages = %+v", aug.Packages)
	}
	scan.ConfigEnv = []string{"PYTHON_VERSION=3.12.14", "PYTHON_VERSION=3.15.0rc3"}
	if aug := a.Augment(scan, allSeverities); len(aug.Packages) != 0 {
		t.Errorf("a later invalid value must win: %+v", aug)
	}
}

func TestAugmentWithoutSnapshot(t *testing.T) {
	var a Advisor
	aug := a.Augment(pyScan("3.12.14"), allSeverities)
	if len(aug.Unchecked) != 1 || aug.Unchecked[0] != "Python runtime" ||
		len(aug.Findings) != 0 || len(aug.Packages) != 0 {
		t.Errorf("got %+v, want Unchecked [Python runtime] only", aug)
	}
	if aug := a.Augment(pyScan("3.12"), allSeverities); len(aug.Unchecked) > 0 {
		t.Error("undetected runtime must not be Unchecked")
	}
	a.Set(fixtureSnapshot(t))
	a.Set(nil)
	if aug := a.Augment(pyScan("3.12.14"), allSeverities); len(aug.Unchecked) == 0 {
		t.Error("Set(nil) should make runtimes unchecked")
	}
}

func TestAdvisorConcurrent(t *testing.T) {
	a := &Advisor{}
	sn := fixtureSnapshot(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if j%2 == 0 {
					a.Set(sn)
				} else {
					a.Set(nil)
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				aug := a.Augment(pyScan("3.12.14"), allSeverities)
				if len(aug.Unchecked) == 0 && len(aug.Findings) == 0 {
					t.Error("checked scan without findings")
				}
			}
		}()
	}
	wg.Wait()
}
