package nodecore

import (
	"fmt"
	"sync"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

var allSeverities = []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

func nodeScan(ver string) scanner.ImageScan {
	return scanner.ImageScan{
		Image:     "app:1",
		ConfigEnv: []string{"PATH=/usr/local/bin", "NODE_VERSION=" + ver},
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
	aug := advisorWithFixture(t).Augment(nodeScan("22.23.3"), allSeverities)
	if len(aug.Unchecked) > 0 {
		t.Fatal("Unchecked")
	}
	var f *scanner.Finding
	for i := range aug.Findings {
		if aug.Findings[i].VulnID == "CVE-2026-111497" {
			f = &aug.Findings[i]
		}
	}
	if f == nil {
		t.Fatal("CVE-2026-111497 missing")
	}
	want := scanner.Finding{
		Image: "app:1", Class: scanner.ClassLang, Package: "Node.js", InstalledVer: "22.23.3",
		FixedVer: "22.23.4", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh,
		VulnID: "CVE-2026-111497", URL: octoberURL,
		Title: "Node.js Brotli decoder out-of-bounds write permits remote code execution",
		Type:  "node-runtime", Target: "usr/local/bin/node", PkgPath: "usr/local/bin/node",
	}
	if *f != want {
		t.Errorf("finding =\n%+v\nwant\n%+v", *f, want)
	}
	for _, fd := range aug.Findings {
		if fd.LayerDiffID != "" || fd.LayerDigest != "" {
			t.Errorf("%s has layer fields", fd.VulnID)
		}
		if fd.VulnID == "CVE-2026-105483" {
			t.Error("24/26-only CVE-2026-105483 reported for 22")
		}
	}
	for i := 1; i < len(aug.Findings); i++ {
		if aug.Findings[i-1].VulnID >= aug.Findings[i].VulnID {
			t.Errorf("findings not sorted: %s, %s", aug.Findings[i-1].VulnID, aug.Findings[i].VulnID)
		}
	}

	if len(aug.Packages) != 1 {
		t.Fatalf("Packages = %v", aug.Packages)
	}
	wantPkgs := scanner.ResultPackages{
		Target: "usr/local/bin/node", Class: scanner.ClassLang, Type: "node-runtime",
		Packages: []scanner.Package{{Name: "Node.js", Version: "22.23.3", PkgPath: "usr/local/bin/node"}},
	}
	if fmt.Sprint(aug.Packages[0]) != fmt.Sprint(wantPkgs) {
		t.Errorf("Packages[0] = %+v, want %+v", aug.Packages[0], wantPkgs)
	}
}

func TestAugmentEqualizesFixedVersion(t *testing.T) {
	aug := advisorWithFixture(t).Augment(nodeScan("22.23.1"), allSeverities)
	fixed := 0
	have := map[string]bool{}
	for _, f := range aug.Findings {
		have[f.VulnID] = true
		if f.Status == scanner.StatusFixed {
			fixed++
			if f.FixedVer != "22.23.4" {
				t.Errorf("%s FixedVer = %s, want 22.23.4", f.VulnID, f.FixedVer)
			}
		}
	}
	if fixed == 0 || !have["CVE-2026-58045"] || !have["CVE-2026-56846"] {
		t.Errorf("fixed=%d, July CVEs present=%v/%v", fixed, have["CVE-2026-58045"], have["CVE-2026-56846"])
	}
}

func TestAugmentEOLHasNoFixedVersion(t *testing.T) {
	aug := advisorWithFixture(t).Augment(nodeScan("20.20.0"), allSeverities)
	eol, fixed := 0, 0
	for _, f := range aug.Findings {
		switch f.Status {
		case scanner.StatusEndOfLife:
			eol++
			if f.FixedVer != "" {
				t.Errorf("%s EOL with FixedVer %s", f.VulnID, f.FixedVer)
			}
		case scanner.StatusFixed:
			fixed++
			if f.FixedVer != "20.20.2" {
				t.Errorf("%s FixedVer = %s", f.VulnID, f.FixedVer)
			}
		}
	}
	if eol == 0 || fixed == 0 {
		t.Errorf("eol=%d fixed=%d, want both > 0", eol, fixed)
	}
}

func TestAugmentSeverityFilter(t *testing.T) {
	a := advisorWithFixture(t)
	if aug := a.Augment(nodeScan("22.23.3"), []string{"CRITICAL"}); len(aug.Findings) != 0 || len(aug.Packages) != 1 {
		t.Errorf("CRITICAL only: findings=%d packages=%d, want 0 findings and the package list", len(aug.Findings), len(aug.Packages))
	}
	aug := a.Augment(nodeScan("22.23.3"), []string{"HIGH"})
	if len(aug.Findings) == 0 {
		t.Fatal("no HIGH findings")
	}
	for _, f := range aug.Findings {
		if f.Severity != scanner.SeverityHigh {
			t.Errorf("%s severity %s", f.VulnID, f.Severity)
		}
	}
}

func TestAugmentNodeVersionDetection(t *testing.T) {
	a := advisorWithFixture(t)
	for _, v := range []string{"v22.1.0", "22.1", "22.01.0", "22.1.0-rc1", "22.1.0 ", "", "lts"} {
		aug := a.Augment(nodeScan(v), allSeverities)
		if len(aug.Findings) != 0 || len(aug.Packages) != 0 || len(aug.Unchecked) > 0 {
			t.Errorf("NODE_VERSION=%q: got %+v, want empty", v, aug)
		}
	}
	if aug := a.Augment(scanner.ImageScan{Image: "x"}, allSeverities); len(aug.Packages) != 0 || len(aug.Unchecked) > 0 {
		t.Errorf("no env: got %+v", aug)
	}

	// The last occurrence wins, and a similarly named variable is not it.
	scan := nodeScan("22.23.3")
	scan.ConfigEnv = []string{"NODE_VERSION=18.0.0", "MY_NODE_VERSION=1.0.0", "NODE_VERSION=22.23.3"}
	aug := a.Augment(scan, allSeverities)
	if len(aug.Packages) != 1 || aug.Packages[0].Packages[0].Version != "22.23.3" {
		t.Errorf("packages = %+v", aug.Packages)
	}
}

func TestAugmentWithoutSnapshot(t *testing.T) {
	var a Advisor
	aug := a.Augment(nodeScan("22.23.3"), allSeverities)
	if len(aug.Unchecked) == 0 || len(aug.Findings) != 0 || len(aug.Packages) != 0 {
		t.Errorf("got %+v, want Unchecked only", aug)
	}
	if aug := a.Augment(nodeScan("v22"), allSeverities); len(aug.Unchecked) > 0 {
		t.Error("undetected runtime must not be Unchecked")
	}
	a.Set(fixtureSnapshot(t))
	a.Set(nil)
	if aug := a.Augment(nodeScan("22.23.3"), allSeverities); len(aug.Unchecked) == 0 {
		t.Error("Set(nil) should make runtimes unchecked")
	}
}

func TestAugmentPlatformOS(t *testing.T) {
	a := advisorWithFixture(t)
	linux := nodeScan("4.0.0")
	empty := nodeScan("4.0.0")
	empty.Platform.OS = ""
	win := nodeScan("4.0.0")
	win.Platform.OS = "win32"
	l, e, w := a.Augment(linux, allSeverities), a.Augment(empty, allSeverities), a.Augment(win, allSeverities)
	if len(l.Findings) != len(e.Findings) {
		t.Errorf("empty OS gave %d findings, linux %d", len(e.Findings), len(l.Findings))
	}
	if len(w.Findings) <= len(l.Findings) {
		t.Errorf("win32 gave %d findings, linux %d: win32-only entries should add some", len(w.Findings), len(l.Findings))
	}
}

func TestBinaryPath(t *testing.T) {
	tests := []struct {
		name string
		pkgs []scanner.ResultPackages
		want string
	}{
		{"none", nil, "usr/local/bin/node"},
		{"usr/local npm", []scanner.ResultPackages{{Packages: []scanner.Package{{Name: "npm", PkgPath: "usr/local/lib/node_modules/npm/package.json"}}}}, "usr/local/bin/node"},
		{"other prefix", []scanner.ResultPackages{{Packages: []scanner.Package{{PkgPath: "opt/node/lib/node_modules/npm/package.json"}}}}, "opt/node/bin/node"},
		{"leading slash", []scanner.ResultPackages{{Packages: []scanner.Package{{PkgPath: "/usr/lib/node_modules/npm/package.json"}}}}, "usr/bin/node"},
		{"root prefix", []scanner.ResultPackages{{Packages: []scanner.Package{{PkgPath: "lib/node_modules/npm/package.json"}}}}, "bin/node"},
		{"unrelated", []scanner.ResultPackages{{Packages: []scanner.Package{{PkgPath: "app/node_modules/left-pad/package.json"}}}}, "usr/local/bin/node"},
	}
	for _, tc := range tests {
		if got := binaryPath(tc.pkgs); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestBinaryPathFromTrivyReport(t *testing.T) {
	scan, err := scanner.ParseReport(readTestdata(t, "regfis-frontend-trivy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := binaryPath(scan.Packages); got != "usr/local/bin/node" {
		t.Errorf("binaryPath = %q", got)
	}
	if v, ok := detectVersion(scan.ConfigEnv); !ok || v != "22.23.3" {
		t.Errorf("detectVersion = %q, %v", v, ok)
	}

	aug := advisorWithFixture(t).Augment(scan, allSeverities)
	found := false
	for _, f := range aug.Findings {
		if f.VulnID == "CVE-2026-111497" && f.FixedVer == "22.23.4" && f.Target == "usr/local/bin/node" {
			found = true
		}
	}
	if !found {
		t.Error("CVE-2026-111497 not reported for the real regfis-frontend report")
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
				aug := a.Augment(nodeScan("22.23.3"), allSeverities)
				if len(aug.Unchecked) == 0 && len(aug.Findings) == 0 {
					t.Error("checked scan without findings")
				}
			}
		}()
	}
	wg.Wait()
}
