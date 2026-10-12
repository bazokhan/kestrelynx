package remediation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestIntegrationLangUpdatePnpmProjectsWithADeclaredManager runs the update
// stage over two pnpm projects that declare packageManager pnpm@10.34.4, with
// the pnpm release they name fetched the way the main process fetches it, on
// the official Node.js image. The projects are not part of the repository:
// KESTRELYNX_PNPM_PROJECTS_DIR names a directory with the subdirectories
// backend and frontend, each holding package.json, pnpm-lock.yaml and
// pnpm-workspace.yaml. KESTRELYNX_WORKER_IT and the settings of
// TestIntegrationLangUpdate apply.
func TestIntegrationLangUpdatePnpmProjectsWithADeclaredManager(t *testing.T) {
	dir := os.Getenv("KESTRELYNX_PNPM_PROJECTS_DIR")
	if dir == "" {
		t.Skip("set KESTRELYNX_PNPM_PROJECTS_DIR to run this test")
	}
	e := itSetup(t)
	node := func(name, ver string, cves ...CVERef) *findingGroup {
		o := FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "app/node_modules/" + name + "/package.json"}
		return group(typeNodePkg, name, ver, o, cves...)
	}
	cases := []struct {
		name   string
		dir    string
		groups []*findingGroup
		// updated are the packages the run must take to a version at or above
		// their target, left out the ones it must leave out.
		updated, leftOut []string
		// wantFailure is the reason the run must end with instead of a pull
		// request candidate.
		wantFailure Reason
	}{
		{"backend", "backend", []*findingGroup{
			node("proxy-addr", "2.0.7", CVERef{VulnID: "CVE-2026-90711", FixedVers: []string{"2.0.8"}}),
			node("undici", "6.27.0", CVERef{VulnID: "CVE-2026-19534", FixedVers: []string{"6.28.1", "7.29.1", "8.10.2"}}),
			node("multer", "2.1.1", CVERef{VulnID: "CVE-2026-5079", FixedVers: []string{"2.2.0", "3.0.0-alpha.2"}},
				CVERef{VulnID: "CVE-2026-77078", FixedVers: []string{"2.3.0"}}, CVERef{VulnID: "CVE-2026-82333", FixedVers: []string{"2.3.0"}}),
		}, []string{"proxy-addr", "undici"}, []string{"multer"}, ""},
		{"frontend", "frontend", []*findingGroup{
			node("next", "16.2.11", CVERef{VulnID: "CVE-2026-75604", FixedVers: []string{"15.5.24", "16.3.3"}},
				CVERef{VulnID: "GHSA-vcvr-r3jv-pc5j", FixedVers: []string{"16.3.6"}}, CVERef{VulnID: "CVE-2026-94483", FixedVers: []string{"16.3.8"}}),
			node("nanoid", "3.3.12", CVERef{VulnID: "CVE-2026-67213", FixedVers: []string{"3.3.18", "5.1.6"}}, CVERef{VulnID: "CVE-2026-67214", FixedVers: []string{"3.3.16", "5.1.16"}}),
			node("nanoid", "3.3.16", CVERef{VulnID: "CVE-2026-67213", FixedVers: []string{"3.3.18", "5.1.6"}}),
			node("sharp", "0.34.5", CVERef{VulnID: "GHSA-f88m-g3jw-g9cj", FixedVers: []string{"0.35.0"}},
				CVERef{VulnID: "GHSA-rgj7-g3m4-5g8c", FixedVers: []string{"0.35.4"}}, CVERef{VulnID: "GHSA-wq5f-xc86-pv6w", FixedVers: []string{"0.35.5"}}),
			node("source-map-js", "1.2.1", CVERef{VulnID: "CVE-2026-93749", FixedVers: []string{"1.2.2"}}),
		}, []string{"next", "nanoid", "sharp", "source-map-js"}, nil, ""},
		{"frontend_without_next", "frontend", []*findingGroup{
			node("nanoid", "3.3.12", CVERef{VulnID: "CVE-2026-67213", FixedVers: []string{"3.3.18", "5.1.6"}}, CVERef{VulnID: "CVE-2026-67214", FixedVers: []string{"3.3.16", "5.1.16"}}),
			node("nanoid", "3.3.16", CVERef{VulnID: "CVE-2026-67213", FixedVers: []string{"3.3.18", "5.1.6"}}),
			node("sharp", "0.34.5", CVERef{VulnID: "GHSA-f88m-g3jw-g9cj", FixedVers: []string{"0.35.0"}},
				CVERef{VulnID: "GHSA-rgj7-g3m4-5g8c", FixedVers: []string{"0.35.4"}}, CVERef{VulnID: "GHSA-wq5f-xc86-pv6w", FixedVers: []string{"0.35.5"}}),
			node("source-map-js", "1.2.1", CVERef{VulnID: "CVE-2026-93749", FixedVers: []string{"1.2.2"}}),
		}, []string{"nanoid", "source-map-js"}, []string{"sharp"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{}
			for _, f := range []string{"package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"} {
				b, err := os.ReadFile(filepath.Join(dir, c.dir, f))
				if err != nil {
					t.Fatal(err)
				}
				files[f] = string(b)
			}
			it := itemFor(t, ManagerPnpm, files, c.groups...)
			if it.Category != CategoryDependencyUpdateCandidate {
				t.Fatalf("not an update candidate: %s %s %s", it.Category, it.Reason, it.Detail)
			}
			plan := &Plan{LanguageItems: []LanguageItem{it}}
			up, err := NewLangUpdater(e.config(LangUpdateConfig{
				GitHub: ghFor(files), Images: map[string]ImageEnv{"img": e.image}, MaxJobs: 4, JobIDPrefix: "it",
			}))
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			use := up.Run(e.ctx, plan)
			got := plan.LanguageItems[0]
			t.Logf("%s: category=%s reason=%s detail=%q jobs=%d took=%s", c.name, got.Category, got.Reason, got.Detail, use.Jobs, time.Since(start).Round(time.Millisecond))
			if got.Update != nil {
				t.Logf("tool=%+v steps=%+v notes=%v", got.Update.Tool, got.Update.Steps, got.Update.Notes)
				if d := got.Update.Diff; d != nil {
					t.Logf("diff added=%v changed=%v removed=%v", d.Added, d.Changed, d.Removed)
				}
				t.Logf("deprecated notes changed: %d", got.Update.DeprecatedChanged)
			}
			for _, p := range got.Packages {
				t.Logf("package %s %s: %s %s %s adopted=%s leftout=%v", p.Name, p.Installed, p.Action, p.Reason, p.Detail, p.AdoptedVersion, p.LeftOut)
			}
			if c.wantFailure != "" {
				if got.Category != CategoryManual || got.Reason != c.wantFailure {
					t.Fatalf("category = %s (%s: %s), want manual / %s", got.Category, got.Reason, got.Detail, c.wantFailure)
				}
				if tl := got.Update.Tool; tl == nil || tl.Version != "10.34.4" || tl.Source != "declared" {
					t.Errorf("tool record = %+v, want pnpm 10.34.4 declared", tl)
				}
				return
			}
			if got.Category != CategoryPRCandidate {
				t.Fatalf("category = %s (%s: %s), want pr_candidate", got.Category, got.Reason, got.Detail)
			}
			if tl := got.Update.Tool; tl == nil || tl.Name != "pnpm" || tl.Version != "10.34.4" || tl.Source != "declared" {
				t.Errorf("tool record = %+v, want pnpm 10.34.4 declared", tl)
			}
			names := func(left bool) []string {
				var out []string
				for _, p := range got.Packages {
					if p.LeftOut == left && (left || p.Action == ActionUpdate) {
						out = append(out, p.Name)
					}
				}
				return uniqueSorted(out)
			}
			if a, b := strings.Join(names(false), ","), strings.Join(uniqueSorted(c.updated), ","); a != b {
				t.Errorf("updated = %s, want %s", a, b)
			}
			if a, b := strings.Join(names(true), ","), strings.Join(uniqueSorted(c.leftOut), ","); a != b {
				t.Errorf("left out = %s, want %s", a, b)
			}
			if d := got.Update.Diff; d != nil {
				t.Logf("followed: %+v", d.Followed)
			}
			if got.SourceCheck == nil || !got.SourceCheck.Passed {
				t.Fatalf("source check = %+v", got.SourceCheck)
			}
		})
	}
}
