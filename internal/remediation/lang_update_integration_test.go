package remediation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// These tests run the update stage against a real work image, a real Docker
// daemon, the real PyPI and a real Trivy with its database cached. They run
// only when KESTRELYNX_WORKER_IT_IMAGE names the work image by digest
// ("repository@sha256:..."; the image must be in a registry or in the local
// image store under that reference). Optional settings:
//
//	KESTRELYNX_DOCKER_SOCK  the Docker socket (default /var/run/docker.sock)
//	KESTRELYNX_TRIVY_BIN    the trivy executable (default ~/.local/bin/trivy)
//	KESTRELYNX_TRIVY_CACHE  its cache directory (default ~/.cache/trivy)
func TestIntegrationLangUpdate(t *testing.T) {
	image := os.Getenv("KESTRELYNX_WORKER_IT_IMAGE")
	if image == "" {
		t.Skip("set KESTRELYNX_WORKER_IT_IMAGE to a digest-pinned work image to run this test")
	}
	sock := os.Getenv("KESTRELYNX_DOCKER_SOCK")
	if sock == "" {
		sock = "/var/run/docker.sock"
	}
	home, _ := os.UserHomeDir()
	trivyBin := os.Getenv("KESTRELYNX_TRIVY_BIN")
	if trivyBin == "" {
		trivyBin = filepath.Join(home, ".local", "bin", "trivy")
	}
	cache := os.Getenv("KESTRELYNX_TRIVY_CACHE")
	if cache == "" {
		cache = filepath.Join(home, ".cache", "trivy")
	}

	var idb [16]byte
	if _, err := rand.Read(idb[:]); err != nil {
		t.Fatal(err)
	}
	wc, err := docker.NewWork(sock, docker.WorkConfig{
		Image:          image,
		Entrypoint:     []string{"/usr/local/libexec/kestrelynx-worker", "run", "/work/job.json"},
		AllowedEnvKeys: []string{"PATH", "HOME"},
		Env:            []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/home/worker"},
		InstanceID:     hex.EncodeToString(idb[:]),
		Limits: docker.TransferLimits{
			MaxInputBytes: 8 << 20, MaxInputTarBytes: 16 << 20, MaxInputFiles: 16, MaxInputPathBytes: 256,
			LogMaxBytes: 8 << 20, MaxStdoutBytes: 8 << 20,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	t.Cleanup(func() {
		if _, err := wc.CleanupStale(ctx); err != nil {
			t.Errorf("cleanup: %v", err)
		}
		out, err := exec.Command("docker", "ps", "-a", "-q", "--filter", "label=io.kestrelynx.work.instance="+hex.EncodeToString(idb[:])).Output()
		if err == nil && strings.TrimSpace(string(out)) != "" {
			t.Errorf("work containers left behind: %s", out)
		}
	})
	if err := wc.EnsureImage(ctx); err != nil {
		t.Fatalf("EnsureImage: %v", err)
	}

	tr := scanner.Trivy{BinPath: trivyBin, Severity: []string{"HIGH", "CRITICAL"}, CacheDir: cache, SkipDBUpdate: true}
	prepared, err := tr.CurrentConditions(ctx)
	if err != nil {
		t.Fatalf("trivy conditions: %v", err)
	}

	env := ImageEnv{Platform: inventory.Platform{OS: "linux", Architecture: "amd64"}, OSFamily: "debian", OSName: "12.5"}
	nodeOrigin := FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "app/node_modules/minimist/package.json"}
	pyOrigin := FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "usr/local/lib/python3.12/site-packages/urllib3-1.26.4.dist-info/METADATA", Target: "Python"}
	minimist := func() *findingGroup {
		return group(typeNodePkg, "minimist", "1.2.5", nodeOrigin, CVERef{VulnID: "CVE-2021-44906", FixedVers: []string{"0.2.4", "1.2.6"}})
	}
	urllib3 := func() *findingGroup {
		return group(typePythonPkg, "urllib3", "1.26.4", pyOrigin,
			CVERef{VulnID: "CVE-2021-33503", FixedVers: []string{"1.26.5"}},
			CVERef{VulnID: "CVE-2023-43804", FixedVers: []string{"1.26.17", "2.0.6"}})
	}

	cases := []struct {
		name    string
		manager DependencyManager
		dir     string
		files   []string
		group   func() *findingGroup
		pkg     string
		// mutate changes the fixture files before the item is planned, and
		// wantNote is a text one note of the run must contain.
		mutate   func(map[string]string)
		wantNote string
		// wantEdit is "from>to" of the one manifest edit the run must make.
		wantEdit string
	}{
		{"npm", ManagerNpm, "npm", []string{"package.json", "package-lock.json"}, minimist, "minimist", nil, "", ""},
		{"pnpm", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist", nil, "", ""},
		{"uv", ManagerUv, "uv", []string{"pyproject.toml", "uv.lock"}, urllib3, "urllib3", nil, "", ""},
		{"pip", ManagerPip, "pip", []string{"requirements.txt"}, urllib3, "urllib3", nil, "", ""},
		{"npm_direct_pinned_out_of_range", ManagerNpm, "npm", []string{"package.json", "package-lock.json"}, minimist, "minimist",
			func(f map[string]string) {
				f["package.json"] = strings.Replace(f["package.json"], `"mkdirp": "0.5.5"`, `"minimist": "1.2.5",
    "mkdirp": "0.5.5"`, 1)
				f["package-lock.json"] = strings.Replace(f["package-lock.json"], `"dependencies": {
        "mkdirp": "0.5.5"`, `"dependencies": {
        "minimist": "1.2.5",
        "mkdirp": "0.5.5"`, 1)
			}, "", "1.2.5>1.2.6"},
		{"pnpm_direct_pinned_out_of_range", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist",
			func(f map[string]string) {
				f["package.json"] = strings.Replace(f["package.json"], `"mkdirp": "0.5.5"`, `"minimist": "1.2.5",
    "mkdirp": "0.5.5"`, 1)
				f["pnpm-lock.yaml"] = strings.Replace(f["pnpm-lock.yaml"], `    dependencies:
      mkdirp:`, `    dependencies:
      minimist:
        specifier: 1.2.5
        version: 1.2.5
      mkdirp:`, 1)
			}, "", "1.2.5>1.2.6"},
		{"uv_direct_pinned_out_of_range", ManagerUv, "uv", []string{"pyproject.toml", "uv.lock"}, urllib3, "urllib3",
			func(f map[string]string) {
				f["pyproject.toml"] = strings.Replace(f["pyproject.toml"], `"urllib3>=1.26,<2"`, `"urllib3==1.26.4"`, 1)
				f["uv.lock"] = strings.Replace(f["uv.lock"], `specifier = ">=1.26,<2"`, `specifier = "==1.26.4"`, 1)
			}, "", "urllib3==1.26.4>urllib3==1.26.17"},
		{"pnpm_workspace_allow_builds", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist",
			func(f map[string]string) { f["pnpm-workspace.yaml"] = backendWorkspace }, "", ""},
		{"pnpm_workspace_supported_architectures", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist",
			func(f map[string]string) { f["pnpm-workspace.yaml"] = frontendWorkspace }, "", ""},
		{"pnpm_declared_manager", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"}, minimist, "minimist",
			func(f map[string]string) {
				f["package.json"] = strings.Replace(f["package.json"], `"private": true,`, `"private": true, "packageManager": "pnpm@9.0.0",`, 1)
			}, "configured to use 9.0.0 of pnpm", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := readTestdata(t, c.dir, c.files...)
			if c.mutate != nil {
				c.mutate(files)
			}
			it := itemFor(t, c.manager, files, c.group())
			if it.Category != CategoryDependencyUpdateCandidate {
				t.Fatalf("the fixture is not an update candidate: %s %s", it.Category, it.Detail)
			}
			plan := &Plan{LanguageItems: []LanguageItem{it}}
			up, err := NewLangUpdater(LangUpdateConfig{
				Work: wc, Scanner: tr, PyPI: &PyPIClient{}, Npm: &NpmClient{}, GitHub: ghFor(files),
				Prepared: prepared, Images: map[string]ImageEnv{"img": env},
				MaxJobs: 4, JobIDPrefix: "it",
			})
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			use := up.Run(ctx, plan)
			got := plan.LanguageItems[0]
			t.Logf("%s: category=%s reason=%s detail=%q jobs=%d took=%s", c.name, got.Category, got.Reason, got.Detail, use.Jobs, time.Since(start).Round(time.Millisecond))
			if got.Update != nil {
				t.Logf("steps=%+v notes=%v diff=%+v", got.Update.Steps, got.Update.Notes, got.Update.Diff)
			}
			if got.Category != CategoryPRCandidate {
				for _, p := range got.Packages {
					t.Logf("package %s: %s %s %s", p.Name, p.Action, p.Reason, p.Detail)
				}
				t.Fatalf("category = %s (%s), want pr_candidate", got.Category, got.Reason)
			}
			if !got.UpdateExecuted || !got.PostUpdateCheckExecuted {
				t.Errorf("executed flags = %v %v", got.UpdateExecuted, got.PostUpdateCheckExecuted)
			}
			if c.wantEdit != "" {
				edits := got.Update.ManifestEdits
				if len(edits) != 1 || edits[0].From+">"+edits[0].To != c.wantEdit {
					t.Errorf("manifest edits = %+v, want %s", edits, c.wantEdit)
				}
				t.Logf("edit %+v", edits[0])
			}
			if c.wantNote != "" {
				found := false
				for _, n := range got.Update.Notes {
					found = found || strings.Contains(n, c.wantNote)
				}
				if !found {
					t.Errorf("notes %v lack %q", got.Update.Notes, c.wantNote)
				}
			}
			p := got.Packages[0]
			t.Logf("%s %s -> adopted %s (lower bound %s)", p.Name, p.Installed, p.AdoptedVersion, p.SelectionLowerBound)
			if got.SourceCheck == nil || !got.SourceCheck.Passed {
				t.Fatalf("source check = %+v", got.SourceCheck)
			}
			sc := got.SourceCheck
			t.Logf("fs check: before=%v after=%v resolved=%v remaining=%v introduced=%v", sc.Before, sc.After, sc.Resolved, sc.Remaining, sc.Introduced)
			wantArtifacts := 1
			if c.wantEdit != "" {
				wantArtifacts = 2
			}
			if len(got.Artifacts) != wantArtifacts || len(got.Artifacts[0].Content) == 0 {
				t.Fatalf("artifacts = %+v", got.Artifacts)
			}
			for _, cv := range p.CVEs {
				found := false
				for _, r := range sc.Resolved {
					found = found || r.VulnID == cv.VulnID
				}
				if !found {
					t.Errorf("%s is not among the resolved findings", cv.VulnID)
				}
			}
		})
	}
}

// TestIntegrationLangUpdateRealisticProjects runs the update stage over
// lockfiles of mid-size projects (express and axios, vite, fastapi and httpx,
// requests with hashes), each built with the work image's tools and an old
// release date so that the transitive packages are old, and checks that
// output that is honest is accepted. The projects are not part of the
// repository: KESTRELYNX_REALISTIC_DIR names a directory with the
// subdirectories npm, pnpm, uv and pip, each holding the project's files.
// KESTRELYNX_WORKER_IT_IMAGE and the settings of TestIntegrationLangUpdate apply.
func TestIntegrationLangUpdateRealisticProjects(t *testing.T) {
	image := os.Getenv("KESTRELYNX_WORKER_IT_IMAGE")
	dir := os.Getenv("KESTRELYNX_REALISTIC_DIR")
	if image == "" || dir == "" {
		t.Skip("set KESTRELYNX_WORKER_IT_IMAGE and KESTRELYNX_REALISTIC_DIR to run this test")
	}
	sock := os.Getenv("KESTRELYNX_DOCKER_SOCK")
	if sock == "" {
		sock = "/var/run/docker.sock"
	}
	home, _ := os.UserHomeDir()
	trivyBin := os.Getenv("KESTRELYNX_TRIVY_BIN")
	if trivyBin == "" {
		trivyBin = filepath.Join(home, ".local", "bin", "trivy")
	}
	cache := os.Getenv("KESTRELYNX_TRIVY_CACHE")
	if cache == "" {
		cache = filepath.Join(home, ".cache", "trivy")
	}
	var idb [16]byte
	if _, err := rand.Read(idb[:]); err != nil {
		t.Fatal(err)
	}
	wc, err := docker.NewWork(sock, docker.WorkConfig{
		Image:          image,
		Entrypoint:     []string{"/usr/local/libexec/kestrelynx-worker", "run", "/work/job.json"},
		AllowedEnvKeys: []string{"PATH", "HOME"},
		Env:            []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/home/worker"},
		InstanceID:     hex.EncodeToString(idb[:]),
		Limits: docker.TransferLimits{
			MaxInputBytes: 8 << 20, MaxInputTarBytes: 16 << 20, MaxInputFiles: 16, MaxInputPathBytes: 256,
			LogMaxBytes: 8 << 20, MaxStdoutBytes: 8 << 20,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	t.Cleanup(func() {
		if _, err := wc.CleanupStale(ctx); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	if err := wc.EnsureImage(ctx); err != nil {
		t.Fatalf("EnsureImage: %v", err)
	}
	tr := scanner.Trivy{BinPath: trivyBin, Severity: []string{"HIGH", "CRITICAL"}, CacheDir: cache, SkipDBUpdate: true}
	prepared, err := tr.CurrentConditions(ctx)
	if err != nil {
		t.Fatalf("trivy conditions: %v", err)
	}
	env := ImageEnv{Platform: inventory.Platform{OS: "linux", Architecture: "amd64"}, OSFamily: "debian", OSName: "12.5"}
	node := func(name, ver string, cves ...CVERef) func() *findingGroup {
		o := FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "app/node_modules/" + name + "/package.json"}
		return func() *findingGroup { return group(typeNodePkg, name, ver, o, cves...) }
	}
	py := func(name, ver string, cves ...CVERef) func() *findingGroup {
		o := FindingOrigin{Entity: "img", Workload: "compose/p/web", PkgPath: "usr/local/lib/python3.12/site-packages/" + name + "-" + ver + ".dist-info/METADATA", Target: "Python"}
		return func() *findingGroup { return group(typePythonPkg, name, ver, o, cves...) }
	}
	cases := []struct {
		name    string
		manager DependencyManager
		dir     string
		files   []string
		group   func() *findingGroup
		// wantFailure is the reason an update the tool itself cannot do ends
		// with (the project pins a package that holds the target back); empty
		// means pr_candidate is required.
		wantFailure Reason
	}{
		{"npm_follow_redirects_under_axios_and_express", ManagerNpm, "npm", []string{"package.json", "package-lock.json"},
			node("follow-redirects", "1.13.0", CVERef{VulnID: "CVE-2022-0155", FixedVers: []string{"1.14.7"}}), ""},
		{"npm_proxy_addr_under_express", ManagerNpm, "npm", []string{"package.json", "package-lock.json"},
			node("proxy-addr", "2.0.6", CVERef{VulnID: "CVE-2026-90711", FixedVers: []string{"2.0.8"}}), ""},
		{"pnpm_nanoid_under_vite", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"},
			node("nanoid", "3.3.6", CVERef{VulnID: "CVE-2026-67213", FixedVers: []string{"3.3.18"}}), ""},
		{"pnpm_rollup_under_vite", ManagerPnpm, "pnpm", []string{"package.json", "pnpm-lock.yaml"},
			node("rollup", "3.29.3", CVERef{VulnID: "CVE-2024-47068", FixedVers: []string{"3.29.5"}}), ""},
		{"pnpm_frontend_nanoid_with_supported_architectures", ManagerPnpm, "pnpm_frontend", []string{"package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"},
			node("nanoid", "3.3.7", CVERef{VulnID: "CVE-2026-67213", FixedVers: []string{"3.3.18"}}), ""},
		{"pnpm_frontend_sharp_direct_pinned", ManagerPnpm, "pnpm_frontend", []string{"package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"},
			node("sharp", "0.33.0", CVERef{VulnID: "GHSA-wq5f-xc86-pv6w", FixedVers: []string{"0.35.5"}}), ""},
		{"pnpm_backend_allow_builds", ManagerPnpm, "pnpm_backend", []string{"package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"},
			node("nanoid", "3.3.6", CVERef{VulnID: "CVE-2026-67213", FixedVers: []string{"3.3.18"}}), ""},
		{"uv_certifi_under_httpx", ManagerUv, "uv", []string{"pyproject.toml", "uv.lock"},
			py("certifi", "2022.12.7", CVERef{VulnID: "CVE-2023-37920", FixedVers: []string{"2023.7.22"}}), ""},
		{"uv_anyio_under_httpx_and_starlette", ManagerUv, "uv", []string{"pyproject.toml", "uv.lock"},
			py("anyio", "3.6.2", CVERef{VulnID: "CVE-2026-63374", FixedVers: []string{"4.14.2"}}), ReasonUpdateStepFailed},
		{"pip_urllib3_under_requests", ManagerPip, "pip", []string{"requirements.txt"},
			py("urllib3", "1.26.9", CVERef{VulnID: "CVE-2023-43804", FixedVers: []string{"1.26.17"}}), ""},
		{"pip_certifi_under_requests", ManagerPip, "pip", []string{"requirements.txt"},
			py("certifi", "2022.5.18.1", CVERef{VulnID: "CVE-2023-37920", FixedVers: []string{"2023.7.22"}}), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{}
			for _, f := range c.files {
				b, err := os.ReadFile(filepath.Join(dir, c.dir, f))
				if err != nil {
					t.Fatal(err)
				}
				files[f] = string(b)
			}
			it := itemFor(t, c.manager, files, c.group())
			if it.Category != CategoryDependencyUpdateCandidate {
				t.Fatalf("the project is not an update candidate: %s %s %s", it.Category, it.Reason, it.Detail)
			}
			plan := &Plan{LanguageItems: []LanguageItem{it}}
			up, err := NewLangUpdater(LangUpdateConfig{
				Work: wc, Scanner: tr, PyPI: &PyPIClient{}, Npm: &NpmClient{}, GitHub: ghFor(files),
				Prepared: prepared, Images: map[string]ImageEnv{"img": env},
				MaxJobs: 4, JobIDPrefix: "it",
			})
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			use := up.Run(ctx, plan)
			got := plan.LanguageItems[0]
			t.Logf("%s: category=%s reason=%s detail=%q jobs=%d took=%s", c.name, got.Category, got.Reason, got.Detail, use.Jobs, time.Since(start).Round(time.Millisecond))
			if got.Update != nil {
				t.Logf("notes=%v diff=%+v", got.Update.Notes, got.Update.Diff)
			}
			for _, p := range got.Packages {
				t.Logf("package %s %s: %s %s %s adopted=%s", p.Name, p.Installed, p.Action, p.Reason, p.Detail, p.AdoptedVersion)
			}
			if c.wantFailure != "" {
				if got.Reason != c.wantFailure {
					t.Fatalf("reason = %s, want %s", got.Reason, c.wantFailure)
				}
				return
			}
			if got.Category != CategoryPRCandidate {
				t.Fatalf("category = %s (%s: %s), want pr_candidate", got.Category, got.Reason, got.Detail)
			}
		})
	}
}
