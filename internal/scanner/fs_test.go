package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fsFake is a fake trivy that answers "version" from versionFile and "fs"
// with a fixed report, recording what it was run with.
type fsFake struct {
	bin, log, cwd, listing, scanDir, cwdListing, env, versionFile, failFile, sizes string
}

func newFSFake(t *testing.T, report string) fsFake {
	t.Helper()
	dir := t.TempDir()
	f := fsFake{
		bin: filepath.Join(dir, "trivy"), log: filepath.Join(dir, "log"), cwd: filepath.Join(dir, "cwd"),
		listing: filepath.Join(dir, "listing"), scanDir: filepath.Join(dir, "scandir"), cwdListing: filepath.Join(dir, "cwdlisting"),
		sizes: filepath.Join(dir, "sizes"), env: filepath.Join(dir, "env"), versionFile: filepath.Join(dir, "version.json"), failFile: filepath.Join(dir, "fail"),
	}
	reportFile := filepath.Join(dir, "report.json")
	if err := os.WriteFile(reportFile, []byte(report), 0o644); err != nil {
		t.Fatal(err)
	}
	copyVersionFixture(t, f.versionFile)
	script := fmt.Sprintf(`#!/bin/sh
echo "$*" >> %[1]q
if [ "$1" = version ]; then cat %[2]q; exit 0; fi
if [ "$1" = fs ]; then
  if [ -e %[3]q ]; then echo "fs failed" >&2; exit 1; fi
  pwd > %[4]q
  for last; do :; done
  echo "$last" > %[5]q
  ls -A "$last" > %[6]q
  ls -A . > %[7]q
  env | grep '^TRIVY_' > %[8]q
  prev=""
  for a in "$@"; do
    if [ "$prev" = --config ] || [ "$prev" = --ignorefile ]; then wc -c < "$a" >> %[10]q; fi
    prev="$a"
  done
  cat %[9]q
fi
`, f.log, f.versionFile, f.failFile, f.cwd, f.scanDir, f.listing, f.cwdListing, f.env, reportFile, f.sizes)
	if err := os.WriteFile(f.bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return f
}

const fsReportJSON = `{"ArtifactName":"/x","Trivy":{"Version":"0.71.2"},"Results":[
 {"Target":"package-lock.json","Class":"lang-pkgs","Type":"npm",
  "Packages":[{"Name":"minimist","Version":"1.2.5"}],
  "Vulnerabilities":[{"VulnerabilityID":"CVE-2021-44906","PkgName":"minimist","InstalledVersion":"1.2.5","FixedVersion":"1.2.6","Status":"fixed","Severity":"CRITICAL"}]}]}`

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestScanFS(t *testing.T) {
	f := newFSFake(t, fsReportJSON)
	cache := t.TempDir()
	writeCache(t, cache)
	tr := Trivy{BinPath: f.bin, CacheDir: cache, SkipDBUpdate: true, Severity: []string{"HIGH", "CRITICAL"}}
	ctx := context.Background()
	prepared, err := tr.PrepareDB(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Whatever the process environment says, Trivy is run without it.
	t.Setenv("TRIVY_SEVERITY", "LOW")
	t.Setenv("TRIVY_IGNOREFILE", "/etc/passwd")

	files := map[string][]byte{"package.json": []byte(`{"name":"x"}`), "package-lock.json": []byte(`{"lockfileVersion":3}`)}
	res, err := tr.ScanFS(ctx, files, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Findings) != 1 || res.Report.Findings[0].VulnID != "CVE-2021-44906" || res.Report.Findings[0].Package != "minimist" || res.Report.Findings[0].Type != "npm" {
		t.Errorf("findings = %+v", res.Report.Findings)
	}
	if len(res.Report.Packages) != 1 || res.Report.Packages[0].Type != "npm" || res.Report.Packages[0].Packages[0].Name != "minimist" {
		t.Errorf("packages = %+v", res.Report.Packages)
	}
	want := prepared
	want.AnalysisSettings = res.Conditions.AnalysisSettings
	if !res.Conditions.Equal(want) || res.Conditions.AnalysisSettings == prepared.AnalysisSettings || !strings.HasPrefix(res.Conditions.AnalysisSettings, "fs;") {
		t.Errorf("conditions = %+v", res.Conditions)
	}

	// The command line.
	lines := readLog(t, f.log)
	args := strings.Fields(lines[len(lines)-1])
	if args[0] != "fs" {
		t.Fatalf("last command = %v", args)
	}
	has := func(flag string) bool {
		for _, a := range args {
			if a == flag {
				return true
			}
		}
		return false
	}
	for _, flag := range []string{"--skip-db-update", "--skip-java-db-update", "--skip-vex-repo-update", "--include-dev-deps", "--list-all-pkgs", "--quiet", "--disable-telemetry", "--skip-version-check"} {
		if !has(flag) {
			t.Errorf("no %s in %v", flag, args)
		}
	}
	joined := " " + strings.Join(args, " ") + " "
	for _, part := range []string{" --severity HIGH,CRITICAL ", " --scanners vuln ", " --format json ", " --cache-dir " + cache + " "} {
		if !strings.Contains(joined, part) {
			t.Errorf("no %q in %v", part, args)
		}
	}
	// Configuration and ignore files are given and empty, outside the scanned directory.
	scanDir := strings.TrimSpace(read(t, f.scanDir))
	for _, flag := range []string{"--config", "--ignorefile"} {
		var p string
		for i, a := range args {
			if a == flag {
				p = args[i+1]
			}
		}
		if p == "" {
			t.Fatalf("no %s", flag)
		}
		if st, err := os.Stat(p); err == nil {
			t.Errorf("%s file %s survived the scan (%d bytes)", flag, p, st.Size())
		}
		if strings.HasPrefix(p, scanDir) {
			t.Errorf("%s file %s is inside the scanned directory", flag, p)
		}
	}
	if got := strings.Fields(read(t, f.sizes)); len(got) != 2 || got[0] != "0" || got[1] != "0" {
		t.Errorf("the configuration and ignore files were not empty: %v", got)
	}
	// Only the given files were in the scanned directory; Trivy ran in
	// another, empty directory with no TRIVY_* variable.
	if got := strings.Fields(read(t, f.listing)); strings.Join(got, ",") != "package-lock.json,package.json" {
		t.Errorf("scanned directory held %v", got)
	}
	if got := strings.TrimSpace(read(t, f.cwdListing)); got != "" {
		t.Errorf("the working directory held %q", got)
	}
	if cwd := strings.TrimSpace(read(t, f.cwd)); cwd == scanDir || strings.HasPrefix(cwd, scanDir) {
		t.Errorf("trivy ran in %s, the scanned directory %s", cwd, scanDir)
	}
	if got := strings.TrimSpace(read(t, f.env)); got != "" {
		t.Errorf("TRIVY_ variables reached trivy: %q", got)
	}
	// Everything the scan created is gone.
	if _, err := os.Stat(scanDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the scan directory survived: %v", err)
	}
}

func TestScanFSConditions(t *testing.T) {
	f := newFSFake(t, fsReportJSON)
	cache := t.TempDir()
	writeCache(t, cache)
	tr := Trivy{BinPath: f.bin, CacheDir: cache, SkipDBUpdate: true}
	ctx := context.Background()
	prepared, err := tr.PrepareDB(ctx)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"requirements.txt": []byte("a==1\n")}

	t.Run("current conditions are the prepared ones", func(t *testing.T) {
		c, err := tr.CurrentConditions(ctx)
		if err != nil || !c.Equal(prepared) {
			t.Errorf("%+v %v", c, err)
		}
		if _, err := (Trivy{BinPath: f.bin, CacheDir: cache}).CurrentConditions(ctx); err == nil {
			t.Error("accepted outside comparison mode")
		}
	})
	t.Run("unknown conditions", func(t *testing.T) {
		if _, err := tr.ScanFS(ctx, files, ScanConditions{}); !errors.Is(err, ErrConditionsUnknown) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("a database changed since", func(t *testing.T) {
		cache2 := t.TempDir()
		writeCache(t, cache2)
		tr2 := Trivy{BinPath: f.bin, CacheDir: cache2, SkipDBUpdate: true}
		p2, err := tr2.PrepareDB(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cache2, "db", "trivy.db"), []byte("replaced"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := tr2.ScanFS(ctx, files, p2); !errors.Is(err, ErrConditionsDiffer) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("severities differ", func(t *testing.T) {
		tr3 := tr
		tr3.Severity = []string{"CRITICAL"}
		if _, err := tr3.ScanFS(ctx, files, prepared); !errors.Is(err, ErrConditionsDiffer) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("prepared without a fixed environment", func(t *testing.T) {
		loose, err := (Trivy{BinPath: f.bin, CacheDir: cache}).PrepareDB(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tr.ScanFS(ctx, files, loose); !errors.Is(err, ErrConditionsDiffer) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("not the comparison mode", func(t *testing.T) {
		if _, err := (Trivy{BinPath: f.bin, CacheDir: cache}).ScanFS(ctx, files, prepared); err == nil || errors.Is(err, ErrConditionsDiffer) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("a report of another Trivy", func(t *testing.T) {
		g := newFSFake(t, strings.Replace(fsReportJSON, `"0.71.2"`, `"0.70.0"`, 1))
		c2 := t.TempDir()
		writeCache(t, c2)
		tr4 := Trivy{BinPath: g.bin, CacheDir: c2, SkipDBUpdate: true}
		p4, err := tr4.PrepareDB(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tr4.ScanFS(ctx, files, p4); !errors.Is(err, ErrConditionsDiffer) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("trivy fails", func(t *testing.T) {
		g := newFSFake(t, fsReportJSON)
		c2 := t.TempDir()
		writeCache(t, c2)
		tr5 := Trivy{BinPath: g.bin, CacheDir: c2, SkipDBUpdate: true}
		p5, _ := tr5.PrepareDB(ctx)
		if err := os.WriteFile(g.failFile, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := tr5.ScanFS(ctx, files, p5)
		if err == nil || !strings.Contains(err.Error(), "fs failed") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("a report that is not JSON", func(t *testing.T) {
		g := newFSFake(t, "not json")
		c2 := t.TempDir()
		writeCache(t, c2)
		tr6 := Trivy{BinPath: g.bin, CacheDir: c2, SkipDBUpdate: true}
		p6, _ := tr6.PrepareDB(ctx)
		if _, err := tr6.ScanFS(ctx, files, p6); err == nil {
			t.Error("accepted")
		}
	})
}

func TestScanFSRefusesBadFiles(t *testing.T) {
	f := newFSFake(t, fsReportJSON)
	cache := t.TempDir()
	writeCache(t, cache)
	tr := Trivy{BinPath: f.bin, CacheDir: cache, SkipDBUpdate: true}
	ctx := context.Background()
	prepared, _ := tr.PrepareDB(ctx)
	many := map[string][]byte{}
	for i := 0; i <= maxFSFiles; i++ {
		many[fmt.Sprintf("f%d", i)] = nil
	}
	for name, files := range map[string]map[string][]byte{
		"none":      {},
		"nil":       nil,
		"too many":  many,
		"parent":    {"../x": nil},
		"nested":    {"a/b": nil},
		"hidden":    {".trivyignore": nil},
		"backslash": {`a\b`: nil},
		"empty":     {"": nil},
		"nul":       {"a\x00b": nil},
		"too big":   {"big": make([]byte, maxFSFileBytes+1)},
	} {
		if _, err := tr.ScanFS(ctx, files, prepared); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := os.Stat(f.listing); err == nil {
		t.Error("trivy ran for refused files")
	}
}

func TestParseReportOSName(t *testing.T) {
	scan, err := ParseReport([]byte(`{"Metadata":{"OS":{"Family":"debian","Name":"12.5"}},"Results":[]}`))
	if err != nil || scan.OSFamily != "debian" || scan.OSName != "12.5" {
		t.Errorf("%+v %v", scan, err)
	}
	for _, f := range []string{"real_alpine_3.19.json", "real_debian_12-slim.json", "real_python_3.12.3-slim_layers.json"} {
		data, err := os.ReadFile(filepath.Join(testdataDir, f))
		if err != nil {
			t.Fatal(err)
		}
		s, err := ParseReport(data)
		if err != nil || s.OSName == "" {
			t.Errorf("%s: OSName = %q, %v", f, s.OSName, err)
		}
	}
}
