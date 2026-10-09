package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func knownConditions() ScanConditions {
	return ScanConditions{
		TrivyVersion:       "0.71.2",
		VulnerabilityDB:    DBInfo{Version: 2, UpdatedAt: time.Date(2026, 10, 6, 1, 8, 27, 0, time.UTC)},
		JavaDB:             DBInfo{Version: 1, UpdatedAt: time.Date(2026, 10, 7, 1, 10, 24, 0, time.UTC)},
		Severities:         []string{"CRITICAL", "HIGH"},
		AnalysisSettings:   analysisBase + ";env=x;workdir=isolated",
		VulnerabilityDBSHA: "aa", JavaDBSHA: "bb", TrivySHA: "cc",
	}
}

func TestScanConditions_KnownAndEqual(t *testing.T) {
	a := knownConditions()
	if !a.Known() {
		t.Fatal("fully populated conditions must be known")
	}
	b := knownConditions()
	// The same instant in another zone is the same database.
	b.VulnerabilityDB.UpdatedAt = b.VulnerabilityDB.UpdatedAt.In(time.FixedZone("x", 9*3600))
	if !a.Equal(b) {
		t.Error("equal conditions compared unequal")
	}

	mutations := map[string]func(*ScanConditions){
		"version":        func(c *ScanConditions) { c.TrivyVersion = "0.71.3" },
		"vulndb":         func(c *ScanConditions) { c.VulnerabilityDB.UpdatedAt = c.VulnerabilityDB.UpdatedAt.Add(time.Second) },
		"vulnver":        func(c *ScanConditions) { c.VulnerabilityDB.Version = 3 },
		"javadb":         func(c *ScanConditions) { c.JavaDB.UpdatedAt = c.JavaDB.UpdatedAt.Add(time.Hour) },
		"severity":       func(c *ScanConditions) { c.Severities = []string{"HIGH"} },
		"settings":       func(c *ScanConditions) { c.AnalysisSettings = "fs" },
		"vulndb content": func(c *ScanConditions) { c.VulnerabilityDBSHA = "zz" },
		"javadb content": func(c *ScanConditions) { c.JavaDBSHA = "zz" },
		"trivy binary":   func(c *ScanConditions) { c.TrivySHA = "zz" },
	}
	for name, mut := range mutations {
		c := knownConditions()
		mut(&c)
		if a.Equal(c) {
			t.Errorf("%s difference must make conditions unequal", name)
		}
	}
}

func TestScanConditions_UnknownIsNeverEqual(t *testing.T) {
	empties := map[string]func(*ScanConditions){
		"version":        func(c *ScanConditions) { c.TrivyVersion = "" },
		"vulndb":         func(c *ScanConditions) { c.VulnerabilityDB = DBInfo{} },
		"javadb":         func(c *ScanConditions) { c.JavaDB = DBInfo{} },
		"severity":       func(c *ScanConditions) { c.Severities = nil },
		"settings":       func(c *ScanConditions) { c.AnalysisSettings = "" },
		"vulndb content": func(c *ScanConditions) { c.VulnerabilityDBSHA = "" },
		"javadb content": func(c *ScanConditions) { c.JavaDBSHA = "" },
		"trivy binary":   func(c *ScanConditions) { c.TrivySHA = "" },
	}
	for name, mut := range empties {
		c := knownConditions()
		mut(&c)
		if c.Known() {
			t.Errorf("missing %s must make conditions not known", name)
		}
		if c.Equal(c) {
			t.Errorf("unknown conditions (%s) must not equal even themselves", name)
		}
	}
	if (ScanConditions{}).Known() {
		t.Error("zero value must not be known")
	}
}

func TestNormalizeSeverities(t *testing.T) {
	got := normalizeSeverities([]string{"high", "CRITICAL,high", " medium "})
	want := []string{"CRITICAL", "HIGH", "MEDIUM"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseVersionReport_Real(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(testdataDir, "real_trivy_version.json"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := parseVersionReport(data)
	if err != nil {
		t.Fatal(err)
	}
	if c.TrivyVersion != "0.71.2" {
		t.Errorf("TrivyVersion = %q", c.TrivyVersion)
	}
	wantVuln := time.Date(2026, 10, 6, 1, 8, 27, 805176720, time.UTC)
	if c.VulnerabilityDB.Version != 2 || !c.VulnerabilityDB.UpdatedAt.Equal(wantVuln) {
		t.Errorf("VulnerabilityDB = %+v", c.VulnerabilityDB)
	}
	if c.JavaDB.Version != 1 || c.JavaDB.UpdatedAt.IsZero() {
		t.Errorf("JavaDB = %+v", c.JavaDB)
	}
}

func TestParseVersionReport_MissingDBsAndBadJSON(t *testing.T) {
	c, err := parseVersionReport([]byte(`{"Version":"0.71.2"}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.VulnerabilityDB.Known() || c.JavaDB.Known() {
		t.Errorf("absent databases must stay unknown: %+v", c)
	}
	if _, err := parseVersionReport([]byte(`not json`)); err == nil {
		t.Error("bad JSON must be an error")
	}
}

// writeDBFakeTrivy installs a shell script standing in for trivy that logs
// every invocation (one line, arguments space-joined) to logFile. "version"
// prints the current content of versionFile; every other command prints
// nothing and exits failCode-style: it fails when a "fail" file exists.
func writeDBFakeTrivy(t *testing.T) (bin, logFile, versionFile, failFile string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "trivy")
	logFile = filepath.Join(dir, "log")
	versionFile = filepath.Join(dir, "version.json")
	failFile = filepath.Join(dir, "fail")
	script := fmt.Sprintf(`#!/bin/sh
echo "$*" >> %q
if [ -e %q ]; then echo boom >&2; exit 1; fi
if [ "$1" = version ]; then cat %q; fi
`, logFile, failFile, versionFile)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return
}

func readLog(t *testing.T, logFile string) []string {
	t.Helper()
	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

// writeCache lays out a Trivy cache holding both database files.
// testdataDir is absolute so tests that change directory still find fixtures.
var testdataDir, _ = filepath.Abs("testdata")

func writeCache(t *testing.T, root string) {
	t.Helper()
	for path, content := range map[string]string{
		filepath.Join(root, "db", "trivy.db"):           "vuln-db-v1",
		filepath.Join(root, "java-db", "trivy-java.db"): "java-db-v1",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func copyVersionFixture(t *testing.T, dst string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testdataDir, "real_trivy_version.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareDB_CommandsAndConditions(t *testing.T) {
	bin, logFile, versionFile, _ := writeDBFakeTrivy(t)
	copyVersionFixture(t, versionFile)
	cache := t.TempDir()
	writeCache(t, cache)
	tr := Trivy{BinPath: bin, Severity: []string{"high", "CRITICAL"}, CacheDir: cache}

	c, err := tr.PrepareDB(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"image --quiet --download-db-only --cache-dir " + cache,
		"image --quiet --download-java-db-only --cache-dir " + cache,
		"version --format json --cache-dir " + cache,
	}
	if got := readLog(t, logFile); !reflect.DeepEqual(got, want) {
		t.Errorf("commands = %q, want %q", got, want)
	}
	if !c.Known() {
		t.Fatalf("conditions from a complete version report must be known: %+v", c)
	}
	if !reflect.DeepEqual(c.Severities, []string{"CRITICAL", "HIGH"}) {
		t.Errorf("Severities = %v", c.Severities)
	}
	if c.VulnerabilityDBSHA != sha256Hex("vuln-db-v1") || c.JavaDBSHA != sha256Hex("java-db-v1") {
		t.Errorf("db hashes = %q, %q", c.VulnerabilityDBSHA, c.JavaDBSHA)
	}
	binData, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if c.TrivySHA != sha256Hex(string(binData)) {
		t.Errorf("TrivySHA = %q", c.TrivySHA)
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestPrepareDB_DefaultCacheDirFollowsXDG(t *testing.T) {
	bin, logFile, versionFile, _ := writeDBFakeTrivy(t)
	copyVersionFixture(t, versionFile)
	xdg := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", xdg)
	writeCache(t, filepath.Join(xdg, "trivy"))
	c, err := (Trivy{BinPath: bin}).PrepareDB(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c.VulnerabilityDBSHA != sha256Hex("vuln-db-v1") {
		t.Errorf("the default cache was not the one hashed: %q", c.VulnerabilityDBSHA)
	}
	for _, line := range readLog(t, logFile) {
		if !strings.HasSuffix(line, "--cache-dir "+filepath.Join(xdg, "trivy")) {
			t.Errorf("the resolved default cache must be passed explicitly, got %q", line)
		}
	}
}

func TestPrepareDB_Failures(t *testing.T) {
	bin, _, versionFile, failFile := writeDBFakeTrivy(t)
	copyVersionFixture(t, versionFile)
	if err := os.WriteFile(failFile, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cache := t.TempDir()
	writeCache(t, cache)
	_, err := (Trivy{BinPath: bin, CacheDir: cache}).PrepareDB(context.Background())
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("download failure must be reported with stderr, got %v", err)
	}

	// A version report without the Java DB means scans could not skip its
	// update safely.
	bin, _, versionFile, _ = writeDBFakeTrivy(t)
	if err := os.WriteFile(versionFile, []byte(`{"Version":"0.71.2","VulnerabilityDB":{"Version":2,"UpdatedAt":"2026-10-06T01:08:27Z"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (Trivy{BinPath: bin, CacheDir: cache}).PrepareDB(context.Background()); err == nil {
		t.Error("missing Java DB identity must be an error")
	}

	// A missing database file cannot be hashed.
	bin, _, versionFile, _ = writeDBFakeTrivy(t)
	copyVersionFixture(t, versionFile)
	if _, err := (Trivy{BinPath: bin, CacheDir: t.TempDir()}).PrepareDB(context.Background()); err == nil {
		t.Error("missing database files must be an error")
	}
}

func TestVerifyDB(t *testing.T) {
	bin, logFile, versionFile, failFile := writeDBFakeTrivy(t)
	copyVersionFixture(t, versionFile)
	cache := t.TempDir()
	writeCache(t, cache)
	tr := Trivy{BinPath: bin, CacheDir: cache}
	base, err := tr.PrepareDB(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	same, err := tr.VerifyDB(context.Background(), base)
	if err != nil || !same {
		t.Fatalf("unchanged DBs: same=%v err=%v", same, err)
	}
	if got := readLog(t, logFile); got[len(got)-1] != "version --format json --cache-dir "+cache {
		t.Errorf("VerifyDB must only re-read the version, last command %q", got[len(got)-1])
	}

	// Another process replaced the vulnerability DB.
	if err := os.WriteFile(versionFile, []byte(`{"Version":"0.71.2","VulnerabilityDB":{"Version":2,"UpdatedAt":"2026-10-08T01:08:27Z"},"JavaDB":{"Version":1,"UpdatedAt":"2026-10-07T01:10:24.784068105Z"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	same, err = tr.VerifyDB(context.Background(), base)
	if err != nil || same {
		t.Errorf("replaced DB: same=%v err=%v", same, err)
	}

	if err := os.WriteFile(failFile, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if same, err = tr.VerifyDB(context.Background(), base); err == nil || same {
		t.Errorf("failed re-read must be an error and not 'same': same=%v err=%v", same, err)
	}
}

func TestTrivyArgs_SkipDBUpdate(t *testing.T) {
	id := "sha256:" + strings.Repeat("c", 64)
	target := pinnedTarget(t, "nginx:1.25", id)

	// Default: byte-for-byte the arguments without the option.
	def := Trivy{Severity: []string{"HIGH", "CRITICAL"}, CacheDir: "/c"}.trivyArgs(target)
	want := []string{"image", "--quiet", "--format", "json", "--severity", "HIGH,CRITICAL", "--image-src", "docker", id}
	if !reflect.DeepEqual(def, want) {
		t.Errorf("default args changed (CacheDir alone must not matter): %q", def)
	}
	if got := New().trivyArgs(refTarget("nginx:1.25")); !reflect.DeepEqual(got,
		[]string{"image", "--quiet", "--format", "json", "--severity", "HIGH,CRITICAL", "nginx:1.25"}) {
		t.Errorf("ref-fallback default args changed: %q", got)
	}

	on := Trivy{SkipDBUpdate: true, CacheDir: "/c"}.trivyArgs(target)
	wantOn := []string{"image", "--quiet", "--format", "json", "--severity", "HIGH,CRITICAL",
		"--skip-db-update", "--skip-java-db-update", "--cache-dir", "/c", "--image-src", "docker", id}
	if !reflect.DeepEqual(on, wantOn) {
		t.Errorf("args = %q", on)
	}
	noCache := Trivy{SkipDBUpdate: true}.trivyArgs(refTarget("nginx:1.25"))
	wantNC := []string{"image", "--quiet", "--format", "json", "--severity", "HIGH,CRITICAL",
		"--skip-db-update", "--skip-java-db-update", "nginx:1.25"}
	if !reflect.DeepEqual(noCache, wantNC) {
		t.Errorf("args = %q", noCache)
	}
}

func TestScan_FakeBinary_SkipDBUpdateArgsReachTrivy(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args")
	bin := writeFakeTrivy(t, argsFile, `{"ArtifactName":"x","Results":[]}`, false)
	tr := Trivy{BinPath: bin, SkipDBUpdate: true, CacheDir: "/c"}
	got := tr.Scan(context.Background(), refTarget("nginx:1.25"))
	if got.Err != nil {
		t.Fatal(got.Err)
	}
	args := readArgs(t, argsFile)
	if args[len(args)-1] != "nginx:1.25" {
		t.Errorf("the scan target must stay the last argument: %q", args)
	}
	if !strings.Contains(strings.Join(args, " "), "--skip-db-update --skip-java-db-update --cache-dir /c") {
		t.Errorf("args = %q", args)
	}
}

// prepared returns a Trivy over a fresh cache and fake binary, with its
// PrepareDB conditions.
func prepared(t *testing.T, skipDBUpdate bool) (Trivy, ScanConditions, string, string) {
	t.Helper()
	bin, _, versionFile, _ := writeDBFakeTrivy(t)
	copyVersionFixture(t, versionFile)
	cache := t.TempDir()
	writeCache(t, cache)
	tr := Trivy{BinPath: bin, CacheDir: cache, SkipDBUpdate: skipDBUpdate}
	base, err := tr.PrepareDB(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return tr, base, bin, cache
}

func TestVerifyDB_ContentChangeWithSameMetadata(t *testing.T) {
	for name, file := range map[string]string{"vulnerability": "db/trivy.db", "java": "java-db/trivy-java.db"} {
		tr, base, _, cache := prepared(t, true)
		if err := os.WriteFile(filepath.Join(cache, file), []byte("replaced"), 0o644); err != nil {
			t.Fatal(err)
		}
		same, err := tr.VerifyDB(context.Background(), base)
		if err != nil || same {
			t.Errorf("%s db content changed: same=%v err=%v", name, same, err)
		}
		now, err := tr.current(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		// Version and DB metadata are untouched; only the content hash differs.
		now.Severities = base.Severities
		if now.VulnerabilityDB != base.VulnerabilityDB || now.JavaDB != base.JavaDB || now.Equal(base) {
			t.Errorf("%s: metadata must be identical while Equal is false", name)
		}
	}
}

func TestVerifyDB_ExecutableChange(t *testing.T) {
	tr, base, bin, _ := prepared(t, true)
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, append(data, []byte("# patched\n")...), 0o755); err != nil {
		t.Fatal(err)
	}
	if same, err := tr.VerifyDB(context.Background(), base); err != nil || same {
		t.Errorf("same=%v err=%v", same, err)
	}
}

func TestAnalysisSettings_EnvAndIgnoreFile(t *testing.T) {
	t.Run("TRIVY_ env", func(t *testing.T) {
		tr, base, _, _ := prepared(t, false)
		t.Setenv("TRIVY_IGNORE_UNFIXED", "true")
		if same, err := tr.VerifyDB(context.Background(), base); err != nil || same {
			t.Errorf("same=%v err=%v", same, err)
		}
		if strings.Contains(base.AnalysisSettings, "TRIVY_") {
			t.Error("settings must hold hashes, not variable names")
		}
	})
	t.Run("env value never stored", func(t *testing.T) {
		t.Setenv("TRIVY_PASSWORD", "hunter2-secret")
		_, base, _, _ := prepared(t, true)
		if strings.Contains(base.AnalysisSettings, "hunter2") || strings.Contains(base.AnalysisSettings, "PASSWORD") {
			t.Errorf("settings leak the environment: %q", base.AnalysisSettings)
		}
	})
	t.Run("non-TRIVY env ignored", func(t *testing.T) {
		tr, base, _, _ := prepared(t, true)
		t.Setenv("UNRELATED_VARIABLE", "x")
		if same, err := tr.VerifyDB(context.Background(), base); err != nil || !same {
			t.Errorf("same=%v err=%v", same, err)
		}
	})
	t.Run(".trivyignore in the working directory", func(t *testing.T) {
		wd := t.TempDir()
		t.Chdir(wd)
		tr, base, _, _ := prepared(t, false)
		if !strings.Contains(base.AnalysisSettings, ".trivyignore=absent") {
			t.Errorf("settings = %q", base.AnalysisSettings)
		}
		if err := os.WriteFile(filepath.Join(wd, ".trivyignore"), []byte("CVE-2024-0001\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		now, err := tr.current(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		now.Severities = base.Severities
		if now.Equal(base) {
			t.Error("a new .trivyignore must change the conditions")
		}
		if same, err := tr.VerifyDB(context.Background(), base); err != nil || same {
			t.Errorf("same=%v err=%v", same, err)
		}
	})
	t.Run("comparison mode ignores the working directory", func(t *testing.T) {
		wd := t.TempDir()
		t.Chdir(wd)
		tr, base, _, _ := prepared(t, true)
		if err := os.WriteFile(filepath.Join(wd, "trivy.yaml"), []byte("severity: [LOW]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if same, err := tr.VerifyDB(context.Background(), base); err != nil || !same {
			t.Errorf("same=%v err=%v", same, err)
		}
		if !strings.Contains(base.AnalysisSettings, "workdir=isolated") {
			t.Errorf("settings = %q", base.AnalysisSettings)
		}
	})
}

// writePwdTrivy installs a fake trivy that records its working directory.
func writePwdTrivy(t *testing.T, pwdFile string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "trivy")
	script := fmt.Sprintf("#!/bin/sh\npwd > %q\necho '{\"ArtifactName\":\"x\",\"Results\":[]}'\n", pwdFile)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestScan_WorkingDirectory(t *testing.T) {
	wd := t.TempDir()
	t.Chdir(wd)
	resolvedWd, err := filepath.EvalSymlinks(wd)
	if err != nil {
		t.Fatal(err)
	}

	pwdFile := filepath.Join(t.TempDir(), "pwd")
	bin := writePwdTrivy(t, pwdFile)
	if got := (Trivy{BinPath: bin}).Scan(context.Background(), refTarget("x:1")); got.Err != nil {
		t.Fatal(got.Err)
	}
	data, _ := os.ReadFile(pwdFile)
	if got := strings.TrimSpace(string(data)); got != resolvedWd && got != wd {
		t.Errorf("default scan ran in %q, want the process directory %q", got, wd)
	}

	if got := (Trivy{BinPath: bin, SkipDBUpdate: true}).Scan(context.Background(), refTarget("x:1")); got.Err != nil {
		t.Fatal(got.Err)
	}
	data, _ = os.ReadFile(pwdFile)
	iso := strings.TrimSpace(string(data))
	if iso == resolvedWd || iso == wd || !strings.Contains(iso, "kestrelynx-trivy-") {
		t.Errorf("comparison scan ran in %q, want a private directory", iso)
	}
	if _, err := os.Stat(iso); !os.IsNotExist(err) {
		t.Errorf("private directory must be removed after the scan, stat err = %v", err)
	}
}

func TestResolvedCacheDir_TrivyCacheDirEnv(t *testing.T) {
	bin, _, versionFile, _ := writeDBFakeTrivy(t)
	copyVersionFixture(t, versionFile)
	envCache := t.TempDir()
	writeCache(t, envCache)
	xdg := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", xdg)
	writeCache(t, filepath.Join(xdg, "trivy"))
	if err := os.WriteFile(filepath.Join(xdg, "trivy", "db", "trivy.db"), []byte("other-db"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRIVY_CACHE_DIR", envCache)

	tr := Trivy{BinPath: bin, SkipDBUpdate: true}
	base, err := tr.PrepareDB(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if base.VulnerabilityDBSHA != sha256Hex("vuln-db-v1") {
		t.Errorf("hashed %q, want the TRIVY_CACHE_DIR database", base.VulnerabilityDBSHA)
	}
	if same, err := tr.VerifyDB(context.Background(), base); err != nil || !same {
		t.Errorf("same=%v err=%v", same, err)
	}

	// An explicit CacheDir wins over the environment.
	explicit := t.TempDir()
	writeCache(t, explicit)
	if err := os.WriteFile(filepath.Join(explicit, "db", "trivy.db"), []byte("explicit-db"), 0o644); err != nil {
		t.Fatal(err)
	}
	c2, err := (Trivy{BinPath: bin, CacheDir: explicit}).PrepareDB(context.Background())
	if err != nil || c2.VulnerabilityDBSHA != sha256Hex("explicit-db") {
		t.Errorf("explicit: %q, %v", c2.VulnerabilityDBSHA, err)
	}

	// Scans in comparison mode carry the same directory as a flag, because
	// their environment no longer holds TRIVY_CACHE_DIR.
	argsFile := filepath.Join(t.TempDir(), "args")
	scanBin := writeFakeTrivy(t, argsFile, `{"ArtifactName":"x","Results":[]}`, false)
	if got := (Trivy{BinPath: scanBin, SkipDBUpdate: true}).Scan(context.Background(), refTarget("x:1")); got.Err != nil {
		t.Fatal(got.Err)
	}
	if !strings.Contains(strings.Join(readArgs(t, argsFile), " "), "--cache-dir "+envCache) {
		t.Errorf("scan args = %q", readArgs(t, argsFile))
	}
}

func TestScan_ComparisonModeEnvironment(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "other.yaml")
	if err := os.WriteFile(cfgFile, []byte("severity: [LOW]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRIVY_CONFIG", cfgFile)
	t.Setenv("TRIVY_IGNOREFILE", cfgFile)
	t.Setenv("KEEP_ME", "yes")

	envFile := filepath.Join(t.TempDir(), "env")
	bin := filepath.Join(t.TempDir(), "trivy")
	script := fmt.Sprintf("#!/bin/sh\nenv > %q\necho '{\"ArtifactName\":\"x\",\"Results\":[]}'\n", envFile)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cache := t.TempDir()
	if got := (Trivy{BinPath: bin, CacheDir: cache, SkipDBUpdate: true}).Scan(context.Background(), refTarget("x:1")); got.Err != nil {
		t.Fatal(got.Err)
	}
	env, _ := os.ReadFile(envFile)
	if strings.Contains(string(env), "TRIVY_") {
		t.Errorf("comparison-mode trivy saw TRIVY_* variables:\n%s", env)
	}
	if !strings.Contains(string(env), "KEEP_ME=yes") || !strings.Contains(string(env), "PATH=") {
		t.Errorf("other variables must be kept:\n%s", env)
	}

	// Default mode keeps the whole environment.
	if got := (Trivy{BinPath: bin}).Scan(context.Background(), refTarget("x:1")); got.Err != nil {
		t.Fatal(got.Err)
	}
	env, _ = os.ReadFile(envFile)
	if !strings.Contains(string(env), "TRIVY_CONFIG="+cfgFile) {
		t.Errorf("default mode must not change the environment:\n%s", env)
	}
}

func TestAnalysisSettings_ComparisonModeIgnoresUnappliedConfig(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "other.yaml")
	if err := os.WriteFile(cfgFile, []byte("a: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRIVY_CONFIG", cfgFile)
	tr, base, _, _ := prepared(t, true)
	if !strings.Contains(base.AnalysisSettings, "env=sanitized") {
		t.Errorf("settings = %q", base.AnalysisSettings)
	}
	if err := os.WriteFile(cfgFile, []byte("a: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRIVY_CONFIG", cfgFile+".moved")
	if same, err := tr.VerifyDB(context.Background(), base); err != nil || !same {
		t.Errorf("an unapplied config must not matter: same=%v err=%v", same, err)
	}
}

func TestResolved_RelativePaths(t *testing.T) {
	wd := t.TempDir()
	t.Chdir(wd)
	if err := os.MkdirAll("bin", 0o755); err != nil {
		t.Fatal(err)
	}
	fake, _, versionFile, _ := writeDBFakeTrivy(t)
	copyVersionFixture(t, versionFile)
	script, err := os.ReadFile(fake)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("bin/trivy", script, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCache(t, "cache")

	absWd, _ := filepath.EvalSymlinks(wd)
	tr := Trivy{BinPath: "./bin/trivy", CacheDir: "cache", SkipDBUpdate: true}
	rt, err := tr.resolved()
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(rt.BinPath) || !filepath.IsAbs(rt.CacheDir) ||
		(rt.CacheDir != filepath.Join(wd, "cache") && rt.CacheDir != filepath.Join(absWd, "cache")) {
		t.Errorf("resolved = %+v", rt)
	}

	base, err := tr.PrepareDB(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if same, err := tr.VerifyDB(context.Background(), base); err != nil || !same {
		t.Errorf("same=%v err=%v", same, err)
	}

	// Scans run in another directory, yet still find the binary and cache.
	pwdScript := "#!/bin/sh\nfor a in \"$@\"; do echo \"$a\"; done > ARGS\necho '{\"ArtifactName\":\"x\",\"Results\":[]}'\n"
	argsFile := filepath.Join(wd, "args.out")
	pwdScript = strings.Replace(pwdScript, "ARGS", argsFile, 1)
	if err := os.WriteFile("bin/trivy", []byte(pwdScript), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := tr.Scan(context.Background(), refTarget("x:1")); got.Err != nil {
		t.Fatal(got.Err)
	}
	args := readArgs(t, argsFile)
	idx := -1
	for i, a := range args {
		if a == "--cache-dir" {
			idx = i
		}
	}
	if idx < 0 || !filepath.IsAbs(args[idx+1]) {
		t.Errorf("--cache-dir must be absolute, args = %q", args)
	}

	// A bare name is looked up on PATH.
	t.Setenv("PATH", filepath.Join(wd, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	rt, err = (Trivy{CacheDir: "cache"}).resolved()
	if err != nil || rt.BinPath != filepath.Join(wd, "bin", "trivy") && rt.BinPath != filepath.Join(absWd, "bin", "trivy") {
		t.Errorf("PATH lookup: %+v, %v", rt, err)
	}
}
