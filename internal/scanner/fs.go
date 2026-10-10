package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// fsAnalysisBase identifies the scan settings KestreLynx fixes for a
// filesystem scan of dependency files: the vulnerability scanner only, every
// package listed, development dependencies included, and no configuration,
// ignore or VEX input. A change to the arguments that alters what is reported
// must change this value.
const fsAnalysisBase = "fs;scanners=vuln;pkg-types=default;ignore-unfixed=false;list-all-pkgs=true;dev-deps=included;config=none;ignorefile=none;vex=none"

// Limits of a filesystem scan.
const (
	maxFSFiles       = 16
	maxFSFileBytes   = 32 << 20
	maxFSReportBytes = 64 << 20
)

var (
	// ErrConditionsUnknown: the conditions the scan was to be taken under are
	// incomplete, so nothing can be compared with them.
	ErrConditionsUnknown = errors.New("scan conditions are not known")
	// ErrConditionsDiffer: Trivy, its databases or its settings are not those
	// of the prepared conditions.
	ErrConditionsDiffer = errors.New("scan conditions differ from the prepared conditions")
)

// FSScan is the result of scanning a set of dependency files.
type FSScan struct {
	// Conditions are the conditions measured immediately before the scan. Its
	// AnalysisSettings names the filesystem settings; every other field is
	// equal to the prepared conditions the scan was checked against.
	Conditions ScanConditions
	// Report is the parsed report: Findings and Packages are the filesystem
	// scan's. It carries no image identity.
	Report ImageScan
}

// ScanFS scans dependency files that the caller holds in memory (name to
// content) for vulnerabilities, under the databases, severities and Trivy of
// prepared (the conditions of the cycle's image scans). Only the given files
// are put in a private temporary directory and scanned; Trivy runs in another
// empty directory with no TRIVY_* variable, and its configuration file and
// ignore file are pointed at empty files, so nothing from the repository the
// files came from or from the host can change what is reported. Databases are
// never updated. It fails with ErrConditionsUnknown or ErrConditionsDiffer
// when the conditions cannot be shown to be those of prepared.
//
// t must be in comparison mode (SkipDBUpdate).
func (t Trivy) ScanFS(ctx context.Context, files map[string][]byte, prepared ScanConditions) (FSScan, error) {
	if !t.SkipDBUpdate {
		return FSScan{}, errors.New("filesystem scans need the comparison mode (databases fixed)")
	}
	if len(files) == 0 || len(files) > maxFSFiles {
		return FSScan{}, fmt.Errorf("filesystem scan needs 1..%d files, got %d", maxFSFiles, len(files))
	}
	for name, content := range files {
		if name == "" || len(name) > 255 || strings.HasPrefix(name, ".") || strings.ContainsAny(name, "/\\\x00") {
			return FSScan{}, fmt.Errorf("filesystem scan file name %q is not a plain file name", name)
		}
		if len(content) > maxFSFileBytes {
			return FSScan{}, fmt.Errorf("filesystem scan file %q is over %d bytes", name, maxFSFileBytes)
		}
	}
	if !prepared.Known() {
		return FSScan{}, ErrConditionsUnknown
	}
	rt, err := t.resolved()
	if err != nil {
		return FSScan{}, err
	}
	now, err := rt.current(ctx)
	if err != nil {
		return FSScan{}, err
	}
	now.Severities = normalizeSeverities(strings.Split(rt.severity(), ","))
	// The prepared conditions come from image scans in comparison mode; the
	// filesystem settings are the only field allowed to differ from them.
	if prepared.AnalysisSettings != analysisBase+";env=sanitized;workdir=isolated" {
		return FSScan{}, fmt.Errorf("%w: the prepared analysis settings are not those of a comparison-mode scan", ErrConditionsDiffer)
	}
	now.AnalysisSettings = fsAnalysisBase + ";env=sanitized;workdir=isolated"
	want := prepared
	want.AnalysisSettings = now.AnalysisSettings
	if !now.Equal(want) {
		return FSScan{}, ErrConditionsDiffer
	}

	root, err := os.MkdirTemp("", "kestrelynx-trivyfs-")
	if err != nil {
		return FSScan{}, fmt.Errorf("create scan directory: %w", err)
	}
	defer os.RemoveAll(root)
	scanDir := filepath.Join(root, "scan")
	cwd := filepath.Join(root, "cwd")
	for _, d := range []string{scanDir, cwd} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return FSScan{}, fmt.Errorf("create scan directory: %w", err)
		}
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(scanDir, name), content, 0o600); err != nil {
			return FSScan{}, fmt.Errorf("write scan file: %w", err)
		}
	}
	cfgPath := filepath.Join(root, "config.yaml")
	ignorePath := filepath.Join(root, "ignore")
	for _, p := range []string{cfgPath, ignorePath} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			return FSScan{}, fmt.Errorf("write scan settings: %w", err)
		}
	}

	args := []string{
		"fs", "--quiet", "--format", "json",
		"--severity", rt.severity(),
		"--scanners", "vuln",
		"--list-all-pkgs", "--include-dev-deps",
		"--skip-db-update", "--skip-java-db-update", "--skip-vex-repo-update",
		"--skip-version-check", "--disable-telemetry", "--no-progress",
		"--cache-dir", rt.CacheDir,
		"--config", cfgPath, "--ignorefile", ignorePath,
		scanDir,
	}
	cmd := exec.CommandContext(ctx, rt.bin(), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, n: maxFSReportBytes}
	cmd.Stderr = &limitedWriter{w: &stderr, n: 64 << 10}
	cmd.Dir = cwd
	cmd.Env = withoutTrivyEnv(os.Environ())
	if err := cmd.Run(); err != nil {
		return FSScan{}, fmt.Errorf("trivy fs scan: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	report, err := ParseReport(stdout.Bytes())
	if err != nil {
		return FSScan{}, fmt.Errorf("trivy fs scan: %w", err)
	}
	if report.TrivyVersion != now.TrivyVersion {
		return FSScan{}, fmt.Errorf("%w: the report names Trivy %q, not %q", ErrConditionsDiffer, report.TrivyVersion, now.TrivyVersion)
	}
	return FSScan{Conditions: now, Report: report}, nil
}

// CurrentConditions reads the conditions of Trivy, its databases and its
// settings as they are now, with the severities this Trivy scans, without
// downloading or changing anything. In comparison mode (SkipDBUpdate) the
// result equals what PrepareDB returned when the databases have not changed
// since.
func (t Trivy) CurrentConditions(ctx context.Context) (ScanConditions, error) {
	if !t.SkipDBUpdate {
		return ScanConditions{}, errors.New("current conditions are read in the comparison mode (databases fixed)")
	}
	rt, err := t.resolved()
	if err != nil {
		return ScanConditions{}, err
	}
	c, err := rt.current(ctx)
	if err != nil {
		return ScanConditions{}, err
	}
	c.Severities = normalizeSeverities(strings.Split(rt.severity(), ","))
	return c, nil
}
