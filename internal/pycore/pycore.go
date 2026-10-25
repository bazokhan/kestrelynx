// Package pycore checks the CPython runtime of an image against the Python
// Software Foundation's security advisories. Trivy reports the packages pip
// installed, but not the CPython the official python images build into
// /usr/local, so KestreLynx reads PYTHON_VERSION from the image configuration
// and matches it here.
//
// The advisory datasets are public bulk downloads joined locally, the same
// way as the KEV and EPSS feeds: nothing about the images being scanned is
// sent anywhere.
package pycore

import (
	"context"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// Default dataset URLs. Each is overridable in config for mirrors.
const (
	DefaultAdvisoryDBURL    = "https://codeload.github.com/psf/advisory-database/tar.gz/refs/heads/main"
	DefaultCVERecordBaseURL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/"
	DefaultReleasesURL      = "https://www.python.org/api/v2/downloads/release/?is_published=true"
	DefaultReleaseCycleURL  = "https://peps.python.org/api/release-cycle.json"
)

// binaryPrefix is where the official python images keep the interpreter
// (container-rooted, without a leading slash like Trivy's paths); python3
// there is a symlink to python3.Y, and the Sensor records the resolved path.
const binaryPrefix = "usr/local/bin/python3."

var pythonVersionRe = regexp.MustCompile(`^3\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// Advisor is the scanner.RuntimeAdvisor for CPython. Its zero value is ready
// to use and has no snapshot, so every detected runtime is unchecked. It is
// safe for concurrent use.
type Advisor struct {
	snap atomic.Pointer[Snapshot]
}

// Set fixes the snapshot every following Augment uses; nil means the
// advisories are unavailable.
func (a *Advisor) Set(s *Snapshot) { a.snap.Store(s) }

// Augment implements scanner.RuntimeAdvisor.
func (a *Advisor) Augment(scan scanner.ImageScan, severities []string) scanner.RuntimeAugment {
	ver, ok := detectVersion(scan.ConfigEnv)
	if !ok {
		return scanner.RuntimeAugment{}
	}
	snap := a.snap.Load()
	if snap == nil {
		return scanner.RuntimeAugment{Unchecked: []string{inventory.PythonRuntimePackage}}
	}
	bin := binaryPrefix + strconv.Itoa(ver.minor)

	want := make(map[string]bool, len(severities))
	for _, s := range severities {
		want[strings.ToUpper(strings.TrimSpace(s))] = true
	}

	var findings []scanner.Finding
	var highest version
	haveFixed := false
	for _, adv := range snap.Match(ver, scan.Platform.OS) {
		if !want[adv.Severity] {
			continue
		}
		f := scanner.Finding{
			Image:        scan.Image,
			Class:        scanner.ClassLang,
			Package:      inventory.PythonRuntimePackage,
			InstalledVer: ver.String(),
			FixedVer:     adv.FixedVer,
			Status:       adv.Status,
			Severity:     scanner.Severity(adv.Severity),
			VulnID:       adv.VulnID,
			URL:          adv.URL,
			Title:        adv.Title,
			Type:         string(inventory.EcosystemPythonRuntime),
			Target:       bin,
			PkgPath:      bin,
		}
		if adv.Status == scanner.StatusFixed {
			if fv, ok := parseVersion(adv.FixedVer); ok && (!haveFixed || fv.compare(highest) > 0) {
				highest, haveFixed = fv, true
			}
		}
		findings = append(findings, f)
	}
	// The group's fixed version is the first finding's, so every fixed
	// finding carries the version that fixes them all.
	if haveFixed {
		for i := range findings {
			if findings[i].Status == scanner.StatusFixed {
				findings[i].FixedVer = highest.String()
			}
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].VulnID < findings[j].VulnID })

	return scanner.RuntimeAugment{
		Findings: findings,
		Packages: []scanner.ResultPackages{{
			Target: bin,
			Class:  scanner.ClassLang,
			Type:   string(inventory.EcosystemPythonRuntime),
			Packages: []scanner.Package{{
				Name:    inventory.PythonRuntimePackage,
				Version: ver.String(),
				PkgPath: bin,
			}},
		}},
	}
}

// detectVersion reads the version variable from the image's Env (the last
// occurrence wins, as in a container runtime). Only a plain 3.Y.Z decimal
// version counts: a pre-release such as 3.15.0rc3 is not a version this
// package can match.
func detectVersion(env []string) (version, bool) {
	versionEnv := inventory.RuntimeVersionEnv(inventory.EcosystemPythonRuntime)
	val := ""
	found := false
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, versionEnv+"="); ok {
			val, found = v, true
		}
	}
	if !found || !pythonVersionRe.MatchString(val) {
		return version{}, false
	}
	return parseVersion(val)
}

// Refresher loads a Source into an Advisor once per cycle.
type Refresher struct {
	Source  *Source
	Advisor *Advisor
}

// Refresh loads the datasets and fixes them in the Advisor for the cycle's
// scans. On failure the Advisor is left with no snapshot and the error is
// returned for logging.
func (r Refresher) Refresh(ctx context.Context) error {
	snap, err := r.Source.Load(ctx)
	r.Advisor.Set(snap)
	return err
}
