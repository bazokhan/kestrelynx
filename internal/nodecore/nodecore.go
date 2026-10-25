// Package nodecore checks the Node.js runtime of an image against Node.js's
// own security advisories. Trivy reports the packages a package manager
// installed, but not the node binary the official node images unpack from
// nodejs.org's tarball, so KestreLynx reads NODE_VERSION from the image
// configuration and matches it here.
//
// The advisory datasets are public bulk downloads joined locally, the same
// way as the KEV and EPSS feeds: nothing about the images being scanned is
// sent anywhere.
package nodecore

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// Default dataset URLs. Each is overridable in config for mirrors.
const (
	DefaultSecurityWGURL   = "https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json"
	DefaultBlogFeedURL     = "https://nodejs.org/en/feed/vulnerability.xml"
	DefaultBlogPostBaseURL = "https://raw.githubusercontent.com/nodejs/nodejs.org/main/apps/site/pages/en/blog/vulnerability/"
	DefaultReleasesURL     = "https://nodejs.org/dist/index.json"
	DefaultScheduleURL     = "https://raw.githubusercontent.com/nodejs/Release/main/schedule.json"
)

// defaultBinaryPath is where the official node images keep the node binary
// (container-rooted, without a leading slash like Trivy's paths).
const defaultBinaryPath = "usr/local/bin/node"

// npmManifestSuffix is the tail of the npm package.json path that locates
// the prefix node was unpacked into.
const npmManifestSuffix = "/lib/node_modules/npm/package.json"

var nodeVersionRe = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// Advisor is the scanner.RuntimeAdvisor for Node.js. Its zero value is ready
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
		return scanner.RuntimeAugment{Unchecked: true}
	}
	bin := binaryPath(scan.Packages)

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
			Package:      inventory.NodeRuntimePackage,
			InstalledVer: ver,
			FixedVer:     adv.FixedVer,
			Status:       adv.Status,
			Severity:     scanner.Severity(adv.Severity),
			VulnID:       adv.VulnID,
			URL:          adv.URL,
			Title:        adv.Title,
			Type:         string(inventory.EcosystemNodeRuntime),
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
			Type:   string(inventory.EcosystemNodeRuntime),
			Packages: []scanner.Package{{
				Name:    inventory.NodeRuntimePackage,
				Version: ver,
				PkgPath: bin,
			}},
		}},
	}
}

// detectVersion reads NODE_VERSION from the image's Env (the last
// occurrence wins, as in a container runtime). Only a plain X.Y.Z decimal
// version counts: anything else is not a version this package can match.
func detectVersion(env []string) (string, bool) {
	val := ""
	found := false
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, "NODE_VERSION="); ok {
			val, found = v, true
		}
	}
	if !found || !nodeVersionRe.MatchString(val) {
		return "", false
	}
	if _, ok := parseVersion(val); !ok {
		return "", false
	}
	return val, true
}

// binaryPath locates the node executable: next to the npm Trivy found when
// there is one (the prefix node was unpacked into), else where the official
// images put it.
func binaryPath(pkgs []scanner.ResultPackages) string {
	for _, rp := range pkgs {
		for _, p := range rp.Packages {
			path := strings.TrimPrefix(p.PkgPath, "/")
			if prefix, ok := strings.CutSuffix(path, npmManifestSuffix); ok {
				return prefix + "/bin/node"
			}
			if path == strings.TrimPrefix(npmManifestSuffix, "/") {
				return "bin/node"
			}
		}
	}
	return defaultBinaryPath
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
