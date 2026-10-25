package analyze

import (
	"strconv"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

var fixedTime = time.Date(2026, 6, 24, 9, 0, 0, 0, time.UTC)

// f builds a Finding with the common fields used across tests.
func f(image string, class scanner.PkgClass, pkg, installed, fixed string, status scanner.Status, sev scanner.Severity, vuln string) scanner.Finding {
	return scanner.Finding{
		Image: image, Class: class, Package: pkg,
		InstalledVer: installed, FixedVer: fixed,
		Status: status, Severity: sev, VulnID: vuln,
	}
}

func pkgGroup(t *testing.T, section []ImageFindings, image, pkg string) PackageGroup {
	t.Helper()
	for _, img := range section {
		if img.Image != image {
			continue
		}
		for _, g := range img.Packages {
			if g.Package == pkg {
				return g
			}
		}
	}
	t.Fatalf("package %q not found for image %q", pkg, image)
	return PackageGroup{}
}

func TestBuild_RoutesByStatus(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			f("demo:1.0", scanner.ClassOS, "libc-bin", "2.28-10", "2.28-10+deb10u2", scanner.StatusFixed, scanner.SeverityCritical, "CVE-1"),
			f("demo:1.0", scanner.ClassOS, "e2fsprogs", "1.44", "", scanner.StatusAffected, scanner.SeverityHigh, "CVE-2"),
			f("demo:1.0", scanner.ClassOS, "gcc-8-base", "8.3", "", scanner.StatusWontFix, scanner.SeverityHigh, "CVE-3"),
		},
	}}
	r := Build(scans, nil, Triage{}, fixedTime)

	if len(r.Actionable) != 1 || len(r.Watch) != 1 || len(r.WontFix) != 1 {
		t.Fatalf("section sizes: actionable=%d watch=%d wontfix=%d", len(r.Actionable), len(r.Watch), len(r.WontFix))
	}
	if !r.GeneratedAt.Equal(fixedTime) {
		t.Errorf("GeneratedAt = %v", r.GeneratedAt)
	}
}

func TestBuild_GroupsByPackageAndCounts(t *testing.T) {
	// libc-bin has 4 CRITICAL CVEs sharing one fix → one group, Critical=4.
	var finds []scanner.Finding
	for _, id := range []string{"CVE-A", "CVE-B", "CVE-C", "CVE-D"} {
		finds = append(finds, f("demo:1.0", scanner.ClassOS, "libc-bin", "2.28-10", "2.28-10+deb10u2", scanner.StatusFixed, scanner.SeverityCritical, id))
	}
	finds = append(finds, f("demo:1.0", scanner.ClassOS, "libc-bin", "2.28-10", "2.28-10+deb10u2", scanner.StatusFixed, scanner.SeverityHigh, "CVE-E"))

	r := Build([]scanner.ImageScan{{Image: "demo:1.0", Findings: finds}}, nil, Triage{}, fixedTime)
	g := pkgGroup(t, r.Actionable, "demo:1.0", "libc-bin")

	if g.Critical != 4 || g.High != 1 {
		t.Errorf("counts: critical=%d high=%d, want 4/1", g.Critical, g.High)
	}
	if g.Total() != 5 {
		t.Errorf("Total = %d, want 5", g.Total())
	}
	ids := g.VulnIDs()
	if len(ids) != 5 {
		t.Errorf("VulnIDs = %v, want 5 unique", ids)
	}
	// deterministic ordering
	if ids[0] != "CVE-A" {
		t.Errorf("VulnIDs not sorted: %v", ids)
	}
}

func TestBuild_RiskLabels(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			// OS fixed → distro update (semver not applied)
			f("demo:1.0", scanner.ClassOS, "libc-bin", "2.28-10", "2.28-10+deb10u2", scanner.StatusFixed, scanner.SeverityCritical, "CVE-OS"),
			// lang minor bump → safe
			f("demo:1.0", scanner.ClassLang, "pip", "21.0.1", "21.1", scanner.StatusFixed, scanner.SeverityHigh, "CVE-PIP"),
			// lang major bump → caution
			f("demo:1.0", scanner.ClassLang, "setuptools", "53.0.0", "78.1.1", scanner.StatusFixed, scanner.SeverityHigh, "CVE-ST"),
			// lang unparseable → unknown
			f("demo:1.0", scanner.ClassLang, "weird", "abc", "xyz", scanner.StatusFixed, scanner.SeverityHigh, "CVE-W"),
		},
	}}
	r := Build(scans, nil, Triage{}, fixedTime)

	cases := map[string]Risk{
		"libc-bin":   RiskDistroUpdate,
		"pip":        RiskSafe,
		"setuptools": RiskCaution,
		"weird":      RiskUnknown,
	}
	for pkg, want := range cases {
		if got := pkgGroup(t, r.Actionable, "demo:1.0", pkg).Risk; got != want {
			t.Errorf("%s Risk = %q, want %q", pkg, got, want)
		}
	}
}

func TestBuild_NonFixedHasNoRisk(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			f("demo:1.0", scanner.ClassOS, "e2fsprogs", "1.44", "", scanner.StatusAffected, scanner.SeverityHigh, "CVE-2"),
		},
	}}
	r := Build(scans, nil, Triage{}, fixedTime)
	if got := pkgGroup(t, r.Watch, "demo:1.0", "e2fsprogs").Risk; got != RiskNone {
		t.Errorf("affected Risk = %q, want empty", got)
	}
}

func TestBuild_EOSLAndErrors(t *testing.T) {
	scans := []scanner.ImageScan{
		{Image: "old:1", OSEOSL: true, Findings: nil},
		{Image: "broken:1", Err: errString("pull failed")},
	}
	r := Build(scans, nil, Triage{}, fixedTime)

	if len(r.EOSLImages) != 1 || r.EOSLImages[0] != "old:1" {
		t.Errorf("EOSLImages = %v", r.EOSLImages)
	}
	if len(r.ScanErrors) != 1 || r.ScanErrors[0].Image != "broken:1" {
		t.Errorf("ScanErrors = %+v", r.ScanErrors)
	}
	if !r.HasFindings() {
		t.Errorf("HasFindings = false, but an EOSL image should count")
	}
	if !r.HasIssues() {
		t.Errorf("HasIssues = false, want true (EOSL present)")
	}
}

func TestBuild_SortsCriticalFirst(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			f("demo:1.0", scanner.ClassOS, "aaa-high", "1", "2", scanner.StatusFixed, scanner.SeverityHigh, "CVE-H"),
			f("demo:1.0", scanner.ClassOS, "zzz-crit", "1", "2", scanner.StatusFixed, scanner.SeverityCritical, "CVE-C"),
		},
	}}
	r := Build(scans, nil, Triage{}, fixedTime)
	pkgs := r.Actionable[0].Packages
	// zzz-crit (CRITICAL) must sort before aaa-high despite alphabetical order.
	if pkgs[0].Package != "zzz-crit" {
		t.Errorf("first package = %q, want zzz-crit (critical first)", pkgs[0].Package)
	}
}

func TestBuild_VulnRefCarriesTitle(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			{Image: "demo:1.0", Class: scanner.ClassOS, Package: "libc-bin", InstalledVer: "2.28-10", FixedVer: "2.28-10+deb10u2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-T", Title: "glibc: example title"},
		},
	}}
	r := Build(scans, nil, Triage{}, fixedTime)
	g := pkgGroup(t, r.Actionable, "demo:1.0", "libc-bin")
	if got := g.TopVuln().Title; got != "glibc: example title" {
		t.Errorf("TopVuln().Title = %q, want %q", got, "glibc: example title")
	}
}

// The same CVE ID can appear on more than one Trivy result line (e.g. an OS
// package matched by more than one data source); a title-less line must not
// blank out a title already captured for that ID, regardless of arrival order.
func TestBuild_DuplicateVulnIDPrefersNonEmptyTitle(t *testing.T) {
	titledFirst := []scanner.Finding{
		{Image: "demo:1.0", Class: scanner.ClassOS, Package: "libc-bin", InstalledVer: "2.28-10", FixedVer: "2.28-10+deb10u2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-T", Title: "glibc: example title"},
		{Image: "demo:1.0", Class: scanner.ClassOS, Package: "libc-bin", InstalledVer: "2.28-10", FixedVer: "2.28-10+deb10u2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-T", Title: ""},
	}
	titledSecond := []scanner.Finding{
		{Image: "demo:1.0", Class: scanner.ClassOS, Package: "libc-bin", InstalledVer: "2.28-10", FixedVer: "2.28-10+deb10u2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-T", Title: ""},
		{Image: "demo:1.0", Class: scanner.ClassOS, Package: "libc-bin", InstalledVer: "2.28-10", FixedVer: "2.28-10+deb10u2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-T", Title: "glibc: example title"},
	}
	for name, finds := range map[string][]scanner.Finding{"titled_first": titledFirst, "titled_second": titledSecond} {
		t.Run(name, func(t *testing.T) {
			r := Build([]scanner.ImageScan{{Image: "demo:1.0", Findings: finds}}, nil, Triage{}, fixedTime)
			g := pkgGroup(t, r.Actionable, "demo:1.0", "libc-bin")
			if got := g.TopVuln().Title; got != "glibc: example title" {
				t.Errorf("TopVuln().Title = %q, want the non-empty title regardless of arrival order", got)
			}
		})
	}
}

// --- Phase 2 identity model: inventory and (Ref, ContentID) aggregation ---

const (
	contentA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	contentB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// mustConfigKey parses s as a config digest EntityKey or panics — only ever
// used to build well-formed test fixtures, never production data.
func mustConfigKey(s string) inventory.EntityKey {
	d, ok := inventory.ParseDigest(inventory.DigestConfig, s)
	if !ok {
		panic("test fixture: invalid digest " + s)
	}
	return inventory.EntityKey{Digest: d}
}

// failedResolvedScan builds a scan whose Subject resolved to contentID (the
// caller had a Docker-observed identity to pin to) but whose Trivy scan
// itself failed — Subject.Resolved survives the failure unchanged, while
// Pinned stays false (Err != nil fails the pin check regardless).
func failedResolvedScan(ref, contentID string, err error) scanner.ImageScan {
	return scanner.ImageScan{
		Image:   ref,
		Subject: inventory.ImageSubject{Ref: ref, Key: mustConfigKey(contentID), Resolved: true},
		Err:     err,
	}
}

// resolvedScan builds a Pinned ImageScan confirmed against contentID, the
// shape runner.scanAll produces for a running entity whose EntityKey
// resolved and was confirmed.
func resolvedScan(ref, contentID string, digests []string, finds ...scanner.Finding) scanner.ImageScan {
	key := mustConfigKey(contentID)
	return scanner.ImageScan{
		Image:           ref,
		Subject:         inventory.ImageSubject{Ref: ref, Key: key, Resolved: true},
		ScannedKey:      key,
		Pinned:          true,
		Source:          scanner.SourceLocal,
		RegistryDigests: digests,
		Findings:        finds,
	}
}

// configDigest parses s (expected to be a well-formed sha256 fixture like
// contentA/contentB) into the inventory.Digest an inventory.RunningImage
// carries as Config.
func configDigest(t *testing.T, s string) inventory.Digest {
	t.Helper()
	d, ok := inventory.ParseDigest(inventory.DigestConfig, s)
	if !ok {
		t.Fatalf("test fixture: invalid digest %q", s)
	}
	return d
}

func imgObs(t *testing.T, images []ImageObservation, ref string) ImageObservation {
	t.Helper()
	for _, o := range images {
		if o.Ref == ref {
			return o
		}
	}
	t.Fatalf("no ImageObservation for ref %q in %+v", ref, images)
	return ImageObservation{}
}

func TestBuild_InventorySingleResolvedEntity(t *testing.T) {
	r := Build([]scanner.ImageScan{
		resolvedScan("web:1", contentA, []string{"web@sha256:reg1"}),
	}, nil, Triage{}, fixedTime)

	o := imgObs(t, r.Images, "web:1")
	if len(o.ContentIDs) != 1 || o.ContentIDs[0] != contentA {
		t.Errorf("ContentIDs = %v, want [%s]", o.ContentIDs, contentA)
	}
	if !o.IdentityResolved || o.Ambiguous || o.ScanFailed || o.PartialFailure {
		t.Errorf("flags = %+v, want resolved/non-ambiguous/non-failed", o)
	}
	if len(o.RegistryDigests) != 1 || o.RegistryDigests[0] != "web@sha256:reg1" {
		t.Errorf("RegistryDigests = %v", o.RegistryDigests)
	}
}

func TestBuild_InventoryUnresolvedReferenceExcludesFallbackAttributes(t *testing.T) {
	// A reference-fallback scan can still carry a ScannedContentID/RepoDigests
	// (whatever Trivy happened to resolve), but these are never attributes of
	// a specific running entity and must not enter the inventory's verified
	// sets.
	r := Build([]scanner.ImageScan{{
		Image: "web:1", ScannedKey: mustConfigKey(contentA),
		RegistryDigests: []string{"web@sha256:whatever"},
	}}, nil, Triage{}, fixedTime)

	o := imgObs(t, r.Images, "web:1")
	if len(o.ContentIDs) != 0 {
		t.Errorf("ContentIDs = %v, want empty for unresolved reference", o.ContentIDs)
	}
	if len(o.RegistryDigests) != 0 {
		t.Errorf("RegistryDigests = %v, want empty (fallback attributes excluded)", o.RegistryDigests)
	}
	if o.IdentityResolved {
		t.Error("IdentityResolved should be false")
	}
}

func TestBuild_InventoryAmbiguousReference(t *testing.T) {
	r := Build([]scanner.ImageScan{
		resolvedScan("web:1", contentA, []string{"web@sha256:reg1"}),
		resolvedScan("web:1", contentB, []string{"web@sha256:reg2"}),
	}, nil, Triage{}, fixedTime)

	o := imgObs(t, r.Images, "web:1")
	if !o.Ambiguous {
		t.Error("Ambiguous should be true for two distinct verified ContentIDs under one ref")
	}
	if len(o.ContentIDs) != 2 || o.ContentIDs[0] != contentA || o.ContentIDs[1] != contentB {
		t.Errorf("ContentIDs = %v, want sorted [%s %s]", o.ContentIDs, contentA, contentB)
	}
	if len(o.RegistryDigests) != 2 {
		t.Errorf("RegistryDigests = %v, want union of both entities", o.RegistryDigests)
	}
	if !o.IdentityResolved {
		t.Error("IdentityResolved should be true when every entity resolved")
	}
}

func TestBuild_InventoryFullFailure(t *testing.T) {
	r := Build([]scanner.ImageScan{
		{Image: "web:1", Err: errString("pull failed")},
	}, nil, Triage{}, fixedTime)

	o := imgObs(t, r.Images, "web:1")
	if !o.ScanFailed || o.PartialFailure {
		t.Errorf("flags = %+v, want ScanFailed only", o)
	}
}

func TestBuild_InventoryPartialFailure(t *testing.T) {
	r := Build([]scanner.ImageScan{
		resolvedScan("web:1", contentA, nil),
		failedResolvedScan("web:1", contentB, errString("pull failed")),
	}, nil, Triage{}, fixedTime)

	o := imgObs(t, r.Images, "web:1")
	if !o.PartialFailure || o.ScanFailed {
		t.Errorf("flags = %+v, want PartialFailure only (one of two entities failed)", o)
	}
	// ContentIDs is caller-observed, not Trivy-scan-observed: the failed
	// entity's Subject survives the scan failure (scanner/exec.go), so it
	// still belongs in the set even though Trivy never actually scanned it.
	if len(o.ContentIDs) != 2 || o.ContentIDs[0] != contentA || o.ContentIDs[1] != contentB {
		t.Errorf("ContentIDs = %v, want both Docker-observed entities [%s %s]", o.ContentIDs, contentA, contentB)
	}
	if !o.Ambiguous {
		t.Error("Ambiguous should be true: two distinct verified ContentIDs are running, regardless of scan outcome")
	}
	if !o.IdentityResolved {
		t.Error("IdentityResolved should be true: every entity had a Docker-observed ContentID, independent of scan success")
	}
	if len(o.RegistryDigests) != 0 {
		t.Errorf("RegistryDigests = %v, want empty: the failed entity never produced Trivy Metadata", o.RegistryDigests)
	}
}

// TestBuild_InventoryFailedResolvedEntityStillContributesIdentity is the
// single-entity case of the same principle: a Trivy scan failure must not
// demote a caller-observed, boundary-validated ContentID to "unresolved" —
// those are independent facts (scanner/exec.go).
func TestBuild_InventoryFailedResolvedEntityStillContributesIdentity(t *testing.T) {
	r := Build([]scanner.ImageScan{
		failedResolvedScan("web:1", contentA, errString("pull failed")),
	}, nil, Triage{}, fixedTime)

	o := imgObs(t, r.Images, "web:1")
	if !o.ScanFailed {
		t.Error("ScanFailed should be true: the only entity's scan failed")
	}
	if !o.IdentityResolved {
		t.Error("IdentityResolved should be true: Docker still resolved the ContentID even though the scan failed")
	}
	if len(o.ContentIDs) != 1 || o.ContentIDs[0] != contentA {
		t.Errorf("ContentIDs = %v, want [%s] even though the scan failed", o.ContentIDs, contentA)
	}
}

// TestBuild_InventoryMixedResolvedAndUnresolvedEntities covers the case
// state.Compute relies on to blank Entry.ContentID: one entity resolves a
// ContentID and scans fine, a sibling under the same reference never had one
// (reference-fallback). The reference is not Ambiguous (only one verified
// ContentID exists) but is not fully IdentityResolved either.
func TestBuild_InventoryMixedResolvedAndUnresolvedEntities(t *testing.T) {
	r := Build([]scanner.ImageScan{
		resolvedScan("web:1", contentA, nil),
		{Image: "web:1"}, // reference-fallback: no ExpectedContentID
	}, nil, Triage{}, fixedTime)

	o := imgObs(t, r.Images, "web:1")
	if o.Ambiguous {
		t.Error("Ambiguous should be false: only one verified ContentID exists")
	}
	if o.IdentityResolved {
		t.Error("IdentityResolved should be false: one entity never resolved a ContentID")
	}
	if len(o.ContentIDs) != 1 || o.ContentIDs[0] != contentA {
		t.Errorf("ContentIDs = %v, want the one verified entity [%s]", o.ContentIDs, contentA)
	}
}

func TestBuild_AmbiguousRefSplitsIntoSeparateSections(t *testing.T) {
	r := Build([]scanner.ImageScan{
		resolvedScan("web:1", contentA, nil, f("web:1", scanner.ClassLang, "pip", "1.0.0", "1.0.1", scanner.StatusFixed, scanner.SeverityHigh, "CVE-A")),
		resolvedScan("web:1", contentB, nil, f("web:1", scanner.ClassLang, "pip", "1.0.0", "1.0.1", scanner.StatusFixed, scanner.SeverityHigh, "CVE-B")),
	}, nil, Triage{}, fixedTime)

	if len(r.Actionable) != 2 {
		t.Fatalf("Actionable = %+v, want 2 separate entries (one per ContentID)", r.Actionable)
	}
	seen := map[string]bool{}
	for _, img := range r.Actionable {
		if img.Image != "web:1" {
			t.Errorf("unexpected Image %q", img.Image)
		}
		seen[img.ContentID()] = true
		if len(img.Packages) != 1 || img.Packages[0].VulnIDs()[0] == "" {
			t.Errorf("packages = %+v", img.Packages)
		}
	}
	if !seen[contentA] || !seen[contentB] {
		t.Errorf("ContentIDs seen = %v, want both %s and %s", seen, contentA, contentB)
	}
}

func TestBuild_SingleEntityContentIDIsEmpty(t *testing.T) {
	// The ordinary (non-ambiguous, no ContentID) case must render exactly as
	// before: ContentID empty, one ImageFindings entry.
	scans := []scanner.ImageScan{{
		Image:    "demo:1.0",
		Findings: []scanner.Finding{f("demo:1.0", scanner.ClassOS, "libc-bin", "1", "2", scanner.StatusFixed, scanner.SeverityCritical, "CVE-1")},
	}}
	r := Build(scans, nil, Triage{}, fixedTime)
	if len(r.Actionable) != 1 || r.Actionable[0].ContentID() != "" {
		t.Errorf("Actionable = %+v, want single entry with empty ContentID", r.Actionable)
	}
}

func TestBuild_FromRealSample(t *testing.T) {
	data, err := readSample()
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	scan, err := scanner.ParseReport(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	r := Build([]scanner.ImageScan{scan}, nil, Triage{}, fixedTime)
	if !r.HasIssues() {
		t.Fatal("expected issues from sample")
	}
	if len(r.EOSLImages) != 1 {
		t.Errorf("EOSLImages = %v", r.EOSLImages)
	}
	// setuptools major bump should be flagged caution.
	g := pkgGroup(t, r.Actionable, "demo:1.0", "setuptools")
	if g.Risk != RiskCaution {
		t.Errorf("setuptools Risk = %q, want caution", g.Risk)
	}
}

func TestBuild_CountsEverySeverityExactly(t *testing.T) {
	fixed := func(sev scanner.Severity, id string) scanner.Finding {
		return f("demo:1.0", scanner.ClassOS, "pkg", "1.0", "1.1", scanner.StatusFixed, sev, id)
	}
	r := Build([]scanner.ImageScan{{Image: "demo:1.0", Findings: []scanner.Finding{
		fixed(scanner.SeverityCritical, "C1"),
		fixed(scanner.SeverityHigh, "H1"),
		fixed(scanner.SeverityMedium, "M1"), fixed(scanner.SeverityMedium, "M2"),
		fixed(scanner.SeverityLow, "L1"),
		fixed("UNKNOWN", "U1"),
		fixed("", "U2"),
	}}}, nil, Triage{}, fixedTime)
	g := pkgGroup(t, r.Actionable, "demo:1.0", "pkg")
	want := SeverityCounts{Critical: 1, High: 1, Medium: 2, Low: 1, Unknown: 2}
	if g.Counts() != want {
		t.Errorf("counts = %+v, want %+v", g.Counts(), want)
	}
	if g.Total() != 7 || r.Actionable[0].TotalCount() != 7 || r.Actionable[0].Counts() != want {
		t.Errorf("totals: group %d image %d counts %+v", g.Total(), r.Actionable[0].TotalCount(), r.Actionable[0].Counts())
	}
}

// A MEDIUM-only package must rank below a HIGH-bearing one even when it has
// more CVEs; the same holds for images.
func TestBuild_MediumDoesNotRankAsHigh(t *testing.T) {
	var fs []scanner.Finding
	for _, id := range []string{"M1", "M2", "M3"} {
		fs = append(fs, f("demo:1.0", scanner.ClassOS, "aaa-medium", "1.0", "1.1", scanner.StatusFixed, scanner.SeverityMedium, id))
	}
	fs = append(fs, f("demo:1.0", scanner.ClassOS, "zzz-high", "1.0", "1.1", scanner.StatusFixed, scanner.SeverityHigh, "H1"))
	r := Build([]scanner.ImageScan{{Image: "demo:1.0", Findings: fs}}, nil, Triage{}, fixedTime)
	pk := r.Actionable[0].Packages
	if pk[0].Package != "zzz-high" || pk[1].Package != "aaa-medium" {
		t.Errorf("order = %s, %s; the HIGH package must come first", pk[0].Package, pk[1].Package)
	}

	img := func(name string, sev scanner.Severity, n int) scanner.ImageScan {
		var out []scanner.Finding
		for i := 0; i < n; i++ {
			out = append(out, f(name, scanner.ClassOS, "p", "1.0", "1.1", scanner.StatusFixed, sev, name+strconv.Itoa(i)))
		}
		return scanner.ImageScan{Image: name, Findings: out}
	}
	r2 := Build([]scanner.ImageScan{img("a-medium:1", scanner.SeverityMedium, 3), img("b-high:1", scanner.SeverityHigh, 1)}, nil, Triage{}, fixedTime)
	if r2.Actionable[0].Image != "b-high:1" {
		t.Errorf("image order = %s first; the HIGH image must come first", r2.Actionable[0].Image)
	}
}

func TestBuild_RuntimeUnchecked(t *testing.T) {
	scans := []scanner.ImageScan{
		{Image: "b:1", RuntimeUnchecked: true},
		{Image: "a:1", RuntimeUnchecked: true},
		{Image: "a:1", RuntimeUnchecked: true}, // second entity of the same ref
		{Image: "c:1"},
		{Image: "d:1", RuntimeUnchecked: true, Err: errString("scan failed")},
	}
	r := Build(scans, nil, Triage{}, fixedTime)
	if got := r.RuntimeUnchecked; len(got) != 2 || got[0] != "a:1" || got[1] != "b:1" {
		t.Errorf("RuntimeUnchecked = %v, want [a:1 b:1]", got)
	}
	if r := Build([]scanner.ImageScan{{Image: "c:1"}}, nil, Triage{}, fixedTime); r.RuntimeUnchecked != nil {
		t.Errorf("RuntimeUnchecked = %v, want nil", r.RuntimeUnchecked)
	}
}
