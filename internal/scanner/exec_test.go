package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// pinnedTarget builds a ScanTarget pinned to a config digest, the shape
// runner.scanAll produces for a Docker-observed running entity.
func pinnedTarget(t *testing.T, ref, contentID string) ScanTarget {
	t.Helper()
	return ScanTarget{
		Subject: inventory.ImageSubject{
			Ref:      ref,
			Key:      inventory.EntityKey{Digest: mustParseDigest(t, contentID)},
			Resolved: true,
		},
		Source: SourceLocal,
	}
}

// refTarget builds an unresolved (reference-fallback) ScanTarget.
func refTarget(ref string) ScanTarget {
	return ScanTarget{Subject: inventory.ImageSubject{Ref: ref}, Source: SourceLocal}
}

// registryTarget builds a ScanTarget pinned to a registry digest with a
// known platform, the shape a Kubernetes-observed running entity produces.
func registryTarget(t *testing.T, ref, repository, digest, os, arch string) ScanTarget {
	t.Helper()
	d := mustParseRegistryDigest(t, digest)
	platform := inventory.Platform{OS: os, Architecture: arch}
	return ScanTarget{
		Subject: inventory.ImageSubject{
			Ref:      ref,
			Key:      inventory.EntityKey{Digest: d, Platform: platform},
			Resolved: true,
		},
		Registry: inventory.RegistryRef{Repository: repository, Digest: d},
		Source:   SourceRemote,
	}
}

// TestScan_Integration runs the real trivy binary against a tiny image.
// Skipped in -short mode or when trivy is not installed, so unit runs stay fast
// and hermetic. Requires network on first run (image pull + vuln DB).
func TestScan_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("trivy not on PATH; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	scan := New().Scan(ctx, refTarget("alpine:3.12"))
	if scan.Err != nil {
		t.Fatalf("Scan: %v", scan.Err)
	}
	if scan.Image != "alpine:3.12" {
		t.Errorf("Image = %q, want alpine:3.12", scan.Image)
	}
	if scan.OSFamily != "alpine" {
		t.Errorf("OSFamily = %q, want alpine", scan.OSFamily)
	}
	// Every returned finding must be well-formed.
	for _, f := range scan.Findings {
		if f.VulnID == "" || f.Package == "" {
			t.Errorf("malformed finding: %+v", f)
		}
	}
	t.Logf("alpine:3.12 -> %d findings (eosl=%v)", len(scan.Findings), scan.OSEOSL)
}

func TestScan_BadImage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("trivy not on PATH; skipping")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	scan := New().Scan(ctx, refTarget("kestrelynx.invalid/does-not-exist:0"))
	if scan.Err == nil {
		t.Fatal("expected Err for unresolvable image, got nil")
	}
	if scan.Image != "kestrelynx.invalid/does-not-exist:0" {
		t.Errorf("Image = %q, want the requested ref even on failure", scan.Image)
	}
}

// --- trivyArgs ---

func TestTrivyArgs_ContentIDPinned(t *testing.T) {
	id := "sha256:" + strings.Repeat("a", 64)
	got := New().trivyArgs(pinnedTarget(t, "nginx:1.25", id))
	want := []string{"image", "--quiet", "--format", "json", "--severity", "HIGH,CRITICAL", "--image-src", "docker", id}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("args = %v, want %v", got, want)
	}
}

func TestTrivyArgs_RefFallbackUnchanged(t *testing.T) {
	got := New().trivyArgs(refTarget("nginx:1.25"))
	want := []string{"image", "--quiet", "--format", "json", "--severity", "HIGH,CRITICAL", "nginx:1.25"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("args = %v, want %v (Ref fallback must not change existing behavior)", got, want)
	}
}

// DockerHost points scans that may read the local image store at the
// configured socket; a registry-pinned scan reads no local store.
func TestTrivyArgs_DockerHost(t *testing.T) {
	tr := New()
	tr.DockerHost = "/run/user/1000/docker.sock"
	id := "sha256:" + strings.Repeat("a", 64)
	host := []string{"--docker-host", "unix:///run/user/1000/docker.sock"}
	base := []string{"image", "--quiet", "--format", "json", "--severity", "HIGH,CRITICAL"}

	got := tr.trivyArgs(pinnedTarget(t, "nginx:1.25", id))
	want := append(append(append([]string{}, base...), host...), "--image-src", "docker", id)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("pinned args = %v, want %v", got, want)
	}

	got = tr.trivyArgs(refTarget("nginx:1.25"))
	want = append(append(append([]string{}, base...), host...), "nginx:1.25")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ref args = %v, want %v", got, want)
	}

	digest := "sha256:" + strings.Repeat("f", 64)
	got = tr.trivyArgs(registryTarget(t, "nginx:1.25", "docker.io/library/nginx", digest, "linux", "amd64"))
	for _, a := range got {
		if a == "--docker-host" {
			t.Errorf("registry-pinned args = %v, want no --docker-host", got)
		}
	}
}

func TestTrivyArgs_RegistryPinned(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	target := registryTarget(t, "nginx:1.25", "docker.io/library/nginx", digest, "linux", "amd64")

	got := New().trivyArgs(target)
	want := []string{
		"image", "--quiet", "--format", "json", "--severity", "HIGH,CRITICAL",
		"--image-src", "remote", "--platform", "linux/amd64",
		"docker.io/library/nginx@" + digest,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("args = %v, want %v", got, want)
	}
}

// A registry-digest-resolved target whose Platform is unknown must never
// occur via inventory.EntityKeyOf, but trivyArgs must fall back to the
// reference form defensively rather than emit a bogus --platform argument.
func TestTrivyArgs_RegistryPlatformUnknownFallsBack(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	d := mustParseRegistryDigest(t, digest)
	target := ScanTarget{
		Subject:  inventory.ImageSubject{Ref: "nginx:1.25", Key: inventory.EntityKey{Digest: d}, Resolved: true},
		Registry: inventory.RegistryRef{Repository: "docker.io/library/nginx", Digest: d},
		Source:   SourceRemote,
	}

	got := New().trivyArgs(target)
	want := []string{"image", "--quiet", "--format", "json", "--severity", "HIGH,CRITICAL", "nginx:1.25"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("args = %v, want %v (unknown platform must fall back to the reference)", got, want)
	}
}

// --- reconcileTarget: Expected/Scanned identity check ---

func TestReconcileTarget_ContentIDMismatchIsErr(t *testing.T) {
	expected := "sha256:" + strings.Repeat("a", 64)
	scanned := "sha256:" + strings.Repeat("b", 64)
	scan := ImageScan{Image: "ignored-artifact-name", ScannedKey: inventory.EntityKey{Digest: mustParseDigest(t, scanned)}}
	target := pinnedTarget(t, "nginx:1.25", expected)

	got := reconcileTarget(scan, target)
	if got.Err == nil {
		t.Fatal("expected Err on ContentID mismatch")
	}
	if !strings.Contains(got.Err.Error(), expected) || !strings.Contains(got.Err.Error(), scanned) {
		t.Errorf("Err should mention both expected and scanned content ids, got: %v", got.Err)
	}
	if got.Image != target.Subject.Ref {
		t.Errorf("Image = %q, want %q even on mismatch", got.Image, target.Subject.Ref)
	}
	if !got.Subject.Resolved {
		t.Error("Subject.Resolved should be true: the scan was pinned, even though it mismatched")
	}
	if got.Pinned {
		t.Error("Pinned should be false on a mismatch")
	}
}

func TestReconcileTarget_ContentIDMatchOK(t *testing.T) {
	id := "sha256:" + strings.Repeat("a", 64)
	target := pinnedTarget(t, "nginx:1.25", id)
	scan := ImageScan{Image: "ignored-artifact-name", ScannedKey: target.Subject.Key, Findings: []Finding{{VulnID: "CVE-1"}}}

	got := reconcileTarget(scan, target)
	if got.Err != nil {
		t.Fatalf("unexpected Err: %v", got.Err)
	}
	if !got.Pinned {
		t.Error("Pinned should be true for a matching config-digest-pinned scan")
	}
	if got.Subject != target.Subject {
		t.Errorf("Subject = %+v, want %+v", got.Subject, target.Subject)
	}
	if got.Image != target.Subject.Ref {
		t.Errorf("Image = %q, want %q (display name pinned to the reference)", got.Image, target.Subject.Ref)
	}
	if len(got.Findings) != 1 {
		t.Error("findings must be preserved on a match")
	}
}

func TestReconcileTarget_RefFallbackNotResolved(t *testing.T) {
	scan := ImageScan{Image: "ignored-artifact-name"}
	target := refTarget("nginx:1.25")

	got := reconcileTarget(scan, target)
	if got.Subject.Resolved {
		t.Error("Ref fallback scan must not report Subject.Resolved")
	}
	if got.Pinned {
		t.Error("Ref fallback scan must not report Pinned")
	}
	if got.Err != nil {
		t.Errorf("unexpected Err: %v", got.Err)
	}
	if got.Image != target.Subject.Ref {
		t.Errorf("Image = %q, want %q", got.Image, target.Subject.Ref)
	}
}

// --- reconcileTarget: registry digest pin check ---

func TestReconcileTarget_RegistryDigestAndPlatformMatch_Pinned(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	target := registryTarget(t, "nginx:1.25", "docker.io/library/nginx", digest, "linux", "amd64")
	scan := ImageScan{
		Image:           "ignored-artifact-name",
		RegistryDigests: []string{"docker.io/library/nginx@" + digest},
		Platform:        inventory.Platform{OS: "linux", Architecture: "amd64"},
		Findings:        []Finding{{VulnID: "CVE-1"}},
	}

	got := reconcileTarget(scan, target)
	if got.Err != nil {
		t.Fatalf("unexpected Err: %v", got.Err)
	}
	if !got.Pinned {
		t.Error("Pinned should be true for a matching registry-digest-pinned scan")
	}
	if got.ScannedKey != target.Subject.Key {
		t.Errorf("ScannedKey = %+v, want %+v", got.ScannedKey, target.Subject.Key)
	}
	if len(got.Findings) != 1 {
		t.Error("findings must be preserved on a match")
	}
}

// A requested hex present in RepoDigests but under a platform Trivy actually
// resolved differently must not be treated as a pin: the digest may name a
// multi-platform index, so a hex match alone says nothing about which
// platform's content was scanned.
func TestReconcileTarget_RegistryDigestMatchPlatformMismatchIsErr(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	target := registryTarget(t, "nginx:1.25", "docker.io/library/nginx", digest, "linux", "amd64")
	scan := ImageScan{
		Image:           "ignored-artifact-name",
		RegistryDigests: []string{"docker.io/library/nginx@" + digest},
		Platform:        inventory.Platform{OS: "linux", Architecture: "arm64"},
		Findings:        []Finding{{VulnID: "CVE-1"}},
	}

	got := reconcileTarget(scan, target)
	if got.Err == nil {
		t.Fatal("expected Err on platform mismatch")
	}
	if got.Pinned {
		t.Error("Pinned should be false on a platform mismatch")
	}
	if got.Image != target.Subject.Ref {
		t.Errorf("Image = %q, want %q even on mismatch", got.Image, target.Subject.Ref)
	}
	if len(got.Findings) != 0 {
		t.Error("a mismatch is a scan error, not attributed to the running content: findings must not survive it")
	}
}

func TestReconcileTarget_RegistryDigestNotInRepoDigestsIsErr(t *testing.T) {
	requested := "sha256:" + strings.Repeat("f", 64)
	other := "sha256:" + strings.Repeat("e", 64)
	target := registryTarget(t, "nginx:1.25", "docker.io/library/nginx", requested, "linux", "amd64")
	scan := ImageScan{
		Image:           "ignored-artifact-name",
		RegistryDigests: []string{"docker.io/library/nginx@" + other},
		Platform:        inventory.Platform{OS: "linux", Architecture: "amd64"},
	}

	got := reconcileTarget(scan, target)
	if got.Err == nil {
		t.Fatal("expected Err when the requested digest is absent from RepoDigests")
	}
	if got.Pinned {
		t.Error("Pinned should be false")
	}
}

// The hex match must not care which repository the RepoDigests entry names:
// mirrors and rewrites can put the same content under a different
// repository than the one we fetched from.
func TestReconcileTarget_RegistryDigestMatchAcrossDifferentRepository_Pinned(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	target := registryTarget(t, "nginx:1.25", "docker.io/library/nginx", digest, "linux", "amd64")
	scan := ImageScan{
		Image:           "ignored-artifact-name",
		RegistryDigests: []string{"registry.internal/mirror/nginx@" + digest},
		Platform:        inventory.Platform{OS: "linux", Architecture: "amd64"},
	}

	got := reconcileTarget(scan, target)
	if got.Err != nil {
		t.Fatalf("unexpected Err: %v", got.Err)
	}
	if !got.Pinned {
		t.Error("Pinned should be true: the hex matched even though the repository name differs")
	}
}

// Only one of several RepoDigests entries needs to match the requested hex.
func TestReconcileTarget_RegistryDigestMatchAmongMultiple_Pinned(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	other := "sha256:" + strings.Repeat("e", 64)
	target := registryTarget(t, "nginx:1.25", "docker.io/library/nginx", digest, "linux", "amd64")
	scan := ImageScan{
		Image:           "ignored-artifact-name",
		RegistryDigests: []string{"docker.io/library/nginx@" + other, "docker.io/library/nginx@" + digest},
		Platform:        inventory.Platform{OS: "linux", Architecture: "amd64"},
	}

	got := reconcileTarget(scan, target)
	if got.Err != nil {
		t.Fatalf("unexpected Err: %v", got.Err)
	}
	if !got.Pinned {
		t.Error("Pinned should be true: one of the RepoDigests entries matched")
	}
}

// A RepoDigests entry that only superficially resembles the requested digest
// — wrong letter case, or extra trailing characters — must not match. The
// comparison is an exact suffix match on the canonical "sha256:<hex>" form,
// never a case-insensitive or partial one.
func TestReconcileTarget_RegistryDigestRejectsCaseAndSuffixVariants(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	target := registryTarget(t, "nginx:1.25", "docker.io/library/nginx", digest, "linux", "amd64")

	cases := map[string]string{
		"uppercase hex":    "docker.io/library/nginx@sha256:" + strings.Repeat("F", 64),
		"trailing garbage": "docker.io/library/nginx@" + digest + "0",
	}
	for name, repoDigest := range cases {
		t.Run(name, func(t *testing.T) {
			scan := ImageScan{
				Image:           "ignored-artifact-name",
				RegistryDigests: []string{repoDigest},
				Platform:        inventory.Platform{OS: "linux", Architecture: "amd64"},
			}
			got := reconcileTarget(scan, target)
			if got.Err == nil {
				t.Fatalf("expected Err for RepoDigests entry %q, which must not match %q", repoDigest, digest)
			}
			if got.Pinned {
				t.Error("Pinned should be false")
			}
		})
	}
}

// An empty OS or Architecture on the scan side (ImageConfig missing or
// incomplete) must not match a non-empty requested value: an absence of
// evidence is not evidence of a match.
func TestReconcileTarget_RegistryPlatformPartiallyEmptyIsErr(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	target := registryTarget(t, "nginx:1.25", "docker.io/library/nginx", digest, "linux", "amd64")

	cases := map[string]inventory.Platform{
		"OS differs":         {OS: "windows", Architecture: "amd64"},
		"Architecture empty": {OS: "linux", Architecture: ""},
		"OS empty":           {OS: "", Architecture: "amd64"},
	}
	for name, platform := range cases {
		t.Run(name, func(t *testing.T) {
			scan := ImageScan{
				Image:           "ignored-artifact-name",
				RegistryDigests: []string{"docker.io/library/nginx@" + digest},
				Platform:        platform,
			}
			got := reconcileTarget(scan, target)
			if got.Err == nil {
				t.Fatalf("expected Err for scan Platform %+v against requested %+v", platform, target.Subject.Key.Platform)
			}
			if got.Pinned {
				t.Error("Pinned should be false")
			}
		})
	}
}

// A non-empty Variant on either side is rejected rather than silently
// treated as a match: the platform observed at discovery does not report a
// variant, so nothing here can confirm which variant is actually running.
func TestReconcileTarget_RegistryDigestNonEmptyVariantIsErr(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	target := registryTarget(t, "nginx:1.25", "docker.io/library/nginx", digest, "linux", "arm")
	scan := ImageScan{
		Image:           "ignored-artifact-name",
		RegistryDigests: []string{"docker.io/library/nginx@" + digest},
		Platform:        inventory.Platform{OS: "linux", Architecture: "arm", Variant: "v7"},
	}

	got := reconcileTarget(scan, target)
	if got.Err == nil {
		t.Fatal("expected Err: a non-empty scanned Variant must not be accepted as a match")
	}
	if got.Pinned {
		t.Error("Pinned should be false")
	}
}

// The variant rejection must hold on the real input path, not only on a
// hand-built ImageScan: ParseReport must carry ImageConfig.variant through
// to Platform.Variant, and the pin check must then reject the result.
func TestParseReportThenReconcile_VariantFromJSONIsErr(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	target := registryTarget(t, "nginx:1.25", "docker.io/library/nginx", digest, "linux", "arm")
	raw := fmt.Sprintf(`{"ArtifactName":"whatever","Metadata":{"OS":{"Family":"debian","EOSL":false},"RepoDigests":["docker.io/library/nginx@%s"],"ImageConfig":{"os":"linux","architecture":"arm","variant":"v7"}},"Results":[]}`, digest)

	scan, err := ParseReport([]byte(raw))
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if scan.Platform.Variant != "v7" {
		t.Fatalf("Platform.Variant = %q, want %q carried through from ImageConfig", scan.Platform.Variant, "v7")
	}

	got := reconcileTarget(scan, target)
	if got.Err == nil {
		t.Fatal("expected Err: a JSON-reported variant must reach the pin check and be rejected")
	}
	if got.Pinned {
		t.Error("Pinned should be false")
	}
}

// The same rejection applies to a hand-built target whose requested Platform
// carries a non-empty Variant: the scan metadata comparison covers only OS
// and Architecture, so a variant-qualified key would be "confirmed" on an
// unverified dimension if it were let through.
func TestReconcileTarget_RegistryRequestedVariantIsErr(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	d := mustParseRegistryDigest(t, digest)
	target := ScanTarget{
		Subject: inventory.ImageSubject{
			Ref:      "nginx:1.25",
			Key:      inventory.EntityKey{Digest: d, Platform: inventory.Platform{OS: "linux", Architecture: "arm", Variant: "v7"}},
			Resolved: true,
		},
		Registry: inventory.RegistryRef{Repository: "docker.io/library/nginx", Digest: d},
		Source:   SourceRemote,
	}
	scan := ImageScan{
		Image:           "ignored-artifact-name",
		RegistryDigests: []string{"docker.io/library/nginx@" + digest},
		Platform:        inventory.Platform{OS: "linux", Architecture: "arm"},
	}

	got := reconcileTarget(scan, target)
	if got.Err == nil {
		t.Fatal("expected Err: a requested Platform with a non-empty Variant must not pin")
	}
	if got.Pinned {
		t.Error("Pinned should be false")
	}
}

// A registry-resolved target whose Platform is unknown takes the reference
// fallback (see TestTrivyArgs_RegistryPlatformUnknownFallsBack) rather than
// the registry pin branch. reconcileTarget must still report Source as
// requested and must never claim Pinned for it: nothing here confirmed
// anything about the fetched content.
func TestReconcileTarget_RegistryPlatformUnknownStaysUnpinned(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	d := mustParseRegistryDigest(t, digest)
	target := ScanTarget{
		Subject:  inventory.ImageSubject{Ref: "nginx:1.25", Key: inventory.EntityKey{Digest: d}, Resolved: true},
		Registry: inventory.RegistryRef{Repository: "docker.io/library/nginx", Digest: d},
		Source:   SourceRemote,
	}
	scan := ImageScan{Image: "ignored-artifact-name"}

	got := reconcileTarget(scan, target)
	if got.Err != nil {
		t.Fatalf("unexpected Err: %v", got.Err)
	}
	if got.Source != SourceRemote {
		t.Errorf("Source = %q, want %q", got.Source, SourceRemote)
	}
	if got.Pinned {
		t.Error("Pinned should be false: the platform was never known, so nothing was confirmed")
	}
}

// A hand-built target whose Subject.Key.Digest (what the scan is meant to
// confirm) and Registry.Digest (what was actually fetched) disagree must
// never read back as a confirmed pin, even if the fetched digest and
// platform both check out against the scan's own metadata.
func TestReconcileTarget_RegistryTargetInconsistentDigestsIsErr(t *testing.T) {
	subjectDigest := "sha256:" + strings.Repeat("a", 64)
	fetchedDigest := "sha256:" + strings.Repeat("b", 64)
	subjectKey := mustParseRegistryDigest(t, subjectDigest)
	fetchedKey := mustParseRegistryDigest(t, fetchedDigest)
	target := ScanTarget{
		Subject: inventory.ImageSubject{
			Ref:      "nginx:1.25",
			Key:      inventory.EntityKey{Digest: subjectKey, Platform: inventory.Platform{OS: "linux", Architecture: "amd64"}},
			Resolved: true,
		},
		Registry: inventory.RegistryRef{Repository: "docker.io/library/nginx", Digest: fetchedKey},
		Source:   SourceRemote,
	}
	// The scan metadata confirms the *fetched* digest perfectly; that must
	// not matter, since it isn't the digest Subject.Key claims to confirm.
	scan := ImageScan{
		Image:           "ignored-artifact-name",
		RegistryDigests: []string{"docker.io/library/nginx@" + fetchedDigest},
		Platform:        inventory.Platform{OS: "linux", Architecture: "amd64"},
		Findings:        []Finding{{VulnID: "CVE-1"}},
	}

	got := reconcileTarget(scan, target)
	if got.Err == nil {
		t.Fatal("expected Err: Subject.Key.Digest and Registry.Digest disagree")
	}
	if !strings.Contains(got.Err.Error(), subjectDigest) || !strings.Contains(got.Err.Error(), fetchedDigest) {
		t.Errorf("Err should mention both digests, got: %v", got.Err)
	}
	if got.Pinned {
		t.Error("Pinned should be false")
	}
	if len(got.Findings) != 0 {
		t.Error("an inconsistent target is a scan error, not attributed to the running content")
	}
}

// --- Scan end-to-end against a fake trivy binary. These drive Trivy.Scan
// through its real exec.CommandContext path — argument construction, stdout
// parsing, and failure handling all together — without a real trivy binary,
// network, or Docker daemon.

// writeFakeTrivy creates an executable shell script at <tempdir>/trivy that
// records every argument it was invoked with (one per line, in order) to
// argsFile, then either prints stdout and exits 0, or prints to stderr and
// exits 1. It stands in for the trivy binary via Trivy.BinPath.
func writeFakeTrivy(t *testing.T, argsFile string, stdout string, fail bool) string {
	t.Helper()
	dir := t.TempDir()
	binPath := filepath.Join(dir, "trivy")

	var script string
	if fail {
		script = fmt.Sprintf(`#!/bin/sh
: > %q
for a in "$@"; do printf '%%s\n' "$a" >> %q; done
echo "boom" >&2
exit 1
`, argsFile, argsFile)
	} else {
		stdoutFile := filepath.Join(dir, "stdout.json")
		if err := os.WriteFile(stdoutFile, []byte(stdout), 0o644); err != nil {
			t.Fatalf("write stdout fixture: %v", err)
		}
		script = fmt.Sprintf(`#!/bin/sh
: > %q
for a in "$@"; do printf '%%s\n' "$a" >> %q; done
cat %q
`, argsFile, argsFile, stdoutFile)
	}

	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake trivy: %v", err)
	}
	return binPath
}

// readArgs reads back the arguments writeFakeTrivy's script recorded.
func readArgs(t *testing.T, argsFile string) []string {
	t.Helper()
	data, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read recorded args: %v", err)
	}
	trimmed := strings.TrimSuffix(string(data), "\n")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

func trivyJSON(imageID string, repoDigests ...string) string {
	digests, err := json.Marshal(repoDigests)
	if err != nil {
		panic(err) // repoDigests is always a []string literal in test callers
	}
	return fmt.Sprintf(`{"ArtifactName":"whatever","Metadata":{"OS":{"Family":"debian","EOSL":false},"ImageID":%q,"RepoDigests":%s},"Results":[]}`, imageID, digests)
}

// trivyJSONRegistry builds a fake Trivy report carrying RepoDigests and an
// ImageConfig platform, the shape a registry-kind (--image-src remote) scan
// returns, without an ImageID (a bare digest fetch has no local Docker
// config to report).
func trivyJSONRegistry(osName, arch string, repoDigests ...string) string {
	digests, err := json.Marshal(repoDigests)
	if err != nil {
		panic(err) // repoDigests is always a []string literal in test callers
	}
	return fmt.Sprintf(`{"ArtifactName":"whatever","Metadata":{"OS":{"Family":"debian","EOSL":false},"RepoDigests":%s,"ImageConfig":{"os":%q,"architecture":%q}},"Results":[]}`, digests, osName, arch)
}

func TestScan_FakeBinary_ContentIDPinned_ArgsAndMatch(t *testing.T) {
	id := "sha256:" + strings.Repeat("c", 64)
	target := pinnedTarget(t, "nginx:1.25", id)

	argsFile := filepath.Join(t.TempDir(), "args.txt")
	bin := writeFakeTrivy(t, argsFile, trivyJSON(id, "nginx@sha256:"+strings.Repeat("e", 64)), false)

	tr := Trivy{BinPath: bin, Severity: []string{"HIGH", "CRITICAL"}}
	scan := tr.Scan(context.Background(), target)

	if scan.Err != nil {
		t.Fatalf("Scan: %v", scan.Err)
	}
	if scan.Image != target.Subject.Ref {
		t.Errorf("Image = %q, want %q", scan.Image, target.Subject.Ref)
	}
	if scan.ScannedKey != target.Subject.Key {
		t.Errorf("ScannedKey = %+v, want %+v", scan.ScannedKey, target.Subject.Key)
	}
	if !scan.Pinned {
		t.Error("Pinned should be true for a matching config-digest-pinned scan")
	}

	gotArgs := readArgs(t, argsFile)
	wantArgs := tr.trivyArgs(target)
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Errorf("args recorded by the fake binary = %v, want %v (--image-src docker + positional ContentID)", gotArgs, wantArgs)
	}
}

func TestScan_FakeBinary_RegistryPinned_ArgsAndMatch(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	target := registryTarget(t, "nginx:1.25", "docker.io/library/nginx", digest, "linux", "amd64")

	argsFile := filepath.Join(t.TempDir(), "args.txt")
	bin := writeFakeTrivy(t, argsFile, trivyJSONRegistry("linux", "amd64", "docker.io/library/nginx@"+digest), false)

	tr := Trivy{BinPath: bin, Severity: []string{"HIGH", "CRITICAL"}}
	scan := tr.Scan(context.Background(), target)

	if scan.Err != nil {
		t.Fatalf("Scan: %v", scan.Err)
	}
	if scan.ScannedKey != target.Subject.Key {
		t.Errorf("ScannedKey = %+v, want %+v", scan.ScannedKey, target.Subject.Key)
	}
	if !scan.Pinned {
		t.Error("Pinned should be true for a matching registry-digest-pinned scan")
	}

	gotArgs := readArgs(t, argsFile)
	wantArgs := tr.trivyArgs(target)
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Errorf("args recorded by the fake binary = %v, want %v (--image-src remote + --platform + repo@digest)", gotArgs, wantArgs)
	}
}

func TestScan_FakeBinary_ContentIDPinned_Mismatch(t *testing.T) {
	expected := "sha256:" + strings.Repeat("c", 64)
	scanned := "sha256:" + strings.Repeat("d", 64)
	target := pinnedTarget(t, "nginx:1.25", expected)

	argsFile := filepath.Join(t.TempDir(), "args.txt")
	bin := writeFakeTrivy(t, argsFile, trivyJSON(scanned), false)

	tr := Trivy{BinPath: bin}
	scan := tr.Scan(context.Background(), target)

	if scan.Err == nil {
		t.Fatal("expected Err on ContentID mismatch")
	}
	if !strings.Contains(scan.Err.Error(), expected) || !strings.Contains(scan.Err.Error(), scanned) {
		t.Errorf("Err should mention both expected and scanned content ids, got: %v", scan.Err)
	}
	if scan.Pinned {
		t.Error("Pinned should be false on a mismatch")
	}
	if !scan.Subject.Resolved {
		t.Error("Subject.Resolved should be true: the scan was pinned, even though it mismatched")
	}
	if scan.Image != target.Subject.Ref {
		t.Errorf("Image = %q, want %q even on mismatch", scan.Image, target.Subject.Ref)
	}
}

// Regression: a config-digest-pinned scan whose trivy process exits non-zero
// must still carry Subject on the returned ImageScan (with Pinned false),
// since downstream inventory / partial-failure / scan_target_kind logic
// reads them even on failure.
func TestScan_FakeBinary_ContentIDPinned_ExecFailure_PreservesIdentity(t *testing.T) {
	id := "sha256:" + strings.Repeat("c", 64)
	target := pinnedTarget(t, "nginx:1.25", id)

	argsFile := filepath.Join(t.TempDir(), "args.txt")
	bin := writeFakeTrivy(t, argsFile, "", true)

	tr := Trivy{BinPath: bin}
	scan := tr.Scan(context.Background(), target)

	if scan.Err == nil {
		t.Fatal("expected Err when the trivy process fails")
	}
	if scan.Image != target.Subject.Ref {
		t.Errorf("Image = %q, want %q", scan.Image, target.Subject.Ref)
	}
	if scan.Subject != target.Subject {
		t.Errorf("Subject = %+v, want %+v (must survive exec failure)", scan.Subject, target.Subject)
	}
	if scan.Pinned {
		t.Error("Pinned should be false: the process failed")
	}
}

// Same regression, but for the JSON-parse-failure early return.
func TestScan_FakeBinary_ContentIDPinned_ParseFailure_PreservesIdentity(t *testing.T) {
	id := "sha256:" + strings.Repeat("c", 64)
	target := pinnedTarget(t, "nginx:1.25", id)

	argsFile := filepath.Join(t.TempDir(), "args.txt")
	bin := writeFakeTrivy(t, argsFile, "not valid json", false)

	tr := Trivy{BinPath: bin}
	scan := tr.Scan(context.Background(), target)

	if scan.Err == nil {
		t.Fatal("expected Err when trivy's output doesn't parse")
	}
	if scan.Image != target.Subject.Ref {
		t.Errorf("Image = %q, want %q", scan.Image, target.Subject.Ref)
	}
	if scan.Subject != target.Subject {
		t.Errorf("Subject = %+v, want %+v (must survive parse failure)", scan.Subject, target.Subject)
	}
	if scan.Pinned {
		t.Error("Pinned should be false: parsing failed")
	}
}
