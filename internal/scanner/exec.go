package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// Trivy runs the Trivy CLI. The binary is shelled out to (ADR-002) rather than
// linked as a library, so Trivy can be upgraded independently of KestreLynx.
type Trivy struct {
	// BinPath is the trivy executable; empty means look it up on PATH.
	BinPath string
	// Severity is passed to --severity. Empty means HIGH,CRITICAL.
	Severity []string
	// CacheDir is passed to --cache-dir when non-empty: for the database
	// preparation commands always, and for image scans only when
	// SkipDBUpdate is set.
	CacheDir string
	// SkipDBUpdate makes every image scan use the databases already in the
	// cache (--skip-db-update --skip-java-db-update) instead of updating them,
	// so all scans of a cycle see the databases PrepareDB fixed. Off by
	// default; when off, scan arguments are unchanged.
	SkipDBUpdate bool
}

// New returns a Trivy with KestreLynx defaults (HIGH/CRITICAL, trivy on PATH).
func New() Trivy {
	return Trivy{Severity: []string{"HIGH", "CRITICAL"}}
}

func (t Trivy) bin() string {
	if t.BinPath != "" {
		return t.BinPath
	}
	return "trivy"
}

func (t Trivy) severity() string {
	if len(t.Severity) == 0 {
		return "HIGH,CRITICAL"
	}
	return strings.Join(t.Severity, ",")
}

// pinnedByConfig reports whether target asks for the Docker-style pinned
// invocation: a resolved Subject whose entity key is a config digest. This
// is the sole gate for both the trivyArgs pinned branch and the
// reconcileTarget mismatch check, so the two can never disagree about
// whether a given target was pinned.
func pinnedByConfig(target ScanTarget) bool {
	return target.Subject.Resolved && target.Subject.Key.Digest.Kind == inventory.DigestConfig
}

// pinnedByRegistry reports whether target asks for the registry-kind
// invocation: a resolved Subject whose entity key is a registry digest,
// fetched from a registry over the network (Kubernetes) via a validated
// repository and a registry-kind digest to request, with a known platform
// to ask for. This is the sole gate for both the trivyArgs registry branch
// and the reconcileTarget registry pin check, so the two can never disagree
// about whether a given target was scanned as a registry pin.
//
// This gate does not by itself guarantee Subject.Key.Digest and
// Registry.Digest name the same content: Registry says where to fetch from
// and Subject.Key says what identity the scan is meant to confirm, and the
// two are populated independently by the caller. reconcileTarget checks
// that consistency separately (registryTargetConsistent) before trusting a
// scan against this target as a pin.
func pinnedByRegistry(target ScanTarget) bool {
	return target.Subject.Resolved &&
		target.Subject.Key.Digest.Kind == inventory.DigestRegistry &&
		target.Source == SourceRemote &&
		target.Registry.Digest.Kind == inventory.DigestRegistry &&
		target.Registry.Digest.Valid() &&
		target.Registry.Repository != "" &&
		target.Subject.Key.Platform.Known()
}

// trivyArgs builds the CLI arguments for scanning target. When the target is
// pinned to a config digest, the scan is restricted to the local Docker
// image store (--image-src docker) so Trivy can never resolve a different
// image than the one Docker reported running. When the target is pinned to a
// registry digest, the scan fetches straight from the registry
// (--image-src remote), pinned to the requested platform, so Trivy resolves
// the same platform-specific manifest the caller observed running rather
// than whatever the multi-platform index would resolve to locally. The
// Ref-only fallback path keeps its arguments exactly as before (existing
// behavior; no --image-src is added).
func (t Trivy) trivyArgs(target ScanTarget) []string {
	args := []string{
		"image",
		"--quiet",
		"--format", "json",
		"--severity", t.severity(),
	}
	if t.SkipDBUpdate {
		args = append(args, "--skip-db-update", "--skip-java-db-update")
		if t.CacheDir != "" {
			args = append(args, "--cache-dir", t.CacheDir)
		}
	}
	switch {
	case pinnedByConfig(target):
		return append(args, "--image-src", "docker", target.Subject.Key.Digest.String())
	case pinnedByRegistry(target):
		platform := target.Subject.Key.Platform.OS + "/" + target.Subject.Key.Platform.Architecture
		ref := target.Registry.Repository + "@" + target.Registry.Digest.String()
		return append(args, "--image-src", "remote", "--platform", platform, ref)
	default:
		return append(args, target.Subject.Ref)
	}
}

// pinnedOf derives ImageScan.Pinned: Subject.Resolved, the scan succeeded,
// and the entity Trivy actually scanned matches the one requested. It is the
// only place Pinned is computed.
func pinnedOf(scan ImageScan, target ScanTarget) bool {
	return target.Subject.Resolved && scan.Err == nil && scan.ScannedKey == target.Subject.Key
}

// registryTargetConsistent reports whether target's two identity fields
// agree: the digest Registry says to fetch from must be the exact digest
// Subject.Key claims the scan is meant to confirm. inventory.RegistryRef and
// inventory.EntityKey are populated independently by target's caller and
// have no structural link to each other, so scanner must check this itself
// rather than assume a caller wired the two consistently — a target built
// with Subject.Key naming one digest and Registry naming another must never
// read back as a confirmed pin just because the mismatched one it actually
// fetched happens to check out.
func registryTargetConsistent(target ScanTarget) bool {
	return target.Subject.Key.Digest == target.Registry.Digest
}

// registryDigestConfirmed reports whether scan's own metadata confirms the
// registry digest target requested: the requested digest must appear among
// Metadata.RepoDigests, and Metadata.ImageConfig.{os,architecture} must
// match the requested platform's OS/Architecture. Variants are outside what
// this comparison can confirm (the platform observed at discovery does not
// report one), so a non-empty Variant on either side — the requested
// platform or the scanned ImageConfig — is rejected rather than silently
// accepted as a match: accepting it would guess that the variant named on
// one side is the one actually running, which nothing available here can
// confirm.
func registryDigestConfirmed(scan ImageScan, target ScanTarget) bool {
	want := "@" + target.Registry.Digest.String()
	found := false
	for _, rd := range scan.RegistryDigests {
		if strings.HasSuffix(rd, want) {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	if scan.Platform.Variant != "" || target.Subject.Key.Platform.Variant != "" {
		return false
	}
	wantPlatform := target.Subject.Key.Platform
	return scan.Platform.OS == wantPlatform.OS && scan.Platform.Architecture == wantPlatform.Architecture
}

// reconcileTarget applies the pin check to a freshly parsed report for a
// pinned scan target (config digest or registry digest): a mismatch is an
// environment anomaly, not a finding, so it is surfaced as a scan error
// rather than attributed to the running content.
// scan.Image is always pinned to target.Subject.Ref (ArtifactName is the
// sha256 string for a pinned scan, confirmed in production).
func reconcileTarget(scan ImageScan, target ScanTarget) ImageScan {
	scan.Image = target.Subject.Ref
	scan.Subject = target.Subject
	scan.Source = target.Source
	if pinnedByConfig(target) && scan.ScannedKey != target.Subject.Key {
		return ImageScan{
			Image:      target.Subject.Ref,
			Subject:    target.Subject,
			Source:     target.Source,
			ScannedKey: scan.ScannedKey,
			Err: fmt.Errorf("trivy scan %s: scanned content %q does not match expected %q",
				target.Subject.Ref, scan.ScannedKey.Digest.String(), target.Subject.Key.Digest.String()),
		}
	}
	if pinnedByRegistry(target) {
		if !registryTargetConsistent(target) {
			return ImageScan{
				Image:   target.Subject.Ref,
				Subject: target.Subject,
				Source:  target.Source,
				Err: fmt.Errorf("trivy scan %s: registry target inconsistent: Subject.Key.Digest %q does not match Registry.Digest %q it was fetched from",
					target.Subject.Ref, target.Subject.Key.Digest.String(), target.Registry.Digest.String()),
			}
		}
		if !registryDigestConfirmed(scan, target) {
			return ImageScan{
				Image:      target.Subject.Ref,
				Subject:    target.Subject,
				Source:     target.Source,
				ScannedKey: scan.ScannedKey,
				Err: fmt.Errorf("trivy scan %s: registry digest %s not confirmed by scan metadata (repoDigests=%v, imageConfig platform=%q/%q, want platform %s/%s)",
					target.Subject.Ref, target.Registry.Digest.String(), scan.RegistryDigests,
					scan.Platform.OS, scan.Platform.Architecture,
					target.Subject.Key.Platform.OS, target.Subject.Key.Platform.Architecture),
			}
		}
		// The requested registry digest and platform are both confirmed:
		// this is the entity Trivy actually scanned, even though nothing in
		// Metadata.ImageID (a config digest) says so directly.
		scan.ScannedKey = target.Subject.Key
	}
	scan.Pinned = pinnedOf(scan, target)
	return scan
}

// Scan scans a single image target. A scan failure (e.g. the image cannot be
// pulled) is reported via ImageScan.Err rather than a returned error, so one bad
// image never aborts a whole run; callers iterate and surface Err per image.
func (t Trivy) Scan(ctx context.Context, target ScanTarget) ImageScan {
	if t.SkipDBUpdate {
		// Comparison mode runs elsewhere with a clean environment, so the
		// binary and cache must be absolute and explicit.
		rt, err := t.resolved()
		if err != nil {
			return ImageScan{
				Image:   target.Subject.Ref,
				Subject: target.Subject,
				Source:  target.Source,
				Err:     fmt.Errorf("trivy scan %s: %w", target.Subject.Ref, err),
			}
		}
		t = rt
	}
	args := t.trivyArgs(target)
	scanArg := args[len(args)-1]

	cmd := exec.CommandContext(ctx, t.bin(), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if t.SkipDBUpdate {
		// Comparable scans must not pick up trivy.yaml or .trivyignore from
		// whatever directory the process happens to run in.
		dir, err := os.MkdirTemp("", "kestrelynx-trivy-")
		if err != nil {
			return ImageScan{
				Image:   target.Subject.Ref,
				Subject: target.Subject,
				Source:  target.Source,
				Err:     fmt.Errorf("trivy scan %s: create working directory: %w", scanArg, err),
			}
		}
		defer os.RemoveAll(dir)
		cmd.Dir = dir
		// Settings come from the flags above; none may come from TRIVY_*.
		cmd.Env = withoutTrivyEnv(os.Environ())
	}

	if err := cmd.Run(); err != nil {
		return ImageScan{
			Image:   target.Subject.Ref,
			Subject: target.Subject,
			Source:  target.Source,
			Err:     fmt.Errorf("trivy scan %s: %w: %s", scanArg, err, strings.TrimSpace(stderr.String())),
		}
	}

	scan, err := ParseReport(stdout.Bytes())
	if err != nil {
		return ImageScan{
			Image:   target.Subject.Ref,
			Subject: target.Subject,
			Source:  target.Source,
			Err:     fmt.Errorf("trivy scan %s: %w", scanArg, err),
		}
	}
	return reconcileTarget(scan, target)
}
