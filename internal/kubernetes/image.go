package kubernetes

import (
	"regexp"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// dockerPullablePrefix is the only recognized scheme prefix on a
// containerStatus.imageID. containerd (the runtime under most managed
// Kubernetes) reports it bare (no prefix at all); the dockershim-era
// "docker-pullable://" prefix is still stripped for runtimes that emit it.
const dockerPullablePrefix = "docker-pullable://"

// maxRepositoryBytes mirrors the practical OCI repository name limit; a
// value over this is treated as unusable rather than truncated.
const maxRepositoryBytes = 253

// repoComponentPattern matches one "/"-separated repository path component:
// lowercase alphanumerics, optionally separated by single '.', '_', or '-'
// runs. This is a conservative subset of the full OCI reference grammar
// (rather than a normalizing implementation of it) — good enough to reject
// obviously-wrong values without inventing a canonical form for anything
// borderline.
var repoComponentPattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)

// repoPortPattern matches the numeric port suffix of a "host:port" first
// path segment.
var repoPortPattern = regexp.MustCompile(`^[0-9]{1,5}$`)

// bareImageIDPattern matches a containerStatus.image that is only an image
// ID. containerd reports the image's first tag there, and when the node holds
// the image under no tag (as after a pull by digest alone) it leaves the ID of
// the image config, which names no repository.
var bareImageIDPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// runningImageOf builds what one container status says the container runs:
// status.image as the reference, and status.imageID as the registry reference
// the runtime resolved. Both are the runtime's own report; the spec's image
// is never used. When status.image is only an image ID and imageID names a
// repository, the reference is that repository and digest, under which the
// runtime holds the same image; an image ID alone cannot be shown, scanned by
// name or compared with the spec. badImageID reports a non-empty imageID that
// failed the checks of parseImageID, for the caller to log.
func runningImageOf(cs containerStatus, platform inventory.Platform) (img inventory.RunningImage, badImageID bool) {
	img = inventory.RunningImage{Ref: cs.Image, Platform: platform}
	if cs.ImageID == "" {
		return img, false
	}
	ref, ok := parseImageID(cs.ImageID)
	if !ok {
		return img, true
	}
	img.Registry = ref
	if bareImageIDPattern.MatchString(cs.Image) {
		img.Ref = ref.Repository + "@" + ref.Digest.String()
	}
	return img, false
}

// parseImageID resolves a Kubernetes containerStatus.imageID into a
// RegistryRef, or reports ok == false when the value can't be trusted as a
// registry digest reference. The raw value is never returned on failure —
// callers that want it for diagnostics keep it themselves.
//
// Recognized shape: an optional "docker-pullable://" prefix, then
// "<repository>@sha256:<hex>". Any other "scheme://" prefix is rejected
// outright (an unrecognized runtime-specific format, not something to guess
// at). A bare "sha256:<hex>" with no "@<repository>" is a normal outcome for
// an image that was pre-loaded onto a node or otherwise never resolved
// through a pull — not malformed, but it carries no repository to scan and
// is rejected the same way as anything else without one.
func parseImageID(raw string) (inventory.RegistryRef, bool) {
	s := raw
	switch {
	case strings.HasPrefix(s, dockerPullablePrefix):
		s = strings.TrimPrefix(s, dockerPullablePrefix)
	case strings.Contains(s, "://"):
		return inventory.RegistryRef{}, false
	}
	if s == "" {
		return inventory.RegistryRef{}, false
	}

	i := strings.LastIndex(s, "@")
	if i < 0 {
		return inventory.RegistryRef{}, false
	}
	repo, digestPart := s[:i], s[i+1:]

	if !validRepository(repo) {
		return inventory.RegistryRef{}, false
	}
	d, ok := inventory.ParseDigest(inventory.DigestRegistry, digestPart)
	if !ok {
		return inventory.RegistryRef{}, false
	}
	return inventory.RegistryRef{Repository: repo, Digest: d}, true
}

// validRepository reports whether repo is a plausible OCI repository
// reference: non-empty, within maxRepositoryBytes, and every "/"-separated
// path component matches repoComponentPattern — except the first, which may
// instead be a "host:port" pair (host matching repoComponentPattern, port
// numeric). repo is never normalized, only accepted or rejected as given.
func validRepository(repo string) bool {
	if repo == "" || len(repo) > maxRepositoryBytes {
		return false
	}
	segments := strings.Split(repo, "/")
	for i, seg := range segments {
		if seg == "" {
			return false
		}
		if i == 0 {
			if host, port, ok := strings.Cut(seg, ":"); ok {
				if !repoComponentPattern.MatchString(host) || !repoPortPattern.MatchString(port) {
					return false
				}
				continue
			}
		}
		if !repoComponentPattern.MatchString(seg) {
			return false
		}
	}
	return true
}
