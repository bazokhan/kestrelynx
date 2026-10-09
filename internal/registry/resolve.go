package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime"
	"regexp"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// Manifest media types the client reads.
const (
	mediaOCIIndex      = "application/vnd.oci.image.index.v1+json"
	mediaDockerList    = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaOCIManifest   = "application/vnd.oci.image.manifest.v1+json"
	mediaDockerV2      = "application/vnd.docker.distribution.manifest.v2+json"
	acceptManifestList = mediaOCIIndex + ", " + mediaDockerList + ", " + mediaOCIManifest + ", " + mediaDockerV2
)

var (
	digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tagRE    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
)

// Resolution is the result of Resolve: how a tag or digest maps down to one
// platform's manifest and image config.
type Resolution struct {
	// TopDigest and TopMediaType describe what the tag or digest points at: an
	// index (manifest list) or a single image manifest.
	TopDigest    string
	TopMediaType string
	// ManifestDigest is the image manifest for the requested platform. It
	// equals TopDigest when the top-level object is itself an image manifest.
	ManifestDigest string
	// ConfigDigest is the image config digest the manifest points at.
	ConfigDigest string
	// PlatformVerified is true when the image config, fetched and checked
	// against ConfigDigest, names the requested OS and architecture. It is
	// always true in a successful result.
	PlatformVerified bool
}

type manifestDoc struct {
	digest    string
	mediaType string
	body      []byte
}

func (m manifestDoc) isIndex() bool {
	return m.mediaType == mediaOCIIndex || m.mediaType == mediaDockerList
}

// Resolve fetches the manifest for tagOrDigest, narrows it to platform, then
// fetches the image config and checks its digest and platform.
//
// An index is searched for exactly one entry with the same OS and
// architecture: none is ErrPlatformNotFound and several distinct ones
// ErrPlatformAmbiguous. Bodies fetched by digest are verified against it, the
// digest a registry reports for any body is verified against its content, and
// the config blob must hash to the digest the manifest names. The config's OS
// and architecture must equal the request (ErrPlatformMismatch).
//
// A platform variant is never matched: a non-empty requested variant, or a
// variant on the selected index entry or the config, is ErrVariantUnsupported
// carrying the observed variant. On success PlatformVerified is always true.
func (c *Client) Resolve(ctx context.Context, repo, tagOrDigest string, platform inventory.Platform) (Resolution, error) {
	if !platform.Known() {
		return Resolution{}, fmt.Errorf("%w: platform needs OS and architecture", ErrInvalidInput)
	}
	if platform.Variant != "" {
		return Resolution{}, &VariantError{Requested: platform.Variant}
	}
	if !digestRE.MatchString(tagOrDigest) && !tagRE.MatchString(tagOrDigest) {
		return Resolution{}, fmt.Errorf("%w: reference %q", ErrInvalidInput, tagOrDigest)
	}
	t, err := newTarget(repo)
	if err != nil {
		return Resolution{}, err
	}
	top, err := c.manifest(ctx, t, tagOrDigest)
	if err != nil {
		return Resolution{}, err
	}
	res := Resolution{TopDigest: top.digest, TopMediaType: top.mediaType}

	img := top
	if top.isIndex() {
		var idx struct {
			Manifests []struct {
				Digest   string `json:"digest"`
				Platform *struct {
					OS           string `json:"os"`
					Architecture string `json:"architecture"`
					Variant      string `json:"variant"`
				} `json:"platform"`
			} `json:"manifests"`
		}
		if err := json.Unmarshal(top.body, &idx); err != nil {
			return Resolution{}, fmt.Errorf("%w: index from %s is not JSON", ErrBadResponse, t.host)
		}
		var matches []string
		for _, m := range idx.Manifests {
			p := m.Platform
			if p == nil || p.OS != platform.OS || p.Architecture != platform.Architecture {
				continue
			}
			// Every matching entry is checked before duplicates are dropped, so
			// a variant is refused whatever the entry order.
			if p.Variant != "" {
				return Resolution{}, &VariantError{Observed: p.Variant}
			}
			if !digestRE.MatchString(m.Digest) {
				return Resolution{}, fmt.Errorf("%w: index from %s holds an unusable digest", ErrBadResponse, t.host)
			}
			if !contains(matches, m.Digest) {
				matches = append(matches, m.Digest)
			}
		}
		switch len(matches) {
		case 0:
			return Resolution{}, fmt.Errorf("%w: %s/%s", ErrPlatformNotFound, platform.OS, platform.Architecture)
		case 1:
		default:
			return Resolution{}, fmt.Errorf("%w: %s/%s", ErrPlatformAmbiguous, platform.OS, platform.Architecture)
		}
		img, err = c.manifest(ctx, t, matches[0])
		if err != nil {
			return Resolution{}, err
		}
		if img.isIndex() {
			return Resolution{}, fmt.Errorf("%w: nested index", ErrUnsupported)
		}
	}

	var m struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if err := json.Unmarshal(img.body, &m); err != nil {
		return Resolution{}, fmt.Errorf("%w: manifest from %s is not JSON", ErrBadResponse, t.host)
	}
	if !digestRE.MatchString(m.Config.Digest) {
		return Resolution{}, fmt.Errorf("%w: manifest from %s has no usable config digest", ErrBadResponse, t.host)
	}
	if err := c.verifyConfig(ctx, t, m.Config.Digest, platform); err != nil {
		return Resolution{}, err
	}
	res.ManifestDigest = img.digest
	res.ConfigDigest = m.Config.Digest
	res.PlatformVerified = true
	return res, nil
}

// verifyConfig fetches the config blob, checks that it hashes to digest and
// that its platform is the requested one with no variant.
func (c *Client) verifyConfig(ctx context.Context, t target, digest string, platform inventory.Platform) error {
	r, err := c.get(ctx, t, t.base()+"/blobs/"+digest, "", c.opts.MaxConfigBytes)
	if err != nil {
		return fmt.Errorf("fetch image config %s: %w", digest, err)
	}
	sum := sha256.Sum256(r.body)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != digest {
		return fmt.Errorf("%w: %s sent config for %s that hashes to %s", ErrDigestMismatch, t.host, digest, got)
	}
	var cfg struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant"`
	}
	if err := json.Unmarshal(r.body, &cfg); err != nil {
		return fmt.Errorf("%w: image config from %s is not JSON", ErrBadResponse, t.host)
	}
	if cfg.OS != platform.OS || cfg.Architecture != platform.Architecture {
		return fmt.Errorf("%w: config says %s/%s, requested %s/%s", ErrPlatformMismatch, cfg.OS, cfg.Architecture, platform.OS, platform.Architecture)
	}
	if cfg.Variant != "" {
		return &VariantError{Observed: cfg.Variant}
	}
	return nil
}

func contains(s []string, v string) bool {
	for _, e := range s {
		if e == v {
			return true
		}
	}
	return false
}

// manifest fetches one manifest or index and validates its digest and type.
func (c *Client) manifest(ctx context.Context, t target, ref string) (manifestDoc, error) {
	r, err := c.get(ctx, t, t.base()+"/manifests/"+ref, acceptManifestList, c.opts.MaxManifestBytes)
	if err != nil {
		return manifestDoc{}, err
	}
	sum := sha256.Sum256(r.body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if digestRE.MatchString(ref) && ref != digest {
		return manifestDoc{}, fmt.Errorf("%w: %s sent content for %s that hashes to %s", ErrDigestMismatch, t.host, ref, digest)
	}
	if h := r.header.Get("Docker-Content-Digest"); digestRE.MatchString(h) && h != digest {
		return manifestDoc{}, fmt.Errorf("%w: %s reported %s for content hashing to %s", ErrDigestMismatch, t.host, h, digest)
	}

	mt, _, _ := mime.ParseMediaType(r.header.Get("Content-Type"))
	var body struct {
		MediaType string `json:"mediaType"`
	}
	_ = json.Unmarshal(r.body, &body)
	switch mt {
	case mediaOCIIndex, mediaDockerList, mediaOCIManifest, mediaDockerV2:
	case "", "application/json", "text/plain", "application/octet-stream":
		mt = strings.TrimSpace(body.MediaType)
	}
	switch mt {
	case mediaOCIIndex, mediaDockerList, mediaOCIManifest, mediaDockerV2:
	default:
		return manifestDoc{}, fmt.Errorf("%w: media type %q from %s", ErrUnsupported, mt, t.host)
	}
	if body.MediaType != "" && body.MediaType != mt {
		return manifestDoc{}, fmt.Errorf("%w: %s declares media type %q in a %q response", ErrBadResponse, t.host, body.MediaType, mt)
	}
	return manifestDoc{digest: digest, mediaType: mt, body: r.body}, nil
}
