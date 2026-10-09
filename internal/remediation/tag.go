package remediation

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// TagKind is how a running image reference is treated when looking for an
// update.
type TagKind string

const (
	// TagPinned is a tag naming one release: three numeric dot-separated
	// parts, an optional fixed prefix and an optional "-" suffix
	// ("1.25.3", "v2.4.1-bookworm"). Its candidate is a newer patch of the
	// same series.
	TagPinned TagKind = "pinned"
	// TagFloating is any other tag ("16", "1.25", "latest", "16-alpine"). Its
	// candidate is whatever the same tag points at now.
	TagFloating TagKind = "floating"
	// TagExcluded is a reference no candidate is looked up for; see
	// ExcludeReason.
	TagExcluded TagKind = "excluded"
)

// ExcludeReason says why a reference is excluded from candidate lookup.
type ExcludeReason string

const (
	ExcludeNone         ExcludeReason = ""
	ExcludeDigestOnly   ExcludeReason = "digest_only"    // repo@sha256:..., no tag
	ExcludeTagAndDigest ExcludeReason = "tag_and_digest" // repo:tag@sha256:...
	ExcludePrerelease   ExcludeReason = "prerelease"     // the tag looks like a prerelease or moving development build
	ExcludeBareDigest   ExcludeReason = "bare_digest"    // "sha256:...": no repository or tag can be recovered
	ExcludeUnparsable   ExcludeReason = "unparsable"     // not a well-formed reference
	// ExcludeUnsupportedTag is a numeric tag that is neither a pinned tag nor
	// a plain floating one: more than three numeric parts ("1.25.3.4"), a
	// three-part version followed by something other than a "-" suffix, or
	// numbers written with leading zeros ("2024.01.15").
	ExcludeUnsupportedTag ExcludeReason = "unsupported_tag_format"
)

// TagVersion is the parsed form of a pinned tag.
type TagVersion struct {
	Prefix string `json:"prefix,omitempty"` // fixed text before the first number, e.g. "v"
	Major  int    `json:"major"`
	Minor  int    `json:"minor"`
	Patch  int    `json:"patch"`
	Suffix string `json:"suffix,omitempty"` // starts with "-", e.g. "-alpine"
}

// String renders v as the tag it was parsed from.
func (v TagVersion) String() string {
	return fmt.Sprintf("%s%d.%d.%d%s", v.Prefix, v.Major, v.Minor, v.Patch, v.Suffix)
}

// ImageRef is a running image reference after classification.
type ImageRef struct {
	Raw        string
	Repository string // as written, registry host kept; "" when excluded as unparsable
	// Tag is the tag in use. For a reference written without a tag it is
	// "latest", the tag Docker assumes, and ImplicitTag is set.
	Tag         string
	ImplicitTag bool
	Digest      string // the digest part, "" if none
	Kind        TagKind
	Exclude     ExcludeReason
	// Version is set only when Kind is TagPinned.
	Version TagVersion
}

var (
	// numericTagRE splits a tag into an optional fixed prefix, the leading
	// dot-separated numbers and the rest.
	numericTagRE = regexp.MustCompile(`^([A-Za-z][A-Za-z_-]*)?([0-9]+(?:\.[0-9]+)*)(.*)$`)
	// prereleaseTokenRE matches one token of a tag that marks a prerelease or
	// a moving development build.
	prereleaseTokenRE = regexp.MustCompile(`^(alpha|beta|rc|dev|preview|pre|nightly|snapshot|canary|unstable)$`)
	// attachedPreRE matches the short Python-style markers written straight
	// after a number ("1.2.3a1", "2.0.0b2").
	attachedPreRE = regexp.MustCompile(`[0-9][ab][0-9]+`)
	tokenRE       = regexp.MustCompile(`[a-z]+|[0-9]+`)
	bareDigestRE  = regexp.MustCompile(`^sha256:[0-9A-Za-z]*$`)
)

// maxVersionDigits keeps every version number well inside an int.
const maxVersionDigits = 9

// IsPrerelease reports whether tag contains a prerelease marker, as a token
// ("1.2.3-rc.1", "beta", "nightly") or attached to a number ("1.2.3rc1",
// "1.2.3a1"). Words that merely start like a marker ("alpine", "predictable")
// are not markers.
func IsPrerelease(tag string) bool {
	lower := strings.ToLower(tag)
	for _, tok := range tokenRE.FindAllString(lower, -1) {
		if prereleaseTokenRE.MatchString(tok) {
			return true
		}
	}
	return attachedPreRE.MatchString(lower)
}

func canonicalNumber(s string) (int, bool) {
	if len(s) > maxVersionDigits || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

// classifyTag classifies a tag that is not a prerelease. Pinned is exactly
// three numeric parts with an optional prefix and an optional "-" suffix.
// One or two numeric parts, and names without leading numbers, are floating.
// Every other numeric shape is unsupported rather than guessed at.
func classifyTag(tag string) (TagKind, TagVersion, ExcludeReason) {
	m := numericTagRE.FindStringSubmatch(tag)
	if m == nil {
		if strings.HasPrefix(tag, ".") {
			return TagExcluded, TagVersion{}, ExcludeUnsupportedTag
		}
		return TagFloating, TagVersion{}, ExcludeNone
	}
	parts := strings.Split(m[2], ".")
	rest := m[3]
	switch {
	case len(parts) <= 2 && strings.HasPrefix(rest, "."):
		// A dangling or doubled dot after the numbers ("1.", "1..2", "1.2.x").
		return TagExcluded, TagVersion{}, ExcludeUnsupportedTag
	case len(parts) <= 2:
		return TagFloating, TagVersion{}, ExcludeNone
	case len(parts) > 3:
		return TagExcluded, TagVersion{}, ExcludeUnsupportedTag
	case rest != "" && !(strings.HasPrefix(rest, "-") && len(rest) > 1):
		return TagExcluded, TagVersion{}, ExcludeUnsupportedTag
	}
	var nums [3]int
	for i, p := range parts {
		n, ok := canonicalNumber(p)
		if !ok {
			return TagExcluded, TagVersion{}, ExcludeUnsupportedTag
		}
		nums[i] = n
	}
	return TagPinned, TagVersion{Prefix: m[1], Major: nums[0], Minor: nums[1], Patch: nums[2], Suffix: rest}, ExcludeNone
}

// ParseTagVersion parses a pinned tag. ok is false for any tag that is not
// exactly three numeric parts with an optional prefix and "-" suffix, and for
// numbers written with leading zeros or too long to read back unchanged.
func ParseTagVersion(tag string) (TagVersion, bool) {
	kind, v, _ := classifyTag(tag)
	return v, kind == TagPinned
}

// ParseImageRef classifies a running image reference. The result never
// guesses: anything it cannot place is TagExcluded with a reason.
func ParseImageRef(ref string) ImageRef {
	out := ImageRef{Raw: ref, Kind: TagExcluded}
	if !strings.ContainsAny(ref, "/@") && bareDigestRE.MatchString(ref) {
		out.Exclude = ExcludeBareDigest
		return out
	}
	repo, ok := inventory.RepositoryOf(ref)
	if !ok {
		out.Exclude = ExcludeUnparsable
		return out
	}
	out.Repository = repo
	out.Digest = inventory.DigestOf(ref)
	tag := inventory.TagOf(ref)
	switch {
	case tag != "" && out.Digest != "":
		out.Tag = tag
		out.Exclude = ExcludeTagAndDigest
		return out
	case out.Digest != "":
		out.Exclude = ExcludeDigestOnly
		return out
	}
	if tag == "" {
		tag, out.ImplicitTag = "latest", true
	}
	out.Tag = tag
	if IsPrerelease(tag) {
		out.Exclude = ExcludePrerelease
		return out
	}
	kind, v, why := classifyTag(tag)
	out.Kind, out.Exclude = kind, why
	if kind == TagPinned {
		out.Version = v
	}
	return out
}
