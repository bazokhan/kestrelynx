package remediation

import (
	"fmt"
	"regexp"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// diffIDRE is a filesystem layer ID: a lower-case sha256 digest.
var diffIDRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// BaseLayerStatus is the outcome of comparing a running image's layers with a
// base image's.
type BaseLayerStatus string

const (
	// BaseLayersConfirmed means the base's layers are the first layers of the
	// running image.
	BaseLayersConfirmed BaseLayerStatus = "confirmed"
	// BaseLayersMismatch means both layer lists are usable and the base's are
	// not the start of the image's: the tag changed after the build, or the
	// image was built another way.
	BaseLayersMismatch BaseLayerStatus = "mismatch"
	// BaseLayersUnusable means the comparison cannot be made: a list is empty
	// or malformed, or the base's rootfs is not of type "layers".
	BaseLayersUnusable BaseLayerStatus = "unusable"
)

// BaseLayers is the result of MatchBaseLayers.
type BaseLayers struct {
	Status BaseLayerStatus
	// Count is the number of layers the base contributes, the length of the
	// prefix of the image's layers; set only when Status is
	// BaseLayersConfirmed.
	Count  int
	Detail string // why the status is not confirmed
}

// MatchBaseLayers compares a running image's layer IDs (the scan's
// Metadata.DiffIDs, bottom layer first) with the rootfs of a base image's
// config. The base is confirmed when its rootfs type is "layers" and its
// non-empty diff_ids equal the first layers of the image, a prefix match of
// any length up to the whole image.
//
// This shows only that the filesystem layers agree. It says nothing about how
// the image was built or about the rest of the base's config.
func MatchBaseLayers(imageDiffIDs []string, baseRootFSType string, baseDiffIDs []string) BaseLayers {
	unusable := func(format string, args ...any) BaseLayers {
		return BaseLayers{Status: BaseLayersUnusable, Detail: fmt.Sprintf(format, args...)}
	}
	switch {
	case baseRootFSType != "layers":
		return unusable("the base's rootfs type is %q, not \"layers\"", baseRootFSType)
	case len(baseDiffIDs) == 0:
		return unusable("the base has no diff_ids")
	case len(imageDiffIDs) == 0:
		return unusable("the running image's scan has no layer IDs")
	}
	for i, id := range baseDiffIDs {
		if !diffIDRE.MatchString(id) {
			return unusable("base diff_ids[%d] is not a sha256 digest", i)
		}
	}
	for i, id := range imageDiffIDs {
		if !diffIDRE.MatchString(id) {
			return unusable("the running image's layer ID %d is not a sha256 digest", i)
		}
	}
	if len(baseDiffIDs) > len(imageDiffIDs) {
		return BaseLayers{Status: BaseLayersMismatch, Detail: "the base has more layers than the running image"}
	}
	for i, id := range baseDiffIDs {
		if imageDiffIDs[i] != id {
			return BaseLayers{Status: BaseLayersMismatch, Detail: fmt.Sprintf("layer %d differs", i)}
		}
	}
	return BaseLayers{Status: BaseLayersConfirmed, Count: len(baseDiffIDs)}
}

// FindingsByLayer splits findings by where their layer sits relative to a
// confirmed base.
type FindingsByLayer struct {
	Base    []scanner.Finding // in a layer within the base's prefix
	Upper   []scanner.Finding // in a layer above it
	Unknown []scanner.Finding // no layer reported, a layer not in the image, or one that cannot be placed
}

// ClassifyFindingsByLayer places each finding by the layer Trivy attributed it
// to. baseLayers is BaseLayers.Count of a confirmed base. The order of the
// findings is kept within each group.
//
// A finding with no layer, or with a layer ID the image does not have, is
// Unknown. So is one whose layer ID occurs both within the base's prefix and
// above it, because a repeated layer cannot be told apart by its ID. When
// baseLayers is not a usable prefix length (less than 1, or more than the
// image has), nothing can be placed and every finding is Unknown.
//
// Trivy reports the lowest layer that holds a package of that name and
// version, so a package reinstalled above the base can still be attributed
// to a base layer. The result is a mapping of findings to layers, not proof
// that the base is their source.
func ClassifyFindingsByLayer(imageDiffIDs []string, baseLayers int, findings []scanner.Finding) FindingsByLayer {
	var out FindingsByLayer
	usable := baseLayers >= 1 && baseLayers <= len(imageDiffIDs)
	inBase := map[string]bool{}
	above := map[string]bool{}
	if usable {
		for i, id := range imageDiffIDs {
			if i < baseLayers {
				inBase[id] = true
			} else {
				above[id] = true
			}
		}
	}
	for _, f := range findings {
		id := f.LayerDiffID
		switch {
		case !usable || id == "":
			out.Unknown = append(out.Unknown, f)
		case inBase[id] && above[id]:
			out.Unknown = append(out.Unknown, f)
		case inBase[id]:
			out.Base = append(out.Base, f)
		case above[id]:
			out.Upper = append(out.Upper, f)
		default:
			out.Unknown = append(out.Unknown, f)
		}
	}
	return out
}
