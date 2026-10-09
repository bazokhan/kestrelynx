package remediation

import "github.com/kitsunetrail/kestrelynx/internal/registry"

// SelectionOutcome is the result of looking for a newer pinned tag.
type SelectionOutcome string

const (
	// SelectionFound means a newer patch exists in a complete listing.
	SelectionFound SelectionOutcome = "found"
	// SelectionNone means a complete listing holds no newer patch.
	SelectionNone SelectionOutcome = "none"
	// SelectionIncomplete means the listing was cut short, so nothing can be
	// said about newer patches.
	SelectionIncomplete SelectionOutcome = "incomplete"
)

// Selection is the chosen candidate tag of a pinned image.
type Selection struct {
	Outcome SelectionOutcome
	Tag     string     // set when Outcome is SelectionFound
	Version TagVersion // the parsed Tag
}

// SelectPinned picks the highest-patch tag of the same series as cur: the
// same prefix, suffix, major and minor, a patch greater than cur's, and not
// a prerelease. All pinned tags have three numeric parts, so precision
// matches by construction. A truncated listing is never read as "no
// candidate" and its partial maximum is never used.
func SelectPinned(cur TagVersion, list registry.TagList) Selection {
	if list.Truncated {
		return Selection{Outcome: SelectionIncomplete}
	}
	best := Selection{Outcome: SelectionNone}
	for _, tag := range list.Tags {
		if IsPrerelease(tag) {
			continue
		}
		v, ok := ParseTagVersion(tag)
		if !ok || v.Prefix != cur.Prefix || v.Suffix != cur.Suffix || v.Major != cur.Major || v.Minor != cur.Minor {
			continue
		}
		if v.Patch <= cur.Patch {
			continue
		}
		if best.Outcome == SelectionNone || v.Patch > best.Version.Patch {
			best = Selection{Outcome: SelectionFound, Tag: tag, Version: v}
		}
	}
	return best
}
