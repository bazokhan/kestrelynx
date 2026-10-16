package remediation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// LangKeyEntry is one updated package of a language update as the update key
// takes it: the package, the places in the lockfile it is updated at and the
// version it is updated to.
type LangKeyEntry struct {
	Ecosystem string   `json:"ecosystem"`
	Name      string   `json:"name"`
	Positions []string `json:"positions"`
	Adopted   string   `json:"adopted"`
	// Through names the direct dependencies the package was brought to its
	// version through (a chain update), none otherwise.
	Through []string `json:"through,omitempty"`
}

// LangChainMove is a direct dependency a chain update moved: the package that
// required an older version of a held back package, from and to the versions
// it ends at, and the package it held back with the range it asked for.
type LangChainMove struct {
	Name      string `json:"name"`
	From      string `json:"from"`
	To        string `json:"to"`
	Held      string `json:"held,omitempty"`
	HeldRange string `json:"held_range,omitempty"`
	// HeldBy is the package between this direct dependency and the held back
	// package that asked for the range, when that is not the direct dependency
	// itself.
	HeldBy string `json:"held_by,omitempty"`
}

// LangRemaining is one package a language update leaves out: its place in the
// record is the package's ecosystem and matching name, and Reason says why it
// was left out.
type LangRemaining struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Reason    Reason `json:"reason"`
}

// LangEdit is one version specifier of a manifest a language update changes.
type LangEdit struct {
	File    string `json:"file"`
	Section string `json:"section"`
	Name    string `json:"name"`
	From    string `json:"from"`
	To      string `json:"to"`
	// Major marks a change after which the specifier no longer allows the
	// major version the old one allowed. It follows from From and To and is
	// not part of the update key.
	Major bool `json:"major,omitempty"`
}

// LangRecord is what identifies a language update beyond its target: the
// manager, the packages and the manifest edits. A marker carries it so the
// update key can be computed again from the marker alone.
type LangRecord struct {
	Manager       string         `json:"manager"`
	Packages      []LangKeyEntry `json:"packages"`
	ManifestEdits []LangEdit     `json:"manifest_edits,omitempty"`
	// Chain are the direct dependencies a chain update moved to bring the
	// packages to their versions; they are part of the update key.
	Chain []LangChainMove `json:"chain,omitempty"`
	// Remaining are the packages the update was planned for and left out
	// because they did not reach their target while the others did. They are
	// not part of the update key: the key names what the update changes.
	Remaining []LangRemaining `json:"remaining,omitempty"`
	// InputFingerprint names the inputs the update was made from (see
	// LanguageInputFingerprint); it is not part of the update key. A record
	// without one was made before it existed.
	InputFingerprint string `json:"input_fingerprint,omitempty"`
	// Runtime and Tool are what the update ran in and with. They are not part
	// of the update key. A record without them was made before they were
	// kept.
	Runtime *RuntimeRecord `json:"runtime,omitempty"`
	Tool    *ToolRecord    `json:"tool,omitempty"`
	// DeprecatedChanged is how many lockfile entries gained, lost or changed a
	// deprecated note in the update. It is not part of the update key.
	DeprecatedChanged int `json:"deprecated_changed,omitempty"`
	// DeprecatedNotes names those package versions and what happened to the
	// note of each. It is not part of the update key.
	DeprecatedNotes []DeprecationChange `json:"deprecated_notes,omitempty"`
	// Followed are the entries whose dependencies moved to new versions along
	// with the update. They are not part of the update key.
	Followed []FollowedEntry `json:"followed,omitempty"`
}

// deprecatedNotes are the package versions of the record whose deprecation
// note changed, none for no record.
func (l *LangRecord) deprecatedNotes() []DeprecationChange {
	if l == nil {
		return nil
	}
	return l.DeprecatedNotes
}

// sortedLangEntries returns a sorted copy of entries with sorted positions.
func sortedLangEntries(entries []LangKeyEntry) []LangKeyEntry {
	out := make([]LangKeyEntry, len(entries))
	for i, e := range entries {
		e.Positions = sortedCopy(e.Positions)
		if e.Positions == nil {
			e.Positions = []string{}
		}
		e.Through = sortedCopy(e.Through)
		out[i] = e
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if pa, pb := strings.Join(a.Positions, "\x00"), strings.Join(b.Positions, "\x00"); pa != pb {
			return pa < pb
		}
		return a.Adopted < b.Adopted
	})
	return out
}

// sortedLangEdits returns a sorted copy of edits.
func sortedLangEdits(edits []LangEdit) []LangEdit {
	out := append([]LangEdit{}, edits...)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Section != b.Section {
			return a.Section < b.Section
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.From != b.From {
			return a.From < b.From
		}
		return a.To < b.To
	})
	return out
}

// sortedLangChain returns a sorted copy of moves.
func sortedLangChain(moves []LangChainMove) []LangChainMove {
	out := append([]LangChainMove{}, moves...)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.From != b.From {
			return a.From < b.From
		}
		return a.To < b.To
	})
	return out
}

// LangUpdateKey identifies one proposed update of a lockfile: its target, the
// packages with their places and versions, and the manifest edits. Like
// UpdateKey it does not depend on the base commit, so the same update built
// again on a newer base has the same key.
//
// The direct dependencies a chain update moved are part of the key, by name and
// versions; an update without them has the key it always had.
func LangUpdateKey(targetKey string, packages []LangKeyEntry, edits []LangEdit, chain ...LangChainMove) string {
	type move struct {
		Name string `json:"name"`
		From string `json:"from"`
		To   string `json:"to"`
	}
	var moves []move
	for _, m := range sortedLangChain(chain) {
		moves = append(moves, move{m.Name, m.From, m.To})
	}
	type edit struct {
		File    string `json:"file"`
		Section string `json:"section"`
		Name    string `json:"name"`
		From    string `json:"from"`
		To      string `json:"to"`
	}
	es := make([]edit, 0, len(edits))
	for _, e := range sortedLangEdits(edits) {
		es = append(es, edit{e.File, e.Section, e.Name, e.From, e.To})
	}
	return hashCanonical(struct {
		TargetKey string         `json:"target_key"`
		Kind      string         `json:"kind"`
		Packages  []LangKeyEntry `json:"packages"`
		Edits     []edit         `json:"manifest_edits"`
		Chain     []move         `json:"chain,omitempty"`
	}{targetKey, prKindLanguage, sortedLangEntries(packages), es, moves})
}

// LanguageBranchName is the branch of a language attempt:
// kestrelynx/language/<display>-<manager>-<12 hex of the attempt key>, with
// the display part built as BranchName builds it, from the services of the
// workloads.
func LanguageBranchName(services []string, manager, attemptKey string) (string, error) {
	return branchNameFor(languageBranchPrefix, services, manager, attemptKey)
}

// inputSetSHA names the set of files a language update was made from by a
// 40-hex value shaped like a git object ID: the first 40 hex digits of the
// SHA-256 of the sorted path and blob pairs.
func inputSetSHA(files []SourceFile) string {
	lines := make([]string, 0, len(files))
	for _, f := range files {
		lines = append(lines, f.Path+"\x00"+f.BlobSHA)
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])[:40]
}

// languageUnitTitle is the pull request title and commit message of a
// language update.
func languageUnitTitle(pkgs []PRLanguagePackage, lockPath string) string {
	var t string
	switch len(pkgs) {
	case 0:
		t = fmt.Sprintf("Update packages in %s", lockPath)
	case 1:
		t = fmt.Sprintf("Update %s %s to %s in %s", pkgs[0].Name, pkgs[0].From, pkgs[0].To, lockPath)
	default:
		t = fmt.Sprintf("Update %s and %d more packages in %s", pkgs[0].Name, len(pkgs)-1, lockPath)
	}
	t = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, t)
	if rs := []rune(t); len(rs) > 250 {
		t = string(rs[:250]) + "..."
	}
	return t
}

// followed is the entries of the record whose dependencies moved, none for no
// record.
func (l *LangRecord) followed() []FollowedEntry {
	if l == nil {
		return nil
	}
	return l.Followed
}
