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
	// InputFingerprint names the inputs the update was made from (see
	// LanguageInputFingerprint); it is not part of the update key. A record
	// without one was made before it existed.
	InputFingerprint string `json:"input_fingerprint,omitempty"`
}

// sortedLangEntries returns a sorted copy of entries with sorted positions.
func sortedLangEntries(entries []LangKeyEntry) []LangKeyEntry {
	out := make([]LangKeyEntry, len(entries))
	for i, e := range entries {
		e.Positions = sortedCopy(e.Positions)
		if e.Positions == nil {
			e.Positions = []string{}
		}
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

// LangUpdateKey identifies one proposed update of a lockfile: its target, the
// packages with their places and versions, and the manifest edits. Like
// UpdateKey it does not depend on the base commit, so the same update built
// again on a newer base has the same key.
func LangUpdateKey(targetKey string, packages []LangKeyEntry, edits []LangEdit) string {
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
	}{targetKey, prKindLanguage, sortedLangEntries(packages), es})
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
