package remediation

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// languageUnitData is what a language update unit carries beyond a Compose
// unit's fields. The unit reuses those fields: path is the lockfile,
// locations hold the dependency directory, workloads and services are those of
// the plan item, and there is no candidate image.
type languageUnitData struct {
	// item is the plan item the unit was built from. Its artifacts are the
	// only place the files' content exists.
	item     *LanguageItem
	manager  DependencyManager
	root     string
	lockPath string

	// proposedFP, when set, says the item is bound to a pull request made from
	// the same inputs (its fingerprint): there is no update to write, and the
	// unit's outcome is that pull request's.
	proposedFP string

	record     *LangRecord
	fixTargets []FixTarget
	view       *PRLanguage
	title      string

	// artifacts and sources are the item's files by path; sources are the
	// files the plan read in the repository that is written to.
	artifacts map[string]ArtifactFile
	sources   map[string]SourceFile
}

// maxLanguageMarkerChars is the most characters the marker of a language
// pull request may take; the rest of the description has to fit beside it.
const maxLanguageMarkerChars = 30000

// buildLanguageUnits turns the pr_candidate language items of the plan into
// update units, one per item: the packages of one dependency directory that
// one update changes together. A unit that cannot be written is manual with a
// reason; the item stays in the plan alone.
func buildLanguageUnits(plan Plan) []*composeUnit {
	var out []*composeUnit
	for i := range plan.LanguageItems {
		it := &plan.LanguageItems[i]
		if it.Category != CategoryPRCandidate {
			continue
		}
		out = append(out, buildLanguageUnit(it, i))
	}
	return out
}

func buildLanguageUnit(it *LanguageItem, order int) *composeUnit {
	root := it.Source.Directory
	if root == "" {
		root = "."
	}
	u := &composeUnit{
		repo: it.Source.Repository, baseBranch: it.Source.BaseBranch, locations: []string{root},
		workloads: sortedCopy(it.Workloads), order: order,
	}
	for _, w := range it.Workloads {
		u.services = append(u.services, workloadService(w))
	}
	u.services = dedupeSorted(sortedCopy(u.services))
	ld := &languageUnitData{
		item: it, manager: it.Manager, root: root,
		artifacts: map[string]ArtifactFile{}, sources: map[string]SourceFile{},
	}
	u.lang = ld
	manual := func(reason Reason, format string, args ...any) *composeUnit {
		u.manual, u.manualReason, u.manualDetail = true, reason, fmt.Sprintf(format, args...)
		if u.path == "" {
			u.path = it.Manager.LockfileName()
		}
		u.key = strings.Join([]string{prKindLanguage, strings.ToLower(u.repo), u.baseBranch, u.path, it.Key}, "|")
		return u
	}

	var lockPaths []string
	for _, f := range it.Source.Files {
		if f.Repository != "" {
			continue
		}
		ld.sources[f.Path] = f
		if path.Base(f.Path) == it.Manager.LockfileName() {
			lockPaths = append(lockPaths, f.Path)
		}
	}
	if len(lockPaths) != 1 {
		return manual(ReasonArtifactsUnusable, "the plan read %d files named %s, so the lockfile to update is not clear", len(lockPaths), it.Manager.LockfileName())
	}
	ld.lockPath = lockPaths[0]
	u.path = ld.lockPath
	u.key = strings.Join([]string{prKindLanguage, strings.ToLower(u.repo), u.baseBranch, u.path}, "|")
	if it.Reason == ReasonUpdateAlreadyProposed {
		ld.proposedFP = LanguageInputFingerprint(*it)
		return u
	}

	switch {
	case it.SourceCheck == nil || !it.SourceCheck.Passed:
		return manual(ReasonArtifactsUnusable, "the item has no passed check of its dependency files")
	case len(it.Artifacts) == 0:
		return manual(ReasonArtifactsUnusable, "the item has no files to write")
	}
	for _, a := range it.Artifacts {
		if _, dup := ld.artifacts[a.Path]; dup {
			return manual(ReasonArtifactsUnusable, "the item lists %s twice", a.Path)
		}
		ld.artifacts[a.Path] = a
	}

	rec := LangRecord{Manager: string(it.Manager), InputFingerprint: LanguageInputFingerprint(*it)}
	seen := map[string]bool{}
	for _, p := range it.Packages {
		if p.Action != ActionUpdate {
			continue
		}
		if p.AdoptedVersion == "" {
			return manual(ReasonArtifactsUnusable, "%s has no version the update resolved to", p.Name)
		}
		name := p.matchName()
		positions := languagePositions(p, ld.lockPath)
		entry := LangKeyEntry{Ecosystem: p.Ecosystem, Name: name, Positions: positions, Adopted: p.AdoptedVersion}
		if k := hashCanonical(entry); !seen[k] {
			seen[k] = true
			rec.Packages = append(rec.Packages, entry)
		}
		coord := PackageCoord{Ecosystem: inventory.Ecosystem(p.Ecosystem), Class: inventory.ClassLang, Name: name}
		for _, pos := range positions {
			for _, c := range p.CVEs {
				ld.fixTargets = append(ld.fixTargets, FixTarget{Location: pos, VulnID: c.VulnID, Package: coord})
			}
		}
		ld.view = ensureLanguageView(ld.view, it.Manager, root)
		ld.view.Packages = append(ld.view.Packages, PRLanguagePackage{
			Name: p.Name, Ecosystem: p.Ecosystem, Relation: string(p.Relation), From: p.Installed, To: p.AdoptedVersion,
			Major: majorChanged(p.Installed, p.AdoptedVersion),
		})
	}
	if len(rec.Packages) == 0 {
		return manual(ReasonArtifactsUnusable, "the item has no package the update changed")
	}
	for _, p := range it.Packages {
		if !p.LeftOut {
			continue
		}
		rec.Remaining = append(rec.Remaining, LangRemaining{Ecosystem: p.Ecosystem, Name: p.matchName(), Reason: p.Reason})
		ld.view.Remaining = append(ld.view.Remaining, PRLanguageRemaining{
			Name: p.Name, Ecosystem: p.Ecosystem, Relation: string(p.Relation), From: p.Installed,
			Target: p.SelectionLowerBound, Reason: p.Reason, Detail: p.Detail,
		})
	}
	if it.Update != nil {
		rec.Runtime, rec.Tool = it.Update.Runtime, it.Update.Tool
		rec.DeprecatedChanged = it.Update.DeprecatedChanged
		if d := it.Update.Diff; d != nil {
			rec.Followed = d.Followed
		}
		for _, e := range it.Update.ManifestEdits {
			rec.ManifestEdits = append(rec.ManifestEdits, LangEdit{File: e.File, Section: e.Section, Name: e.Name, From: e.From, To: e.To, Major: e.MajorChange})
		}
	}
	rec.Packages = sortedLangEntries(rec.Packages)
	rec.ManifestEdits = sortedLangEdits(rec.ManifestEdits)
	sort.Slice(rec.Remaining, func(i, j int) bool {
		a, b := rec.Remaining[i], rec.Remaining[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		return a.Name < b.Name
	})
	sort.Slice(ld.view.Remaining, func(i, j int) bool {
		a, b := ld.view.Remaining[i], ld.view.Remaining[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.From < b.From
	})
	ld.record = &rec
	sortFixTargets(ld.fixTargets)
	ld.fixTargets = dedupeFixTargets(ld.fixTargets)
	sort.Slice(ld.view.Packages, func(i, j int) bool {
		a, b := ld.view.Packages[i], ld.view.Packages[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.From < b.From
	})
	ld.view.ManifestEdits = rec.ManifestEdits
	ld.title = languageUnitTitle(ld.view.Packages, ld.lockPath)

	// The marker has to fit in the description with the rest of the text.
	var changes []FileChange
	for p := range ld.artifacts {
		changes = append(changes, FileChange{Path: p, Mode: "100644", BlobSHA: strings.Repeat("0", 40)})
	}
	probe := PRMarker{
		V: markerV, Kind: prKindLanguage, RepoID: 1 << 40, BaseBranch: u.baseBranch, Path: ld.lockPath, Locations: []string{root},
		BaseSHA: strings.Repeat("0", 40), HeadSHA: strings.Repeat("0", 40), InputBlobSHA: strings.Repeat("0", 40),
		Changes: changes, TargetKey: strings.Repeat("0", 64), UpdateKey: strings.Repeat("0", 64), AttemptKey: strings.Repeat("0", 64),
		FixTargets: ld.fixTargets, Lang: ld.record,
	}
	if n := len(encodeMarker(probe)); n > maxLanguageMarkerChars {
		return manual(ReasonLanguageSetTooLarge, "the marker of the pull request would take %d characters, more than the %d it may", n, maxLanguageMarkerChars)
	}
	return u
}

// languagePositions are the places in the lockfile a package is updated at:
// its occurrences of the version the image runs, else all occurrences, else
// the lockfile itself.
func languagePositions(p LanguagePackage, lockPath string) []string {
	var matched, all []string
	for _, o := range p.Occurrences {
		if o.Path == "" {
			continue
		}
		all = append(all, o.Path)
		if o.Matched {
			matched = append(matched, o.Path)
		}
	}
	switch {
	case len(matched) > 0:
		return dedupeSorted(sortedCopy(matched))
	case len(all) > 0:
		return dedupeSorted(sortedCopy(all))
	}
	return []string{lockPath}
}

func ensureLanguageView(v *PRLanguage, m DependencyManager, root string) *PRLanguage {
	if v == nil {
		return &PRLanguage{Manager: string(m), Root: root, Packages: []PRLanguagePackage{}}
	}
	return v
}

func dedupeFixTargets(in []FixTarget) []FixTarget {
	out := in[:0:0]
	var last string
	for i, f := range in {
		if k := f.key(); i == 0 || k != last {
			out = append(out, f)
			last = k
		}
	}
	return out
}

var releaseRE = regexp.MustCompile(`^[vV=\s]*(?:[0-9]+!)?([0-9]+)(?:\.([0-9]+))?`)

// releaseLineOf is the major version of v, or for a 0.x version the minor
// one too, "" when v has no release number.
func releaseLineOf(v string) string {
	m := releaseRE.FindStringSubmatch(v)
	if m == nil {
		return ""
	}
	if m[1] == "0" {
		return "0." + m[2]
	}
	return m[1]
}

// majorChanged reports whether moving from one version to the other changes
// the major version (for 0.x, the minor version). Versions that cannot be read
// are not reported as a change.
func majorChanged(from, to string) bool {
	a, b := releaseLineOf(from), releaseLineOf(to)
	return a != "" && b != "" && a != b
}
