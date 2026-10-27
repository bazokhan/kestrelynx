package remediation

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// maxListedEntries caps the lists of lockfile entries in the body.
const maxListedEntries = 20

// languageBodyInput is what the body of a language pull request describes.
type languageBodyInput struct {
	Repo, BaseBranch, BaseSHA string
	// LockPath is the lockfile and Root the dependency directory.
	LockPath, Root        string
	Item                  *LanguageItem
	Record                *LangRecord
	Files                 []FileChange // the files the commit changes
	Workloads             []string
	UpdateKey, AttemptKey string
	Marker                string
	Language              BodyLanguage
}

// registryName is the public registry a manager's packages come from.
func registryName(t *prText, m DependencyManager) string {
	if m == ManagerUv || m == ManagerPip {
		return t.RegistryPyPI
	}
	return t.RegistryNpm
}

// installCheck is an example of a CI step that installs from the changed
// files.
func installCheck(m DependencyManager) string {
	switch m {
	case ManagerNpm:
		return "npm ci"
	case ManagerPnpm:
		return "pnpm install --frozen-lockfile"
	case ManagerUv:
		return "uv sync --locked"
	}
	return "pip install -r requirements.txt"
}

// buildLanguagePRBody renders the body of a language package pull request. It
// says what was run and checked, and ends by asking for a CI run that installs
// from the changed files. The text is cut like buildPRBody's and ends with the
// marker.
func buildLanguagePRBody(in languageBodyInput) (string, error) {
	t := textFor(in.Language)
	it := in.Item
	var b strings.Builder
	b.WriteString("## " + t.HeadWhat + "\n\n")
	fmt.Fprintf(&b, t.LWhat,
		len(in.Record.Packages), entryWord(t, len(in.Record.Packages)), mdCode(in.LockPath), mdCode(in.Repo), mdCode(string(it.Manager)),
		mdCode(in.BaseBranch), mdCode(in.BaseSHA))
	fmt.Fprintf(&b, t.LDir, mdCode(in.Root))
	fmt.Fprintf(&b, t.LManager, mdCode(string(it.Manager)))
	fmt.Fprintf(&b, t.LWorkloads, codeListIn(t, in.Workloads, maxListedNames))
	keep := 0
	if anyStandalone(in.Workloads) {
		b.WriteString(t.SourceNote)
		keep = utf8.RuneCountInString(b.String())
	}
	var paths []string
	for _, f := range in.Files {
		paths = append(paths, f.Path)
	}
	fmt.Fprintf(&b, t.LFiles, codeListIn(t, paths, maxListedNames))

	pkgs := updatedPackages(it)
	var majorPkgs, majorEdits int
	for _, p := range pkgs {
		if majorChanged(p.Installed, p.AdoptedVersion) {
			majorPkgs++
		}
	}
	for _, e := range in.Record.ManifestEdits {
		if e.Major {
			majorEdits++
		}
	}
	if majorPkgs+majorEdits > 0 {
		b.WriteString("\n")
		if majorPkgs > 0 {
			fmt.Fprintf(&b, t.LMajorPkgs, majorPkgs)
		}
		if majorEdits > 0 {
			fmt.Fprintf(&b, t.LMajorEdits, majorEdits)
		}
	}

	b.WriteString("\n## " + t.HeadChange + "\n\n")
	b.WriteString(t.LChangeIntro)
	for i, p := range pkgs {
		if i == maxListedNames {
			fmt.Fprintf(&b, t.LineMore, len(pkgs)-maxListedNames)
			break
		}
		fmt.Fprintf(&b, t.LPkgLine, mdCode(p.Name), mdCode(p.Installed), mdCode(p.AdoptedVersion), relationText(t, p.Relation))
		if majorChanged(p.Installed, p.AdoptedVersion) {
			b.WriteString(t.LMajor)
		}
		b.WriteString("\n")
	}

	b.WriteString("\n### " + t.HeadVulnTargets + "\n\n")
	for i, p := range pkgs {
		if i == maxListedNames {
			fmt.Fprintf(&b, t.LineMorePkgs, len(pkgs)-maxListedNames)
			break
		}
		for j, c := range p.CVEs {
			if j == maxListedVulns {
				fmt.Fprintf(&b, t.LineMoreFor, len(p.CVEs)-maxListedVulns, mdCode(p.Name))
				break
			}
			fmt.Fprintf(&b, t.VulnLineLang, mdCode(c.VulnID), mdCode(p.Name))
			if c.Severity != "" {
				fmt.Fprintf(&b, t.VulnSeverity, mdCode(string(c.Severity)))
			}
			if c.KEV {
				b.WriteString(t.VulnKEV)
			}
			if c.Priority != PriorityNone {
				fmt.Fprintf(&b, t.VulnPriority, mdCode(string(c.Priority)))
			}
			b.WriteString("\n")
		}
	}

	if chain := in.Record.Chain; len(chain) > 0 {
		b.WriteString("\n### " + t.HeadChain + "\n\n")
		fmt.Fprintf(&b, t.LChainIntro, mdCode(manifestFileName(it.Manager)))
		for i, m := range chain {
			if i == maxListedEntries {
				fmt.Fprintf(&b, t.LineMore, len(chain)-maxListedEntries)
				break
			}
			format := t.LChainLine
			if m.HeldBy != "" {
				format = t.LChainViaLine
			}
			line := fmt.Sprintf(format, mdCode(m.Name), mdCode(m.From), mdCode(m.To), mdCode(m.Held), mdCode(m.HeldRange), mdCode(m.HeldBy))
			if majorChanged(m.From, m.To) {
				line = strings.TrimSuffix(line, "\n") + t.LMajor + "\n"
			}
			b.WriteString(line)
		}
	}

	if edits := in.Record.ManifestEdits; len(edits) > 0 {
		b.WriteString("\n### " + t.HeadManifestEdits + "\n\n")
		b.WriteString(t.LEditsIntro)
		var major []LangEdit
		for _, e := range edits {
			if e.Major {
				major = append(major, e)
			}
		}
		if len(major) > 0 {
			fmt.Fprintf(&b, t.LEditsMajor, len(major))
		}
		for i, e := range edits {
			if i == maxListedNames {
				fmt.Fprintf(&b, t.LineMore, len(edits)-maxListedNames)
				break
			}
			fmt.Fprintf(&b, t.LEditLine, mdCode(e.File), mdCode(e.Section), mdCode(e.Name), mdCode(e.From), mdCode(e.To))
			if e.Major {
				b.WriteString(t.LMajor)
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\n## " + t.HeadVerification + "\n\n")
	writeEnvironment(t, &b, in.Record)
	if up := it.Update; up != nil {
		b.WriteString(t.LOps)
		if len(up.Steps) == 0 {
			b.WriteString(t.LNoOps)
		}
		for _, s := range up.Steps {
			fmt.Fprintf(&b, t.LStep, mdCode(s.Op), s.ExitCode)
			if s.Scratch {
				b.WriteString(t.LScratch)
			}
			b.WriteString("\n")
		}
		if d := up.Diff; d != nil {
			fmt.Fprintf(&b, t.LEntries, len(d.Added), len(d.Changed), len(d.Removed))
			if d.Truncated {
				b.WriteString(t.LTruncated)
			}
			b.WriteString("\n\n")
			writeEntryList(t, &b, t.LTitleChanged, d.Changed)
			writeEntryList(t, &b, t.LTitleAdded, d.Added)
			writeEntryList(t, &b, t.LTitleRemoved, d.Removed)
			fmt.Fprintf(&b, t.LLookup, registryName(t, it.Manager))
		}
		if notes := in.Record.deprecatedNotes(); len(notes) > 0 {
			b.WriteString("\n")
			for i, n := range notes {
				if i == maxListedEntries {
					fmt.Fprintf(&b, t.LineMore, len(notes)-maxListedEntries)
					break
				}
				format := t.LDeprecatedChanged
				switch n.Kind {
				case DeprecationGained:
					format = t.LDeprecatedGained
				case DeprecationLost:
					format = t.LDeprecatedLost
				case DeprecationPresent:
					format = t.LDeprecatedPresent
				}
				fmt.Fprintf(&b, format, mdCode(n.Name+"@"+n.Version))
			}
		}
		if f := in.Record.followed(); len(f) > 0 {
			fmt.Fprintf(&b, "\n**%s (%d)**\n\n", t.LFollowedTitle, len(f))
			for i, e := range f {
				if i == maxListedEntries {
					fmt.Fprintf(&b, t.LineMore, len(f)-maxListedEntries)
					break
				}
				var moves []string
				for _, m := range e.Moves {
					moves = append(moves, fmt.Sprintf(t.LFollowedMove, mdCode(m.Name), mdCode(m.From), mdCode(m.To)))
				}
				fmt.Fprintf(&b, t.LFollowedLine, mdCode(e.Entry), strings.Join(moves, "; "))
			}
		}
		for _, n := range up.Notes {
			fmt.Fprintf(&b, t.LNote, mdCode(n))
		}
	}

	if sc := it.SourceCheck; sc != nil {
		b.WriteString(t.LSourceHead)
		fmt.Fprintf(&b, t.LBefore, hashedFileList(t, sc.Before))
		fmt.Fprintf(&b, t.LAfter, hashedFileList(t, sc.After))
		fmt.Fprintf(&b, t.LSourceCounts, sc.Counts[0], sc.Counts[1], sc.Counts[2])
		switch sc.Basis {
		case "":
		case chainScanPositionsBasis:
			b.WriteString(t.LSourceBasisPositions)
		default:
			b.WriteString(t.LSourceBasis)
		}
		if len(sc.ChainCarried) > 0 {
			c := sc.ChainCarried[0]
			fmt.Fprintf(&b, t.LChainCarried, len(sc.ChainCarried), mdCode(c.VulnID), mdCode(c.Package), mdCode(c.From), mdCode(c.To))
		}
		if sc.Truncated {
			b.WriteString(t.LListCut)
		}
		writeSourceVulns(t, &b, t.TitleResolved, sc.Resolved, sc.Counts[0])
		writeSourceVulns(t, &b, t.TitleRemaining, sc.Remaining, sc.Counts[1])
		writeSourceVulns(t, &b, t.TitleIntroduced, sc.Introduced, sc.Counts[2])
		fmt.Fprintf(&b, t.LBothScans, mdCode(sc.Conditions.TrivyVersion))
		if at := sc.Conditions.VulnerabilityDB.UpdatedAt; !at.IsZero() {
			fmt.Fprintf(&b, t.LDBBuilt, at.UTC().Format(time.RFC3339))
		}
		fmt.Fprintf(&b, t.LScanTail, codeListIn(t, sc.Conditions.Severities, 10))
	}

	if !strings.HasSuffix(b.String(), "\n\n") {
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, t.LInstallCheck, mdCode(installCheck(it.Manager)))

	return assembleBodyKeeping(b.String(), in.Marker, t.CutNote, keep)
}

// entryWord is the word for n lockfile entries.
func entryWord(t *prText, n int) string {
	if n == 1 {
		return t.LEntryOne
	}
	return t.LEntryMany
}

func relationText(t *prText, r Relation) string {
	switch r {
	case RelationDirect:
		return t.RelDirect
	case RelationTransitive:
		return t.RelTransitive
	case RelationMixed:
		return t.RelMixed
	}
	return t.RelUnknown
}

// updatedPackages are the item's packages the update changed, sorted.
func updatedPackages(it *LanguageItem) []LanguagePackage {
	var out []LanguagePackage
	for _, p := range it.Packages {
		if p.Action == ActionUpdate {
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Installed < out[j].Installed
	})
	return out
}

func writeEntryList(t *prText, b *strings.Builder, title string, entries []string) {
	if len(entries) == 0 {
		return
	}
	fmt.Fprintf(b, "%s:\n\n", title)
	for i, e := range entries {
		if i == maxListedEntries {
			fmt.Fprintf(b, t.LineMore, len(entries)-maxListedEntries)
			break
		}
		fmt.Fprintf(b, "- %s\n", mdCode(e))
	}
	b.WriteString("\n")
}

func hashedFileList(t *prText, files []HashedFile) string {
	if len(files) == 0 {
		return t.NoFiles
	}
	var parts []string
	for _, f := range files {
		h := f.SHA256
		if len(h) > 12 {
			h = h[:12]
		}
		parts = append(parts, f.Path+" sha256:"+h)
	}
	return codeListIn(t, parts, maxListedNames)
}

func writeSourceVulns(t *prText, b *strings.Builder, title string, vs []SourceVuln, total int) {
	fmt.Fprintf(b, t.ListTitle, title, total)
	if len(vs) == 0 && total == 0 {
		b.WriteString(t.None)
		return
	}
	shown := len(vs)
	if shown > maxListedVulns {
		shown = maxListedVulns
	}
	for _, v := range vs[:shown] {
		fmt.Fprintf(b, t.SourceVulnLine, mdCode(v.VulnID), mdCode(v.Package), mdCode(v.Version))
		if v.Severity != "" {
			fmt.Fprintf(b, t.VulnSeverity, mdCode(string(v.Severity)))
		}
		if v.KEV {
			b.WriteString(t.VulnKEV)
		}
		if v.FixedVer != "" {
			fmt.Fprintf(b, t.SourceFixed, mdCode(v.FixedVer))
		}
		b.WriteString("\n")
	}
	if total > shown {
		fmt.Fprintf(b, t.LineMore, total-shown)
	}
}

// writeEnvironment lists the runtime and the package manager the update ran
// with, or says there is no record of them.
func writeEnvironment(t *prText, b *strings.Builder, rec *LangRecord) {
	if rec == nil || (rec.Runtime == nil && rec.Tool == nil) {
		b.WriteString(t.LEnvNone + "\n")
		return
	}
	if r := rec.Runtime; r != nil {
		if why := runtimeWhy(t, r); why != "" {
			fmt.Fprintf(b, t.LEnvRuntimeWhy, mdCode(r.ID), mdCode(r.Version), mdCode(r.Image), why)
		} else {
			fmt.Fprintf(b, t.LEnvRuntime, mdCode(r.ID), mdCode(r.Version), mdCode(r.Image))
		}
		if r.Pip != "" {
			fmt.Fprintf(b, t.LEnvPip, mdCode(r.Pip))
		}
		if r.EnginesFloor != "" {
			fmt.Fprintf(b, t.LEnvFloor, mdCode(r.EnginesFloor))
		}
	}
	if tl := rec.Tool; tl != nil {
		var source string
		switch tl.Source {
		case toolSourceDefault:
			source = t.LEnvToolDefault
		case toolSourceDeclared:
			source = t.LEnvToolDeclared
		case toolSourceDefaultInRange:
			source = t.LEnvToolInRange
		default:
			source = fmt.Sprintf(t.LEnvToolSource, mdCode(tl.Source))
		}
		fmt.Fprintf(b, t.LEnvTool, mdCode(tl.Name), mdCode(tl.Version), source, mdCode(tl.SHA256))
	}
	b.WriteString("\n")
}

// runtimeWhy words how the runtime was chosen from its record, or returns ""
// for a record that says nothing of it.
func runtimeWhy(t *prText, r *RuntimeRecord) string {
	var decls []string
	for _, d := range r.Declared {
		decls = append(decls, mdCode(d.Source)+" "+mdCode(d.Value))
	}
	python := strings.HasPrefix(r.ID, "python")
	pick := func(node, py string) string {
		if python {
			return py
		}
		return node
	}
	var parts []string
	switch r.Basis {
	case RuntimeBasisFile:
		parts = append(parts, fmt.Sprintf(pick(t.LEnvBasisFile, t.LEnvPyBasisFile), strings.Join(decls, t.ListSep)))
	case RuntimeBasisLowestInRange:
		parts = append(parts, fmt.Sprintf(pick(t.LEnvBasisRange, t.LEnvPyBasisRange), strings.Join(decls, t.ListSep)))
	case RuntimeBasisDefault:
		parts = append(parts, t.LEnvBasisDefault)
	default:
		return ""
	}
	for _, x := range r.Excluded {
		series := strings.TrimPrefix(strings.TrimPrefix(x.ID, "node"), "python")
		switch x.Why {
		case ExcludedEndOfLife:
			parts = append(parts, fmt.Sprintf(pick(t.LEnvExcludedEOL, t.LEnvPyExcludedEOL), mdCode(series), mdCode(x.EOL)))
		case ExcludedManagerEngines:
			parts = append(parts, fmt.Sprintf(t.LEnvExcludedEngines, mdCode(series), mdCode(x.Manager), mdCode(x.ManagerVersion), mdCode(x.Engines)))
		default:
			parts = append(parts, fmt.Sprintf(pick(t.LEnvExcludedDecl, t.LEnvPyExcludedDecl), mdCode(series)))
		}
	}
	return strings.Join(parts, t.LEnvWhySep)
}

// manifestFileName is the file a manager's direct dependencies are declared in.
func manifestFileName(m DependencyManager) string {
	if m == ManagerUv {
		return "pyproject.toml"
	}
	return "package.json"
}
