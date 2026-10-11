package remediation

import (
	"fmt"
	"sort"
	"strings"
	"time"
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
}

// registryName is the public registry a manager's packages come from.
func registryName(m DependencyManager) string {
	if m == ManagerUv || m == ManagerPip {
		return "PyPI"
	}
	return "the npm registry"
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
// says what was run and checked, and states plainly what was not: the image
// is not rebuilt, compatibility and tests are not checked, and the checks of
// the installer's view of the files go only as far as they can. The text is
// cut like buildPRBody's and ends with the marker.
func buildLanguagePRBody(in languageBodyInput) (string, error) {
	it := in.Item
	var b strings.Builder
	b.WriteString("## What\n\n")
	fmt.Fprintf(&b, "KestreLynx proposes updating %d package entr%s in %s of %s with %s, against base branch %s at commit %s.\n\n",
		len(in.Record.Packages), pluralY(len(in.Record.Packages)), mdCode(in.LockPath), mdCode(in.Repo), mdCode(string(it.Manager)),
		mdCode(in.BaseBranch), mdCode(in.BaseSHA))
	fmt.Fprintf(&b, "- Dependency directory: %s\n", mdCode(in.Root))
	fmt.Fprintf(&b, "- Package manager: %s\n", mdCode(string(it.Manager)))
	fmt.Fprintf(&b, "- Workloads running these packages: %s\n", codeList(in.Workloads, maxListedNames))
	var paths []string
	for _, f := range in.Files {
		paths = append(paths, f.Path)
	}
	fmt.Fprintf(&b, "- Files changed: %s\n", codeList(paths, maxListedNames))

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
			fmt.Fprintf(&b, "**%d package(s) move to another major version (for 0.x, another minor version). Review these first: the application may need changes.**\n", majorPkgs)
		}
		if majorEdits > 0 {
			fmt.Fprintf(&b, "**%d manifest edit(s) allow a new major version and no longer allow the one before; see Manifest edits below.**\n", majorEdits)
		}
	}

	b.WriteString("\n## Change\n\n")
	b.WriteString("Running version to version after the update, with how the project requires the package:\n\n")
	for i, p := range pkgs {
		if i == maxListedNames {
			fmt.Fprintf(&b, "- and %d more\n", len(pkgs)-maxListedNames)
			break
		}
		fmt.Fprintf(&b, "- %s: %s to %s (%s)", mdCode(p.Name), mdCode(p.Installed), mdCode(p.AdoptedVersion), relationText(p.Relation))
		if majorChanged(p.Installed, p.AdoptedVersion) {
			b.WriteString(" — **major version change**")
		}
		b.WriteString("\n")
	}

	b.WriteString("\n### Vulnerabilities this update targets\n\n")
	for i, p := range pkgs {
		if i == maxListedNames {
			fmt.Fprintf(&b, "- and %d more packages\n", len(pkgs)-maxListedNames)
			break
		}
		for j, c := range p.CVEs {
			if j == maxListedVulns {
				fmt.Fprintf(&b, "- and %d more for %s\n", len(p.CVEs)-maxListedVulns, mdCode(p.Name))
				break
			}
			fmt.Fprintf(&b, "- %s in %s", mdCode(c.VulnID), mdCode(p.Name))
			if c.Severity != "" {
				fmt.Fprintf(&b, ", severity %s", mdCode(string(c.Severity)))
			}
			if c.KEV {
				b.WriteString(", in the CISA KEV catalog")
			}
			if c.Priority != PriorityNone {
				fmt.Fprintf(&b, ", priority %s", mdCode(string(c.Priority)))
			}
			b.WriteString("\n")
		}
	}

	if edits := in.Record.ManifestEdits; len(edits) > 0 {
		b.WriteString("\n### Manifest edits\n\n")
		b.WriteString("The version specifier of these direct dependencies did not allow a fixed version, so it was edited before the lockfile was updated.\n\n")
		var major []LangEdit
		for _, e := range edits {
			if e.Major {
				major = append(major, e)
			}
		}
		if len(major) > 0 {
			fmt.Fprintf(&b, "**%d edit(s) below allow a new major version (for 0.x, a new minor version) and no longer allow the one before. Review these first: the application may need changes.**\n\n", len(major))
		}
		for i, e := range edits {
			if i == maxListedNames {
				fmt.Fprintf(&b, "- and %d more\n", len(edits)-maxListedNames)
				break
			}
			fmt.Fprintf(&b, "- %s, %s, %s: %s to %s", mdCode(e.File), mdCode(e.Section), mdCode(e.Name), mdCode(e.From), mdCode(e.To))
			if e.Major {
				b.WriteString(" — **major version change**")
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\n## Why these versions\n\n")
	b.WriteString("For each package the target is the lowest version that the vulnerability data lists as fixed for every vulnerability found in the running image; the version in the updated file is the lowest version of the package it holds.\n")

	b.WriteString("\n## Verification\n\n")
	fmt.Fprintf(&b, "The update ran in a throwaway container built from a fixed work image, with fixed operations and no credentials. Its result was treated as untrusted and checked by KestreLynx itself.\n\n")
	if up := it.Update; up != nil {
		b.WriteString("**Operations run**\n\n")
		if len(up.Steps) == 0 {
			b.WriteString("- none recorded\n")
		}
		for _, s := range up.Steps {
			fmt.Fprintf(&b, "- %s, exit code %d", mdCode(s.Op), s.ExitCode)
			if s.Scratch {
				b.WriteString(" (run on a scratch copy; its result was only compared)")
			}
			b.WriteString("\n")
		}
		if d := up.Diff; d != nil {
			fmt.Fprintf(&b, "\n**Lockfile entries**: %d added, %d changed, %d removed", len(d.Added), len(d.Changed), len(d.Removed))
			if d.Truncated {
				b.WriteString(" (the lists are cut)")
			}
			b.WriteString("\n\n")
			writeEntryList(&b, "Changed", d.Changed)
			writeEntryList(&b, "Added", d.Added)
			writeEntryList(&b, "Removed", d.Removed)
			fmt.Fprintf(&b, "Every version the update added or changed was looked up in %s and compared with the distribution the lockfile points at.\n", registryName(it.Manager))
		}
		for _, n := range up.Notes {
			fmt.Fprintf(&b, "\n- Note from the run: %s\n", mdCode(n))
		}
	}

	if sc := it.SourceCheck; sc != nil {
		b.WriteString("\n**Scan of the dependency files before and after (Trivy, filesystem mode)**\n\n")
		fmt.Fprintf(&b, "- Before: %s\n", hashedFileList(sc.Before))
		fmt.Fprintf(&b, "- After: %s\n", hashedFileList(sc.After))
		fmt.Fprintf(&b, "- Resolved %d, remaining %d, introduced %d (over every package of the files, not only the updated ones)\n", sc.Counts[0], sc.Counts[1], sc.Counts[2])
		if sc.Truncated {
			b.WriteString("- The lists below are cut\n")
		}
		writeSourceVulns(&b, "Resolved", sc.Resolved, sc.Counts[0])
		writeSourceVulns(&b, "Remaining", sc.Remaining, sc.Counts[1])
		writeSourceVulns(&b, "Introduced", sc.Introduced, sc.Counts[2])
		fmt.Fprintf(&b, "\nBoth scans used Trivy %s", mdCode(sc.Conditions.TrivyVersion))
		if t := sc.Conditions.VulnerabilityDB.UpdatedAt; !t.IsZero() {
			fmt.Fprintf(&b, ", the vulnerability database built at %s", t.UTC().Format(time.RFC3339))
		}
		fmt.Fprintf(&b, ", the same severity range (%s) and the same settings; the repository's own Trivy configuration, ignore files and VEX documents were not read. The scan shows that the target vulnerabilities are no longer detected in the lockfile; it is a check of the source files, not of an image.\n",
			codeList(sc.Conditions.Severities, 10))
	}

	b.WriteString("\n## Not verified\n\n")
	b.WriteString("- Whether the image built from these files has the vulnerabilities resolved: the image is not rebuilt or scanned, and what a build installs can differ from the lockfile\n")
	b.WriteString("- Whether the application works with the updated packages, and its tests: compatibility and tests were not run\n")
	fmt.Fprintf(&b, "- Whether the dependencies in the updated files agree exactly with what the registry declares for each version, and whether the installer accepts the format: both were checked only as far as possible, so run a CI job that installs from the lockfile (for example %s) before merging\n", mdCode(installCheck(it.Manager)))
	b.WriteString("- Continuous integration; opening this pull request may start the repository's CI\n")
	b.WriteString("- Deployment after merge: merging changes the files only, and running containers keep the old image until it is built again and they are recreated\n")
	b.WriteString("- Vulnerabilities of severities outside the range above\n")

	b.WriteString("\n---\n\n")
	fmt.Fprintf(&b, "Opened by KestreLynx. Update key %s, attempt key %s.\n", mdCode(in.UpdateKey), mdCode(in.AttemptKey))

	return assembleBody(b.String(), in.Marker)
}

func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func relationText(r Relation) string {
	switch r {
	case RelationDirect:
		return "direct dependency"
	case RelationTransitive:
		return "transitive dependency"
	case RelationMixed:
		return "direct and transitive dependency"
	}
	return "relation not known"
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

func writeEntryList(b *strings.Builder, title string, entries []string) {
	if len(entries) == 0 {
		return
	}
	fmt.Fprintf(b, "%s:\n\n", title)
	for i, e := range entries {
		if i == maxListedEntries {
			fmt.Fprintf(b, "- and %d more\n", len(entries)-maxListedEntries)
			break
		}
		fmt.Fprintf(b, "- %s\n", mdCode(e))
	}
	b.WriteString("\n")
}

func hashedFileList(files []HashedFile) string {
	if len(files) == 0 {
		return "no files"
	}
	var parts []string
	for _, f := range files {
		h := f.SHA256
		if len(h) > 12 {
			h = h[:12]
		}
		parts = append(parts, f.Path+" sha256:"+h)
	}
	return codeList(parts, maxListedNames)
}

func writeSourceVulns(b *strings.Builder, title string, vs []SourceVuln, total int) {
	fmt.Fprintf(b, "\n**%s (%d)**\n\n", title, total)
	if len(vs) == 0 && total == 0 {
		b.WriteString("- none\n")
		return
	}
	shown := len(vs)
	if shown > maxListedVulns {
		shown = maxListedVulns
	}
	for _, v := range vs[:shown] {
		fmt.Fprintf(b, "- %s in %s %s", mdCode(v.VulnID), mdCode(v.Package), mdCode(v.Version))
		if v.Severity != "" {
			fmt.Fprintf(b, ", severity %s", mdCode(string(v.Severity)))
		}
		if v.KEV {
			b.WriteString(", in the CISA KEV catalog")
		}
		if v.FixedVer != "" {
			fmt.Fprintf(b, ", fixed in %s", mdCode(v.FixedVer))
		}
		b.WriteString("\n")
	}
	if total > shown {
		fmt.Fprintf(b, "- and %d more\n", total-shown)
	}
}
