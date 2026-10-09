package remediation

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func typedFinding(typ, vuln, pkg, ver, fixed string) scanner.Finding {
	return scanner.Finding{
		Class: inventory.ClassLang, Type: typ, Target: "Node.js", Package: pkg, InstalledVer: ver, FixedVer: fixed,
		Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: vuln,
	}
}

func nodeFinding(vuln, pkg, ver, fixed string) scanner.Finding {
	return typedFinding("node-pkg", vuln, pkg, ver, fixed)
}

func pyFinding(vuln, pkg, ver, fixed string) scanner.Finding {
	return typedFinding("python-pkg", vuln, pkg, ver, fixed)
}

// sources wraps findings as they come from one scanned image of the api
// service.
func sources(fs ...scanner.Finding) []srcFinding {
	var out []srcFinding
	for _, f := range fs {
		out = append(out, srcFinding{f: f, entity: "config:sha256:aa", workloads: []string{"compose/shop/api"}})
	}
	return out
}

func TestGroupLanguageFindings(t *testing.T) {
	kevIntel := func(id string) (VulnIntel, bool) {
		if id == "CVE-2" {
			return VulnIntel{Priority: PriorityActNow, KEV: true}, true
		}
		return VulnIntel{}, false
	}
	other := nodeFinding("CVE-9", "os-thing", "1.0.0", "")
	other.Status = scanner.StatusAffected
	osf := finding("CVE-3", "libc", "1", "2", scanner.SeverityHigh)
	gs := groupLanguageFindings(sources(
		nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"),
		nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"), // the same finding from a second path
		nodeFinding("CVE-2", "lodash", "4.17.20", "4.17.19, 5.0.0"),
		nodeFinding("CVE-4", "qs", "6.11.0", "6.11.1"),
		pyFinding("CVE-5", "Typing_Extensions", "4.5.0", "4.6.0"),
		pyFinding("CVE-6", "typing-extensions", "4.5.0", "4.6.1"),
		other, osf,
	), kevIntel)
	if len(gs) != 3 {
		t.Fatalf("groups = %d, want 3 (lodash, qs, typing-extensions)", len(gs))
	}
	if gs[0].Name != "lodash" || gs[0].priority != PriorityActNow {
		t.Errorf("the strongest group comes first: %+v", gs[0])
	}
	if len(gs[0].cves) != 2 || gs[0].cves[1].VulnID != "CVE-2" || !gs[0].cves[1].KEV {
		t.Errorf("lodash cves = %+v", gs[0].cves)
	}
	if got := gs[0].cves[1].FixedVers; len(got) != 2 || got[0] != "4.17.19" || got[1] != "5.0.0" {
		t.Errorf("alternatives are split: %v", got)
	}
	var py *findingGroup
	for _, g := range gs {
		if g.Type == "python-pkg" {
			py = g
		}
	}
	if py == nil || len(py.cves) != 2 {
		t.Fatalf("python names are grouped by their normalized form: %+v", py)
	}
}

func lockOf(t *testing.T, m DependencyManager, files ...string) *lockfile {
	t.Helper()
	var l *lockfile
	var err error
	switch m {
	case ManagerNpm:
		l, err = parseNpm([]byte(npmManifest), []byte(files[0]))
	case ManagerPnpm:
		l, err = parsePnpm([]byte(pnpmManifest), []byte(files[0]))
	case ManagerUv:
		l, err = parseUv([]byte(uvPyproject), []byte(files[0]))
	default:
		l, err = parseRequirements([]byte(files[0]))
	}
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func match(t *testing.T, l *lockfile, fs ...scanner.Finding) []LanguagePackage {
	t.Helper()
	var out []LanguagePackage
	for _, g := range groupLanguageFindings(sources(fs...), nil) {
		out = append(out, matchPackage(l, g))
	}
	reconcileVersions(l, out)
	return out
}

func find(t *testing.T, ps []LanguagePackage, name, ver string) LanguagePackage {
	t.Helper()
	for _, p := range ps {
		if p.Name == name && p.Installed == ver {
			return p
		}
	}
	t.Fatalf("no package %s %s in %+v", name, ver, ps)
	return LanguagePackage{}
}

func TestMatchNpm(t *testing.T) {
	l := lockOf(t, ManagerNpm, npmLockV3)
	ps := match(t, l,
		nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"),
		nodeFinding("CVE-2", "qs", "6.11.0", "6.11.3"),
		nodeFinding("CVE-3", "ghost", "1.0.0", "1.0.1"),
		nodeFinding("CVE-4", "mylib", "1.0.0", "1.0.1"),
		nodeFinding("CVE-5", "lodash-es", "4.17.20", "4.17.21"),
	)

	lodash := find(t, ps, "lodash", "4.17.20")
	if lodash.Action != ActionUpdate || lodash.SelectionLowerBound != "4.17.21" || lodash.Relation != RelationDirect || lodash.AdoptedVersion != "" {
		t.Errorf("lodash = %+v", lodash)
	}
	if len(lodash.Occurrences) != 1 || !lodash.Occurrences[0].Matched {
		t.Errorf("lodash occurrences = %+v", lodash.Occurrences)
	}

	// qs is installed twice at different versions; the image runs 6.11.0
	// (nested under express). The other copy, 6.11.2, is below the target
	// and has no finding, so this is not one update.
	qs := find(t, ps, "qs", "6.11.0")
	if qs.Action != ActionManual || qs.Reason != ReasonMultipleVersions {
		t.Errorf("qs = %+v", qs)
	}
	if len(qs.Occurrences) != 2 {
		t.Errorf("the occurrences are kept: %+v", qs.Occurrences)
	}

	if p := find(t, ps, "ghost", "1.0.0"); p.Action != ActionManual || p.Reason != ReasonNotFoundInSource {
		t.Errorf("ghost = %+v", p)
	}
	if p := find(t, ps, "mylib", "1.0.0"); p.Action != ActionManual || p.Reason != ReasonNonRegistrySource {
		t.Errorf("a git dependency = %+v", p)
	}
	if p := find(t, ps, "lodash-es", "4.17.20"); p.Reason != ReasonNotFoundInSource {
		t.Errorf("a name that only resembles a listed one = %+v", p)
	}
}

func TestMatchNpmInstalledVersionNotListed(t *testing.T) {
	l := lockOf(t, ManagerNpm, npmLockV3)
	p := match(t, l, nodeFinding("CVE-1", "lodash", "4.17.15", "4.17.21"))[0]
	if p.Action != ActionManual || p.Reason != ReasonNotFoundInSource {
		t.Errorf("a version the files do not list = %+v", p)
	}
}

func TestMatchTransitiveAndSharedTargets(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{
	  "":{"dependencies":{"a":"1"}},
	  "node_modules/a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz"},
	  "node_modules/semver":{"version":"7.5.1","resolved":"https://registry.npmjs.org/semver/-/semver-7.5.1.tgz"},
	  "node_modules/a/node_modules/semver":{"version":"7.5.2","resolved":"https://registry.npmjs.org/semver/-/semver-7.5.2.tgz"},
	  "node_modules/b/node_modules/semver":{"version":"6.3.0","resolved":"https://registry.npmjs.org/semver/-/semver-6.3.0.tgz"}
	}}`
	l, err := parseNpm([]byte(npmManifest), []byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	// Two installed versions with the same target are one update when every
	// other copy is covered or already at the target.
	ps := match(t, l,
		nodeFinding("CVE-1", "semver", "7.5.1", "7.5.2"),
		nodeFinding("CVE-1", "semver", "6.3.0", "7.5.2"),
	)
	for _, p := range ps {
		if p.Action != ActionUpdate || p.SelectionLowerBound != "7.5.2" || p.Relation != RelationTransitive || len(p.Occurrences) != 3 {
			t.Errorf("%s %s = %+v", p.Name, p.Installed, p)
		}
	}
	// Different targets per version are not one update.
	ps = match(t, l,
		nodeFinding("CVE-1", "semver", "7.5.1", "7.5.2"),
		nodeFinding("CVE-2", "semver", "6.3.0", "6.3.1"),
	)
	for _, p := range ps {
		if p.Action != ActionManual || p.Reason != ReasonMultipleVersions {
			t.Errorf("%s %s = %+v", p.Name, p.Installed, p)
		}
	}
}

func TestMatchPnpmPeerContextOccurrences(t *testing.T) {
	l := lockOf(t, ManagerPnpm, pnpmLock)
	ps := match(t, l,
		nodeFinding("CVE-1", "react-dom", "18.2.0", "18.3.0"),
		nodeFinding("CVE-2", "scheduler", "0.23.0", "0.23.1"),
		nodeFinding("CVE-3", "tarball-pkg", "1.0.0", "1.0.1"),
		nodeFinding("CVE-4", "local-lib", "1.0.0", "1.0.1"),
	)
	if p := find(t, ps, "react-dom", "18.2.0"); p.Action != ActionUpdate || p.Relation != RelationDirect || p.SelectionLowerBound != "18.3.0" {
		t.Errorf("react-dom = %+v", p)
	}
	if p := find(t, ps, "scheduler", "0.23.0"); p.Action != ActionUpdate || p.Relation != RelationTransitive {
		t.Errorf("scheduler = %+v", p)
	}
	if p := find(t, ps, "tarball-pkg", "1.0.0"); p.Reason != ReasonNonRegistrySource {
		t.Errorf("tarball-pkg = %+v", p)
	}
	if p := find(t, ps, "local-lib", "1.0.0"); p.Reason != ReasonNonRegistrySource {
		t.Errorf("a linked dependency whose version cannot match = %+v", p)
	}
}

func TestMatchUv(t *testing.T) {
	l := lockOf(t, ManagerUv, uvLock)
	ps := match(t, l,
		pyFinding("CVE-1", "requests", "2.31.0", "2.32.0"),
		pyFinding("CVE-2", "Certifi", "2024.2.2", "2024.7.4"),
		pyFinding("CVE-3", "oldpkg", "1.0.0", "1.0.1"),
		pyFinding("CVE-4", "gitpkg", "0.2.0", "0.2.1"),
		pyFinding("CVE-5", "flask_cors", "4.0.0", "4.0.2"),
	)
	if p := find(t, ps, "requests", "2.31.0"); p.Action != ActionUpdate || p.Relation != RelationDirect || p.Normalized != "requests" {
		t.Errorf("requests = %+v", p)
	}
	if p := find(t, ps, "Certifi", "2024.2.2"); p.Action != ActionUpdate || p.Relation != RelationTransitive || p.Normalized != "certifi" {
		t.Errorf("a differently spelled name still matches: %+v", p)
	}
	if p := find(t, ps, "oldpkg", "1.0.0"); p.Reason != ReasonSdistOnly {
		t.Errorf("sdist only = %+v", p)
	}
	if p := find(t, ps, "gitpkg", "0.2.0"); p.Reason != ReasonNonRegistrySource {
		t.Errorf("git source = %+v", p)
	}
	if p := find(t, ps, "flask_cors", "4.0.0"); p.Action != ActionUpdate {
		t.Errorf("flask_cors = %+v", p)
	}
}

func TestMatchPip(t *testing.T) {
	l := lockOf(t, ManagerPip, requirements)
	ps := match(t, l,
		pyFinding("CVE-1", "requests", "2.31.0", "2.32.0"),
		pyFinding("CVE-2", "urllib3", "1.26.18", "2.2.2"), // >=1.26,<3 allows it
		pyFinding("CVE-3", "Django", "4.2.0", "4.2.14"),   // no version: rebuild
		pyFinding("CVE-4", "PyYAML", "6.0.0", "7.0.0"),    // ~=6.0 excludes 7
		pyFinding("CVE-5", "numpy", "1.26.4", "1.26.5"),   // pin with extras
		pyFinding("CVE-6", "idna", "3.4", "3.7"),          // not listed
		pyFinding("CVE-7", "direct", "1.0", "1.1"),        // direct reference
	)
	if p := find(t, ps, "requests", "2.31.0"); p.Action != ActionUpdate || p.Relation != RelationDirect || p.SelectionLowerBound != "2.32.0" {
		t.Errorf("requests = %+v", p)
	}
	if p := find(t, ps, "urllib3", "1.26.18"); p.Action != ActionRebuildExpected || p.Reason != ReasonRangeAllowsFix {
		t.Errorf("urllib3 = %+v", p)
	}
	if p := find(t, ps, "Django", "4.2.0"); p.Action != ActionRebuildExpected {
		t.Errorf("an unversioned requirement = %+v", p)
	}
	if p := find(t, ps, "PyYAML", "6.0.0"); p.Action != ActionManual || p.Reason != ReasonRangeExcludesFix {
		t.Errorf("PyYAML = %+v", p)
	}
	if p := find(t, ps, "numpy", "1.26.4"); p.Action != ActionUpdate {
		t.Errorf("numpy = %+v", p)
	}
	if p := find(t, ps, "idna", "3.4"); p.Reason != ReasonNotFoundInSource {
		t.Errorf("idna = %+v", p)
	}
	if p := find(t, ps, "direct", "1.0"); p.Reason != ReasonNonRegistrySource {
		t.Errorf("a URL requirement = %+v", p)
	}
}

func TestMatchPipPinnedTwice(t *testing.T) {
	l := lockOf(t, ManagerPip, "foo==1.0\nfoo==2.0\nbar==1.0\nbar>=0.5\n")
	ps := match(t, l,
		pyFinding("CVE-1", "foo", "1.0", "1.1"),
		pyFinding("CVE-2", "foo", "2.0", "2.1"),
		pyFinding("CVE-3", "bar", "1.0", "1.2"),
	)
	// Different targets for the two pins, and a pin next to a range: none of
	// these is one update.
	for _, p := range ps {
		if p.Action != ActionManual || p.Reason != ReasonMultipleVersions {
			t.Errorf("%s %s = %+v", p.Name, p.Installed, p)
		}
	}
	// The same target for both pins is one update.
	ps = match(t, l,
		pyFinding("CVE-1", "foo", "1.0", "2.1"),
		pyFinding("CVE-2", "foo", "2.0", "2.1"),
	)
	for _, p := range ps {
		if p.Action != ActionUpdate {
			t.Errorf("%s %s = %+v", p.Name, p.Installed, p)
		}
	}
}

func TestMatchPipMarkersAreNotEvaluated(t *testing.T) {
	l := lockOf(t, ManagerPip, "foo==1.0 ; python_version<'3.9'\nbar>=1 ; sys_platform=='win32'\nbaz==1.0 ; (python_version<'3.9'\nqux[security,socks]==2.0\n")
	ps := match(t, l,
		pyFinding("CVE-1", "foo", "1.0", "1.1"),
		pyFinding("CVE-2", "bar", "1.5", "1.6"),
		pyFinding("CVE-3", "baz", "1.0", "1.1"),
		pyFinding("CVE-4", "qux", "2.0", "2.1"),
	)
	if p := find(t, ps, "foo", "1.0"); p.Action != ActionManual || p.Reason != ReasonMarkerNotEvaluated {
		t.Errorf("a pin with a marker = %+v", p)
	}
	if p := find(t, ps, "bar", "1.5"); p.Action != ActionManual || p.Reason != ReasonMarkerNotEvaluated {
		t.Errorf("a range with a marker is not a rebuild expectation = %+v", p)
	}
	if p := find(t, ps, "baz", "1.0"); p.Action != ActionManual || p.Reason != ReasonInvalidMarker {
		t.Errorf("an invalid marker = %+v", p)
	}
	// Extras are recorded and do not stop the pin from being a candidate.
	qux := find(t, ps, "qux", "2.0")
	if qux.Action != ActionUpdate || len(qux.Occurrences[0].Extras) != 2 || qux.Occurrences[0].Extras[0] != "security" {
		t.Errorf("qux = %+v", qux)
	}
}

func TestMatchPipPrereleaseTargetIsNotExpected(t *testing.T) {
	l := lockOf(t, ManagerPip, "foo>=1.0\n")
	p := match(t, l, pyFinding("CVE-1", "foo", "1.0", "2.0rc1"))[0]
	if p.Action != ActionManual || p.Reason != ReasonRangeNotEvaluable {
		t.Errorf("a pre-release fix is not something a rebuild takes: %+v", p)
	}
}

func TestMatchForcedByOverride(t *testing.T) {
	l, err := parseNpm([]byte(`{"overrides":{"lodash":"4.17.20"}}`), []byte(`{"lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"4"}},"node_modules/lodash":{"version":"4.17.20","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	p := match(t, l, nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.21"))[0]
	if p.Action != ActionManual || p.Reason != ReasonForcedByOverride {
		t.Errorf("lodash = %+v", p)
	}
}

func TestMatchTargetFailuresAreManual(t *testing.T) {
	l := lockOf(t, ManagerNpm, npmLockV3)
	ps := match(t, l,
		nodeFinding("CVE-1", "lodash", "4.17.20", "4.17.19"),
		nodeFinding("CVE-2", "jest", "29.7.0", "see advisory"),
	)
	if p := find(t, ps, "lodash", "4.17.20"); p.Reason != ReasonNoFixedVersion {
		t.Errorf("lodash = %+v", p)
	}
	if p := find(t, ps, "jest", "29.7.0"); p.Reason != ReasonUnparsableVersion {
		t.Errorf("jest = %+v", p)
	}
}
