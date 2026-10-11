package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// What is trusted and what is not, in this file and in the checks of an
// update's result:
//
//   - The public registries (registry.npmjs.org and pypi.org, over TLS) are
//     trusted for one thing: which distribution file (URL, integrity or
//     sha256) and which declared dependencies belong to "name at version". A
//     user's own npm ci or pip install trusts the same correspondence. The
//     contents of a distribution file are not opened and compared.
//   - The output of the work container (the lockfile, the pip report,
//     result.json) is not trusted. A claim in it is accepted only when the
//     registry's metadata or a computation of this program backs it: the file
//     recorded for each added or changed entry must be the one the registry
//     publishes for that name and version, the dependencies an entry records
//     must be the ones the registry declares, and the version an updated
//     package ended at must satisfy the ranges that bind it, which come from
//     the project's own manifest and from the registry's declarations of its
//     parents, never from the lockfile's own record of them.
//
// Every lookup is made by this program, after the name and version are
// checked, under a count, size and time bound; a registry response is cached by
// name and version, while every occurrence in the file is compared on its own.

// maxRegistryChecks bounds how many distinct package versions one update looks
// up in the registries. It is a budget of this program's, not a property of
// the output, so reaching it defers the item.
const maxRegistryChecks = 256

// errRegistryBudget: the update has used its registry lookups.
var errRegistryBudget = errors.New("the registry lookup budget of the update is used up")

// npmRelease looks up a package version in the npm registry once per update.
func (r *updateRun) npmRelease(ctx context.Context, name, version string) (NpmDist, error) {
	key := name + "@" + version
	if d, ok := r.npmDocs[key]; ok {
		return d, nil
	}
	if r.lookups >= maxRegistryChecks {
		return NpmDist{}, errRegistryBudget
	}
	r.lookups++
	d, err := r.u.cfg.Npm.VersionDist(ctx, name, version)
	if err != nil {
		return NpmDist{}, err
	}
	if r.npmDocs == nil {
		r.npmDocs = map[string]NpmDist{}
	}
	r.npmDocs[key] = d
	return d, nil
}

// pyRelease looks up a release on PyPI once per update.
func (r *updateRun) pyRelease(ctx context.Context, name, version string) (PyPIRelease, error) {
	key := normalizePyName(name) + "==" + version
	if d, ok := r.pyDocs[key]; ok {
		return d, nil
	}
	if r.lookups >= maxRegistryChecks {
		return PyPIRelease{}, errRegistryBudget
	}
	r.lookups++
	d, err := r.u.cfg.PyPI.Release(ctx, name, version)
	if err != nil {
		return PyPIRelease{}, err
	}
	if r.pyDocs == nil {
		r.pyDocs = map[string]PyPIRelease{}
	}
	r.pyDocs[key] = d
	return d, nil
}

// lookupFailure maps an error from a registry lookup.
func lookupFailure(ctx context.Context, err error, what string) *updateFailure {
	switch {
	case errors.Is(err, errRegistryBudget):
		return &updateFailure{category: CategoryDeferred, reason: ReasonRegistryCheckLimit,
			detail: fmt.Sprintf("the update needs more than the %d registry lookups one update may make (at %s)", maxRegistryChecks, what)}
	case errors.Is(err, ErrReleaseNotFound):
		return manualFailure(ReasonDistributionMismatch, "%s is not published", what)
	case ctx.Err() != nil:
		return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
	}
	return failedFailure(ReasonDistributionLookup, "look up %s: %v", what, clip(err.Error(), 200))
}

// --- ranges ---

// rangeProblem judges version ver of package n against a requirement made by
// who. It returns nil when the requirement allows the version.
func rangeProblem(n, who, spec, ver string, python bool) *updateFailure {
	var ok, evaluable bool
	if python {
		if v, parsed := parsePEP440(ver); parsed {
			ok, evaluable = pySatisfies(v, spec)
		}
	} else if v, parsed := parseSemver(ver); parsed {
		ok, evaluable = npmRangeAllows(spec, v)
	}
	switch {
	case !evaluable:
		return pkgFailure(n, ReasonRangeNotEvaluable, "%s asks for %s %q, which cannot be judged against the updated version %s", who, n, spec, ver)
	case !ok:
		return pkgFailure(n, ReasonRangeExcludesFix, "%s asks for %s %q, which the updated version %s does not satisfy", who, n, spec, ver)
	}
	return nil
}

// rootVersions returns the versions the project's own requirements resolve
// name to in the updated graph. ok is false when a requirement for it is
// unresolved or there is none. byName indexes the roots by name.
func rootVersions(g *depGraph, byName map[string][]depEdge, name string) (vers []string, ok bool) {
	for _, e := range byName[name] {
		n := g.target(e)
		if n == nil {
			return nil, false
		}
		vers = append(vers, n.version)
	}
	return uniqSorted(vers), len(vers) > 0
}

// uniqSorted returns the distinct strings of l in order.
func uniqSorted(l []string) []string {
	sort.Strings(l)
	out := l[:0]
	for i, x := range l {
		if i == 0 || x != l[i-1] {
			out = append(out, x)
		}
	}
	return out
}

// maxRangeComparisons bounds the direct-requirement comparisons of an update
// (one per distinct requirement and version).
var maxRangeComparisons = 20000

// rangeBudget counts the comparisons made against maxRangeComparisons and
// watches ctx; running out of either defers the item.
type rangeBudget struct {
	ctx context.Context
	n   int
}

func (b *rangeBudget) spend() *updateFailure {
	if b.n++; b.n > maxRangeComparisons {
		return &updateFailure{category: CategoryDeferred, reason: ReasonUpdateInputLimit,
			detail: fmt.Sprintf("the project's requirements need more than %d range comparisons", maxRangeComparisons)}
	}
	if b.n%256 == 0 {
		if err := b.ctx.Err(); err != nil {
			return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: err.Error()}
		}
	}
	return nil
}

func rootIndex(g *depGraph) map[string][]depEdge {
	out := map[string][]depEdge{}
	for _, e := range g.roots {
		out[e.name] = append(out[e.name], e)
	}
	return out
}

// checkRanges judges the versions the updated file ends at against the
// requirements that bind them.
//
// A direct dependency is determined by the project's manifest (package.json,
// or pyproject.toml), not by a flag in the lockfile. The manifest and the
// lockfile's record of the project's requirements (the root entry of
// package-lock.json, the importer of pnpm-lock.yaml, the requires-dist of the
// root package of uv.lock) must say the same about each updated package, and
// the version the lockfile resolves it to must satisfy the manifest's range.
//
// A transitive dependency is judged by every parent that requires it in the
// updated graph: the parent's range comes from what the registry declares for
// the parent's name and version. A requirement of a PyPI package that has a
// marker counts as in force here, because uv.lock holds every environment
// at once and a marker is not evaluated for it.
func (r *updateRun) checkRanges(ctx context.Context, g *depGraph, newLock []byte, check map[string]bool) *updateFailure {
	if fail := r.checkDirectRanges(ctx, g, newLock); fail != nil {
		return fail
	}
	return r.checkParentRanges(ctx, g, check)
}

func (r *updateRun) checkDirectRanges(ctx context.Context, g *depGraph, newLock []byte) *updateFailure {
	roots := rootIndex(g)
	budget := &rangeBudget{ctx: ctx}
	switch r.it.Manager {
	case ManagerNpm, ManagerPnpm:
		pj, err := readManifest(r.manifest)
		if err != nil {
			return manualFailure(ReasonDependencyFileUnusable, "%v", err)
		}
		var recorded map[string]map[string]string
		if r.it.Manager == ManagerNpm {
			entries, err := npmEntriesOf(newLock)
			if err != nil {
				return manualFailure(ReasonOutputFilesInvalid, "package-lock.json cannot be read: %v", err)
			}
			root := entries[""]
			recorded = map[string]map[string]string{
				"dependencies": root.Dependencies, "devDependencies": root.DevDependencies,
				"optionalDependencies": root.OptionalDependencies, "peerDependencies": root.PeerDependencies,
			}
		} else {
			if recorded, err = pnpmImporterSpecs(newLock); err != nil {
				return manualFailure(ReasonOutputFilesInvalid, "pnpm-lock.yaml cannot be read: %v", err)
			}
		}
		for _, n := range r.set.names {
			listed := false
			for _, field := range manifestDepFields {
				mspec, inManifest := pj.deps[field][n]
				lspec, inLock := recorded[field][n]
				if r.it.Manager == ManagerPnpm && field == "peerDependencies" {
					continue // pnpm's importer does not list peers
				}
				if inManifest != inLock || mspec != lspec {
					return pkgFailure(n, ReasonLockfileInconsistent, "package.json lists %s as %q in %s and the lockfile records %q (listed there: %v)", n, mspec, field, lspec, inLock)
				}
				listed = listed || inManifest
			}
			if !listed {
				continue
			}
			vers, ok := rootVersions(g, roots, n)
			if !ok {
				return pkgFailure(n, ReasonLockfileInconsistent, "package.json requires %s and the lockfile does not resolve it for the project", n)
			}
			for _, field := range manifestDepFields {
				if spec, ok := pj.deps[field][n]; ok {
					for _, v := range vers {
						if f := budget.spend(); f != nil {
							return f
						}
						if f := rangeProblem(n, "package.json "+field, spec, v, false); f != nil {
							return f
						}
					}
				}
			}
		}
	case ManagerUv:
		py, err := parseTOML(r.manifest)
		if err != nil {
			return manualFailure(ReasonDependencyFileUnusable, "pyproject.toml cannot be read: %v", err)
		}
		recorded, err := uvRootRequirements(newLock)
		if err != nil {
			return manualFailure(ReasonOutputFilesInvalid, "uv.lock cannot be read: %v", err)
		}
		declared := map[string][]string{}
		unreadable := map[string]bool{}
		for _, s := range pyprojectRequirements(py) {
			name, constraint, ok := pythonRequirement(s)
			if !ok {
				if m := pipNameRE.FindStringSubmatch(strings.TrimSpace(s)); m != nil {
					unreadable[normalizePyName(m[1])] = true
				}
				continue
			}
			declared[name] = append(declared[name], constraint)
		}
		for _, n := range r.set.names {
			if unreadable[n] {
				return pkgFailure(n, ReasonRangeNotEvaluable, "pyproject.toml requires %s in a form that cannot be judged", n)
			}
			mine, theirs := append([]string(nil), declared[n]...), append([]string(nil), recorded[n]...)
			sort.Strings(mine)
			sort.Strings(theirs)
			if strings.Join(mine, "\x00") != strings.Join(theirs, "\x00") {
				return pkgFailure(n, ReasonLockfileInconsistent, "pyproject.toml requires %s as %q and uv.lock records %q", n, mine, theirs)
			}
			if len(mine) == 0 {
				continue
			}
			vers, ok := rootVersions(g, roots, n)
			if !ok {
				return pkgFailure(n, ReasonLockfileInconsistent, "pyproject.toml requires %s and uv.lock does not resolve it for the project", n)
			}
			for _, c := range uniqSorted(mine) {
				for _, v := range vers {
					if f := budget.spend(); f != nil {
						return f
					}
					if f := rangeProblem(n, "pyproject.toml", c, v, true); f != nil {
						return f
					}
				}
			}
		}
	}
	return nil
}

// pnpmImporterSpecs lists the specifiers of the importer "." by group.
func pnpmImporterSpecs(lock []byte) (map[string]map[string]string, error) {
	doc, err := readPnpmLock(lock)
	if err != nil {
		return nil, err
	}
	importers := gmap(gmap(doc.top["importers"])["."])
	out := map[string]map[string]string{}
	for _, grp := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
		out[grp] = map[string]string{}
		for n, d := range gmap(importers[grp]) {
			out[grp][n] = gstr(gmap(d)["specifier"])
		}
	}
	return out, nil
}

// uvRootRequirements lists, by PEP 503 name, the version specifiers (clauses
// joined by commas, "" for none) the root package of uv.lock records in its
// metadata for the project's requirements, groups and extras included.
func uvRootRequirements(lock []byte) (map[string][]string, error) {
	doc, err := parseTOML(lock)
	if err != nil {
		return nil, err
	}
	if err := checkTOMLKeys(doc); err != nil {
		return nil, err
	}
	pkgs, _ := doc["package"].([]any)
	var meta map[string]any
	for _, p := range pkgs {
		m, _ := p.(map[string]any)
		src, _ := m["source"].(map[string]any)
		if d, _ := src["virtual"].(string); d == "." {
			meta, _ = m["metadata"].(map[string]any)
		} else if d, _ := src["editable"].(string); d == "." {
			meta, _ = m["metadata"].(map[string]any)
		}
	}
	out := map[string][]string{}
	add := func(v any) {
		list, _ := v.([]any)
		for _, e := range list {
			d, _ := e.(map[string]any)
			name, _ := d["name"].(string)
			spec, _ := d["specifier"].(string)
			clauses := []string{}
			for _, c := range strings.Split(spec, ",") {
				if c = strings.ReplaceAll(strings.TrimSpace(c), " ", ""); c != "" {
					clauses = append(clauses, c)
				}
			}
			out[normalizePyName(name)] = append(out[normalizePyName(name)], strings.Join(clauses, ","))
		}
	}
	add(meta["requires-dist"])
	groups, _ := meta["requires-dev"].(map[string]any)
	for _, l := range groups {
		add(l)
	}
	return out, nil
}

// checkParentRanges judges the version of every package that an update added,
// changed or updated by the declarations of the packages that require it, and
// the declarations of an added or changed package by the versions it requires:
// for each requirement in the updated graph whose parent or child is one of the
// entries in check, the parent's declared range for the child must allow the
// child's version. A parent or child that was not touched is judged too,
// because moving one end of a requirement can break the other end (an update
// of tar can move the mkdirp only it needs out of the range tar allows).
func (r *updateRun) checkParentRanges(ctx context.Context, g *depGraph, check map[string]bool) *updateFailure {
	var keys []string
	for k := range g.nodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	targets := r.targetSet()
	// The entries to check are marked by number once; a requirement is then
	// judged without looking up the long key of the entry it points to.
	g.link()
	checked := make([]bool, len(g.list))
	for k := range check {
		if n := g.nodes[k]; n != nil {
			checked[n.id] = true
		}
	}
	for _, k := range keys {
		parent := g.nodes[k]
		for _, e := range parent.deps {
			child := g.target(e)
			if child == nil {
				continue
			}
			if !checked[parent.id] && !checked[child.id] && !targets[parent.name] && !targets[child.name] {
				continue
			}
			who := parent.name + " " + parent.version
			switch r.it.Manager {
			case ManagerNpm, ManagerPnpm:
				d, err := r.npmRelease(ctx, parent.name, parent.version)
				if err != nil {
					return lookupFailure(ctx, err, who+" in the npm registry")
				}
				found := false
				for _, m := range []map[string]string{d.Dependencies, d.OptionalDependencies, d.peersFor(r.it.Manager)} {
					if spec, ok := m[e.name]; ok {
						found = true
						if f := rangeProblem(child.name, who, spec, child.version, false); f != nil {
							return f
						}
					}
				}
				if !found {
					return pkgFailure(child.name, ReasonDistributionMismatch, "the lockfile has %s require %s, which the registry does not list among its dependencies", who, e.name)
				}
			case ManagerUv:
				rel, err := r.pyRelease(ctx, parent.name, parent.version)
				if err != nil {
					return lookupFailure(ctx, err, who+" on PyPI")
				}
				found := false
				for _, rd := range rel.RequiresDist {
					name, constraint, _, ok := requirementOf(rd)
					if !ok || name != child.name {
						continue
					}
					found = true
					if f := rangeProblem(child.name, who, constraint, child.version, true); f != nil {
						return f
					}
				}
				if !found {
					return pkgFailure(child.name, ReasonDistributionMismatch, "the lockfile has %s require %s, which the index does not list among its requirements", who, e.name)
				}
			}
		}
	}
	return nil
}

// --- distributions ---

// checkDistributions compares each entry the update added or changed, each
// occurrence on its own, with what the public registry publishes for that
// name and version:
//
//   - the distribution file: for npm the tarball URL and integrity, for pnpm
//     the integrity, for uv every file's URL and hash. A lockfile that names the
//     right version but another file is the way a different package gets
//     installed.
//   - the dependencies: the names the entry records must be those the registry
//     declares. npm records dependencies and optionalDependencies together with
//     peerDependencies separately, and each set must match the registry's; a
//     pnpm snapshot lists the dependencies and optional dependencies and also
//     the peers it installed, so the registry's dependencies and optional
//     dependencies must all be there and nothing outside them and the peers;
//     a uv package lists the names of its requirements, and every requirement
//     of the index that has no extra in its marker must be among them (markers
//     are not evaluated) and, the other way, every name the entry records as a
//     dependency must be one the index declares (a requirement without an extra
//     for a plain dependency, a requirement for that extra for an optional one).
//     Dropping a declared dependency from an entry is the way to hide the removal
//     of what it needs, and adding an undeclared one the way to pull something
//     in.
//
// A lookup that fails is a failure of the check, not of the item's files.
func (r *updateRun) checkDistributions(ctx context.Context, g *depGraph, touched []string) *updateFailure {
	targets := r.targetSet()
	mismatch := func(n *depNode, format string, args ...any) *updateFailure {
		f := manualFailure(ReasonDistributionMismatch, "%s %s: %s", n.name, n.version, fmt.Sprintf(format, args...))
		if targets[n.name] {
			f.pkgs = map[string]updateFailureDetail{n.name: {ReasonDistributionMismatch, f.detail}}
		}
		return f
	}
	keys := append([]string(nil), touched...)
	sort.Strings(keys)
	projectLow := ""
	var tgt *worker.Target
	if r.it.Manager == ManagerUv {
		var fail *updateFailure
		if projectLow, fail = r.uvProjectPython(); fail != nil {
			return fail
		}
		if tgt, fail = r.uvTarget(); fail != nil {
			return fail
		}
	}
	var lowReach, mayInstall map[string]bool
	if r.it.Manager == ManagerUv {
		var fail *updateFailure
		if lowReach, fail = uvLowReach(ctx, g, projectLow); fail != nil {
			return fail
		}
		// An entry no requirement reaches in the image's environment (a
		// dependency for another platform, say) is not installed there, so it
		// needs no wheel for it; one whose markers cannot be decided does.
		if mayInstall, fail = uvReach(ctx, g, markerEnv{pyMinor: tgt.PythonVersion, machine: pipMachine(tgt)}, true); fail != nil {
			return fail
		}
	}
	for _, k := range keys {
		n := g.nodes[k]
		what := n.name + " " + n.version
		switch r.it.Manager {
		case ManagerNpm, ManagerPnpm:
			if !worker.ValidNpmName(n.name) || !worker.ValidSemver(n.version) || len(n.dist) != 1 {
				return mismatch(n, "not a package version the registry is asked about")
			}
			d, err := r.npmRelease(ctx, n.name, n.version)
			if err != nil {
				return lookupFailure(ctx, err, what+" in the npm registry")
			}
			if len(n.declared)+len(n.declPeers) > 2*maxDeclaredDeps {
				return mismatch(n, "%s records more than %d dependencies", k, 2*maxDeclaredDeps)
			}
			if why := installProblem(r.it.Manager, n, d); why != "" {
				return mismatch(n, "%s %s", k, why)
			}
			if r.it.Manager == ManagerNpm {
				if f := r.checkNotBundled(ctx, g, k, n, d, mismatch); f != nil {
					return f
				}
			}
			ref := n.dist[0]
			if ref.hash != d.Integrity {
				return mismatch(n, "%s records the integrity %q, the registry publishes %q", k, clip(ref.hash, 100), clip(d.Integrity, 100))
			}
			if r.it.Manager == ManagerNpm && ref.url != d.Tarball {
				return mismatch(n, "%s records the tarball %q, the registry publishes %q", k, clip(ref.url, 200), clip(d.Tarball, 200))
			}
			// The kind of each requirement is what the registry declares, not
			// what the section of the lockfile it was written in says.
			peers := d.peersFor(r.it.Manager)
			for i := range n.deps {
				_, opt := d.OptionalDependencies[n.deps[i].name]
				_, peer := peers[n.deps[i].name]
				n.deps[i].optional = opt || peer
				n.deps[i].confirmed = true
			}
			regDeps := depNames(d.Dependencies, d.OptionalDependencies)
			if r.it.Manager == ManagerNpm {
				if !sameStrings(n.declared, regDeps) || !sameStrings(n.declPeers, depNames(d.PeerDependencies)) {
					return mismatch(n, "%s records the dependencies %v (peers %v), the registry declares %v (peers %v)", k, n.declared, n.declPeers, regDeps, depNames(d.PeerDependencies))
				}
			} else {
				have, allowed := stringSet(n.declared), stringSet(regDeps)
				for _, p := range depNames(peers) {
					allowed[p] = true
				}
				for _, want := range regDeps {
					if !have[want] {
						return mismatch(n, "%s lacks the dependency %s the registry declares", k, want)
					}
				}
				for _, h := range n.declared {
					if !allowed[h] {
						return mismatch(n, "%s records the dependency %s, which the registry does not declare", k, h)
					}
				}
			}
		case ManagerUv:
			if !worker.ValidPythonName(n.name) || !worker.ValidPythonVersion(n.version) || len(n.dist) == 0 {
				return mismatch(n, "no distribution file is recorded, or not a package version the index is asked about")
			}
			if len(n.unknown) > 0 {
				return mismatch(n, "%s records the member(s) %s, which this program does not know the effect of", k, strings.Join(n.unknown, ", "))
			}
			if len(n.declared)+len(n.extraDeps) > 2*maxDeclaredDeps {
				return mismatch(n, "%s records more than %d dependencies", k, 2*maxDeclaredDeps)
			}
			rel, err := r.pyRelease(ctx, n.name, n.version)
			if err != nil {
				return lookupFailure(ctx, err, what+" on PyPI")
			}
			fitting, pythonOK := 0, 0
			// The files PyPI publishes are indexed once by location, hash and
			// kind, so that each file the entry records is looked up, not
			// searched for. A file is read (name, tags, Python) only after it
			// has matched one the index publishes.
			published := make(map[[3]string]*PyPIFile, len(rel.Files))
			for i, f := range rel.Files {
				if f.Yanked {
					continue
				}
				kind := ""
				switch {
				case f.Wheel:
					kind = "wheel"
				case f.Sdist:
					kind = "sdist"
				default:
					continue
				}
				key := [3]string{f.URL, "sha256:" + f.SHA256, kind}
				if published[key] == nil {
					published[key] = &rel.Files[i]
				}
			}
			for _, ref := range n.dist {
				base := path.Base(ref.url)
				matched := published[[3]string{ref.url, ref.hash, ref.kind}]
				if matched == nil {
					return mismatch(n, "PyPI does not publish a %s at %q with the hash %q", ref.kind, clip(ref.url, 200), clip(ref.hash, 100))
				}
				if (ref.kind == "wheel" && !wheelNameOK(base, n.name, n.version)) || (ref.kind == "sdist" && !sdistNameOK(base, n.name, n.version)) {
					return mismatch(n, "the %s file name %q is not that of %s %s", ref.kind, clip(base, 200), n.name, n.version)
				}
				spec := matched.RequiresPython
				if spec == "" {
					spec = rel.RequiresPython
				}
				if lowReach[k] {
					if f := r.checkUvPython(n, spec, projectLow); f != nil {
						return f
					}
				}
				if ref.kind == "wheel" && wheelFitsTarget(base, tgt) {
					fitting++
					if ok, decided := pythonMinorAllows(spec, tgt.PythonVersion); decided && ok {
						pythonOK++
					}
				}
			}
			// The project is installed in the image's environment: some wheel
			// must fit its tags, and be one that its Python can use. A source
			// distribution alone would be built there.
			switch {
			case !mayInstall[k]:
				// not installed in the image's environment
			case fitting == 0:
				return mismatch(n, "%s records no wheel that fits the image's environment (Python %s; %s); a source distribution alone has to be built", k, tgt.PythonVersion, strings.Join(tgt.Platforms[:min(3, len(tgt.Platforms))], ", "))
			case pythonOK == 0:
				f := pkgFailure(n.name, ReasonRequiresPythonUnsupported, "%s %s has no wheel for the image's environment whose requires-python admits Python %s", n.name, n.version, tgt.PythonVersion)
				return f
			}
			if f := r.checkUvDeclarations(ctx, n, rel, mismatch); f != nil {
				return f
			}
			// Every dependency of a package in uv.lock is required, and the
			// records were just compared with the index's.
			for i := range n.deps {
				n.deps[i].optional, n.deps[i].confirmed = false, true
			}
		}
	}
	return nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// extraNamesOf returns the extras a marker names ("extra == 'socks'"), as PEP
// 685 names, and ok is false when the marker mentions extra in a form that is
// not a plain comparison with a string.
func extraNamesOf(marker string) (names []string, ok bool) {
	rest := marker
	for {
		i := strings.Index(rest, "extra")
		if i < 0 {
			return names, true
		}
		after := strings.TrimLeft(rest[i+len("extra"):], " \t")
		op := ""
		for _, o := range []string{"==", "!="} {
			if strings.HasPrefix(after, o) {
				op = o
			}
		}
		if op == "" {
			return nil, false
		}
		after = strings.TrimLeft(after[len(op):], " \t")
		if after == "" || (after[0] != '"' && after[0] != '\'') {
			return nil, false
		}
		end := strings.IndexByte(after[1:], after[0])
		if end < 0 {
			return nil, false
		}
		names = append(names, normExtra(after[1:1+end]))
		rest = after[end+2:]
	}
}

// checkUvDeclarations compares the dependency records of a uv package with the
// requirements the index declares for it, in both directions. An extra's
// records must be requirements that name that extra. A form of record that
// cannot be put against the index is refused.
func (r *updateRun) checkUvDeclarations(ctx context.Context, n *depNode, rel PyPIRelease, mismatch func(*depNode, string, ...any) *updateFailure) *updateFailure {
	if n.otherRecords {
		return mismatch(n, "the entry has dependency records a registry package does not have")
	}
	plain := map[string]bool{} // names required in any form
	byExtra := map[string]map[string]bool{}
	noExtra := map[string]bool{} // names with a requirement that has no extra
	for _, rd := range rel.RequiresDist {
		name, _, marker, ok := requirementOf(rd)
		if !ok {
			return mismatch(n, "the index declares the requirement %q, which cannot be read", clip(rd, 100))
		}
		plain[name] = true
		extras, ok := extraNamesOf(marker)
		if !ok {
			return mismatch(n, "the index declares the requirement %q with a marker on extra that cannot be read", clip(rd, 100))
		}
		if len(extras) == 0 {
			// A requirement whose marker names only the Python version and is
			// false for every Python the project admits is never in force, so
			// an entry need not record it.
			if marker != "" {
				never, f := r.neverInForce(ctx, marker)
				if f != nil {
					return f
				}
				if never {
					continue
				}
			}
			noExtra[name] = true
		}
		for _, x := range extras {
			if byExtra[x] == nil {
				byExtra[x] = map[string]bool{}
			}
			byExtra[x][name] = true
		}
	}
	declared := stringSet(n.declared)
	for name := range noExtra {
		if !declared[name] {
			return mismatch(n, "the entry lacks the requirement %s the index declares", name)
		}
	}
	for _, have := range n.declared {
		if !plain[have] {
			return mismatch(n, "the entry records the dependency %s, which the index does not declare", have)
		}
	}
	for extra, names := range n.extraDeps {
		for _, have := range names {
			if !byExtra[extra][have] {
				return mismatch(n, "the entry records %s for the extra %s, which the index does not declare", have, extra)
			}
		}
	}
	return nil
}

// neverInForce reports whether a requirement's marker is false for every
// Python minor version the project's requires-python admits, whatever the
// platform: the marker is evaluated with only the Python version known and
// every other variable unknown, so "python_version < '3.10' and sys_platform
// == 'linux'" is false throughout where the lowest admitted Python is 3.12,
// and "python_version < '3.10' or sys_platform == 'linux'" is not. A marker
// that cannot be decided for some admitted version, or a requires-python that
// cannot be read, is not "never".
func (r *updateRun) neverInForce(ctx context.Context, marker string) (bool, *updateFailure) {
	if v, ok := r.falseThrough[marker]; ok {
		return v, nil
	}
	if r.declMarkers == nil {
		r.declMarkers = &markerBudget{ctx: ctx, max: maxMarkerEvals}
		r.falseThrough = map[string]bool{}
	}
	py, perr := parseTOML(r.manifest)
	if perr != nil {
		return false, manualFailure(ReasonDependencyFileUnusable, "pyproject.toml cannot be read: %v", perr)
	}
	project, _ := py["project"].(map[string]any)
	spec, _ := project["requires-python"].(string)
	never, admitted := true, 0
	for m := 0; m < 100 && never; m++ {
		minor := "3." + strconv.Itoa(m)
		if ok, decided := pythonMinorAllows(spec, minor); decided && !ok {
			continue
		}
		admitted++
		v, err := markerEnv{pyMinor: minor, pythonOnly: true, budget: r.declMarkers}.eval(marker)
		switch {
		case err == nil:
			never = !v
		case errors.Is(err, errMarkerUnknown):
			never = false
		default:
			return false, markerFailure(ctx, err, "the requirements of "+marker)
		}
	}
	never = never && admitted > 0
	r.falseThrough[marker] = never
	return never, nil
}

// uvProjectPython returns the lowest Python the project's requires-python
// admits.
func (r *updateRun) uvProjectPython() (string, *updateFailure) {
	py, err := parseTOML(r.manifest)
	if err != nil {
		return "", manualFailure(ReasonDependencyFileUnusable, "pyproject.toml cannot be read: %v", err)
	}
	project, _ := py["project"].(map[string]any)
	spec, _ := project["requires-python"].(string)
	low, ok := pythonLowerBound(spec)
	if !ok {
		return "", manualFailure(ReasonRequiresPythonUnsupported, "requires-python %q of pyproject.toml has no lower bound that can be read", spec)
	}
	return low, nil
}

// uvReach returns the entries of a uv.lock graph reached from the project
// through requirements whose markers are true in env, and resolved for an
// environment (resolution-markers) env belongs to. A marker that cannot be
// decided in env counts as true when undecided is set and as false when it
// is not: the first gives the entries that may be installed, the second the
// ones that surely are.
func uvReach(ctx context.Context, g *depGraph, env markerEnv, undecided bool) (map[string]bool, *updateFailure) {
	budget := &markerBudget{ctx: ctx, max: maxMarkerEvals}
	env.budget = budget
	// holds: the marker is true in env; empty is always true.
	// The answer for a marker is kept (a marker is evaluated once however
	// many edges carry it), and so is the answer for an entry's forks.
	held := map[string]bool{}
	holds := func(marker string) (bool, *updateFailure) {
		if marker == "" {
			return true, nil
		}
		if v, ok := held[marker]; ok {
			return v, nil
		}
		v, err := env.eval(marker)
		switch {
		case err == nil:
		case errors.Is(err, errMarkerUnknown):
			v = undecided
		default:
			return false, markerFailure(ctx, err, "the markers of uv.lock")
		}
		held[marker] = v
		return v, nil
	}
	forked := map[int]bool{}
	inFork := func(n *depNode) (bool, *updateFailure) {
		if len(n.resMarkers) == 0 {
			return true, nil
		}
		if v, ok := forked[n.id]; ok {
			return v, nil
		}
		result := false
		for _, m := range n.resMarkers {
			ok, f := holds(m)
			if f != nil {
				return false, f
			}
			if ok {
				result = true
				break
			}
		}
		forked[n.id] = result
		return result, nil
	}
	g.link()
	reached := make([]bool, len(g.list))
	var queue []int
	visit := func(es []depEdge) *updateFailure {
		for _, e := range es {
			t := g.target(e)
			if t == nil || reached[t.id] {
				continue
			}
			ok, f := holds(e.marker)
			if f != nil {
				return f
			}
			if !ok {
				continue
			}
			if ok, f = inFork(t); f != nil {
				return f
			} else if !ok {
				continue
			}
			reached[t.id] = true
			queue = append(queue, t.id)
		}
		return nil
	}
	if f := visit(g.roots); f != nil {
		return nil, f
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if f := visit(g.list[id].deps); f != nil {
			return nil, f
		}
	}
	out := map[string]bool{}
	for id, ok := range reached {
		if ok {
			out[g.list[id].key] = true
		}
	}
	return out, nil
}

// uvLowReach is uvReach for the lowest Python the project admits, with the
// markers that cannot be decided for that Python alone (they name the
// platform, say) counted as not reached: for such an entry the check of the
// image's own environment is the one that counts.
func uvLowReach(ctx context.Context, g *depGraph, projectLow string) (map[string]bool, *updateFailure) {
	low, ok := parsePEP440(projectLow)
	if !ok || len(low.release) < 2 {
		return nil, manualFailure(ReasonRequiresPythonUnsupported, "the project's lowest Python %q cannot be read", projectLow)
	}
	return uvReach(ctx, g, markerEnv{pyMinor: low.release[0] + "." + low.release[1]}, false)
}

// checkUvPython requires the Python a distribution file supports (its
// requires-python, or the release's) to admit the lowest Python the project
// admits: a file the project's own lowest Python cannot use makes the
// project's requires-python untrue. It is asked only of an entry that the
// lowest Python reaches (see uvLowReach).
func (r *updateRun) checkUvPython(n *depNode, spec, projectLow string) *updateFailure {
	norm, ok := normalizeSpecifier(spec)
	low, parsed := parsePEP440(projectLow)
	if !ok || !parsed {
		return manualFailure(ReasonRequiresPythonUnsupported, "%s %s: requires-python %q cannot be judged", n.name, n.version, clip(spec, 100))
	}
	if norm == "" {
		return nil
	}
	allowed, evaluable := pySatisfies(low, norm)
	if !evaluable || !allowed {
		f := manualFailure(ReasonRequiresPythonUnsupported, "%s %s asks for Python %q, which the project's lowest Python %s does not satisfy", n.name, n.version, spec, projectLow)
		f.pkgs = map[string]updateFailureDetail{n.name: {ReasonRequiresPythonUnsupported, f.detail}}
		return f
	}
	return nil
}

// Bounds on the legacy dependencies tree of a lockfileVersion 2 file.
const (
	maxNpmNameBytes   = 214 // npm's own limit on a package name
	legacyCtxInterval = 1024
)

// maxLegacyPathSum bounds the total length of the paths built from the tree.
var maxLegacyPathSum = 16 << 20

// legacyNode is one node of the legacy tree: its path as "packages" would
// name it, its members and the text of the members apart from its children.
type legacyNode struct {
	path, name string
	members    map[string]json.RawMessage
}

// walkLegacy visits the nodes of a legacy "dependencies" tree, parents
// before children, in name order. The paths are built from the names under
// bounds on a name, a path, the depth, the node count and the total length.
func walkLegacy(ctx context.Context, raw []byte, visit func(legacyNode) *updateFailure) *updateFailure {
	count, pathBytes := 0, 0
	var walk func(raw []byte, parent string, depth int) *updateFailure
	walk = func(raw []byte, parent string, depth int) *updateFailure {
		if depth > maxNpmPathDepth {
			return manualFailure(ReasonOutputFilesInvalid, "the legacy dependencies tree is nested more than %d levels", maxNpmPathDepth)
		}
		nodes, err := nameMap(raw)
		if err != nil {
			return manualFailure(ReasonOutputFilesInvalid, "the legacy dependencies tree: %v", err)
		}
		names := make([]string, 0, len(nodes))
		for name := range nodes {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if count++; count > maxGraphNodes {
				return manualFailure(ReasonOutputFilesInvalid, "the legacy dependencies tree holds more than %d entries", maxGraphNodes)
			}
			if count%legacyCtxInterval == 0 {
				if err := ctx.Err(); err != nil {
					return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: err.Error()}
				}
			}
			if len(name) == 0 || len(name) > maxNpmNameBytes || len(parent)+len(npmModules)+len(name)+1 > maxNpmPathBytes {
				return manualFailure(ReasonOutputFilesInvalid, "the legacy dependencies tree has a name or a path that is too long")
			}
			path := npmModules + name
			if parent != "" {
				path = parent + "/" + npmModules + name
			}
			if pathBytes += len(path); pathBytes > maxLegacyPathSum {
				return manualFailure(ReasonOutputFilesInvalid, "the legacy dependencies tree has more than %d bytes of paths", maxLegacyPathSum)
			}
			nm, err := strictObject(nodes[name])
			if err != nil {
				return manualFailure(ReasonOutputFilesInvalid, "the legacy dependencies tree, %s: %v", clip(name, 100), err)
			}
			if f := visit(legacyNode{path: path, name: name, members: nm}); f != nil {
				return f
			}
			if sub, ok := nm["dependencies"]; ok {
				if f := walk(sub, path, depth+1); f != nil {
					return f
				}
			}
		}
		return nil
	}
	return walk(raw, "", 0)
}

// ownText is the normalized JSON of a legacy node's members other than its
// children, which are nodes of their own.
func (n legacyNode) ownText() (string, error) {
	m := make(map[string]any, len(n.members))
	for k, v := range n.members {
		if k == "dependencies" {
			continue
		}
		x, err := decodeJSONValue(v)
		if err != nil {
			return "", err
		}
		m[k] = x
	}
	return canonicalJSON(m)
}

// legacyTable returns the legacy "dependencies" tree of a lockfile of
// version 2 and whether it has one.
func legacyTable(doc *npmLockDoc) ([]byte, bool) {
	raw, ok := doc.top["dependencies"]
	return raw, ok && doc.version == 2
}

// checkNpmLegacy compares, for every package, the legacy "dependencies" tree
// that a lockfileVersion 2 package-lock.json keeps beside "packages" with the
// entries of "packages". npm of version 6 and older install from the legacy
// tree, so a version, tarball or integrity that differs there from the one in
// "packages" is a second answer to what gets installed that nothing else
// checks. Every node of the tree must be an entry of packages at the same
// place with the same version, tarball and integrity, and every entry of
// packages that has a tarball must be in the tree; the tree may be missing
// only when the original file has none. A node of an alias or a link cannot
// be compared that way, so it must be the same, as normalized JSON, as the
// original's node at that place.
func (r *updateRun) checkNpmLegacy(ctx context.Context, newLock []byte) *updateFailure {
	doc, err := readNpmLock(newLock)
	if err != nil {
		return manualFailure(ReasonOutputFilesInvalid, "%v", err)
	}
	orig, err := readNpmLock(r.src.lock)
	if err != nil {
		return manualFailure(ReasonOutputFilesInvalid, "the original package-lock.json: %v", err)
	}
	raw, ok := legacyTable(doc)
	origRaw, origHas := legacyTable(orig)
	switch {
	case doc.version != 2:
		return nil
	case !ok && origHas:
		return manualFailure(ReasonOutputFilesInvalid, "the updated package-lock.json lacks the legacy dependencies tree the original has")
	case !ok:
		return nil
	}
	bad := func(format string, args ...any) *updateFailure {
		return manualFailure(ReasonDistributionMismatch, "the legacy dependencies tree of package-lock.json "+format, args...)
	}
	// The original's alias and link nodes.
	origOwn := map[string]string{}
	if origHas {
		f := walkLegacy(ctx, origRaw, func(n legacyNode) *updateFailure {
			e, found := orig.entries[n.path]
			if found && !legacyComparable(e, n.name) {
				t, err := n.ownText()
				if err != nil {
					return manualFailure(ReasonOutputFilesInvalid, "the original's legacy dependencies tree, %s: %v", clip(n.name, 100), err)
				}
				origOwn[n.path] = t
			}
			return nil
		})
		if f != nil {
			return f
		}
	}
	seen := map[string]bool{}
	f := walkLegacy(ctx, raw, func(n legacyNode) *updateFailure {
		seen[n.path] = true
		e, found := doc.entries[n.path]
		if found && !legacyComparable(e, n.name) {
			t, err := n.ownText()
			if err != nil {
				return manualFailure(ReasonOutputFilesInvalid, "the legacy dependencies tree, %s: %v", clip(n.name, 100), err)
			}
			if want, had := origOwn[n.path]; !had || want != t {
				return bad("has a node for %s at %s that is an alias or a link and differs from the original's", clip(n.name, 100), clip(n.path, 200))
			}
			return nil
		}
		ver, err1 := optString(n.members, "version")
		res, err2 := optString(n.members, "resolved")
		integ, err3 := optString(n.members, "integrity")
		if err := errors.Join(err1, err2, err3); err != nil {
			return manualFailure(ReasonOutputFilesInvalid, "the legacy dependencies tree, %s: %v", clip(n.name, 100), err)
		}
		if !found || e.Version != ver || e.Resolved != res || e.Integrity != integ {
			f := bad("gives %s at %s (%q, %q, %q) where packages gives %q (%q, %q)", clip(n.name, 100), clip(n.path, 200), ver, clip(res, 100), clip(integ, 40), e.Version, clip(e.Resolved, 100), clip(e.Integrity, 40))
			if r.targetSet()[n.name] {
				f.pkgs = map[string]updateFailureDetail{n.name: {ReasonDistributionMismatch, f.detail}}
			}
			return f
		}
		return nil
	})
	if f != nil {
		return f
	}
	var missing []string
	for path, e := range doc.entries {
		if path == "" || seen[path] {
			continue
		}
		if _, was := origOwn[path]; was || (e.Resolved != "" && !e.Link) {
			missing = append(missing, path)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return bad("lacks %s, which packages lists", clip(missing[0], 200))
	}
	return nil
}

// legacyComparable reports whether an entry of packages is a registry entry
// whose version, tarball and integrity the legacy node repeats: not a link,
// and not installed under another name than its path's.
func legacyComparable(e npmGraphEntry, name string) bool {
	return !e.Link && (e.Name == "" || e.Name == name)
}

// stringSet returns the elements of s as a set.
func stringSet(s []string) map[string]bool {
	out := make(map[string]bool, len(s))
	for _, x := range s {
		out[x] = true
	}
	return out
}

// uvTarget decides the environment the project's packages are installed in
// from the scanned image the same way a pip update does: the Python version
// from where the packages were found, the platform tags from the image's
// operating system and architecture. It is the environment a wheel is judged
// against.
func (r *updateRun) uvTarget() (*worker.Target, *updateFailure) {
	var pkgs []LanguagePackage
	for _, i := range r.set.idx {
		pkgs = append(pkgs, r.it.Packages[i])
	}
	t, undecided, mismatch, why := pipTargetOf(pkgs, r.u.cfg.Images)
	switch {
	case undecided:
		return nil, manualFailure(ReasonPipTargetUndecidable, "the environment the packages run in cannot be decided: %s", why)
	case mismatch:
		return nil, manualFailure(ReasonPipTargetMismatch, "%s", why)
	}
	return t, nil
}

// installProblem compares what a lockfile entry of npm or pnpm records about
// how the package is installed with what the registry publishes for the
// version, and refuses what it does not know: members of the entry outside
// the format, flags that place the entry outside the tree, a platform
// restriction, engines, commands, bundled or optional-peer lists that differ.
func installProblem(m DependencyManager, n *depNode, d NpmDist) string {
	if len(n.unknown) > 0 {
		return "records the member(s) " + strings.Join(n.unknown, ", ") + ", which this program does not know the effect of"
	}
	if n.installErr != "" {
		return "records install fields that cannot be read: " + n.installErr
	}
	if n.flags["inBundle"] || n.flags["extraneous"] {
		return "is recorded as bundled in another package or as extraneous, which an updated entry is not"
	}
	reg := d.Install
	if m == ManagerPnpm {
		reg = map[string]string{}
		for k, v := range d.Install {
			reg[k] = v
		}
		if reg["bin"] != "" {
			reg["bin"] = "present"
		}
		// pnpm leaves an engine whose range is "*" out of the lockfile, and
		// the member with it when none is left.
		if eng, ok := asStringMap(json.RawMessage(reg["engines"])); ok {
			for k, v := range eng {
				if v == "*" {
					delete(eng, k)
				}
			}
			if len(eng) == 0 {
				delete(reg, "engines")
			} else {
				reg["engines"] = plainJSON(eng)
			}
		}
	}
	if k, x, y, same := sameRecord(n.install, reg); !same {
		return fmt.Sprintf("records %s as %q where the registry has %q", k, clip(x, 100), clip(y, 100))
	}
	peers := d.peersFor(m)
	if !sameMap(n.peerRanges, peers) {
		return "records peer dependency ranges that differ from the registry's"
	}
	return ""
}

// checkFlags compares the flags a lockfile records for the entries an update
// added or changed with the ones the dependency graph gives them. An entry is
// dev if every path to it from the project passes a development dependency,
// optional if every path passes an optional dependency (or an optional peer),
// and devOptional if every path passes one or the other; a package manager
// leaves such an entry out of a production install or an install without
// optional dependencies, so the flags decide what is installed. npm records
// all three; pnpm records optional on a snapshot.
func (r *updateRun) checkFlags(g *depGraph, touched []string) *updateFailure {
	g.link()
	reach := func(startOK func(depEdge) bool, edgeOK func(depEdge) bool) map[string]bool {
		var starts []int
		for _, e := range g.roots {
			if e.to >= 0 && startOK(e) {
				starts = append(starts, e.to)
			}
		}
		seen := make([]bool, len(g.list))
		for len(starts) > 0 {
			id := starts[len(starts)-1]
			starts = starts[:len(starts)-1]
			if seen[id] {
				continue
			}
			seen[id] = true
			for _, e := range g.list[id].deps {
				if e.to >= 0 && edgeOK(e) && !seen[e.to] {
					starts = append(starts, e.to)
				}
			}
		}
		out := map[string]bool{}
		for id, ok := range seen {
			if ok {
				out[g.list[id].key] = true
			}
		}
		return out
	}
	all := func(depEdge) bool { return true }
	nonSoft := func(e depEdge) bool { return !e.soft }
	nonDev := reach(func(e depEdge) bool { return !e.dev }, all)
	nonOpt := reach(func(e depEdge) bool { return !e.soft }, nonSoft)
	nonDevNonOpt := reach(func(e depEdge) bool { return !e.dev && !e.soft }, nonSoft)
	keys := append([]string(nil), touched...)
	sort.Strings(keys)
	for _, k := range keys {
		n := g.nodes[k]
		want := map[string]bool{}
		if r.it.Manager == ManagerNpm {
			dev := !nonDev[k]
			opt := !nonOpt[k]
			want["dev"], want["optional"] = dev, opt
			want["devOptional"] = !nonDevNonOpt[k] && !dev && !opt
		} else {
			want["optional"] = !nonOpt[k]
		}
		for _, f := range []string{"dev", "optional", "devOptional"} {
			if r.it.Manager == ManagerPnpm && f != "optional" {
				continue
			}
			if n.flags[f] != want[f] {
				return manualFailure(ReasonDistributionMismatch, "%s %s: %s records %s=%v where its place in the dependency graph gives %v", n.name, n.version, k, f, n.flags[f], want[f])
			}
		}
	}
	return nil
}

func sameMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// checkNotBundled refuses an entry that npm may install from the tarball of
// a package: one that bundles dependencies or carries its own
// npm-shrinkwrap.json (which npm reads again after unpacking it), or is nested
// below a package that does. Which entries are in a bundle is not what the entry says
// (its inBundle flag is the tool's output) and not only the names a package
// lists: npm puts what a bundled package needs in the same bundle. So the
// rule is computed here and is the cautious one: if the entry, or any package
// it is nested in, has a non-empty bundleDependencies (or true) in the
// lockfile's record or in the registry's declaration for its version, the
// entry is taken to be in a bundle, whatever its name. The contents of a
// bundle are not compared with anything, so an update of such an entry is
// left to a person. d is the registry's document for the entry itself.
func (r *updateRun) checkNotBundled(ctx context.Context, g *depGraph, k string, n *depNode, d NpmDist, mismatch func(*depNode, string, ...any) *updateFailure) *updateFailure {
	if recordBundlesAnything(n.install["bundleDependencies"]) || recordBundlesAnything(d.Install["bundleDependencies"]) {
		return mismatch(n, "%s bundles dependencies itself", k)
	}
	if n.flags["hasShrinkwrap"] || d.HasShrinkwrap {
		return mismatch(n, "%s carries its own npm-shrinkwrap.json", k)
	}
	for _, anc := range npmAncestors(k) {
		p := g.nodes[anc]
		if p == nil {
			return mismatch(n, "%s is nested in %s, which the file has no entry for", k, clip(anc, 100))
		}
		if recordBundlesAnything(p.install["bundleDependencies"]) || p.flags["hasShrinkwrap"] {
			return mismatch(n, "%s is nested in %s %s, which bundles dependencies or carries its own npm-shrinkwrap.json according to the lockfile", k, p.name, p.version)
		}
		pd, err := r.npmRelease(ctx, p.name, p.version)
		if err != nil {
			return lookupFailure(ctx, err, p.name+" "+p.version+" in the npm registry")
		}
		if recordBundlesAnything(pd.Install["bundleDependencies"]) || pd.HasShrinkwrap {
			return mismatch(n, "%s is nested in %s %s, which bundles dependencies or carries its own npm-shrinkwrap.json according to the registry", k, p.name, p.version)
		}
	}
	return nil
}
