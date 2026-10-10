package remediation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// workImagePython is the one Python the work image has; uv locks with it, so
// a project whose requires-python does not admit it cannot be locked there.
const workImagePython = "3.13.16"

// run reads the unit's files and carries out the update of its manager.
func (r *updateRun) run(ctx context.Context) *updateFailure {
	src, fail := r.u.readSources(ctx, r.it)
	if fail != nil {
		return fail
	}
	r.src = src
	var out *updateFailure
	switch r.it.Manager {
	case ManagerNpm:
		out = r.runNpm(ctx)
	case ManagerPnpm:
		out = r.runPnpm(ctx)
	case ManagerUv:
		out = r.runUv(ctx)
	case ManagerPip:
		out = r.runPip(ctx)
	default:
		out = failedFailure(ReasonUpdateInputInvalid, "unknown manager %q", r.it.Manager)
	}
	r.upd.Notes = uniqueSorted(r.upd.Notes)
	return out
}

// exec runs one job of the update and notes whether its update step ran.
func (r *updateRun) exec(ctx context.Context, m worker.Manager, inputs map[string][]byte, steps []worker.Step, role string) (*jobOutput, *updateFailure) {
	out, fail := r.u.execute(ctx, r.u.newJob(m, inputs, steps), inputs, r.u.jobID(r.n, role), r.upd)
	if out != nil {
		for _, s := range out.result.Steps {
			if s.ID == stepUpdate && s.ExitCode == 0 && !s.TimedOut && s.Error == "" {
				r.it.UpdateExecuted = true
			}
		}
	}
	return out, fail
}

// packageArgs lists the packages the update step names, one per matching
// name, with a version where withVersion says so.
func (r *updateRun) packageArgs(withVersion func(name string) bool) []worker.Package {
	var out []worker.Package
	for _, n := range r.set.names {
		p := worker.Package{Name: r.nameOf(n)}
		if withVersion(n) {
			p.Version = r.set.target[n]
		}
		out = append(out, p)
	}
	return out
}

// nameOf returns the name as the image reports it for a matching name.
func (r *updateRun) nameOf(match string) string {
	for _, i := range r.set.idx {
		if p := r.it.Packages[i]; p.matchName() == match {
			return p.Name
		}
	}
	return match
}

// isDirect reports whether the package named by match is required by the
// project itself in any occurrence that is being updated.
func (r *updateRun) isDirect(match string) bool {
	for _, i := range r.set.idx {
		p := r.it.Packages[i]
		if p.matchName() != match {
			continue
		}
		for _, o := range p.Occurrences {
			if o.Matched && o.Direct {
				return true
			}
		}
	}
	return false
}

// --- manifest checks (before the update) ---

// checkNodeManifest requires the package.json range of every direct package
// to allow its target: this stage does not edit a manifest.
func (r *updateRun) checkNodeManifest() *updateFailure {
	pj, err := readManifest(r.src.manifest)
	if err != nil {
		return manualFailure(ReasonDependencyFileUnusable, "%v", err)
	}
	f := &updateFailure{category: CategoryManual, reason: ReasonManifestEditRequired, pkgs: map[string]updateFailureDetail{}}
	for _, n := range r.set.names {
		if !r.isDirect(n) {
			continue
		}
		tv, ok := parseSemver(r.set.target[n])
		for _, field := range manifestDepFields {
			spec, listed := pj.deps[field][n]
			if !listed {
				continue
			}
			allowed, evaluable := false, false
			if ok {
				allowed, evaluable = npmRangeAllows(spec, tv)
			}
			switch {
			case !evaluable:
				f.pkgs[n] = updateFailureDetail{ReasonManifestEditRequired, fmt.Sprintf("package.json asks for %s %q in %s, which cannot be judged against %s", n, spec, field, r.set.target[n])}
			case !allowed:
				f.pkgs[n] = updateFailureDetail{ReasonManifestEditRequired, fmt.Sprintf("package.json asks for %s %q in %s, which does not allow %s; the manifest would have to be edited", n, spec, field, r.set.target[n])}
			}
		}
	}
	if len(f.pkgs) == 0 {
		return nil
	}
	f.detail = firstDetail(f.pkgs)
	return f
}

// firstDetail is the detail of the first package (by name) in a failure.
func firstDetail(m map[string]updateFailureDetail) string {
	var names []string
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	d := m[names[0]].detail
	if len(names) > 1 {
		d += fmt.Sprintf(" (and %d more)", len(names)-1)
	}
	return d
}

// pyprojectRequirements lists the requirement strings of a pyproject.toml's
// dependencies: the project's, its optional ones, the dependency groups and
// the uv development dependencies.
func pyprojectRequirements(py map[string]any) []string {
	var out []string
	add := func(v any) {
		list, _ := v.([]any)
		for _, e := range list {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	}
	project, _ := py["project"].(map[string]any)
	add(project["dependencies"])
	opt, _ := project["optional-dependencies"].(map[string]any)
	for _, v := range opt {
		add(v)
	}
	groups, _ := py["dependency-groups"].(map[string]any)
	for _, v := range groups {
		add(v)
	}
	tool, _ := py["tool"].(map[string]any)
	uv, _ := tool["uv"].(map[string]any)
	add(uv["dev-dependencies"])
	return out
}

// checkUvProject requires the project to be lockable in the work image and
// the specifier of every direct package to allow its target.
func (r *updateRun) checkUvProject() *updateFailure {
	py, err := parseTOML(r.src.manifest)
	if err != nil {
		return manualFailure(ReasonDependencyFileUnusable, "pyproject.toml cannot be read: %v", err)
	}
	project, _ := py["project"].(map[string]any)
	rp, present := project["requires-python"]
	spec, isStr := rp.(string)
	if !present || !isStr {
		return manualFailure(ReasonRequiresPythonUnsupported, "pyproject.toml has no requires-python; uv would lock for the work image's Python %s", workImagePython)
	}
	var clauses []string
	for _, c := range strings.Split(spec, ",") {
		cm := pipClauseRE.FindStringSubmatch(strings.TrimSpace(c))
		if cm == nil {
			return manualFailure(ReasonRequiresPythonUnsupported, "requires-python %q cannot be read", spec)
		}
		clauses = append(clauses, cm[1]+cm[2])
	}
	pv, _ := parsePEP440(workImagePython)
	if ok, evaluable := pySatisfies(pv, strings.Join(clauses, ",")); !evaluable || !ok {
		return manualFailure(ReasonRequiresPythonUnsupported, "requires-python %q does not admit the work image's Python %s", spec, workImagePython)
	}

	reqs := pyprojectRequirements(py)
	f := &updateFailure{category: CategoryManual, reason: ReasonManifestEditRequired, pkgs: map[string]updateFailureDetail{}}
	for _, n := range r.set.names {
		if !r.isDirect(n) {
			continue
		}
		tv, tvOK := parsePEP440(r.set.target[n])
		for _, s := range reqs {
			name, constraint, ok := pythonRequirement(s)
			if !ok {
				m := pipNameRE.FindStringSubmatch(strings.TrimSpace(s))
				if m == nil || normalizePyName(m[1]) != n {
					continue
				}
				f.pkgs[n] = updateFailureDetail{ReasonManifestEditRequired, fmt.Sprintf("pyproject.toml requires %q, which cannot be judged against %s", s, r.set.target[n])}
				continue
			}
			if name != n {
				continue
			}
			allowed, evaluable := false, false
			if tvOK {
				allowed, evaluable = pySatisfies(tv, constraint)
			}
			switch {
			case !evaluable:
				f.pkgs[n] = updateFailureDetail{ReasonManifestEditRequired, fmt.Sprintf("pyproject.toml requires %q, which cannot be judged against %s", s, r.set.target[n])}
			case !allowed:
				f.pkgs[n] = updateFailureDetail{ReasonManifestEditRequired, fmt.Sprintf("pyproject.toml requires %q, which does not allow %s; the manifest would have to be edited", s, r.set.target[n])}
			}
		}
	}
	if len(f.pkgs) == 0 {
		return nil
	}
	f.detail = firstDetail(f.pkgs)
	return f
}

// --- npm ---

func (r *updateRun) runNpm(ctx context.Context) *updateFailure {
	if fail := r.checkNodeManifest(); fail != nil {
		return fail
	}
	steps := []worker.Step{
		{ID: stepBaseline, Op: worker.OpNpmRelock, Scratch: true},
		{ID: stepUpdate, Op: worker.OpNpmUpdate, Packages: r.packageArgs(func(string) bool { return false })},
	}
	inputs := map[string][]byte{"package.json": r.src.manifest, "package-lock.json": r.src.lock}
	out, fail := r.exec(ctx, worker.ManagerNpm, inputs, steps, "update")
	if fail != nil {
		return fail
	}
	relocked, ok := out.stepFile(stepBaseline, "package-lock.json")
	if !ok {
		return failedFailure(ReasonUpdateResultInvalid, "the baseline step returned no package-lock.json")
	}
	if why := npmPackageSetDiff(r.src.lock, relocked); why != "" {
		return manualFailure(ReasonLockfileInconsistent, "package-lock.json does not match package.json: relocking the original changes the package set (%s)", why)
	}
	return r.finishLockfile(ctx, out, nil)
}

// npmPackageSet reads the packages of a package-lock.json as path to
// "name version resolved integrity".
func npmPackageSet(lock []byte) (map[string]string, error) {
	doc, err := readNpmLock(lock)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(doc.entries))
	for k, p := range doc.entries {
		out[k] = fmt.Sprintf("%s %s %s %s %t", p.Name, p.Version, p.Resolved, p.Integrity, p.Link)
	}
	return out, nil
}

// npmPackageSetDiff says how two lockfiles' package sets differ, "" if they
// are the same.
func npmPackageSetDiff(a, b []byte) string {
	sa, err := npmPackageSet(a)
	if err != nil {
		return "the original cannot be read"
	}
	sb, err := npmPackageSet(b)
	if err != nil {
		return "the relocked file cannot be read"
	}
	var diff []string
	for k, v := range sa {
		if w, ok := sb[k]; !ok {
			diff = append(diff, "gone: "+k)
		} else if w != v {
			diff = append(diff, "changed: "+k)
		}
	}
	for k := range sb {
		if _, ok := sa[k]; !ok {
			diff = append(diff, "new: "+k)
		}
	}
	sort.Strings(diff)
	if len(diff) > 3 {
		diff = append(diff[:3], fmt.Sprintf("%d more", len(diff)-3))
	}
	return strings.Join(diff, ", ")
}

// --- pnpm ---

func (r *updateRun) runPnpm(ctx context.Context) *updateFailure {
	if fail := r.checkNodeManifest(); fail != nil {
		return fail
	}
	steps := []worker.Step{
		{ID: stepBaseline, Op: worker.OpPnpmFrozen, Scratch: true},
		// A direct dependency is pinned to its target; pnpm refuses a version
		// for a transitive one, which moves within what its dependents allow.
		{ID: stepUpdate, Op: worker.OpPnpmUpdate, Packages: r.packageArgs(r.isDirect)},
		{ID: stepCheck, Op: worker.OpPnpmFrozen, Scratch: true},
	}
	inputs := map[string][]byte{"package.json": r.src.manifest, "pnpm-lock.yaml": r.src.lock}
	out, fail := r.exec(ctx, worker.ManagerPnpm, inputs, steps, "update")
	if fail != nil {
		return fail
	}
	return r.finishLockfile(ctx, out, steps)
}

// --- uv ---

func (r *updateRun) runUv(ctx context.Context) *updateFailure {
	if fail := r.checkUvProject(); fail != nil {
		return fail
	}
	steps := []worker.Step{
		{ID: stepBaseline, Op: worker.OpUvCheck, Scratch: true},
		{ID: stepUpdate, Op: worker.OpUvUpgrade, Packages: r.packageArgs(func(string) bool { return true })},
		{ID: stepCheck, Op: worker.OpUvCheck, Scratch: true},
	}
	inputs := map[string][]byte{"pyproject.toml": r.src.manifest, "uv.lock": r.src.lock}
	out, fail := r.exec(ctx, worker.ManagerUv, inputs, steps, "update")
	if fail != nil {
		return fail
	}
	return r.finishLockfile(ctx, out, steps)
}

// --- the checks every lockfile manager shares ---

// finishLockfile inspects the result of an npm, pnpm or uv job. checked is
// the job's steps when the manager has check steps whose lockfile must be the
// original (before) and the final one (after); nil for npm.
func (r *updateRun) finishLockfile(ctx context.Context, out *jobOutput, checked []worker.Step) *updateFailure {
	lockName, manifestName := r.src.lockName, r.src.manifestName
	r.it.PostUpdateCheckExecuted = true

	finalManifest, ok1 := out.finalFile(manifestName)
	newLock, ok2 := out.finalFile(lockName)
	if !ok1 || !ok2 {
		return manualFailure(ReasonOutputFilesInvalid, "the final tree lacks %s or %s", manifestName, lockName)
	}
	if !bytes.Equal(finalManifest, r.src.manifest) {
		return manualFailure(ReasonManifestChanged, "%s was changed by the update", manifestName)
	}
	if checked != nil {
		base, ok := out.stepFile(stepBaseline, lockName)
		if !ok || !bytes.Equal(base, r.src.lock) {
			return manualFailure(ReasonLockfileInconsistent, "the baseline check changed %s, so it was not consistent with %s", lockName, manifestName)
		}
		again, ok := out.stepFile(stepCheck, lockName)
		if !ok || !bytes.Equal(again, newLock) {
			return manualFailure(ReasonPostUpdateLockUnstable, "checking the updated %s again changed it", lockName)
		}
	}
	if bytes.Equal(newLock, r.src.lock) {
		return manualFailure(ReasonTargetNotUpdated, "the update left %s unchanged", lockName)
	}
	return r.verifyAndScan(ctx, newLock)
}

// parseLockfile reads a lockfile of the item's manager with the plan's own
// parser; the manifest is the original one, which the update did not change.
func (r *updateRun) parseLockfile(lock []byte) (*lockfile, error) {
	switch r.it.Manager {
	case ManagerNpm:
		return parseNpm(r.src.manifest, lock)
	case ManagerPnpm:
		return parsePnpm(r.src.manifest, lock)
	case ManagerUv:
		return parseUv(r.src.manifest, lock)
	}
	return parseRequirements(lock)
}

// buildGraph reads a lockfile as a dependency graph.
func buildGraph(ctx context.Context, m DependencyManager, lock []byte) (*depGraph, error) {
	var g *depGraph
	var err error
	switch m {
	case ManagerNpm:
		g, err = npmGraph(ctx, lock)
	case ManagerPnpm:
		g, err = pnpmGraph(ctx, lock)
	case ManagerUv:
		g, err = uvGraph(ctx, lock)
	default:
		return nil, fmt.Errorf("no dependency graph is read for %s", m)
	}
	if err != nil {
		return nil, err
	}
	g.dropDangling()
	return g, nil
}

// lockFormat identifies the format of a lockfile: what a tool that rewrites
// the file in another format would change.
func lockFormat(m DependencyManager, lock []byte) (string, error) {
	switch m {
	case ManagerNpm:
		doc, err := readNpmLock(lock)
		if err != nil {
			return "", err
		}
		return "lockfileVersion " + strconv.Itoa(doc.version), nil
	case ManagerPnpm:
		doc, err := readPnpmLock(lock)
		if err != nil {
			return "", err
		}
		d := struct{ V string }{doc.versionText}
		return "lockfileVersion " + d.V, nil
	case ManagerUv:
		doc, err := parseTOML(lock)
		if err != nil {
			return "", err
		}
		if err := checkTOMLKeys(doc); err != nil {
			return "", err
		}
		return fmt.Sprintf("version %v revision %v", doc["version"], doc["revision"]), nil
	}
	return "", errors.New("no format")
}

// verifyAndScan checks a lockfile an update produced and scans the files
// before and after. It is the part of the update stage that does not depend
// on how the file was produced.
func (r *updateRun) verifyAndScan(ctx context.Context, newLock []byte) *updateFailure {
	if fail := r.verifyLock(ctx, newLock); fail != nil {
		return fail
	}
	r.newLock = newLock

	before := map[string][]byte{r.src.lockName: r.src.lock}
	after := map[string][]byte{r.src.lockName: newLock}
	if r.src.manifestName != "" {
		before[r.src.manifestName] = r.src.manifest
		after[r.src.manifestName] = r.src.manifest
	}
	return r.sourceCheck(ctx, before, after)
}

// verifyLock inspects an updated lockfile (or requirements file): format,
// every occurrence of every updated package, and the dependency changes.
func (r *updateRun) verifyLock(ctx context.Context, newLock []byte) *updateFailure {
	it := r.it
	m := it.Manager
	if m != ManagerPip {
		was, err1 := lockFormat(m, r.src.lock)
		now, err2 := lockFormat(m, newLock)
		if err2 != nil {
			return manualFailure(ReasonOutputFilesInvalid, "the updated lockfile cannot be read: %v", err2)
		}
		if err1 != nil {
			return manualFailure(ReasonLockfileInconsistent, "the original lockfile cannot be read: %v", err1)
		}
		if was != now {
			return manualFailure(ReasonLockfileFormatChanged, "the lockfile was %s and is now %s", was, now)
		}
	}
	lf, err := r.parseLockfile(newLock)
	if err != nil {
		var ue *UnsupportedError
		if errors.As(err, &ue) {
			return manualFailure(ReasonOutputFilesInvalid, "the updated file is not one the plan reads: %s", ue.Error())
		}
		return manualFailure(ReasonOutputFilesInvalid, "the updated file cannot be read: %v", err)
	}
	if fail := r.checkVersions(lf); fail != nil {
		return fail
	}
	if m == ManagerPip {
		return nil
	}
	if m == ManagerNpm {
		if fail := r.checkNpmLegacy(ctx, newLock); fail != nil {
			return fail
		}
	}
	gb, err1 := buildGraph(ctx, m, r.src.lock)
	ga, err2 := buildGraph(ctx, m, newLock)
	if err1 != nil || err2 != nil {
		if ctx.Err() != nil {
			return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
		}
		return manualFailure(ReasonOutputFilesInvalid, "the dependency graph cannot be read: %v", errors.Join(err1, err2))
	}
	diff, reason, detail := diffGraphs(ctx, gb, ga, r.targetSet())
	r.upd.Diff = &diff
	if ctx.Err() != nil {
		return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
	}
	if reason != "" {
		return manualFailure(reason, "%s", detail)
	}
	// Every occurrence of an updated package is compared with the registry,
	// whether or not the update changed it: an entry left alone can carry the
	// version of one release and the files of another.
	check := map[string]bool{}
	for _, k := range diff.touched {
		check[k] = true
	}
	targets := r.targetSet()
	for k, n := range ga.nodes {
		if targets[n.name] {
			check[k] = true
		}
	}
	var checkKeys []string
	for k := range check {
		checkKeys = append(checkKeys, k)
	}
	if fail := r.checkDistributions(ctx, ga, checkKeys); fail != nil {
		return fail
	}
	if m == ManagerNpm || m == ManagerPnpm {
		if fail := r.checkFlags(ga, checkKeys); fail != nil {
			return fail
		}
	}
	if reason, detail := checkUnresolved(gb, ga); reason != "" {
		return manualFailure(reason, "%s", detail)
	}
	return r.checkRanges(ctx, ga, newLock, check)
}

// targetSet is the updated packages' matching names as a set.
func (r *updateRun) targetSet() map[string]bool {
	out := map[string]bool{}
	for _, n := range r.set.names {
		out[n] = true
	}
	return out
}

// checkVersions requires every occurrence of every updated package in the
// updated file to be a registry version at or above the target and to meet
// the fixed version of each vulnerability the update is for, and records the
// versions the file holds.
func (r *updateRun) checkVersions(lf *lockfile) *updateFailure {
	it := r.it
	sc := it.Manager.scheme()
	r.adopted = map[string]string{}
	r.afterVersions = map[string][]string{}
	for _, n := range r.set.names {
		target := r.set.target[n]
		lp := lf.lookup(n)
		if lp == nil {
			return pkgFailure(n, ReasonTargetRemoved, "%s is no longer in the updated file", n)
		}
		tv, tvOK := parseVersion(sc, target)
		if !tvOK {
			return failedFailure(ReasonUpdateInputInvalid, "the target %s of %s is not a version", target, n)
		}
		seenVersions := map[string]bool{}
		var low version
		lowStr := ""
		for _, o := range lp.occs {
			if o.ManualReason != "" {
				return pkgFailure(n, ReasonResolvedSourceChanged, "%s at %s: %s", n, o.Path, o.Detail)
			}
			if o.Version == "" {
				return pkgFailure(n, ReasonTargetNotUpdated, "%s at %s is not pinned to a version in the updated file", n, o.Path)
			}
			ov, ok := parseVersion(sc, o.Version)
			if !ok {
				return pkgFailure(n, ReasonTargetNotUpdated, "%s at %s has the version %q, which is not a version", n, o.Path, o.Version)
			}
			if ov.compare(tv) < 0 {
				return pkgFailure(n, ReasonTargetNotUpdated, "%s is at %s at %s in the updated file, below the target %s", n, o.Version, o.Path, target)
			}
			if !seenVersions[o.Version] {
				seenVersions[o.Version] = true
				if len(seenVersions) > maxVersionsPerPackage {
					return manualFailure(ReasonOutputFilesInvalid, "the updated file holds %s at more than %d different versions", n, maxVersionsPerPackage)
				}
				r.afterVersions[n] = append(r.afterVersions[n], o.Version)
			}
			if low == nil || ov.compare(low) < 0 {
				low, lowStr = ov, o.Version
			}
		}
		r.adopted[n] = lowStr
		for _, i := range r.set.idx {
			p := it.Packages[i]
			if p.matchName() != n {
				continue
			}
			for _, c := range p.CVEs {
				for _, v := range r.afterVersions[n] {
					if !meetsFix(sc, v, c.FixedVers) {
						return pkgFailure(n, ReasonFixConditionNotMet, "%s %s does not meet the fixed version %s reports for %s", n, v, strings.Join(c.FixedVers, ", "), c.VulnID)
					}
				}
			}
		}
	}
	return nil
}

// meetsFix reports whether version v is fixed for a vulnerability reported
// fixed in the given versions: v is at or above the highest of them, or there
// is a fixed version of v's own series (the same major and minor) and v is at
// or above it (the highest of them, if there are several). A fixed version of another series does not vouch for v, so 4.2.0
// is not fixed by [4.1.13, 4.2.16]. A pre-release is fixed only by a fixed
// version that is that pre-release itself.
func meetsFix(sc scheme, v string, fixed []string) bool {
	vv, ok := parseVersion(sc, v)
	if !ok {
		return false
	}
	var all []version
	for _, f := range fixed {
		for _, one := range splitFixed(f) {
			fv, ok := parseVersion(sc, one)
			if !ok {
				return false
			}
			all = append(all, fv)
		}
	}
	if len(all) == 0 {
		return false
	}
	if isPre(vv) {
		for _, fv := range all {
			if vv.compare(fv) == 0 {
				return true
			}
		}
		return false
	}
	// A fixed version of v's own series (the same major and minor) is the
	// one that counts, the highest of them if there are several; otherwise v
	// must be at or above every fixed version.
	var ownMax version
	above := true
	for _, fv := range all {
		if seriesOf(vv) == seriesOf(fv) && (ownMax == nil || fv.compare(ownMax) > 0) {
			ownMax = fv
		}
		if vv.compare(fv) < 0 {
			above = false
		}
	}
	if ownMax != nil {
		return vv.compare(ownMax) >= 0
	}
	return above
}

func isPre(v version) bool {
	switch t := v.(type) {
	case semver:
		return t.isPrerelease()
	case pyVersion:
		return t.isPrerelease()
	}
	return false
}

// seriesOf is the major and minor of a version.
func seriesOf(v version) string {
	switch t := v.(type) {
	case semver:
		return t.major + "." + t.minor
	case pyVersion:
		minor := "0"
		if len(t.release) > 1 {
			minor = t.release[1]
		}
		return t.epoch + "!" + t.release[0] + "." + minor
	}
	return ""
}

// maxVersionsPerPackage bounds how many different versions of one package an
// updated file may hold.
const maxVersionsPerPackage = 256
