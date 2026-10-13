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

// run reads the unit's files and carries out the update of its manager.
func (r *updateRun) run(ctx context.Context) *updateFailure {
	src, fail := r.u.readSources(ctx, r.it)
	if fail != nil {
		return fail
	}
	r.src = src
	r.manifest = src.manifest
	if r.it.Manager != ManagerPip {
		in := ToolSpecInput{
			Manager: r.it.Manager, Manifest: src.manifest, Lock: src.lock, Files: src.specFiles, UvToml: src.uvToml,
			Now: r.u.now(),
		}
		if f := r.u.declaredRuntimeEndOfLife(in); f != nil {
			return f
		}
		ts, uerr := ResolveToolSpec(in)
		if uerr != nil {
			return manualFailure(uerr.Reason, "%s", uerr.Detail)
		}
		r.toolSpec = ts
		if r.it.Manager == ManagerPnpm && strings.HasPrefix(ts.ToolVersion, "12.") {
			return manualFailure(ReasonPnpm12RemovalUnsupported, "the project runs pnpm %s, and pnpm 12 does not make a lockfile again from one with entries taken out, which is how pnpm lockfiles are updated here", ts.ToolVersion)
		}
	}
	// Only a lockfile tells where each package ended up; a pip update pins its
	// packages exactly and has nothing to leave out.
	if r.it.Manager == ManagerPip {
		r.noPartial = true
	}
	// The sizes the planning below works over are checked first: the
	// packages named, and the manifest read.
	if len(r.set.names) > worker.MaxPackages {
		return &updateFailure{category: CategoryDeferred, reason: ReasonUpdatePackageLimit,
			detail: fmt.Sprintf("the update names %d packages, more than the %d one job takes", len(r.set.names), worker.MaxPackages)}
	}
	if len(src.manifest) > maxManifestBytes {
		return &updateFailure{category: CategoryDeferred, reason: ReasonUpdateInputLimit,
			detail: fmt.Sprintf("%s is over %d bytes", src.manifestName, maxManifestBytes)}
	}
	// The lockfile is read by this program before it is sent, to make the file
	// that replaces it, so its size is checked here too.
	if len(src.lock) > worker.MaxInputFileBytes {
		return &updateFailure{category: CategoryDeferred, reason: ReasonUpdateInputLimit,
			detail: fmt.Sprintf("%s is %d bytes, more than the %d one job takes", src.lockName, len(src.lock), worker.MaxInputFileBytes)}
	}
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
	return r.execReplacing(ctx, m, inputs, nil, steps, role)
}

// execReplacing is exec for a job that has replacement files, which take the
// place of the inputs of the same name just before its first step that is not
// a scratch step.
func (r *updateRun) execReplacing(ctx context.Context, m worker.Manager, inputs, replacements map[string][]byte, steps []worker.Step, role string) (*jobOutput, *updateFailure) {
	if r.attempt > 0 {
		role = fmt.Sprintf("%s-again%d", role, r.attempt)
	}
	env, fail := r.u.prepareJob(ctx, m, r.toolSpec)
	if fail != nil {
		return nil, fail
	}
	job := r.u.newJob(m, env, inputs, steps)
	for _, name := range worker.InputNames(m) {
		if content, ok := replacements[name]; ok {
			job.Replacements = append(job.Replacements, worker.Input{Path: name, Size: int64(len(content)), SHA256: sha256Hex(content)})
		}
	}
	out, fail := r.u.execute(ctx, job, env, inputs, replacements, r.u.jobID(r.n, role), r.upd)
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
// name that keep accepts (all when it is nil), with a version where
// withVersion says so.
func (r *updateRun) packageArgs(keep func(name string) bool, withVersion func(name string) bool) []worker.Package {
	var out []worker.Package
	for _, n := range r.set.names {
		if keep != nil && !keep(n) {
			continue
		}
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
	if n, ok := r.set.display[match]; ok {
		return n
	}
	return match
}

// isDirect reports whether the package named by match is required by the
// project itself in any occurrence that is being updated.
func (r *updateRun) isDirect(match string) bool { return r.set.direct[match] }

// --- manifest checks (before the update) ---

// planNodeManifest settles the package.json the update runs on. The range of
// every direct package must allow its target: where it does not, and is one of
// the plain forms editNpmSpec handles, the specifier is edited here, before the
// update runs; any other form is left to a person.
func (r *updateRun) planNodeManifest(ctx context.Context) *updateFailure {
	pj, err := readManifest(r.src.manifest)
	if err != nil {
		return manualFailure(ReasonDependencyFileUnusable, "%v", err)
	}
	f := &updateFailure{category: CategoryManual, reason: ReasonManifestEditRequired, pkgs: map[string]updateFailureDetail{}}
	var edits []ManifestEdit
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
			if evaluable && allowed {
				continue
			}
			if npmEditableFields[field] {
				if to, ok := npmEditedSpec(spec, r.set.target[n]); ok {
					edits = append(edits, ManifestEdit{
						File: r.src.manifestPath, Section: field, Name: n, From: spec, To: to,
						MajorChange: releaseLine(semverRelease(spec)) != releaseLine(semverRelease(to)),
					})
					continue
				}
			}
			why := "which does not allow " + r.set.target[n] + " and is not a form this program edits"
			if !evaluable {
				why = "which cannot be judged against " + r.set.target[n]
			}
			f.pkgs[n] = updateFailureDetail{ReasonManifestEditRequired, fmt.Sprintf("package.json asks for %s %q in %s, %s", n, spec, field, why)}
		}
	}
	if len(f.pkgs) != 0 {
		f.detail = firstDetail(f.pkgs)
		return f
	}
	return r.applyManifestEdits(ctx, edits, func() ([]byte, error) { return editPackageJSON(ctx, r.src.manifest, edits) })
}

// applyManifestEdits makes the edited manifest the one the update runs on and
// records the edits.
func (r *updateRun) applyManifestEdits(ctx context.Context, edits []ManifestEdit, edit func() ([]byte, error)) *updateFailure {
	if len(edits) == 0 {
		return nil
	}
	out, err := edit()
	switch {
	case errors.Is(err, errManifestEditLimit):
		return &updateFailure{category: CategoryDeferred, reason: ReasonUpdateInputLimit, detail: err.Error()}
	case err != nil && ctx.Err() != nil:
		return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
	case err != nil:
		f := &updateFailure{category: CategoryManual, reason: ReasonManifestEditRequired, pkgs: map[string]updateFailureDetail{}}
		for _, e := range edits {
			f.pkgs[normalizeIfPython(r.it.Manager, e.Name)] = updateFailureDetail{ReasonManifestEditRequired, fmt.Sprintf("%s cannot be edited without changing more than the specifier of %s: %v", r.src.manifestName, e.Name, err)}
		}
		f.detail = firstDetail(f.pkgs)
		return f
	}
	r.manifest = out
	r.upd.ManifestEdits = edits
	return nil
}

func normalizeIfPython(m DependencyManager, name string) string {
	if m.scheme() == schemePEP440 {
		return normalizePyName(name)
	}
	return name
}

// editedNames are the matching names of the packages whose specifier was
// edited.
func (r *updateRun) editedNames() map[string]bool {
	out := map[string]bool{}
	for _, e := range r.upd.ManifestEdits {
		out[normalizeIfPython(r.it.Manager, e.Name)] = true
	}
	return out
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

// pyprojectRequirement is one requirement string of a pyproject.toml, with
// the section it is in and its place in that section's list.
type pyprojectRequirement struct {
	section string
	index   int
	text    string
}

// pyprojectRequirementEntries lists the requirement strings of
// pyprojectRequirements with where each is.
func pyprojectRequirementEntries(py map[string]any) []pyprojectRequirement {
	var out []pyprojectRequirement
	add := func(section string, v any) {
		list, _ := v.([]any)
		for i, e := range list {
			if s, ok := e.(string); ok {
				out = append(out, pyprojectRequirement{section, i, s})
			}
		}
	}
	project, _ := py["project"].(map[string]any)
	add("project.dependencies", project["dependencies"])
	opt, _ := project["optional-dependencies"].(map[string]any)
	for k, v := range opt {
		add("project.optional-dependencies."+k, v)
	}
	groups, _ := py["dependency-groups"].(map[string]any)
	for k, v := range groups {
		add("dependency-groups."+k, v)
	}
	tool, _ := py["tool"].(map[string]any)
	uv, _ := tool["uv"].(map[string]any)
	add("tool.uv.dev-dependencies", uv["dev-dependencies"])
	return out
}

// planUvProject requires the project to be lockable in the work image, and the
// specifier of every direct package to allow its target; where it does not, and
// is a requirement of [project] dependencies whose only version clause is
// name==X or name~=X.Y, the version in it is edited here, before the update
// runs.
func (r *updateRun) planUvProject(ctx context.Context) *updateFailure {
	py, err := parseTOML(r.src.manifest)
	if err != nil {
		return manualFailure(ReasonDependencyFileUnusable, "pyproject.toml cannot be read: %v", err)
	}
	project, _ := py["project"].(map[string]any)
	lockPy := r.lockPython()
	rp, present := project["requires-python"]
	spec, isStr := rp.(string)
	if !present || !isStr {
		return manualFailure(ReasonRequiresPythonUnsupported, "pyproject.toml has no requires-python; uv would lock for the work image's Python %s", lockPy)
	}
	var clauses []string
	for _, c := range strings.Split(spec, ",") {
		cm := pipClauseRE.FindStringSubmatch(strings.TrimSpace(c))
		if cm == nil {
			return manualFailure(ReasonRequiresPythonUnsupported, "requires-python %q cannot be read", spec)
		}
		clauses = append(clauses, cm[1]+cm[2])
	}
	pv, _ := parsePEP440(lockPy)
	if ok, evaluable := pySatisfies(pv, strings.Join(clauses, ",")); !evaluable || !ok {
		return manualFailure(ReasonRequiresPythonUnsupported, "requires-python %q does not admit the work image's Python %s", spec, lockPy)
	}

	f := &updateFailure{category: CategoryManual, reason: ReasonManifestEditRequired, pkgs: map[string]updateFailureDetail{}}
	var edits []ManifestEdit
	var editIdx []int
	// The requirements are read once and indexed by their normalized name; a
	// target looks up its own, so the work is the number of requirements plus
	// the number of targets, not their product.
	entries := pyprojectRequirementEntries(py)
	if len(entries) > maxManifestRequirements {
		return &updateFailure{category: CategoryDeferred, reason: ReasonUpdateInputLimit,
			detail: fmt.Sprintf("pyproject.toml lists %d requirements, more than the %d one update reads", len(entries), maxManifestRequirements)}
	}
	type readRequirement struct {
		pyprojectRequirement
		constraint string
		readable   bool
	}
	byName := map[string][]readRequirement{}
	for i, e := range entries {
		if i%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: err.Error()}
			}
		}
		name, constraint, ok := pythonRequirement(e.text)
		if !ok {
			m := pipNameRE.FindStringSubmatch(strings.TrimSpace(e.text))
			if m == nil {
				continue
			}
			name = normalizePyName(m[1])
		}
		if r.set.targets[name] {
			byName[name] = append(byName[name], readRequirement{e, constraint, ok})
		}
	}
	for _, n := range r.set.names {
		if !r.isDirect(n) {
			continue
		}
		tv, tvOK := parsePEP440(r.set.target[n])
		for _, e := range byName[n] {
			s := e.text
			if !e.readable {
				f.pkgs[n] = updateFailureDetail{ReasonManifestEditRequired, fmt.Sprintf("pyproject.toml requires %q, which cannot be judged against %s", s, r.set.target[n])}
				continue
			}
			allowed, evaluable := false, false
			if tvOK {
				allowed, evaluable = pySatisfies(tv, e.constraint)
			}
			if evaluable && allowed {
				continue
			}
			if e.section == "project.dependencies" {
				if to, ok := uvEditedRequirement(s, r.set.target[n]); ok {
					edits = append(edits, ManifestEdit{
						File: r.src.manifestPath, Section: e.section, Name: n, From: s, To: to,
						MajorChange: releaseLine(uvRequirementRelease(s)) != releaseLine(uvRequirementRelease(to)),
					})
					editIdx = append(editIdx, e.index)
					continue
				}
			}
			if !evaluable {
				f.pkgs[n] = updateFailureDetail{ReasonManifestEditRequired, fmt.Sprintf("pyproject.toml requires %q, which cannot be judged against %s", s, r.set.target[n])}
			} else {
				f.pkgs[n] = updateFailureDetail{ReasonManifestEditRequired, fmt.Sprintf("pyproject.toml requires %q, which does not allow %s and is not a form this program edits", s, r.set.target[n])}
			}
		}
	}
	if len(f.pkgs) != 0 {
		f.detail = firstDetail(f.pkgs)
		return f
	}
	return r.applyManifestEdits(ctx, edits, func() ([]byte, error) { return editPyproject(ctx, r.src.manifest, editIdx, edits) })
}

// --- npm ---

func (r *updateRun) runNpm(ctx context.Context) *updateFailure {
	if fail := r.planNodeManifest(ctx); fail != nil {
		return fail
	}
	if len(r.upd.ManifestEdits) > 0 {
		return r.runNpmEdited(ctx)
	}
	removal, problem := removeNpmTargets(ctx, r.src.lock, r.targetSet())
	if problem != nil {
		return problem.failure()
	}
	// The original input is relocked on a scratch copy to see that npm takes it
	// as it is; the lockfile with the targets taken out then takes its place
	// and is relocked.
	steps := []worker.Step{
		{ID: stepBaseline, Op: worker.OpNpmRelock, Scratch: true},
		{ID: stepUpdate, Op: worker.OpNpmRelock},
	}
	inputs := map[string][]byte{"package.json": r.src.manifest, "package-lock.json": r.src.lock}
	out, fail := r.execReplacing(ctx, worker.ManagerNpm, inputs, map[string][]byte{"package-lock.json": removal.lock}, steps, "update")
	if fail != nil {
		return fail
	}
	if fail := r.checkNpmBaseline(out); fail != nil {
		return fail
	}
	return r.finishLockfile(ctx, out, nil, nil)
}

// checkNpmBaseline requires relocking the original input to leave its package
// set as it is.
func (r *updateRun) checkNpmBaseline(out *jobOutput) *updateFailure {
	relocked, ok := out.stepFile(stepBaseline, "package-lock.json")
	if !ok {
		return failedFailure(ReasonUpdateResultInvalid, "the baseline step returned no package-lock.json")
	}
	if why := npmPackageSetDiff(r.src.lock, relocked); why != "" {
		return manualFailure(ReasonLockfileInconsistent, "package-lock.json does not match package.json: relocking the original changes the package set (%s)", why)
	}
	return nil
}

// runNpmEdited updates with a package.json whose specifiers for some of the
// targets were edited. The original input is checked as it is in a job of its
// own; the update then relocks the lockfile with the targets taken out against
// the edited manifest.
func (r *updateRun) runNpmEdited(ctx context.Context) *updateFailure {
	base, fail := r.exec(ctx, worker.ManagerNpm, map[string][]byte{"package.json": r.src.manifest, "package-lock.json": r.src.lock},
		[]worker.Step{{ID: stepBaseline, Op: worker.OpNpmRelock, Scratch: true}}, "base")
	if fail != nil {
		return fail
	}
	if fail := r.checkNpmBaseline(base); fail != nil {
		return fail
	}
	removal, problem := removeNpmTargets(ctx, r.src.lock, r.targetSet())
	if problem != nil {
		return problem.failure()
	}
	steps := []worker.Step{{ID: stepUpdate, Op: worker.OpNpmRelock}}
	out, fail := r.exec(ctx, worker.ManagerNpm, map[string][]byte{"package.json": r.manifest, "package-lock.json": removal.lock}, steps, "update")
	if fail != nil {
		return fail
	}
	return r.finishLockfile(ctx, out, nil, nil)
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

// pnpmInputs are the input files of a pnpm job: the manifest, the lockfile and
// the settings file when the project has one.
func (r *updateRun) pnpmInputs(manifest, lock []byte) map[string][]byte {
	in := map[string][]byte{"package.json": manifest, "pnpm-lock.yaml": lock}
	if r.src.settings != nil {
		in[pnpmWorkspaceName] = r.src.settings
	}
	return in
}

func (r *updateRun) runPnpm(ctx context.Context) *updateFailure {
	if fail := r.planNodeManifest(ctx); fail != nil {
		return fail
	}
	if len(r.upd.ManifestEdits) > 0 {
		return r.runPnpmEdited(ctx)
	}
	removal, problem := removePnpmTargets(ctx, r.src.lock, r.targetSet())
	if problem != nil {
		return problem.failure()
	}
	r.pnpmTrigger = removal.trigger
	// The original input is checked as it is on a scratch copy; the lockfile
	// with the targets taken out then takes its place and is relocked, and the
	// result is checked again.
	steps := []worker.Step{
		{ID: stepBaseline, Op: worker.OpPnpmFrozen, Scratch: true},
		{ID: stepUpdate, Op: worker.OpPnpmRelock},
		{ID: stepCheck, Op: worker.OpPnpmFrozen, Scratch: true},
	}
	inputs := r.pnpmInputs(r.src.manifest, r.src.lock)
	out, fail := r.execReplacing(ctx, worker.ManagerPnpm, inputs, map[string][]byte{"pnpm-lock.yaml": removal.lock}, steps, "update")
	if fail != nil {
		return fail
	}
	return r.finishLockfile(ctx, out, steps, nil)
}

// runPnpmEdited is the update with an edited package.json: the original input
// is checked as it is in a job of its own, then the lockfile with the targets
// taken out is relocked against the edited manifest, and the result is
// checked again. The edited specifiers make pnpm resolve again, so no other
// dependency is taken out.
func (r *updateRun) runPnpmEdited(ctx context.Context) *updateFailure {
	baseSteps := []worker.Step{{ID: stepBaseline, Op: worker.OpPnpmFrozen, Scratch: true}}
	base, fail := r.exec(ctx, worker.ManagerPnpm, r.pnpmInputs(r.src.manifest, r.src.lock), baseSteps, "base")
	if fail != nil {
		return fail
	}
	removal, problem := removePnpmTargets(ctx, r.src.lock, r.targetSet())
	if problem != nil {
		return problem.failure()
	}
	r.pnpmTrigger = removal.trigger
	steps := []worker.Step{
		{ID: stepUpdate, Op: worker.OpPnpmRelock},
		{ID: stepCheck, Op: worker.OpPnpmFrozen, Scratch: true},
	}
	out, fail := r.exec(ctx, worker.ManagerPnpm, r.pnpmInputs(r.manifest, removal.lock), steps, "update")
	if fail != nil {
		return fail
	}
	return r.finishLockfile(ctx, out, steps, base)
}

// --- uv ---

func (r *updateRun) runUv(ctx context.Context) *updateFailure {
	if fail := r.planUvProject(ctx); fail != nil {
		return fail
	}
	// uv is told nothing of a package it does not have, and then changes
	// nothing and succeeds, so the names are looked for here first.
	lf, err := parseUv(r.src.manifest, r.src.lock)
	if err != nil {
		return manualFailure(ReasonDependencyFileUnusable, "uv.lock cannot be read: %v", err)
	}
	for _, n := range r.set.names {
		if lf.lookup(n) == nil {
			return pkgFailure(n, ReasonTargetNotInLockfile, "%s has no entry in uv.lock", n)
		}
	}
	steps := []worker.Step{
		{ID: stepBaseline, Op: worker.OpUvCheck, Scratch: true},
		{ID: stepUpdate, Op: worker.OpUvUpgrade, Packages: r.packageArgs(nil, func(string) bool { return true })},
		{ID: stepCheck, Op: worker.OpUvCheck, Scratch: true},
	}
	if len(r.upd.ManifestEdits) > 0 {
		// The original input is checked as it is in a job of its own; the
		// update and its check run on the edited manifest.
		base, fail := r.exec(ctx, worker.ManagerUv, map[string][]byte{"pyproject.toml": r.src.manifest, "uv.lock": r.src.lock}, steps[:1], "base")
		if fail != nil {
			return fail
		}
		out, fail := r.exec(ctx, worker.ManagerUv, map[string][]byte{"pyproject.toml": r.manifest, "uv.lock": r.src.lock}, steps[1:], "update")
		if fail != nil {
			return fail
		}
		return r.finishLockfile(ctx, out, steps, base)
	}
	inputs := map[string][]byte{"pyproject.toml": r.src.manifest, "uv.lock": r.src.lock}
	out, fail := r.exec(ctx, worker.ManagerUv, inputs, steps, "update")
	if fail != nil {
		return fail
	}
	return r.finishLockfile(ctx, out, steps, nil)
}

// --- the checks every lockfile manager shares ---

// finishLockfile inspects the result of an npm, pnpm or uv job. checked is
// the job's steps when the manager has check steps whose lockfile must be the
// original (before) and the final one (after); nil for npm. The baseline
// step's lockfile is read from base when the baseline ran in a job of its own,
// and from out otherwise.
func (r *updateRun) finishLockfile(ctx context.Context, out *jobOutput, checked []worker.Step, base *jobOutput) *updateFailure {
	if base == nil {
		base = out
	}
	lockName, manifestName := r.src.lockName, r.src.manifestName
	r.it.PostUpdateCheckExecuted = true

	finalManifest, ok1 := out.finalFile(manifestName)
	newLock, ok2 := out.finalFile(lockName)
	if !ok1 || !ok2 {
		return manualFailure(ReasonOutputFilesInvalid, "the final tree lacks %s or %s", manifestName, lockName)
	}
	if !bytes.Equal(finalManifest, r.manifest) {
		return manualFailure(ReasonManifestChanged, "%s is not the manifest the update was given", manifestName)
	}
	if checked != nil {
		baseLock, ok := base.stepFile(stepBaseline, lockName)
		if !ok || !bytes.Equal(baseLock, r.src.lock) {
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
		return parseNpm(r.manifest, lock)
	case ManagerPnpm:
		return parsePnpm(r.manifest, lock)
	case ManagerUv:
		return parseUv(r.manifest, lock)
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
	if err := g.linkCtx(ctx); err != nil {
		return nil, err
	}
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
		after[r.src.manifestName] = r.manifest
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
	if len(r.unreached) > 0 {
		if fail := r.leaveOut(lf); fail != nil {
			return fail
		}
	}
	if m == ManagerPip {
		return nil
	}
	if m == ManagerNpm {
		if fail := r.checkNpmLegacy(ctx, newLock); fail != nil {
			return fail
		}
	}
	gb, ga, err1, err2 := r.buildGraphs(ctx, newLock)
	if err1 != nil || err2 != nil {
		if ctx.Err() != nil {
			return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
		}
		return manualFailure(ReasonOutputFilesInvalid, "the dependency graph cannot be read: %v", errors.Join(err1, err2))
	}
	if len(r.upd.ManifestEdits) > 0 {
		// The specifiers this program edited are compared with the manifest
		// (see checkRanges), not with the original lockfile.
		for _, g := range []*depGraph{gb, ga} {
			if err := g.maskEditedSpecs(ctx, m, r.upd.ManifestEdits); err != nil {
				return manualFailure(ReasonOutputFilesInvalid, "the project's own record in the lockfile cannot be compared: %v", err)
			}
		}
	}
	if m == ManagerPnpm {
		if fail := r.checkTriggerReturned(gb, ga, r.src.lock, newLock); fail != nil {
			return fail
		}
	}
	if fail := r.checkReferences(ctx, newLock); fail != nil {
		return fail
	}
	diff, reason, detail := diffGraphs(ctx, gb, ga, r.targetSet())
	r.upd.Diff = &diff
	if ctx.Err() != nil {
		return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
	}
	if reason != "" {
		f := manualFailure(reason, "%s", detail)
		if reason == ReasonUnexplainedDiff && len(r.leftOut) > 0 && !r.noPartial {
			// The result was taken as it was with the packages left out, and
			// something around them moved; the update is made again without them
			// so that nothing is touched on their account.
			f.retryWithout = r.leftOut
		}
		return f
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
	if reason, detail := checkUnresolvedCtx(ctx, gb, ga); reason != "" {
		return manualFailure(reason, "%s", detail)
	}
	if m == ManagerNpm || m == ManagerPnpm {
		if fail := r.checkDeprecated(ctx, gb, ga); fail != nil {
			return fail
		}
	}
	return r.checkRanges(ctx, ga, newLock, check)
}

// targetSet is the updated packages' matching names as a set.
func (r *updateRun) targetSet() map[string]bool { return r.set.targets }

// checkVersions requires every occurrence of every updated package in the
// updated file to be a registry version at or above the target and to meet
// the fixed version of each vulnerability the update is for, and records the
// versions the file holds.
func (r *updateRun) checkVersions(lf *lockfile) *updateFailure {
	it := r.it
	sc := it.Manager.scheme()
	r.adopted = map[string]string{}
	r.afterVersions = map[string][]string{}
	r.unreached = map[string]updateFailureDetail{}
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
				detail := fmt.Sprintf("%s is at %s at %s in the updated file, below the target %s", n, o.Version, o.Path, target)
				if !r.mayLeaveOut() {
					return pkgFailure(n, ReasonTargetNotUpdated, "%s", detail)
				}
				r.unreached[n] = updateFailureDetail{ReasonTargetNotUpdated, detail}
				break
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
		if _, short := r.unreached[n]; short {
			delete(r.afterVersions, n)
			continue
		}
		r.adopted[n] = lowStr
		for _, i := range r.set.byName[n] {
			p := it.Packages[i]
			for _, c := range p.CVEs {
				for _, v := range r.afterVersions[n] {
					if !meetsFix(sc, v, c.FixedVers) {
						return pkgFailure(n, ReasonFixConditionNotMet, "%s %s does not meet the fixed version %s reports for %s", n, v, strings.Join(c.FixedVers, ", "), c.VulnID)
					}
				}
			}
		}
	}
	if len(r.unreached) == len(r.set.names) {
		// Nothing reached its target: there is no part of the set to propose.
		n := r.set.names[0]
		return pkgFailure(n, ReasonTargetNotUpdated, "%s", r.unreached[n].detail)
	}
	return nil
}

// mayLeaveOut reports whether this run may leave packages that did not reach
// their target out of its result.
func (r *updateRun) mayLeaveOut() bool { return !r.noPartial }

// leaveOut settles a result in which some packages of the set did not reach
// their target and others did (r.unreached). The result is used as it is, with
// the packages left out of the set from here on, when it left them where they
// were and the manifest was not edited on their account; then the checks that
// follow judge the result against the packages that did reach their target
// only. Otherwise the failure asks for the update to be run again without
// them, since a result that moved a package to another version that is still
// short of its target cannot be explained by the packages being updated.
func (r *updateRun) leaveOut(lf *lockfile) *updateFailure {
	var names []string
	for n := range r.unreached {
		names = append(names, n)
	}
	sort.Strings(names)
	again := func(format string, args ...any) *updateFailure {
		f := manualFailure(ReasonTargetNotUpdated, format, args...)
		f.retryWithout = r.unreached
		return f
	}
	var orig *lockfile
	var err error
	switch r.it.Manager {
	case ManagerNpm:
		orig, err = parseNpm(r.src.manifest, r.src.lock)
	case ManagerPnpm:
		orig, err = parsePnpm(r.src.manifest, r.src.lock)
	case ManagerUv:
		orig, err = parseUv(r.src.manifest, r.src.lock)
	default:
		err = errors.New("no lockfile")
	}
	if err != nil {
		return again("the original file cannot be compared with the result: %v", err)
	}
	edited := r.editedNames()
	for _, n := range names {
		was, now := orig.lookup(n), lf.lookup(n)
		switch {
		case was == nil || now == nil || !sameVersions(was.occs, now.occs):
			return again("%s", r.unreached[n].detail)
		case edited[n]:
			return again("the manifest was edited for %s, which did not reach its target", n)
		}
	}
	r.leftOut = r.unreached
	r.set = r.set.without(r.unreached)
	return nil
}

// sameVersions reports whether two lists of occurrences hold the same
// versions.
func sameVersions(a, b []SourceOccurrence) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := make([]string, len(a)), make([]string, len(b))
	for i := range a {
		x[i], y[i] = a[i].Version, b[i].Version
	}
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// meetsFix reports whether version v is fixed for a vulnerability reported
// fixed in the given versions. The fixed versions are the first fixed version
// of each line of releases (4.1.13 and 4.2.16, say), and a line is the major
// version (the minor version for 0.x). A version is fixed when
//
//   - a fixed version of its own series (the same major and minor) exists and v
//     is at or above the highest of them: 4.2.0 is not fixed by [4.1.13, 4.2.16];
//   - otherwise, a fixed version of its own line exists and v is at or above
//     every fixed version of that line: 6.29.0 is fixed by [6.28.1, 7.29.1], a
//     later release of the line the fix was made in, while 4.1.20 is not fixed by
//     [4.0.5, 4.2.16], which leaves the series between two fixes undecided;
//   - otherwise v is at or above every fixed version.
//
// A pre-release is fixed only by a fixed version that is that pre-release
// itself.
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
	var ownMax version
	lineAbove, lineAny := true, false
	above := true
	for _, fv := range all {
		if seriesOf(vv) == seriesOf(fv) && (ownMax == nil || fv.compare(ownMax) > 0) {
			ownMax = fv
		}
		if lineOf(vv) == lineOf(fv) {
			lineAny = true
			if vv.compare(fv) < 0 {
				lineAbove = false
			}
		}
		if vv.compare(fv) < 0 {
			above = false
		}
	}
	switch {
	case ownMax != nil:
		return vv.compare(ownMax) >= 0
	case lineAny:
		return lineAbove
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

// lineOf is the line of releases a version belongs to: its major version, or
// the major and minor version for 0.x, where a minor release may break.
func lineOf(v version) string {
	switch t := v.(type) {
	case semver:
		if t.major == "0" {
			return t.major + "." + t.minor
		}
		return t.major
	case pyVersion:
		if len(t.release) > 1 && t.release[0] == "0" {
			return t.epoch + "!" + t.release[0] + "." + t.release[1]
		}
		return t.epoch + "!" + t.release[0]
	}
	return ""
}

// maxVersionsPerPackage bounds how many different versions of one package an
// updated file may hold.
const maxVersionsPerPackage = 256
