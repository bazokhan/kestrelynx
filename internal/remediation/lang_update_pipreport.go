package remediation

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

var cpTagRE = regexp.MustCompile(`^cp3([0-9]+)$`)

// wheelFitsTarget reports whether a wheel file name (name-version[-build]-
// python-abi-platform.whl) can be installed for the environment pip resolved
// for: one of its python tags and abi tags fit the interpreter (a CPython wheel
// of this version, a stable-ABI wheel of this or an older version, or a pure
// Python wheel), and one of its platform tags is a tag pip was given or is
// "any". pip expands the manylinux2014 tag to the older manylinux2010 and
// manylinux1 names, so those fit as well.
func wheelFitsTarget(filename string, t *worker.Target) bool {
	base := strings.TrimSuffix(filename, ".whl")
	if base == filename {
		return false
	}
	parts := strings.Split(base, "-")
	if len(parts) != 5 && len(parts) != 6 {
		return false
	}
	pys := strings.Split(parts[len(parts)-3], ".")
	abis := strings.Split(parts[len(parts)-2], ".")
	plats := strings.Split(parts[len(parts)-1], ".")
	if len(filename) > maxWheelNameBytes || len(pys) > maxWheelTags || len(abis) > maxWheelTags || len(plats) > maxWheelTags {
		return false
	}
	minor, err := strconv.Atoi(strings.TrimPrefix(t.PythonVersion, "3."))
	if err != nil {
		return false
	}
	cp := "cp3" + strconv.Itoa(minor)
	py := "py3" + strconv.Itoa(minor)

	// The python tags and abi tags are judged as sets: a wheel fits when one
	// of the python tags and one of the abi tags make a pair the interpreter
	// accepts, which is decided from what each set holds, not by trying the
	// pairs.
	pySet := make(map[string]bool, len(pys))
	for _, p := range pys {
		pySet[p] = true
	}
	abiSet := make(map[string]bool, len(abis))
	for _, a := range abis {
		abiSet[a] = true
	}
	fitsPython := (pySet[cp] && (abiSet[cp] || abiSet["abi3"] || abiSet["none"])) ||
		((pySet[py] || pySet["py3"]) && abiSet["none"])
	if !fitsPython && abiSet["abi3"] {
		for _, p := range pys {
			if m := cpTagRE.FindStringSubmatch(p); m != nil {
				if k, _ := strconv.Atoi(m[1]); k <= minor {
					fitsPython = true
					break
				}
			}
		}
	}
	if !fitsPython {
		return false
	}
	allowed := map[string]bool{"any": true}
	for _, p := range t.Platforms {
		allowed[p] = true
		if arch, ok := strings.CutPrefix(p, "manylinux2014_"); ok && (arch == "x86_64" || arch == "i686") {
			allowed["manylinux2010_"+arch] = true
			allowed["manylinux1_"+arch] = true
		}
	}
	for _, p := range plats {
		if allowed[p] {
			return true
		}
	}
	return false
}

// requirementHashes lists, by PEP 503 name, the sha256 digests the
// requirements file gives for each package. Each logical line is scanned once.
func requirementHashes(data []byte, lf *lockfile) map[string]map[string]bool {
	lines := splitReqLines(data)
	out := map[string]map[string]bool{}
	for key, p := range lf.pkgs {
		for _, o := range p.occs {
			n, err := occurrenceLine(o.Path)
			if err != nil || n < 1 || n > len(lines) {
				continue
			}
			e := reqSpan(lines, n-1)
			for i := n - 1; i <= e; i++ {
				for _, tok := range reqHashTokRE.FindAllString(pipCommentRE.ReplaceAllString(lines[i].text, ""), -1) {
					if h, ok := strings.CutPrefix(tok, "--hash=sha256:"); ok {
						if out[key] == nil {
							out[key] = map[string]bool{}
						}
						out[key][strings.ToLower(h)] = true
					}
				}
			}
		}
	}
	return out
}

// pipMachine is the platform_machine of the environment pip resolved for,
// read from its platform tags.
func pipMachine(t *worker.Target) string {
	for _, p := range t.Platforms {
		for _, m := range []string{"x86_64", "aarch64"} {
			if strings.HasSuffix(p, "_"+m) {
				return m
			}
		}
	}
	return ""
}

// checkPipReport compares pip's install report for a requirements file with
// what the file says and what PyPI publishes. Every item must be a wheel
// that is not yanked, at the version the file pins (where it pins one), served
// from PyPI's file host, listed on PyPI under that URL and sha256, listed in the
// file's own hashes where the file has any, and installable for the
// environment pip resolved for. The report is output of pip running next to
// code the update does not trust, so none of it is taken as given.
//
// The requirements of each installed package are not read from the report
// either: they are the ones the index declares for its name and version,
// decided by evaluating their markers in the environment pip resolved for
// (extras only where the requirements file asks for them). A requirement that
// is in force and whose package the report does not install is refused, a
// marker that cannot be decided is left to a person, and the version a package
// that was updated ended at must satisfy every such requirement of its
// parents. The in-force requirements are returned, by package name, to build
// the dependency graph from.
func (r *updateRun) checkPipReport(ctx context.Context, report, reqs []byte, target *worker.Target) (*pipChecked, *updateFailure) {
	repp, err := parsePipReport(report)
	if err != nil || repp.Version != "1" {
		return nil, manualFailure(ReasonOutputFilesInvalid, "the pip report cannot be read")
	}
	rep := *repp
	if len(rep.Install) > maxRegistryChecks {
		return nil, &updateFailure{category: CategoryDeferred, reason: ReasonRegistryCheckLimit,
			detail: fmt.Sprintf("pip would install %d packages, more than the %d one update checks against PyPI", len(rep.Install), maxRegistryChecks)}
	}
	if err := checkNodeCount(len(rep.Install)); err != nil {
		return nil, manualFailure(ReasonOutputFilesInvalid, "%v", err)
	}
	lf, err := parseRequirements(reqs)
	if err != nil {
		return nil, manualFailure(ReasonOutputFilesInvalid, "requirements.txt cannot be read: %v", err)
	}
	hashed := requirementsHaveHashes(reqs)
	hashes := requirementHashes(reqs, lf)
	targets := r.targetSet()
	mismatch := func(name, format string, args ...any) *updateFailure {
		f := manualFailure(ReasonDistributionMismatch, "pip report, %s: %s", name, fmt.Sprintf(format, args...))
		if targets[name] {
			f.pkgs = map[string]updateFailureDetail{name: {ReasonDistributionMismatch, f.detail}}
		}
		return f
	}
	installed := map[string]string{} // name to version
	for _, it := range rep.Install {
		installed[normalizePyName(it.Name)] = it.Version
	}
	rels := map[string]PyPIRelease{}
	extras := map[string]map[string]bool{}
	for _, it := range rep.Install {
		name := normalizePyName(it.Name)
		ver := it.Version
		url := it.URL
		sum := strings.ToLower(it.Hashes["sha256"])
		switch {
		case it.IsYanked:
			return nil, mismatch(name, "%s is yanked", ver)
		case it.IsDirect:
			return nil, mismatch(name, "%s is installed from a URL given as a requirement, which is not a file on the index", ver)
		case !pypiFileURL(url) || !strings.HasSuffix(path.Base(url), ".whl"):
			return nil, mismatch(name, "the file %q is not a wheel on %s", clip(url, 200), pypiWheelHost)
		case !sha256HexRE.MatchString(sum):
			return nil, mismatch(name, "no sha256 for %s", ver)
		}
		if p := lf.lookup(name); p != nil {
			for _, o := range p.occs {
				for _, x := range o.Extras {
					if extras[name] == nil {
						extras[name] = map[string]bool{}
					}
					extras[name][normExtra(x)] = true
				}
			}
		}
		if hashed {
			if hs := hashes[name]; len(hs) == 0 || !hs[sum] {
				return nil, mismatch(name, "the wheel's sha256 is not among the hashes the file gives")
			}
		}
		rel, err := r.pyRelease(ctx, name, ver)
		if err != nil {
			return nil, lookupFailure(ctx, err, name+" "+ver+" on PyPI")
		}
		var matched *PyPIFile
		for i, f := range rel.Files {
			if f.Wheel && f.URL == url && f.SHA256 == sum && !f.Yanked {
				matched = &rel.Files[i]
				break
			}
		}
		if matched == nil {
			return nil, mismatch(name, "PyPI does not publish a wheel at %q with sha256 %s", clip(url, 200), sum)
		}
		// The tags of a wheel are read only for a file PyPI publishes.
		if !wheelNameOK(path.Base(url), name, ver) {
			return nil, mismatch(name, "the wheel %q is not a wheel of %s %s", clip(path.Base(url), 200), name, ver)
		}
		if !wheelFitsTarget(path.Base(url), target) {
			return nil, mismatch(name, "the wheel %q does not fit the image's environment (Python %s)", clip(path.Base(url), 200), target.PythonVersion)
		}
		spec := matched.RequiresPython
		if spec == "" {
			spec = rel.RequiresPython
		}
		if ok, decided := pythonMinorAllows(spec, target.PythonVersion); !decided || !ok {
			return nil, pkgFailure(name, ReasonRequiresPythonUnsupported, "%s %s asks for Python %q, which Python %s does not (or not at every patch level) satisfy", name, ver, spec, target.PythonVersion)
		}
		rels[name] = rel
	}

	// Every requirement of the requirements file that is in force in the
	// environment must be installed by the report at a version it allows,
	// whatever form it is written in. The roots of the dependency graph are
	// these requirements, not what the report marks as requested.
	budget := &markerBudget{ctx: ctx, max: maxMarkerEvals}
	roots, fail := r.checkFileRequirements(ctx, lf, installed, target, budget)
	if fail != nil {
		return nil, fail
	}

	// The extras each package is installed with are those the requirements
	// file asks for and those its parents ask for in their requirements, and
	// a package's extras decide which of its own requirements are in force, so
	// they are spread through the graph until nothing more is added.
	env := func(name string) markerEnv {
		return markerEnv{pyMinor: target.PythonVersion, machine: pipMachine(target), extras: extras[name], budget: budget}
	}
	for pass := 0; ; pass++ {
		if pass > maxExtraPasses {
			return nil, manualFailure(ReasonMarkerNotEvaluated, "the extras the packages ask of each other did not settle in %d passes", maxExtraPasses)
		}
		changed := false
		for _, it := range rep.Install {
			if err := ctx.Err(); err != nil {
				return nil, &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: err.Error()}
			}
			name := normalizePyName(it.Name)
			e := env(name)
			for _, rd := range rels[name].RequiresDist {
				dep, _, in, err := e.applies(rd)
				if err != nil {
					return nil, markerFailure(ctx, err, name+" "+installed[name])
				}
				if !in || dep == name {
					continue
				}
				if _, ok := installed[dep]; !ok {
					continue
				}
				for _, x := range requirementExtras(rd) {
					if extras[dep] == nil {
						extras[dep] = map[string]bool{}
					}
					if !extras[dep][x] {
						extras[dep][x] = true
						changed = true
					}
				}
			}
		}
		if !changed {
			break
		}
	}

	requires := map[string][]string{}
	for _, it := range rep.Install {
		name := normalizePyName(it.Name)
		ver := it.Version
		e := env(name)
		for _, rd := range rels[name].RequiresDist {
			dep, constraint, in, err := e.applies(rd)
			if err != nil {
				return nil, markerFailure(ctx, err, name+" "+ver)
			}
			if !in || dep == name {
				continue
			}
			depVer, ok := installed[dep]
			if !ok {
				return nil, manualFailure(ReasonUnexplainedDiff, "%s %s requires %s in this environment and the pip report does not install it", name, ver, dep)
			}
			requires[name] = append(requires[name], dep)
			if f := rangeProblem(dep, name+" "+ver, constraint, depVer, true); f != nil {
				return nil, f
			}
		}
	}
	return &pipChecked{requires: requires, roots: roots}, nil
}

// Bounds on the spreading of extras and on the marker evaluations of one report.
var (
	maxExtraPasses = 32
	maxMarkerEvals = 200000
)

// pipChecked is a pip report that passed its checks: the requirements in
// force for each installed package, and the packages the requirements file
// asks for itself.
type pipChecked struct {
	requires map[string][]string
	roots    []string
}

// checkFileRequirements evaluates every requirement line of the requirements
// file (its marker in the environment pip resolved for) and requires each one
// that is in force to be installed by the report, at the pinned version for
// an exact pin and at a version that satisfies any other specifier. A line
// that names a URL or path is not something the report can be checked
// against.
func (r *updateRun) checkFileRequirements(ctx context.Context, lf *lockfile, installed map[string]string, target *worker.Target, budget *markerBudget) ([]string, *updateFailure) {
	env := markerEnv{pyMinor: target.PythonVersion, machine: pipMachine(target), budget: budget}
	var names []string
	for k := range lf.pkgs {
		names = append(names, k)
	}
	sort.Strings(names)
	targets := r.targetSet()
	var roots []string
	inRoots := map[string]bool{}
	for _, k := range names {
		for _, o := range lf.pkgs[k].occs {
			if o.Marker != "" {
				in, err := env.eval(o.Marker)
				if err != nil {
					return nil, markerFailure(ctx, err, "requirements.txt, "+o.Path)
				}
				if !in {
					continue
				}
			}
			if o.ManualReason == ReasonNonRegistrySource {
				return nil, manualFailure(ReasonNonRegistrySource, "requirements.txt, %s requires %s from a URL or a path, which the pip report cannot be checked against", o.Path, k)
			}
			ver, ok := installed[k]
			if !ok {
				return nil, manualFailure(ReasonDistributionMismatch, "requirements.txt, %s requires %s and the pip report does not install it", o.Path, k)
			}
			var f *updateFailure
			switch {
			case o.Version != "":
				if !versionsEqual(schemePEP440, o.Version, ver) {
					f = manualFailure(ReasonDistributionMismatch, "requirements.txt, %s pins %s to %s and pip installs %s", o.Path, k, o.Version, ver)
					if targets[k] {
						f.pkgs = map[string]updateFailureDetail{k: {ReasonDistributionMismatch, f.detail}}
					}
				}
			case o.Constraint != "":
				f = rangeProblem(k, "requirements.txt, "+o.Path, o.Constraint, ver, true)
			}
			if f != nil {
				return nil, f
			}
			if !inRoots[k] {
				inRoots[k] = true
				roots = append(roots, k)
			}
		}
	}
	return roots, nil
}

// wheelNameOK reports whether a wheel file name is of the form
// name-version[-build]-python-abi-platform.whl and names the given package
// (PEP 503 name) and version.
func wheelNameOK(file, name, version string) bool {
	base := strings.TrimSuffix(file, ".whl")
	if base == file {
		return false
	}
	parts := strings.Split(base, "-")
	if len(parts) != 5 && len(parts) != 6 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	return normalizePyName(parts[0]) == name && versionsEqual(schemePEP440, strings.ReplaceAll(parts[1], "_", "-"), version)
}

// sdistNameOK reports whether a source distribution file name is
// name-version.tar.gz (or .zip) for the given package and version.
func sdistNameOK(file, name, version string) bool {
	for _, ext := range []string{".tar.gz", ".zip"} {
		if base, ok := strings.CutSuffix(file, ext); ok {
			i := strings.LastIndex(base, "-")
			return i > 0 && normalizePyName(base[:i]) == name && versionsEqual(schemePEP440, base[i+1:], version)
		}
	}
	return false
}

// markerFailure maps an error from evaluating a marker: running out of the
// update's budget or time defers the item, a marker that cannot be decided is
// left to a person.
func markerFailure(ctx context.Context, err error, what string) *updateFailure {
	switch {
	case errors.Is(err, errMarkerBudget):
		return &updateFailure{category: CategoryDeferred, reason: ReasonUpdateInputLimit,
			detail: fmt.Sprintf("the requirements of the packages need more than %d marker evaluations (at %s)", maxMarkerEvals, what)}
	case ctx.Err() != nil:
		return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
	}
	return manualFailure(ReasonMarkerNotEvaluated, "%s: %v", what, err)
}
