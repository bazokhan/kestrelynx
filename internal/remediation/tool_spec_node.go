package remediation

import (
	"sort"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/toolfetch"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// The values of RuntimeRecord.Basis: why the Node.js runtime of an update was
// chosen.
const (
	// RuntimeBasisFile: a version file (.node-version, .nvmrc) names the
	// major version.
	RuntimeBasisFile = "declared_file"
	// RuntimeBasisLowestInRange: only ranges declare the Node.js version, and
	// the runtime is the lowest series among those updates run in that they
	// and the package manager allow.
	RuntimeBasisLowestInRange = "lowest_in_range"
	// RuntimeBasisDefault: nothing declares the Node.js version, and the
	// runtime is the highest series updates run in.
	RuntimeBasisDefault = "default"
)

// The values of RuntimeExclusion.Why.
const (
	// The series is past the end of its support (or has no image).
	ExcludedEndOfLife = "end_of_life"
	// The release of the package manager that would run does not run on the
	// Node.js of the series.
	ExcludedManagerEngines = "manager_engines"
	// A declaration about Node.js does not allow the Node.js of the series.
	ExcludedDeclarations = "declarations"
)

// RuntimeExclusion is a series of the runtime table that the declarations
// about Node.js allow and that an update was not run in.
type RuntimeExclusion struct {
	ID  string `json:"id"`
	Why string `json:"why"`
	// EOL is the date the support of the series ended (end_of_life).
	EOL string `json:"eol,omitempty"`
	// Manager, ManagerVersion and Engines name the release and the engines.node
	// it declares (manager_engines).
	Manager        string `json:"manager,omitempty"`
	ManagerVersion string `json:"manager_version,omitempty"`
	Engines        string `json:"engines,omitempty"`
}

// nodeRejection is a Node.js series that was tried and does not fit.
type nodeRejection struct {
	rt  worker.RuntimeSpec
	err *UnsupportedError
	ex  RuntimeExclusion
}

// nodePool lists the Node.js runtimes of the table that an update can run in at
// the time now (they have an image and their support has not ended), lowest
// series first.
func nodePool(now time.Time) []worker.RuntimeSpec {
	var pool []worker.RuntimeSpec
	for _, r := range worker.Runtimes() {
		if r.Kind == worker.KindNode && r.HasImage() && !r.EndOfLife(now) {
			pool = append(pool, r)
		}
	}
	sort.SliceStable(pool, func(i, j int) bool { return seriesNumber(pool[i].ID) < seriesNumber(pool[j].ID) })
	return pool
}

// resolveNodeSpec resolves the declarations of an npm or pnpm unit: the pair of
// a Node.js runtime and a package manager release. The candidates are the
// supported series of the table, each with the exact Node.js of its image and
// the manager release that belongs to it. A candidate stays when the exact
// Node.js satisfies every range that is declared, the major version agrees with
// a version file, the manager release satisfies every declaration about the
// manager, and the engines.node of that release allows the exact Node.js. Of
// those the series a version file names is used, else the lowest one when only
// ranges declare Node.js, else the highest. A failed update never moves on to
// another candidate.
func resolveNodeSpec(in ToolSpecInput) (ToolSpec, *UnsupportedError) {
	spec := ToolSpec{Manager: in.Manager, Runtime: defaultNodeRuntime}
	if uerr := nodeFetchConfigProblem(in); uerr != nil {
		return spec, uerr
	}
	d, uerr := readNodeDeclarations(in)
	if uerr != nil {
		return spec, uerr
	}
	spec.Requested = nodeSeriesOf(d)
	for _, decl := range d.decls {
		spec.Declarations = append(spec.Declarations, ToolDeclaration{Source: decl.source, Value: clip(decl.value, 100)})
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}

	var files, ranges []nodeDecl
	for _, decl := range d.decls {
		if decl.major != "" {
			files = append(files, decl)
		} else {
			ranges = append(ranges, decl)
		}
	}
	pool := nodePool(now)
	if len(pool) == 0 {
		return spec, unsupported(ReasonNodeSpecUnsupported, "no Node.js runtime of the runtime table is in support")
	}
	supported := make([]string, len(pool))
	for i, r := range pool {
		supported[i] = r.Series
	}

	var order []worker.RuntimeSpec
	switch {
	case len(files) > 0:
		spec.RuntimeBasis = RuntimeBasisFile
		for _, r := range pool {
			if r.Series == files[0].major {
				order = append(order, r)
			}
		}
		if len(order) == 0 {
			return spec, unsupported(ReasonNodeSpecUnsupported, "%s asks for Node.js %s, and updates run on Node.js %s", files[0].source, files[0].value, strings.Join(supported, ", "))
		}
	case len(ranges) > 0:
		spec.RuntimeBasis = RuntimeBasisLowestInRange
		order = pool
	default:
		spec.RuntimeBasis = RuntimeBasisDefault
		for i := len(pool) - 1; i >= 0; i-- {
			order = append(order, pool[i])
		}
	}

	// Problems with the manager's own declarations do not depend on the
	// runtime, so they are reported as they are.
	if _, uerr := resolveNodeManager(in, d.top, pool[0].ID); uerr != nil && (uerr.Reason == ReasonManagerSpecInvalid || uerr.Reason == ReasonManagerSpecConflict) {
		return spec, uerr
	}

	var rejected []nodeRejection
	for _, rt := range order {
		mgr, rej := nodeCandidate(in, d, rt)
		if rej != nil {
			rejected = append(rejected, *rej)
			continue
		}
		spec.Runtime = rt.ID
		spec.ToolVersion, spec.ToolSource, spec.SpecHash = mgr.version, mgr.source, mgr.specHash
		spec.Declarations = append(spec.Declarations, mgr.declarations...)
		spec.NodeFloor = nodeFloor(d, rt)
		switch spec.RuntimeBasis {
		case RuntimeBasisFile:
			for _, f := range files {
				spec.RuntimeDeclared = append(spec.RuntimeDeclared, ToolDeclaration{Source: f.source, Value: clip(f.value, 100)})
			}
		case RuntimeBasisLowestInRange:
			for _, r := range ranges {
				spec.RuntimeDeclared = append(spec.RuntimeDeclared, ToolDeclaration{Source: r.source, Value: clip(r.value, 100)})
			}
			spec.RuntimeExcluded = excludedBelow(spec.Requested, rt, rejected)
		}
		return spec, nil
	}
	// Nothing fits: the candidate that would have been used says why.
	return spec, rejected[0].err
}

// nodeCandidate judges one runtime: it returns the manager release that goes
// with it, or why the pair does not fit.
func nodeCandidate(in ToolSpecInput, d *nodeDeclarations, rt worker.RuntimeSpec) (managerChoice, *nodeRejection) {
	reject := func(uerr *UnsupportedError, ex RuntimeExclusion) (managerChoice, *nodeRejection) {
		ex.ID = rt.ID
		return managerChoice{}, &nodeRejection{rt: rt, err: uerr, ex: ex}
	}
	exact, ok := fullVersion(rt.Version)
	if !ok {
		return reject(unsupported(ReasonNodeSpecUnsupported, "the runtime %s has the version %q", rt.ID, rt.Version), RuntimeExclusion{Why: ExcludedDeclarations})
	}
	for _, decl := range d.decls {
		if decl.major == "" && !decl.set.contains(exact) {
			return reject(unsupported(ReasonNodeSpecUnsupported, "%s %s does not allow Node.js %s, which updates run on in the series %s", decl.source, clip(decl.value, 80), rt.Version, rt.Series),
				RuntimeExclusion{Why: ExcludedDeclarations})
		}
	}
	mgr, uerr := resolveNodeManager(in, d.top, rt.ID)
	if uerr != nil {
		return reject(uerr, RuntimeExclusion{Why: ExcludedDeclarations})
	}
	if text, known := toolfetch.NodeEngines(toolfetch.Manager(in.Manager), mgr.version); known {
		if set, readable := rangeSet(text); readable && !set.contains(exact) {
			return reject(unsupported(ReasonManagerSpecUnsupported, "%s %s needs Node.js %s, and the update would run on Node.js %s", in.Manager, mgr.version, text, rt.Version),
				RuntimeExclusion{Why: ExcludedManagerEngines, Manager: string(in.Manager), ManagerVersion: mgr.version, Engines: text})
		}
	}
	return mgr, nil
}

// excludedBelow lists the series the declarations allow that are lower than the
// one chosen, with why each was not used.
func excludedBelow(requested []string, chosen worker.RuntimeSpec, rejected []nodeRejection) []RuntimeExclusion {
	var out []RuntimeExclusion
	for _, id := range requested {
		if seriesNumber(id) >= seriesNumber(chosen.ID) {
			continue
		}
		rt, ok := worker.LookupRuntime(id)
		if !ok {
			continue
		}
		var rej *nodeRejection
		for i := range rejected {
			if rejected[i].rt.ID == id {
				rej = &rejected[i]
			}
		}
		switch {
		case rej != nil && rej.ex.Why == ExcludedManagerEngines:
			out = append(out, rej.ex)
		case !rt.HasImage() || rej == nil:
			// No image, or its support has ended.
			out = append(out, RuntimeExclusion{ID: id, Why: ExcludedEndOfLife, EOL: rt.EOL})
		default:
			out = append(out, rej.ex)
		}
	}
	return out
}

// nodeFloor is the lowest Node.js version every declaration allows, as
// "X.Y.Z"; a partial version stands for the lowest version of its series. It is
// "" when nothing declares Node.js or when that is the Node.js of the runtime.
func nodeFloor(d *nodeDeclarations, rt worker.RuntimeSpec) string {
	if len(d.decls) == 0 {
		return ""
	}
	all := allVersions()
	for _, decl := range d.decls {
		all = all.intersect(decl.set)
	}
	low, ok := all.lowest()
	if !ok {
		return ""
	}
	text := low[0] + "." + low[1] + "." + low[2]
	if text == rt.Version {
		return ""
	}
	return text
}
