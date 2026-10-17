package remediation

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// classifyPyEdge judges the specifier of a requirement for a package, whose
// lowest fixed version is lower and whose vulnerabilities are cves, for uv
// (PEP 440), as classifyEdge does for semver ranges.
//
//   - Pinning: the specifier is one clause "==V" without a wildcard that does
//     not fix some vulnerability, or a set of clauses with no "!=", "===" or
//     wildcard that has an upper bound ("<U", "<=U" or "~=", whose bound is the
//     next release of its prefix) not above the lowest version some
//     vulnerability is fixed in.
//   - Allows the fix: the specifier can be evaluated and allows a version that
//     fixes every vulnerability (the lowest fixed version, or the first fixed
//     version of a line of releases).
//   - Unevaluable: anything else.
func classifyPyEdge(spec, lower string, cves []CVERef) (edgeClass, string) {
	spec = strings.ReplaceAll(strings.TrimSpace(spec), " ", "")
	if spec != "" {
		clauses := strings.Split(spec, ",")
		type bound struct {
			version   string
			inclusive bool
		}
		var uppers []bound
		provable := true
		var parsed []pyClause
		for _, c := range clauses {
			cl, _, ok := parseSpecifierClause(c)
			if !ok {
				provable = false
				break
			}
			if cl.op == "!=" || cl.wildcard {
				provable = false
			}
			parsed = append(parsed, cl)
		}
		if provable && len(parsed) == 1 && parsed[0].op == "==" {
			v := strings.TrimPrefix(clauses[0], "==")
			for _, c := range cves {
				if !meetsFix(schemePEP440, v, c.FixedVers) {
					return edgePinning, proofExact
				}
			}
		}
		if provable {
			for i, cl := range parsed {
				switch cl.op {
				case "<":
					uppers = append(uppers, bound{strings.TrimPrefix(clauses[i], "<"), false})
				case "<=":
					uppers = append(uppers, bound{strings.TrimPrefix(clauses[i], "<="), true})
				case "~=":
					rel := append([]string(nil), cl.version.release[:len(cl.version.release)-1]...)
					rel[len(rel)-1] = incDecimal(rel[len(rel)-1])
					next := strings.Join(rel, ".")
					if cl.version.epoch != "0" {
						next = cl.version.epoch + "!" + next
					}
					uppers = append(uppers, bound{next, false})
				}
			}
			for _, u := range uppers {
				for _, c := range cves {
					m, ok := minFixedIn(schemePEP440, c)
					if !ok {
						continue
					}
					cmp, ok := compareVersions(schemePEP440, u.version, m)
					if ok && ((!u.inclusive && cmp <= 0) || (u.inclusive && cmp < 0)) {
						return edgePinning, proofUpperBound
					}
				}
			}
		}
	}
	candidates := []string{lower}
	for _, c := range cves {
		for _, f := range c.FixedVers {
			candidates = append(candidates, splitFixed(f)...)
		}
	}
	for _, cand := range candidates {
		v, ok := parsePEP440(cand)
		if !ok || len(cves) == 0 || !fixedAt(schemePEP440, cand, cves) {
			continue
		}
		if allowed, evaluable := pySatisfies(v, spec); evaluable && allowed {
			return edgeAllowsFix, ""
		}
	}
	return edgeUnevaluable, ""
}

// normalizeUv reads what a version of a package requires from the index's
// metadata for it, never from the lockfile's record. A requirement counts
// whatever its marker says, as a uv.lock holds every environment at once. A name
// required with different specifiers cannot be reduced to one requirement.
func (s *chainScoper) normalizeUv(p *depNode, cn *chainNorm) (*chainNorm, *updateFailure) {
	rel, err := s.r.pyRelease(s.ctx, p.name, p.version)
	switch {
	case err == nil:
	case isItemBudget(err) != "" || s.ctx.Err() != nil:
		return nil, lookupFailure(s.ctx, err, p.name+" "+p.version+" on PyPI")
	default:
		cn.unknown = fmt.Sprintf("the index's declaration of %s %s is not known: %v", p.name, p.version, clip(err.Error(), 100))
		return cn, nil
	}
	cn.edges = map[string]normEdge{}
	for _, rd := range rel.RequiresDist {
		name, constraint, _, ok := requirementOf(rd)
		if !ok {
			cn.unknown = fmt.Sprintf("a requirement of %s %s cannot be read: %s", p.name, p.version, clip(rd, 100))
			return cn, nil
		}
		if old, seen := cn.edges[name]; seen && old.spec != constraint {
			cn.unsupported[name] = true
		}
		cn.edges[name] = normEdge{spec: constraint}
	}
	return cn, nil
}

// topDeclarations tell where the manifest declares a direct dependency.
type topDeclarations struct {
	npm *manifest
	py  []pyprojectRequirement
}

func newTopDeclarations(m DependencyManager, data []byte) (*topDeclarations, error) {
	if m == ManagerUv {
		py, err := parseTOML(data)
		if err != nil {
			return nil, err
		}
		return &topDeclarations{py: pyprojectRequirementEntries(py)}, nil
	}
	pj, err := readManifest(data)
	if err != nil {
		return nil, err
	}
	return &topDeclarations{npm: pj}, nil
}

// of returns the group and the specifier the manifest declares name with.
func (d *topDeclarations) of(name string) (group, spec string, ok bool) {
	if d.npm != nil {
		for _, f := range manifestDepFields {
			if spec, ok := d.npm.deps[f][name]; ok {
				return f, spec, true
			}
		}
		return "", "", false
	}
	for _, e := range d.py {
		if n, constraint, ok := pythonRequirement(e.text); ok && n == name {
			return e.section, constraint, true
		}
	}
	return "", "", false
}

// chainUpgradePackages are the packages a uv chain update names: a package held
// back may go to any version from its lowest fixed one, the other packages being
// updated are pinned to theirs, and the packages that require a held back one
// are named alone so that uv may move them.
func (r *updateRun) chainUpgradePackages(scope *chainScope) []worker.Package {
	held := map[string]bool{}
	for _, n := range scope.Bn {
		held[n] = true
	}
	var out []worker.Package
	for _, n := range sortedSet(scope.Targets) {
		p := worker.Package{Name: r.nameOf(n)}
		if held[n] {
			p.AtLeast = r.full.target[n]
		} else {
			p.Version = r.full.target[n]
		}
		out = append(out, p)
	}
	var rest []string
	for n := range scope.Names {
		if !scope.Targets[n] {
			rest = append(rest, n)
		}
	}
	sort.Strings(rest)
	for _, n := range rest {
		out = append(out, worker.Package{Name: n})
	}
	return out
}

// runUvChain is the chain update of a uv project: uv locks again with the
// packages that require a held back one free to move and the held back package
// asked for a version from its lowest fixed one up, and the lockfile it makes is
// judged by the checks of the stage. The original input was checked as it is by
// the first update, so that is not done again. When the first update itself made
// a lockfile whose difference from the original the checks refused, that
// lockfile is judged by the chain's rules and no container is used.
func runUvChain(ctx context.Context, r *updateRun, scope *chainScope) *updateFailure {
	if r.recheck != nil {
		return r.verifyAndScan(ctx, r.recheck)
	}
	if r.baseOK == nil {
		return failedFailure(ReasonUpdateInputInvalid, "the original input was not found consistent by the first update, so the chain update has nothing to start from")
	}
	steps := []worker.Step{
		{ID: stepUpdate, Op: worker.OpUvUpgradeChain, Packages: r.chainUpgradePackages(scope)},
		{ID: stepCheck, Op: worker.OpUvCheck, Scratch: true},
	}
	out, fail := r.exec(ctx, worker.ManagerUv, map[string][]byte{"pyproject.toml": r.manifest, "uv.lock": r.src.lock}, steps, "chain")
	if fail != nil {
		return fail
	}
	return r.finishLockfile(ctx, out, steps, r.baseOK)
}
