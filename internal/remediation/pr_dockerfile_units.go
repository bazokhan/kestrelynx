package remediation

import (
	"sort"
	"strings"
)

// dockerfileUnitData is what a Dockerfile update unit carries beyond a
// Compose unit's fields, taken from the plan item it was built from.
type dockerfileUnitData struct {
	// targets are the build stages the unit's workloads name, sorted; "" is
	// the last stage. Every one of them must lead to the edited FROM.
	targets []string
	// stage is the index of the FROM that is edited, stageName its AS name
	// and platform its static --platform, as the plan found them.
	stage     int
	stageName string
	platform  string
	// commit and files are what the plan was made from: the commit its files
	// were read at and their blobs.
	commit string
	files  []SourceFile
	// fixTargets and evidence are fixed when the unit is built from the plan.
	fixTargets []FixTarget
	evidence   *VerificationSummary
}

// buildDockerfileUnits turns the adopted Dockerfile items of the plan into
// update units. An item is adopted only when every running image of its edit
// location confirmed the base and adopted the same candidate, so a unit never
// covers part of them; every other item stays in the plan alone.
func buildDockerfileUnits(plan Plan) []*composeUnit {
	var out []*composeUnit
	for i := range plan.DockerfileItems {
		it := &plan.DockerfileItems[i]
		if it.Category != CategoryPRCandidate || it.Candidate == nil || it.Source.Stage == nil || len(it.Entities) == 0 {
			continue
		}
		loc := dockerfileStageLocation(*it.Source.Stage, it.Source.StageName)
		u := &composeUnit{
			key:        strings.Join([]string{prKindDockerfile, strings.ToLower(it.Source.Repository), it.Source.BaseBranch, it.Source.Path, loc}, "|"),
			repo:       it.Source.Repository,
			baseBranch: it.Source.BaseBranch,
			path:       it.Source.Path,
			current:    it.BaseRef,
			normRef:    normalizedRef(it.BaseRef),
			locations:  []string{loc},
			workloads:  append([]string(nil), it.Workloads...),
			order:      i,
		}
		for _, w := range it.Workloads {
			u.services = append(u.services, workloadService(w))
		}
		sort.Strings(u.services)
		u.services = dedupeSorted(u.services)
		c := *it.Candidate
		u.candidate = &c
		u.df = &dockerfileUnitData{
			targets: append([]string(nil), it.Source.Targets...), stage: *it.Source.Stage, stageName: it.Source.StageName,
			platform: it.Source.Platform, commit: it.Source.CommitSHA,
		}
		for _, f := range it.Source.Files {
			// Only files of the repository that is written to can be compared
			// with its base branch.
			u.df.files = append(u.df.files, f)
		}
		u.df.fixTargets = dockerfileFixTargets(it, loc)
		u.df.evidence = dockerfileEvidence(plan, it, loc)
		out = append(out, u)
	}
	return out
}

// workloadService is the service part of a compose/<project>/<service> key.
func workloadService(key string) string {
	if i := strings.LastIndex(key, "/"); i >= 0 {
		return key[i+1:]
	}
	return key
}

// entityID names a running image of an item in the records.
func entityID(e DockerfileEntity) string { return e.Running.Ref + "|" + e.Running.Entity }

// dockerfileFixTargets are the base findings the comparison resolves, each
// with the running images it is resolved for. A target is a vulnerability in
// a package in a set of layers; the same finding in different layers of two
// images is two targets. Nothing is dropped because another image lacks it.
func dockerfileFixTargets(it *DockerfileItem, loc string) []FixTarget {
	idx := map[string]*FixTarget{}
	var order []string
	for _, e := range it.Entities {
		res := map[verdictKey]bool{}
		if e.Comparison != nil {
			for _, v := range e.Comparison.Verdicts {
				if v.Outcome == OutcomeResolved {
					res[verdictKey{v.VulnID, v.Package}] = true
				}
			}
		}
		for _, t := range e.Targets {
			if !res[verdictKey{t.VulnID, t.Package}] {
				continue
			}
			ft := FixTarget{Location: loc, VulnID: t.VulnID, Package: t.Package, Layers: sortedCopy(t.Layers)}
			k := ft.key()
			have := idx[k]
			if have == nil {
				have = &ft
				idx[k] = have
				order = append(order, k)
			}
			if id := entityID(e); !containsString(have.Entities, id) {
				have.Entities = append(have.Entities, id)
			}
		}
	}
	var out []FixTarget
	for _, k := range order {
		ft := *idx[k]
		sort.Strings(ft.Entities)
		out = append(out, ft)
	}
	sortFixTargets(out)
	return out
}

// dockerfileEvidence summarizes the comparison of every running image of an
// item. Resolved and remaining are listed for the base findings the running
// image has; introduced findings are the candidate base's alone.
func dockerfileEvidence(plan Plan, it *DockerfileItem, loc string) *VerificationSummary {
	vs := &VerificationSummary{
		TrivyVersion:    plan.Conditions.TrivyVersion,
		Severities:      append([]string(nil), plan.Conditions.Severities...),
		PlanGeneratedAt: plan.GeneratedAt,
	}
	if t := plan.Conditions.VulnerabilityDB.UpdatedAt; !t.IsZero() {
		tt := t
		vs.VulnDBUpdatedAt = &tt
	}
	for _, e := range it.Entities {
		ev := ItemEvidence{
			ItemKey: entityID(e), Current: e.Running, BaselineScan: e.BaselineScan, CandidateScan: e.CandidateScan,
			Locations: []string{loc},
		}
		if e.CurrentBase != nil {
			cb := *e.CurrentBase
			ev.CurrentBase = &cb
		}
		if e.CandidateBase != nil {
			ev.Candidate = *e.CandidateBase
		}
		l := e.Layers
		ev.Layers = &l
		intel := map[verdictKey]Target{}
		for _, t := range e.Targets {
			intel[verdictKey{t.VulnID, t.Package}] = t
		}
		summary := func(v VulnVerdict) VulnSummary {
			s := VulnSummary{VulnID: v.VulnID, Package: v.Package, Severity: string(v.Severity)}
			if t, ok := intel[verdictKey{v.VulnID, v.Package}]; ok {
				s.Priority, s.KEV = t.Priority, t.KEV
				s.Layers = sortedCopy(t.Layers)
			}
			return s
		}
		if c := e.Comparison; c != nil {
			if vs.Scope == "" {
				vs.Scope = c.Scope
			}
			if len(c.Severities) > 0 {
				vs.Severities = append([]string(nil), c.Severities...)
			}
			for _, v := range c.Verdicts {
				if _, target := intel[verdictKey{v.VulnID, v.Package}]; !target {
					if v.Outcome == OutcomeRemaining {
						ev.OtherRemaining = append(ev.OtherRemaining, summary(v))
					}
					continue
				}
				switch v.Outcome {
				case OutcomeResolved:
					ev.Resolved = append(ev.Resolved, summary(v))
				case OutcomeRemaining:
					ev.Remaining = append(ev.Remaining, summary(v))
				}
			}
			for _, v := range c.Introduced {
				ev.Introduced = append(ev.Introduced, summary(v))
			}
		}
		vs.Items = append(vs.Items, ev)
	}
	return vs
}
