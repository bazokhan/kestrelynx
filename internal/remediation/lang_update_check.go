package remediation

import (
	"context"
	"errors"
	"sort"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// sourceScanTypes is the scanner result type of each manager's lockfile.
var sourceScanTypes = map[DependencyManager]string{
	ManagerNpm: "npm", ManagerPnpm: "pnpm", ManagerUv: "uv", ManagerPip: "pip",
}

// sourceCheck scans the dependency files before and after the update under
// the cycle's conditions and records the outcome on the item. The files are
// exactly the ones given, so nothing of the repository (a Trivy
// configuration, an ignore file, a VEX document) can change the result.
func (r *updateRun) sourceCheck(ctx context.Context, before, after map[string][]byte) *updateFailure {
	cfg := r.u.cfg
	sc := &SourceCheck{CommitSHA: r.it.Source.CommitSHA, Before: hashedFiles(before), After: hashedFiles(after)}
	r.check = sc

	scan := func(files map[string][]byte) (scanner.FSScan, *updateFailure) {
		res, err := cfg.Scanner.ScanFS(ctx, files, cfg.Prepared)
		switch {
		case err == nil:
			return res, nil
		case errors.Is(err, scanner.ErrConditionsUnknown):
			return res, &updateFailure{category: CategoryNotComparable, reason: ReasonConditionsUnknown, detail: "the scan conditions of the cycle are not known"}
		case errors.Is(err, scanner.ErrConditionsDiffer):
			return res, &updateFailure{category: CategoryNotComparable, reason: ReasonConditionsDiffer, detail: clip(err.Error(), 300)}
		case ctx.Err() != nil:
			return res, &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
		}
		return res, failedFailure(ReasonSourceScanFailed, "%v", clip(err.Error(), 300))
	}
	b, fail := scan(before)
	if fail != nil {
		return fail
	}
	a, fail := scan(after)
	if fail != nil {
		return fail
	}
	sc.Conditions = a.Conditions
	if !b.Conditions.Equal(a.Conditions) {
		return &updateFailure{category: CategoryNotComparable, reason: ReasonConditionsDiffer, detail: "the scan conditions changed between the scan before the update and the scan after it"}
	}
	return r.evaluateSourceCheck(sc, b.Report, a.Report)
}

func hashedFiles(files map[string][]byte) []HashedFile {
	var out []HashedFile
	for name, c := range files {
		out = append(out, HashedFile{Path: name, SHA256: sha256Hex(c)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// srcPair identifies a vulnerability of a package apart from its version: the
// same pair before and after the update is a vulnerability that remains.
type srcPair struct{ pkg, vuln string }

// evaluateSourceCheck judges the two reports of the dependency files.
//
//   - Before: every updated package is among the analysed packages at the
//     version the image runs, and every vulnerability the update is for is
//     reported for it.
//   - After: every updated package is analysed at the versions the updated
//     file holds, and none of the vulnerabilities the update is for is
//     reported for it at any of its occurrences.
//   - The vulnerabilities of all packages are compared: those only after are
//     new ones, those in both remain.
func (r *updateRun) evaluateSourceCheck(sc *SourceCheck, before, after scanner.ImageScan) *updateFailure {
	if before.PackagesTruncated || after.PackagesTruncated {
		return &updateFailure{category: CategoryNotComparable, reason: ReasonSourceScanIncomplete, detail: "a scan listed more packages than are kept"}
	}
	m := r.it.Manager
	typ := sourceScanTypes[m]
	key := func(n string) string {
		if m.scheme() == schemePEP440 {
			return normalizePyName(n)
		}
		return n
	}
	analysed := func(s scanner.ImageScan) map[string]map[string]bool {
		out := map[string]map[string]bool{}
		for _, rp := range s.Packages {
			if rp.Type != typ {
				continue
			}
			for _, p := range rp.Packages {
				k := key(p.Name)
				if out[k] == nil {
					out[k] = map[string]bool{}
				}
				out[k][p.Version] = true
			}
		}
		return out
	}
	findings := func(s scanner.ImageScan) map[srcPair]scanner.Finding {
		out := map[srcPair]scanner.Finding{}
		for _, f := range s.Findings {
			if f.Type != typ {
				continue
			}
			p := srcPair{key(f.Package), f.VulnID}
			if old, ok := out[p]; !ok || f.InstalledVer < old.InstalledVer {
				out[p] = f
			}
		}
		return out
	}
	pkgsBefore, pkgsAfter := analysed(before), analysed(after)
	fb, fa := findings(before), findings(after)

	vuln := func(p srcPair, f scanner.Finding) SourceVuln {
		v := SourceVuln{Package: f.Package, Version: f.InstalledVer, VulnID: p.vuln, Severity: f.Severity, FixedVer: f.FixedVer}
		if in, ok := r.u.cfg.Intel.lookup(p.vuln); ok {
			v.KEV = in.KEV
		}
		return v
	}
	sorted := func(vs []SourceVuln) []SourceVuln {
		sort.Slice(vs, func(i, j int) bool {
			if vs[i].Package != vs[j].Package {
				return vs[i].Package < vs[j].Package
			}
			return vs[i].VulnID < vs[j].VulnID
		})
		return vs
	}
	for p, f := range fb {
		if _, still := fa[p]; still {
			sc.Remaining = append(sc.Remaining, vuln(p, fa[p]))
		} else {
			sc.Resolved = append(sc.Resolved, vuln(p, f))
		}
	}
	for p, f := range fa {
		if _, was := fb[p]; !was {
			sc.Introduced = append(sc.Introduced, vuln(p, f))
		}
	}
	sorted(sc.Resolved)
	sorted(sc.Remaining)
	sorted(sc.Introduced)
	sc.Counts = [3]int{len(sc.Resolved), len(sc.Remaining), len(sc.Introduced)}
	for _, l := range []*[]SourceVuln{&sc.Resolved, &sc.Remaining, &sc.Introduced} {
		if len(*l) > maxSourceVulns {
			*l, sc.Truncated = (*l)[:maxSourceVulns], true
		}
	}

	for _, i := range r.set.idx {
		p := r.it.Packages[i]
		n := p.matchName()
		if !pkgsBefore[n][p.Installed] {
			return manualFailure(ReasonSourceTargetNotDetectedBefore, "the scan of the original files does not list %s at %s", p.Name, p.Installed)
		}
		for _, c := range p.CVEs {
			if _, ok := fb[srcPair{n, c.VulnID}]; !ok {
				return manualFailure(ReasonSourceTargetNotDetectedBefore, "the scan of the original files does not report %s for %s", c.VulnID, p.Name)
			}
		}
	}
	for _, n := range r.set.names {
		have := pkgsAfter[n]
		if len(have) == 0 {
			return manualFailure(ReasonSourceTargetNotAnalysedAfter, "the scan of the updated files does not list %s", n)
		}
		for _, v := range r.afterVersions[n] {
			if !have[v] {
				return manualFailure(ReasonSourceTargetNotAnalysedAfter, "the scan of the updated files does not list %s at %s, the version the file holds", n, v)
			}
		}
	}
	for _, i := range r.set.idx {
		p := r.it.Packages[i]
		for _, c := range p.CVEs {
			if f, ok := fa[srcPair{p.matchName(), c.VulnID}]; ok {
				return manualFailure(ReasonSourceTargetStillDetected, "the scan of the updated files still reports %s for %s %s", c.VulnID, p.Name, f.InstalledVer)
			}
		}
	}
	if len(sc.Introduced) > 0 {
		kev := 0
		for _, v := range sc.Introduced {
			if v.KEV {
				kev++
			}
		}
		first := sc.Introduced[0]
		if kev > 0 {
			return manualFailure(ReasonSourceIntroducedKEV, "the update introduces %d findings, %d of them KEV-listed, such as %s for %s %s", sc.Counts[2], kev, first.VulnID, first.Package, first.Version)
		}
		return manualFailure(ReasonSourceIntroduced, "the update introduces %d findings, such as %s for %s %s", sc.Counts[2], first.VulnID, first.Package, first.Version)
	}
	sc.Passed = true
	return nil
}

// maxSourceVulns bounds each list of findings kept in a SourceCheck.
const maxSourceVulns = 500
