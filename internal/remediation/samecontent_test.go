package remediation

import (
	"context"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func TestSameContentTreatsRunningDigestAsUnknownKind(t *testing.T) {
	res := resolution('b', 'c') // manifest b, config c, index (top) 0
	kinds := []inventory.DigestKind{inventory.DigestConfig, inventory.DigestRegistry}
	cases := []struct {
		name    string
		hex     byte
		same    bool
		matched string
	}{
		{"candidate config digest", 'c', true, "config"},
		{"candidate platform manifest digest", 'b', true, "manifest"},
		{"candidate top-level index digest", '0', true, "index"},
		{"unrelated digest", 'a', false, ""},
	}
	for _, kind := range kinds {
		for _, c := range cases {
			d, _ := inventory.ParseDigest(kind, "sha256:"+hex64(c.hex))
			same, known, matched := sameContent(inventory.EntityKey{Digest: d}, res)
			if !known || same != c.same || matched != c.matched {
				t.Errorf("%s running digest, %s: same=%v known=%v matched=%q; want %v true %q", kind, c.name, same, known, matched, c.same, c.matched)
			}
		}
	}
	if _, known, _ := sameContent(inventory.EntityKey{}, res); known {
		t.Error("an entity without a digest must not be comparable")
	}
}

func TestPlanSameContentByIndexManifestOrConfigDigest(t *testing.T) {
	for _, tc := range []struct {
		name string
		hex  byte
	}{{"index", '0'}, {"manifest", 'b'}, {"config", 'c'}} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv()
			e.reg.res["nginx:latest"] = resolution('b', 'c')
			e.candidateScan("nginx:latest", nil, pkgs("libc", "2"))
			// Docker with the containerd image store reports the index digest
			// where the classic store reports the config digest; either way
			// the running entity is typed as a config digest.
			plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{input("nginx:latest", tc.hex, prepared, fixedA())})
			it := item(t, plan, 0)
			if it.Category != CategoryNoCandidate || it.Reason != ReasonSameContent || it.Candidate != nil {
				t.Fatalf("item = %s/%s (%s)", it.Category, it.Reason, it.Detail)
			}
			if !strings.Contains(it.Detail, tc.name) {
				t.Errorf("detail %q does not name the matched %s digest", it.Detail, tc.name)
			}
			if len(e.scn.calls) != 0 {
				t.Errorf("scans = %v, want none for the same content", e.scn.calls)
			}
		})
	}
}

func TestPlanFlagsUnverifiedRuntimeDigestKind(t *testing.T) {
	e := newEnv()
	e.reg.res["postgres:16"] = resolution('b', 'c')
	e.candidateScan("postgres:16", nil, pkgs("libc", "2"))
	plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{input("postgres:16", 'a', prepared, fixedA())})
	it := item(t, plan, 0)
	if !it.Current.DigestKindUnverified {
		t.Error("a runtime digest typed as config must be flagged as unverified")
	}
	if it.Candidate == nil || it.Candidate.DigestKindUnverified {
		t.Errorf("candidate = %+v; registry-resolved digests are not flagged", it.Candidate)
	}
}

func npmFinding() scanner.Finding {
	return scanner.Finding{
		Class: inventory.ClassLang, Type: "node-pkg", Target: "app/package-lock.json",
		Package: "lodash", InstalledVer: "4.0.0", FixedVer: "4.1.0", Status: scanner.StatusFixed,
		Severity: scanner.SeverityHigh, VulnID: "CVE-NPM",
	}
}

// Targets are fixed before exploration. A target in a kind of package that the
// baseline comparison scan or the candidate scan never analysed cannot be
// judged, however well the other targets fared.
func TestPlanUnanalysedTargetTypeBlocksAdoption(t *testing.T) {
	for _, tc := range []struct {
		name  string
		conds scanner.ScanConditions // differing conditions force a baseline rescan
	}{
		{"baseline rescan", testConds("other")},
		{"original scan as baseline", prepared},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv()
			e.reg.res["app:1"] = resolution('b', 'c')
			// The comparison scans (the rescan and the candidate) list OS
			// packages only; the OS target resolves on the candidate.
			e.scn.scans["app:1"] = func(t scanner.ScanTarget) scanner.ImageScan {
				if t.Source == scanner.SourceRemote {
					return remoteScan(t, nil, pkgs("libc", "2"))
				}
				return configScan("app:1", 'a', []scanner.Finding{fixedA()}, pkgs("libc", "1"))
			}
			in := input("app:1", 'a', tc.conds, fixedA(), npmFinding())
			plan := e.planner(t, bigLimits, nil).Plan(context.Background(), []ImageInput{in})
			it := item(t, plan, 0)
			if it.Category == CategoryPullAgain || it.Category == CategoryPRCandidate {
				t.Fatalf("adopted: %s/%s (%s)", it.Category, it.Reason, it.Detail)
			}
			if it.Category != CategoryNotComparable || it.Reason != ReasonAnalysisIncomplete {
				t.Errorf("item = %s/%s (%s), want not_comparable/analysis_incomplete", it.Category, it.Reason, it.Detail)
			}
			if it.Decision == nil || it.Decision.Unknown != 1 || it.Decision.Resolved != 1 || it.Decision.Propose {
				t.Errorf("decision = %+v, want the npm target unknown and the OS target resolved", it.Decision)
			}
		})
	}
}
