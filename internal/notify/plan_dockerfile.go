package notify

import (
	"fmt"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

// dockerfileKEVResolved counts the KEV-listed targets of an item that every
// running image that has the target resolves.
func dockerfileKEVResolved(it remediation.DockerfileItem) int {
	n := 0
	seen := map[string]bool{}
	for _, e := range it.Entities {
		for _, t := range e.Targets {
			key := t.VulnID + "|" + t.Package.Name + "|" + string(t.Package.Ecosystem) + "|" + string(t.Package.Class)
			if !t.KEV || seen[key] {
				continue
			}
			seen[key] = true
			resolved := true
			for _, o := range it.Entities {
				has := false
				for _, ot := range o.Targets {
					has = has || (ot.VulnID == t.VulnID && ot.Package == t.Package)
				}
				if !has {
					continue
				}
				found := false
				if o.Comparison != nil {
					for _, v := range o.Comparison.Verdicts {
						found = found || (v.VulnID == t.VulnID && v.Package == t.Package && v.Outcome == remediation.OutcomeResolved)
					}
				}
				resolved = resolved && found
			}
			if resolved {
				n++
			}
		}
	}
	return n
}

// dockerfileUnitOf finds the pull request unit of an item's update, if any.
// The unit is the item's status whether or not it has a pull request: one
// that is manual, deferred or blocked is shown too.
func dockerfileUnitOf(it remediation.DockerfileItem, units []remediation.PRUnit) *remediation.PRUnit {
	if it.Candidate == nil || it.Source.Stage == nil {
		return nil
	}
	for i, u := range units {
		if u.Kind == "dockerfile" && strings.EqualFold(u.Repo, it.Source.Repository) && u.BaseBranch == it.Source.BaseBranch &&
			u.Path == it.Source.Path && u.Current == it.BaseRef && u.CandidateTag == it.Candidate.Tag && len(u.Locations) == 1 &&
			strings.HasPrefix(u.Locations[0], fmt.Sprintf("stages[%d]", *it.Source.Stage)) {
			return &units[i]
		}
	}
	return nil
}

// --- generic webhook ---

type dockerfileItemPayload struct {
	Key string `json:"key"`
	// Kind and FixClass say what the item is: an update of the base image a
	// Dockerfile builds from. Verification names what the counts compare: the
	// current base image with the candidate base image.
	Kind         string `json:"kind"`
	FixClass     string `json:"fix_class"`
	Verification string `json:"verification"`
	// FinalImageVerified is false: the image rebuilt from the new Dockerfile
	// is neither built nor scanned.
	FinalImageVerified bool `json:"final_image_verified"`

	Category  string   `json:"category"`
	Reason    string   `json:"reason,omitempty"`
	Detail    string   `json:"detail,omitempty"`
	Priority  string   `json:"priority,omitempty"`
	Workloads []string `json:"workloads"`

	Source    remediation.DockerfileSource `json:"source"`
	BaseRef   string                       `json:"base_ref,omitempty"`
	BaseKind  string                       `json:"base_kind,omitempty"`
	Candidate *imageStatePayload           `json:"candidate,omitempty"`

	// Counts are over the findings the running images have in the base's
	// layers.
	Counts      remediation.DockerfileCounts `json:"counts"`
	Entities    []dockerfileEntityPayload    `json:"entities,omitempty"`
	PullRequest *dockerfilePRPayload         `json:"pull_request,omitempty"`
}

// dockerfileEntityPayload is one running image of an item, with the three
// images kept apart.
type dockerfileEntityPayload struct {
	Services []remediation.ServiceRef `json:"services,omitempty"`

	Running       imageStatePayload  `json:"running_image"`
	CurrentBase   *imageStatePayload `json:"current_base,omitempty"`
	CandidateBase *imageStatePayload `json:"candidate_base,omitempty"`

	LayerConfirmation remediation.LayerConfirmation `json:"layer_confirmation"`
	FindingsByLayer   remediation.LayerCounts       `json:"findings_by_layer"`

	Category string `json:"category"`
	Reason   string `json:"reason,omitempty"`
	Detail   string `json:"detail,omitempty"`

	Targets    int                    `json:"targets"`
	KEVTargets int                    `json:"kev_targets,omitempty"`
	Comparison *comparisonPayload     `json:"comparison,omitempty"`
	Scans      []remediationScanEntry `json:"scans,omitempty"`
}

// dockerfilePRPayload is the state of the pull request unit for an item.
type dockerfilePRPayload struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	Number int    `json:"number,omitempty"`
	URL    string `json:"url,omitempty"`
	State  string `json:"state,omitempty"`
}

func dockerfileItemPayloadOf(it remediation.DockerfileItem, scans map[string]remediation.ScanExecution, units []remediation.PRUnit) dockerfileItemPayload {
	out := dockerfileItemPayload{
		Key: it.Key, Kind: "dockerfile", FixClass: "base_image", Verification: "base_image_comparison",
		FinalImageVerified: it.FinalImageVerified,
		Category:           string(it.Category), Reason: string(it.Reason), Detail: it.Detail, Priority: string(it.Priority),
		Workloads: it.Workloads, Source: it.Source, BaseRef: it.BaseRef, BaseKind: string(it.BaseKind), Counts: it.Counts,
	}
	if out.Workloads == nil {
		out.Workloads = []string{}
	}
	if it.Candidate != nil {
		c := imageStatePayloadOf(*it.Candidate, false)
		out.Candidate = &c
	}
	for _, e := range it.Entities {
		ep := dockerfileEntityPayload{
			Services: e.Services, Running: imageStatePayloadOf(e.Running, true),
			LayerConfirmation: e.Layers, FindingsByLayer: e.Findings,
			Category: string(e.Category), Reason: string(e.Reason), Detail: e.Detail, Targets: len(e.Targets),
		}
		if e.CurrentBase != nil {
			b := imageStatePayloadOf(*e.CurrentBase, false)
			ep.CurrentBase = &b
		}
		if e.CandidateBase != nil {
			b := imageStatePayloadOf(*e.CandidateBase, false)
			ep.CandidateBase = &b
		}
		for _, t := range e.Targets {
			if t.KEV {
				ep.KEVTargets++
			}
		}
		if e.Comparison != nil {
			// The scans of the bases report every finding of the base; the
			// verdicts listed are those of the findings the running image has.
			vr := *e.Comparison
			isTarget := map[string]bool{}
			for _, t := range e.Targets {
				isTarget[t.VulnID+"\x00"+t.Package.Name+"\x00"+string(t.Package.Ecosystem)+"\x00"+string(t.Package.Class)] = true
			}
			vr.Verdicts = nil
			for _, v := range e.Comparison.Verdicts {
				if isTarget[v.VulnID+"\x00"+v.Package.Name+"\x00"+string(v.Package.Ecosystem)+"\x00"+string(v.Package.Class)] {
					vr.Verdicts = append(vr.Verdicts, v)
				}
			}
			ep.Comparison = comparisonPayloadFor(vr, e.Decision, len(e.Targets))
		}
		ep.Scans = scanEntries(scans, e.BaselineScan, e.CandidateScan)
		out.Entities = append(out.Entities, ep)
	}
	if pr := dockerfileUnitOf(it, units); pr != nil {
		out.PullRequest = &dockerfilePRPayload{Status: string(pr.Status), Reason: string(pr.Reason), Number: pr.Number, URL: pr.URL, State: string(pr.State)}
	}
	return out
}
