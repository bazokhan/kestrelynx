package remediation

import (
	"fmt"
	"sort"
	"strings"
)

// kustomizeBodyInput is what the body of a Kustomize images entry pull request
// describes.
type kustomizeBodyInput struct {
	Repo, BaseBranch, BaseSHA, Path string
	Image                           string
	Current, Declared               string
	// Workloads are the containers the entry is declared to act on, and
	// ViaInit those of them that are ordinary init containers.
	Workloads, ViaInit []string
	AlsoRunning        []ServiceRef
	Management         []WorkloadChains
	Change             KustomizeChange
	// Helm says the body is for a Helm values key; Image is then the key and
	// HelmChange the rewrite.
	Helm                  bool
	HelmChange            HelmValuesChange
	CronJob               bool
	CandidateTag          string
	Evidence              *VerificationSummary
	UpdateKey, AttemptKey string
	Marker                string
	Language              BodyLanguage
}

// anyJobWorkload reports whether some workload key is a Job or a CronJob.
func anyJobWorkload(workloads []string) bool {
	for _, w := range workloads {
		if strings.HasPrefix(w, "cronjob/") || strings.HasPrefix(w, "job/") {
			return true
		}
	}
	return false
}

// buildKustomizePRBody renders the body of a Kustomize newTag pull request:
// what is edited, the containers the entry is declared to act on and that this
// is taken on trust, what merging may do, and the comparison of the running
// image with the candidate.
func buildKustomizePRBody(in kustomizeBodyInput) (string, error) {
	t := textFor(in.Language)
	var b strings.Builder
	b.WriteString("## " + t.HeadWhat + "\n\n")
	if in.Helm {
		fmt.Fprintf(&b, t.HelmWhat, mdCode(in.Image), mdCode(in.Path), mdCode(in.Repo), len(in.Workloads))
	} else {
		fmt.Fprintf(&b, t.KustWhat, mdCode(KustomizeLocation(in.Image)), mdCode(in.Path), mdCode(in.Repo), len(in.Workloads))
	}
	fmt.Fprintf(&b, t.KRunning, mdCode(in.Current))
	fmt.Fprintf(&b, t.KDeclared, mdCode(in.Declared))
	fmt.Fprintf(&b, t.KustContainers, codeListIn(t, in.Workloads, maxListedNames))
	if len(in.ViaInit) > 0 {
		fmt.Fprintf(&b, t.KustViaInit, codeListIn(t, in.ViaInit, maxListedNames))
	}
	if len(in.AlsoRunning) > 0 {
		var names []string
		for _, s := range in.AlsoRunning {
			n := s.Workload
			if n == "" {
				n = s.Container
				if s.Project != "" {
					n = s.Project + "/" + s.Service
				}
			}
			names = append(names, n)
		}
		fmt.Fprintf(&b, t.KAlso, codeListIn(t, names, maxListedNames))
	}

	b.WriteString("\n## " + t.HeadChange + "\n\n")
	if in.Helm {
		c := in.HelmChange
		fmt.Fprintf(&b, t.CChange, mdCode(c.Location), mdCode(c.Repository+":"+c.Old), mdCode(c.Repository+":"+c.New))
	} else {
		fmt.Fprintf(&b, t.CChange, mdCode(in.Change.Location), mdCode(in.Change.Repository+":"+in.Change.Old), mdCode(in.Change.Repository+":"+in.Change.New))
	}

	b.WriteString("\n## " + t.HeadPremises + "\n\n")
	b.WriteString(t.KPremiseSource)
	if in.Helm {
		b.WriteString(t.HelmPremiseKey)
		flux, helmFound := helmManagement(in.Workloads, in.Management)
		switch {
		case len(flux) > 0:
			fmt.Fprintf(&b, t.HelmFluxRelease, codeListIn(t, flux, maxListedNames))
		case !helmFound:
			b.WriteString(t.HelmNoRelease)
		}
		if in.HelmChange.Quoted {
			b.WriteString(t.HelmQuoted)
		}
	} else {
		b.WriteString(t.KustPremiseEntry)
	}
	b.WriteString(t.KustPremiseSet)
	b.WriteString(t.KPremiseOwner)
	if in.CronJob {
		b.WriteString(t.KCronJob)
	}
	writeKubernetesDeploy(t, &b, in.Workloads, in.Management)

	writeImageVerification(t, &b, in.Evidence)
	return assembleBodyText(b.String(), in.Marker, t.CutNote)
}

// helmManagement returns the listed workloads on which a Flux HelmRelease
// management marker was detected, and whether a Helm release marker was
// detected on any of them.
func helmManagement(workloads []string, management []WorkloadChains) (flux []string, helm bool) {
	seen := map[string]bool{}
	for _, m := range management {
		if !containsString(workloads, m.Workload) {
			continue
		}
		for _, chain := range m.Chains {
			for _, o := range chain {
				switch {
				case o.Kind == OwnerFlux && o.ResourceID == ResourceIDFluxHelmRelease:
					if !seen[m.Workload] {
						seen[m.Workload] = true
						flux = append(flux, m.Workload)
					}
				case o.Kind == OwnerHelm:
					helm = true
				}
			}
		}
	}
	sort.Strings(flux)
	return flux, helm
}
