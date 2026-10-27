package remediation

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// kubernetesBodyInput is what the body of a manifest tag pull request
// describes.
type kubernetesBodyInput struct {
	Repo, BaseBranch, BaseSHA, Path string
	Current, Declared               string
	Workloads                       []string
	AlsoRunning                     []ServiceRef
	Targets                         []ManifestTarget
	Management                      []WorkloadChains
	Changes                         []ManifestImageChange
	// Unchanged are containers that use the same image and keep it.
	Unchanged             []string
	CandidateTag          string
	Evidence              *VerificationSummary
	UpdateKey, AttemptKey string
	Marker                string
	Language              BodyLanguage
}

// buildKubernetesPRBody renders the body of a manifest tag pull request:
// what is edited, what the edit relies on without checking it, what merging
// may do, and the comparison of the running image with the candidate. The text
// is cut like buildPRBody's and ends with the marker.
func buildKubernetesPRBody(in kubernetesBodyInput) (string, error) {
	t := textFor(in.Language)
	var b strings.Builder
	b.WriteString("## " + t.HeadWhat + "\n\n")
	fmt.Fprintf(&b, t.KWhat, len(in.Workloads), mdCode(in.Path), mdCode(in.Repo))
	fmt.Fprintf(&b, t.KRunning, mdCode(in.Current))
	fmt.Fprintf(&b, t.KDeclared, mdCode(in.Declared))
	fmt.Fprintf(&b, t.KContainers, codeListIn(t, in.Workloads, maxListedNames))
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
	for _, c := range in.Changes {
		fmt.Fprintf(&b, t.CChange, mdCode(c.Location), mdCode(c.Old), mdCode(c.New))
	}

	if len(in.Unchanged) > 0 {
		fmt.Fprintf(&b, t.KUnchanged, codeListIn(t, in.Unchanged, maxListedNames))
	}

	b.WriteString("\n## " + t.HeadPremises + "\n\n")
	b.WriteString(t.KPremiseSource)
	b.WriteString(t.KPremiseOwner)
	for _, tg := range in.Targets {
		if tg.Kind == inventory.WorkloadCronJob || tg.Kind == inventory.WorkloadJob {
			b.WriteString(t.KCronJob)
			break
		}
	}
	writeKubernetesDeploy(t, &b, in.Workloads, in.Management)

	writeImageVerification(t, &b, in.Evidence)
	return assembleBodyText(b.String(), in.Marker, t.CutNote)
}

// writeKubernetesDeploy writes the section on what merging may do: it may
// deploy through a tool outside KestreLynx, and the management chains found on
// the workloads, if any, are shown as claims.
func writeKubernetesDeploy(t *prText, b *strings.Builder, workloads []string, management []WorkloadChains) {
	b.WriteString("\n## " + t.HeadDeploy + "\n\n")
	b.WriteString(t.KReflect)
	shown := 0
	var lines []string
	for _, m := range management {
		if !containsString(workloads, m.Workload) {
			continue
		}
		var chains []string
		for _, c := range m.Chains {
			if len(c) < 2 {
				continue
			}
			var layers []string
			for _, o := range c {
				layers = append(layers, kubernetesOwnerText(t, o))
			}
			chains = append(chains, strings.Join(layers, t.KChainSep))
		}
		if len(chains) == 0 {
			continue
		}
		shown++
		if shown <= maxListedNames {
			lines = append(lines, fmt.Sprintf(t.KChainLine, mdCode(m.Workload), strings.Join(chains, "; ")))
		}
	}
	if shown == 0 {
		b.WriteString(t.KNoChains)
	} else {
		b.WriteString(t.KChainsIntro)
		for _, l := range lines {
			b.WriteString(l)
		}
		if n := shown - len(lines); n > 0 {
			fmt.Fprintf(b, t.LineMore, n)
		}
	}
	b.WriteString(t.KUnconfirmed)
}

// kubernetesOwnerText names one layer of a management chain.
func kubernetesOwnerText(t *prText, o ChainOwner) string {
	name, scope := mdCode(o.Name), mdCode(o.Scope)
	switch {
	case o.Kind == OwnerHelm:
		return fmt.Sprintf(t.KOwnerHelm, name, scope)
	case o.Kind == OwnerArgoCD:
		return fmt.Sprintf(t.KOwnerArgo, name)
	case o.Kind == OwnerFlux && o.ResourceID == ResourceIDFluxHelmRelease:
		return fmt.Sprintf(t.KOwnerFluxHelm, name, scope)
	case o.Kind == OwnerFlux:
		return fmt.Sprintf(t.KOwnerFluxKust, name, scope)
	case o.Scope != "":
		return fmt.Sprintf(t.KOwnerNative, mdCode(string(o.Resource)), mdCode(o.Scope+"/"+o.Name))
	}
	return fmt.Sprintf(t.KOwnerNative, mdCode(string(o.Resource)), name)
}

// isKubernetesKey reports whether a workload key is the Kubernetes form,
// <kind>/<namespace>/<name>/<container>.
func isKubernetesKey(key string) bool { return strings.Count(key, "/") == 3 }

// isStandaloneKey reports whether a workload key is container/<name>, a
// container started outside Compose.
func isStandaloneKey(key string) bool {
	return strings.HasPrefix(key, "container/") && strings.Count(key, "/") == 1
}

// anyStandalone reports whether some workload key is a container/<name> key.
func anyStandalone(workloads []string) bool {
	for _, w := range workloads {
		if isStandaloneKey(w) {
			return true
		}
	}
	return false
}

// anyKubernetes reports whether some workload key is a Kubernetes key.
func anyKubernetes(workloads []string) bool {
	for _, w := range workloads {
		if isKubernetesKey(w) {
			return true
		}
	}
	return false
}

// ManagementOf collects the management chains the plan shows for the
// workloads.
func ManagementOf(plan Plan, workloads []string) []WorkloadChains {
	var out []WorkloadChains
	for _, it := range plan.Items {
		for _, m := range it.Management {
			if containsString(workloads, m.Workload) && !containsChains(out, m) {
				out = append(out, m)
			}
		}
	}
	return out
}

// directoryLister is the part of a source reader that lists a directory.
type directoryLister interface {
	ListDirectory(ctx context.Context, repo, sha, dir string) ([]github.Entry, error)
}

// noImageUpdaterFile checks that the directory of the manifest holds no
// write-back file of Argo CD Image Updater (.argocd-source-*.yaml): where one
// is, another tool owns the image tags. ok is false after the unit's status
// was set. A source that cannot list a directory is not checked.
func (r *prRun) noImageUpdaterFile(c *unitCtx, base string) bool {
	lister, can := r.s.cfg.Source.(directoryLister)
	if !can {
		return true
	}
	dir := path.Dir(c.u.path)
	entries, err := lister.ListDirectory(r.ctx, c.rs.name, base, dir)
	if err != nil {
		if errors.Is(err, github.ErrNotFound) {
			return true // the read of the file reports its absence
		}
		r.readFailure(c, "list the directory of the manifest", err)
		return false
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name, ".argocd-source-") && strings.HasSuffix(e.Name, ".yaml") {
			c.set(PRStatusManual, ReasonImageUpdaterFile, fmt.Sprintf("%s in the directory of the manifest is a write-back file of Argo CD Image Updater, which owns the image tags there", e.Name))
			return false
		}
	}
	return true
}
