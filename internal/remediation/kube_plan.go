package remediation

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// Reasons of a running image that cannot be compared because the workload's
// own definition and the running state disagree or are missing.
const (
	// ReasonDeclaredRefMismatch: the image a Pod spec names is not the
	// reference the container runs under. The runtime may have reused content
	// it already had under another name, so neither the update advice nor a
	// candidate can be trusted for this reference.
	ReasonDeclaredRefMismatch Reason = "declared_ref_mismatch"
	// ReasonDeclaredRefUnavailable: the Pod spec's image of a running
	// container could not be read. The running reference is not taken as the
	// declared one.
	ReasonDeclaredRefUnavailable Reason = "declared_ref_unavailable"
)

// DeclaredInstance is what the definition of one running container says: the
// image reference and the pull policy of its Pod spec. Instances with the same
// workload, reference and policy are listed once.
type DeclaredInstance struct {
	// Workload is the workload key, <kind>/<namespace>/<name>/<container>.
	Workload string `json:"workload"`
	// Ref is the reference of the spec; "" when it could not be read.
	Ref string `json:"ref,omitempty"`
	// PullPolicy is the spec's imagePullPolicy; "" when it is not set.
	PullPolicy string `json:"pull_policy,omitempty"`
}

// ChainOwner is one layer of a management chain as the plan shows it.
type ChainOwner struct {
	Kind       DeployOwnerKind `json:"kind"`
	Resource   ResourceKind    `json:"resource,omitempty"`
	ResourceID string          `json:"resource_id,omitempty"`
	Name       string          `json:"name,omitempty"`
	Scope      string          `json:"scope,omitempty"`
	// Confidence says how far the layer is trusted. The layers above the
	// native resource are read from markers the tool leaves on the object, so
	// they are claims, not verified facts.
	Confidence Confidence `json:"confidence,omitempty"`
}

// WorkloadChains are the management chains of one workload, nearest owner
// first in each chain. More than one chain means several tools claim the
// workload; they are never reduced to one.
type WorkloadChains struct {
	Workload    string         `json:"workload"`
	Chains      [][]ChainOwner `json:"chains"`
	Conflicting bool           `json:"conflicting,omitempty"`
}

// NewWorkloadChains converts the chains of a binding into the plan's form.
func NewWorkloadChains(workload string, chains []OwnerChain) WorkloadChains {
	out := WorkloadChains{Workload: workload, Conflicting: len(chains) > 1}
	for _, c := range chains {
		var owners []ChainOwner
		for _, o := range c.Owners {
			owners = append(owners, ChainOwner{
				Kind: o.Kind, Resource: o.Resource, ResourceID: o.ResourceID,
				Name: o.Name, Scope: o.Scope, Confidence: o.Attribution.Confidence,
			})
		}
		out.Chains = append(out.Chains, owners)
	}
	return out
}

// Key identifies the chains by content, so that the same chains reported by
// several containers of a workload are kept once.
func (w WorkloadChains) Key() string {
	var parts []string
	for _, c := range w.Chains {
		var layers []string
		for _, o := range c {
			layers = append(layers, fmt.Sprintf("%s/%s/%s/%s/%s", o.Kind, o.Resource, o.ResourceID, o.Scope, o.Name))
		}
		parts = append(parts, strings.Join(layers, ">"))
	}
	sort.Strings(parts)
	return w.Workload + "|" + strings.Join(parts, "|")
}

// PullGuidance says what makes a running container take the new content of a
// floating tag.
type PullGuidance string

const (
	// GuidanceRestart: the pull policy is Always, so restarting the workload's
	// Pods pulls the tag again.
	GuidanceRestart PullGuidance = "restart_pulls"
	// GuidanceChangeTag: the pull policy is IfNotPresent, so a node that has
	// the image keeps using it; a restart does not help. A fixed tag or a
	// digest has to replace the floating one.
	GuidanceChangeTag PullGuidance = "change_tag_or_digest"
	// GuidanceImportToNode: the pull policy is Never, so the image has to be
	// brought to the node by other means.
	GuidanceImportToNode PullGuidance = "import_to_node"
)

// PullAdvice is the guidance for the workloads that run an image under one
// effective pull policy.
type PullAdvice struct {
	Guidance PullGuidance `json:"guidance"`
	// Policy is the effective pull policy: the spec's, or the one Kubernetes
	// applies when the spec sets none.
	Policy    string   `json:"policy"`
	Workloads []string `json:"workloads"`
}

// effectivePullPolicy is the policy a container runs with: the spec's own, or
// the default Kubernetes gives an image without one (Always for the tag
// "latest" or no tag, IfNotPresent for any other). A value that is none of
// the three has no policy.
func effectivePullPolicy(declared string, ref ImageRef) string {
	switch declared {
	case "Always", "IfNotPresent", "Never":
		return declared
	case "":
		if ref.Tag == "latest" {
			return "Always"
		}
		return "IfNotPresent"
	}
	return ""
}

// pullAdvice groups the instances' pull policies into guidance for a floating
// tag. It is empty without declarations (Docker), and instances without a
// readable policy are left out.
func pullAdvice(declared []DeclaredInstance, ref ImageRef) []PullAdvice {
	byPolicy := map[string][]string{}
	for _, d := range declared {
		if p := effectivePullPolicy(d.PullPolicy, ref); p != "" && !containsString(byPolicy[p], d.Workload) {
			byPolicy[p] = append(byPolicy[p], d.Workload)
		}
	}
	var out []PullAdvice
	for _, p := range []struct {
		policy string
		g      PullGuidance
	}{{"Always", GuidanceRestart}, {"IfNotPresent", GuidanceChangeTag}, {"Never", GuidanceImportToNode}} {
		if ws := byPolicy[p.policy]; len(ws) > 0 {
			sort.Strings(ws)
			out = append(out, PullAdvice{Guidance: p.g, Policy: p.policy, Workloads: ws})
		}
	}
	return out
}

// sameReference reports whether two references name the same image: the same
// repository after normalisation (so "nginx" and "docker.io/library/nginx"
// agree), the same tag (an absent tag is "latest" when there is no digest) and
// the same digest.
func sameReference(a, b string) bool {
	ak, ok := inventory.RepositoryKey(a)
	if !ok {
		return false
	}
	bk, ok := inventory.RepositoryKey(b)
	if !ok || ak != bk {
		return false
	}
	norm := func(ref string) (tag, digest string) {
		tag, digest = inventory.TagOf(ref), inventory.DigestOf(ref)
		if tag == "" && digest == "" {
			tag = "latest"
		}
		return tag, digest
	}
	at, ad := norm(a)
	bt, bd := norm(b)
	return at == bt && ad == bd
}

// declaredCheck compares what the definitions of an image's running
// containers declare with the reference they run under. It passes when there
// are no declarations (Docker). Any container whose declaration cannot be read
// or names another image stops the comparison: the declaration is never
// replaced by the running reference.
func declaredCheck(declared []DeclaredInstance, running string) (Reason, string, bool) {
	for _, d := range declared {
		if d.Ref == "" {
			return ReasonDeclaredRefUnavailable, fmt.Sprintf("the image the spec of %s names could not be read, so it is not known whether it matches the running reference", d.Workload), false
		}
		if !sameReference(d.Ref, running) {
			return ReasonDeclaredRefMismatch, fmt.Sprintf("the spec of %s names %s but the container runs %s", d.Workload, d.Ref, running), false
		}
	}
	return "", "", true
}

// DeclaredProblems returns the declarations among declared that do not
// match the running reference: unreadable ones, and ones that name another
// image.
func DeclaredProblems(declared []DeclaredInstance, running string) []DeclaredInstance {
	var out []DeclaredInstance
	for _, d := range declared {
		if _, _, ok := declaredCheck([]DeclaredInstance{d}, running); !ok {
			out = append(out, d)
		}
	}
	return out
}
