package kubernetes

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

// Annotation and label keys this package reads to detect a deployment
// management tool's marker on a Kubernetes resource. Each tool's own keys
// are documented next to the detect function that reads them.
const (
	labelHelmManagedBy = "app.kubernetes.io/managed-by"

	annotationHelmReleaseName      = "meta.helm.sh/release-name"
	annotationHelmReleaseNamespace = "meta.helm.sh/release-namespace"

	annotationArgoTrackingID = "argocd.argoproj.io/tracking-id"

	// The Flux name/namespace pair is written as labels, not annotations:
	// both kustomize-controller and helm-controller stamp them on through
	// the same garbage-collection metadata helper in fluxcd/pkg/runtime,
	// which sets labels (they double as the selector Flux uses to prune
	// objects it no longer manages).
	labelFluxKustomizeName      = "kustomize.toolkit.fluxcd.io/name"
	labelFluxKustomizeNamespace = "kustomize.toolkit.fluxcd.io/namespace"
	labelFluxHelmName           = "helm.toolkit.fluxcd.io/name"
	labelFluxHelmNamespace      = "helm.toolkit.fluxcd.io/namespace"
)

// markerMetadata is the subset of a Deployment/StatefulSet/DaemonSet/CronJob
// object this package reads to detect a deployment-management-tool marker:
// UID (to verify the object found by name is truly the one the Pod's
// owner-reference chain led to, not a same-named object that was deleted and
// recreated), plus the labels and annotations the detect functions below
// read.
type markerMetadata struct {
	Namespace   string            `json:"namespace"`
	Name        string            `json:"name"`
	UID         string            `json:"uid"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

// markerObject is the wire shape of one Deployment/StatefulSet/DaemonSet/
// CronJob list item, decoded no deeper than markerMetadata: this package
// never reads spec or status for these four resource kinds.
type markerObject struct {
	Metadata markerMetadata `json:"metadata"`
}

// indexMarkerObjects builds a "<namespace>/<name>" -> markerMetadata lookup.
// Entries with an empty Name are skipped, mirroring indexReplicaSets and
// indexJobs' empty-key exclusion.
func indexMarkerObjects(list []markerObject) map[string]markerMetadata {
	m := make(map[string]markerMetadata, len(list))
	for _, o := range list {
		if o.Metadata.Name == "" {
			continue
		}
		m[o.Metadata.Namespace+"/"+o.Metadata.Name] = o.Metadata
	}
	return m
}

// markerIndexes holds the four marker-checked resource kinds' lookups,
// keyed by "<namespace>/<name>".
type markerIndexes struct {
	deployments  map[string]markerMetadata
	statefulSets map[string]markerMetadata
	daemonSets   map[string]markerMetadata
	cronJobs     map[string]markerMetadata
}

// lookup finds the marker object for a native owner's resource kind and
// name, or ok == false when that resource kind isn't marker-checked (Job,
// Pod) or no object by that namespace+name was listed.
func (idx markerIndexes) lookup(resource remediation.ResourceKind, namespace, name string) (markerMetadata, bool) {
	var table map[string]markerMetadata
	switch resource {
	case remediation.ResourceDeployment:
		table = idx.deployments
	case remediation.ResourceStatefulSet:
		table = idx.statefulSets
	case remediation.ResourceDaemonSet:
		table = idx.daemonSets
	case remediation.ResourceCronJob:
		table = idx.cronJobs
	default:
		return markerMetadata{}, false
	}
	md, ok := table[namespace+"/"+name]
	return md, ok
}

// nativeGroupKind returns the apiVersion group and Kind that a marker-object
// self-reference (Argo CD's tracking-id) must name for the given native
// resource kind. It is only ever called for the four marker-checked kinds;
// Job and Pod are never looked up in markerIndexes in the first place.
func nativeGroupKind(resource remediation.ResourceKind) (group, kind string) {
	if resource == remediation.ResourceCronJob {
		return "batch", "CronJob"
	}
	switch resource {
	case remediation.ResourceDeployment:
		return "apps", "Deployment"
	case remediation.ResourceStatefulSet:
		return "apps", "StatefulSet"
	case remediation.ResourceDaemonSet:
		return "apps", "DaemonSet"
	default:
		return "", ""
	}
}

// resourceKindToWorkloadKind maps the ResourceKind values resolveNativeOwner
// can produce onto the matching inventory.WorkloadKind. It is the single
// place that conversion happens, so a DeployBinding's Workload field is
// always derived from the exact same native owner resolution its OwnerChain
// is built from — never a second, independently-walked resolution that could
// disagree with it.
var resourceKindToWorkloadKind = map[remediation.ResourceKind]inventory.WorkloadKind{
	remediation.ResourceDeployment:  inventory.WorkloadDeployment,
	remediation.ResourceStatefulSet: inventory.WorkloadStatefulSet,
	remediation.ResourceDaemonSet:   inventory.WorkloadDaemonSet,
	remediation.ResourceCronJob:     inventory.WorkloadCronJob,
	remediation.ResourceJob:         inventory.WorkloadJob,
	remediation.ResourcePod:         inventory.WorkloadPod,
}

// nativeOwner is the native Kubernetes chain element resolved from a Pod's
// owner-reference chain, together with the UID of the object it names. It
// mirrors resolveWorkload's allow-list and UID-verification rules exactly —
// same allowed Kinds, same apiVersion-group checks, same "empty UID or
// ambiguous controller reference means unresolved" rules — but additionally
// keeps the resolved object's UID, which resolveWorkload has no reason to
// return to its own caller. It is a separate function rather than a change
// to resolveWorkload's signature so that RunningContainers and its existing
// tests are untouched by this addition.
type nativeOwner struct {
	Owner remediation.DeployOwner
	UID   string
	OK    bool
}

// workload converts n to the inventory.Workload a Container carrying this
// same native owner would be assigned, or the zero Workload when n is not
// OK.
func (n nativeOwner) workload() inventory.Workload {
	if !n.OK {
		return inventory.Workload{}
	}
	return inventory.Workload{
		Kind:  resourceKindToWorkloadKind[n.Owner.Resource],
		Group: n.Owner.Scope,
		Name:  n.Owner.Name,
	}
}

// resolveNativeOwner walks pod's controller owner-reference chain exactly as
// resolveWorkload does (see its doc comment for the full allow-list), except
// it returns a remediation.DeployOwner{Kind: OwnerKubernetes} plus the
// resolved top-level object's UID instead of an inventory.Workload. Anything
// outside the allow-list resolves to the zero nativeOwner (OK == false),
// never a guess.
func resolveNativeOwner(pod podRaw, rsByKey map[string]replicaSetRaw, jobByKey map[string]jobRaw) nativeOwner {
	ns := pod.Metadata.Namespace
	ctrl, ok, ambiguous := controllerOwner(pod.Metadata.OwnerReferences)
	if ambiguous {
		return nativeOwner{}
	}
	if !ok {
		return nativeOwner{
			Owner: remediation.DeployOwner{Kind: remediation.OwnerKubernetes, Resource: remediation.ResourcePod, Name: pod.Metadata.Name, Scope: ns},
			UID:   pod.Metadata.UID,
			OK:    true,
		}
	}

	switch {
	case ctrl.APIVersion == appsV1 && ctrl.Kind == "StatefulSet":
		if ctrl.UID == "" {
			return nativeOwner{}
		}
		return nativeOwner{
			Owner: remediation.DeployOwner{Kind: remediation.OwnerKubernetes, Resource: remediation.ResourceStatefulSet, Name: ctrl.Name, Scope: ns},
			UID:   ctrl.UID,
			OK:    true,
		}

	case ctrl.APIVersion == appsV1 && ctrl.Kind == "DaemonSet":
		if ctrl.UID == "" {
			return nativeOwner{}
		}
		return nativeOwner{
			Owner: remediation.DeployOwner{Kind: remediation.OwnerKubernetes, Resource: remediation.ResourceDaemonSet, Name: ctrl.Name, Scope: ns},
			UID:   ctrl.UID,
			OK:    true,
		}

	case ctrl.APIVersion == appsV1 && ctrl.Kind == "ReplicaSet":
		if ctrl.UID == "" {
			return nativeOwner{}
		}
		rs, found := rsByKey[ownedKey(ns, ctrl.UID)]
		if !found {
			return nativeOwner{}
		}
		rsCtrl, ok, ambiguous := controllerOwner(rs.Metadata.OwnerReferences)
		if ambiguous || !ok || rsCtrl.APIVersion != appsV1 || rsCtrl.Kind != "Deployment" || rsCtrl.UID == "" {
			return nativeOwner{}
		}
		return nativeOwner{
			Owner: remediation.DeployOwner{Kind: remediation.OwnerKubernetes, Resource: remediation.ResourceDeployment, Name: rsCtrl.Name, Scope: ns},
			UID:   rsCtrl.UID,
			OK:    true,
		}

	case ctrl.APIVersion == batchV1 && ctrl.Kind == "Job":
		if ctrl.UID == "" {
			return nativeOwner{}
		}
		job, found := jobByKey[ownedKey(ns, ctrl.UID)]
		if !found {
			return nativeOwner{}
		}
		jobCtrl, ok, ambiguous := controllerOwner(job.Metadata.OwnerReferences)
		if ambiguous {
			return nativeOwner{}
		}
		if !ok {
			return nativeOwner{
				Owner: remediation.DeployOwner{Kind: remediation.OwnerKubernetes, Resource: remediation.ResourceJob, Name: ctrl.Name, Scope: ns},
				UID:   ctrl.UID,
				OK:    true,
			}
		}
		if jobCtrl.APIVersion != batchV1 || jobCtrl.Kind != "CronJob" || jobCtrl.UID == "" {
			return nativeOwner{}
		}
		return nativeOwner{
			Owner: remediation.DeployOwner{Kind: remediation.OwnerKubernetes, Resource: remediation.ResourceCronJob, Name: jobCtrl.Name, Scope: ns},
			UID:   jobCtrl.UID,
			OK:    true,
		}

	default:
		return nativeOwner{}
	}
}

// markerNamespacePattern matches a plausible Kubernetes namespace name: a
// single DNS-1123 label.
var markerNamespacePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// validMarkerNamespace reports whether s is a plausible Kubernetes namespace
// name, for the namespace-shaped values a marker annotation/label carries
// (Helm's release-namespace, Flux's name/namespace pairs).
func validMarkerNamespace(s string) bool {
	return markerNamespacePattern.MatchString(s)
}

// validMarkerName reports whether s is a plausible name-like marker value (a
// Helm release name, an Argo CD Application name, a Flux resource name):
// non-empty, at most 253 bytes, and free of control characters (including
// newlines) — enough to keep unrelated formatting from riding into the
// common model through a field meant to hold a plain human-assigned name,
// without re-implementing any one tool's actual (and differing) naming
// rules.
func validMarkerName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// detectHelm reports the Helm release marker on md. All three conditions
// must hold — the managed-by label set to exactly "Helm", plus a
// validMarkerName release-name annotation and a validMarkerNamespace
// release-namespace annotation — since any one missing or malformed means
// either the object was never actually installed by Helm, or the value
// can't be trusted as-is; the annotations without the label (or the label
// without the annotations) are not treated as partial evidence.
func detectHelm(md markerMetadata, observedAt time.Time) (remediation.DeployOwner, bool) {
	if md.Labels[labelHelmManagedBy] != "Helm" {
		return remediation.DeployOwner{}, false
	}
	release := md.Annotations[annotationHelmReleaseName]
	namespace := md.Annotations[annotationHelmReleaseNamespace]
	if !validMarkerName(release) || !validMarkerNamespace(namespace) {
		return remediation.DeployOwner{}, false
	}
	return remediation.DeployOwner{
		Kind:        remediation.OwnerHelm,
		Name:        release,
		Scope:       namespace,
		Attribution: remediation.Attribution{Origin: remediation.OriginRuntime, Confidence: remediation.ConfidenceClaimed, ObservedAt: observedAt},
	}, true
}

// detectArgoCD reports the Argo CD Application marker on md. The
// argocd.argoproj.io/tracking-id annotation is the only evidence read: its
// value has the form "<app>:<group>/<kind>:<namespace>/<name>", and the
// group/kind/namespace/name portion must self-reference the object it was
// found on (group and kind matching what nativeGroupKind reports for this
// resource kind, namespace and name matching md's own) — proof the
// annotation actually describes this object rather than being a stale or
// misapplied copy; the extracted app name must additionally pass
// validMarkerName. The app.kubernetes.io/instance label is never read: Helm
// and other tools write the same label for unrelated reasons, so on its own
// it is not evidence of Argo CD management, and any disagreement between the
// label and a self-referencing tracking-id is resolved in the annotation's
// favor simply by never consulting the label at all.
func detectArgoCD(md markerMetadata, group, kind string, observedAt time.Time) (remediation.DeployOwner, bool) {
	value := md.Annotations[annotationArgoTrackingID]
	if value == "" {
		return remediation.DeployOwner{}, false
	}
	parts := strings.SplitN(value, ":", 3)
	if len(parts) != 3 {
		return remediation.DeployOwner{}, false
	}
	app, groupKind, nsName := parts[0], parts[1], parts[2]
	if !validMarkerName(app) {
		return remediation.DeployOwner{}, false
	}
	valueGroup, valueKind, ok := strings.Cut(groupKind, "/")
	if !ok || valueKind == "" {
		return remediation.DeployOwner{}, false
	}
	valueNamespace, valueName, ok := strings.Cut(nsName, "/")
	if !ok || valueNamespace == "" || valueName == "" {
		return remediation.DeployOwner{}, false
	}
	if valueGroup != group || valueKind != kind || valueNamespace != md.Namespace || valueName != md.Name {
		return remediation.DeployOwner{}, false
	}
	return remediation.DeployOwner{
		Kind:        remediation.OwnerArgoCD,
		Name:        app,
		Attribution: remediation.Attribution{Origin: remediation.OriginRuntime, Confidence: remediation.ConfidenceClaimed, ObservedAt: observedAt},
	}, true
}

// detectFluxPair reports one Flux marker on md, given the name/namespace
// label keys for the specific Flux resource kind (Kustomization or
// HelmRelease) and the ResourceID that identifies which one. Both labels
// must be present, and pass validMarkerName / validMarkerNamespace
// respectively. Flux writes this pair as labels rather than annotations —
// they double as the selector kustomize-controller/helm-controller use to
// prune objects they no longer manage.
func detectFluxPair(md markerMetadata, nameKey, namespaceKey, resourceID string, observedAt time.Time) (remediation.DeployOwner, bool) {
	name := md.Labels[nameKey]
	namespace := md.Labels[namespaceKey]
	if !validMarkerName(name) || !validMarkerNamespace(namespace) {
		return remediation.DeployOwner{}, false
	}
	return remediation.DeployOwner{
		Kind:        remediation.OwnerFlux,
		ResourceID:  resourceID,
		Name:        name,
		Scope:       namespace,
		Attribution: remediation.Attribution{Origin: remediation.OriginRuntime, Confidence: remediation.ConfidenceClaimed, ObservedAt: observedAt},
	}, true
}

// detectFluxKustomization reports the Flux Kustomization marker on md, read
// from the kustomize.toolkit.fluxcd.io/name and /namespace labels.
func detectFluxKustomization(md markerMetadata, observedAt time.Time) (remediation.DeployOwner, bool) {
	return detectFluxPair(md, labelFluxKustomizeName, labelFluxKustomizeNamespace, remediation.ResourceIDFluxKustomization, observedAt)
}

// detectFluxHelmRelease reports the Flux HelmRelease marker on md, read from
// the helm.toolkit.fluxcd.io/name and /namespace labels. This is distinct
// from detectHelm: a Flux HelmRelease install typically leaves both this
// marker and Helm's own managed-by/release-name markers on the same object,
// and the two must be told apart (a Flux-owned chain, not a
// directly-Helm-owned one).
func detectFluxHelmRelease(md markerMetadata, observedAt time.Time) (remediation.DeployOwner, bool) {
	return detectFluxPair(md, labelFluxHelmName, labelFluxHelmNamespace, remediation.ResourceIDFluxHelmRelease, observedAt)
}

// buildOwnerChains constructs every candidate management chain for one
// Pod's native owner. It returns nil when native.OK is false — the Pod's
// owner-reference chain didn't resolve to a known workload at all, so no
// chain, native or otherwise, can be attached.
//
// When the native owner's resource kind isn't marker-checked (Job, Pod), or
// no marker object was found by namespace+name, or the one found doesn't
// carry the UID native.UID names, the chain is native.Owner alone: no tool
// layer is asserted without a verified marker object to read it from.
// Otherwise, Argo CD and both Flux marker kinds are checked independently;
// each one found becomes the final owner of its own chain (Helm, if also
// found, inserted as the common layer between native and each final owner).
// If none of the three are found but Helm is, Helm itself is the chain's
// final owner. len(result) > 1 signals a genuine multi-tool conflict — never
// collapsed to a single guess about which is authoritative.
func buildOwnerChains(native nativeOwner, idx markerIndexes, observedAt time.Time) []remediation.OwnerChain {
	if !native.OK {
		return nil
	}

	md, found := idx.lookup(native.Owner.Resource, native.Owner.Scope, native.Owner.Name)
	if !found || md.UID != native.UID {
		return []remediation.OwnerChain{{Owners: []remediation.DeployOwner{native.Owner}}}
	}

	var finals []remediation.DeployOwner
	group, kind := nativeGroupKind(native.Owner.Resource)
	if o, ok := detectArgoCD(md, group, kind, observedAt); ok && o.Valid() {
		finals = append(finals, o)
	}
	if o, ok := detectFluxKustomization(md, observedAt); ok && o.Valid() {
		finals = append(finals, o)
	}
	if o, ok := detectFluxHelmRelease(md, observedAt); ok && o.Valid() {
		finals = append(finals, o)
	}
	helm, helmOK := detectHelm(md, observedAt)
	if helmOK && !helm.Valid() {
		helmOK = false
	}

	if len(finals) == 0 {
		if helmOK {
			return []remediation.OwnerChain{{Owners: []remediation.DeployOwner{native.Owner, helm}}}
		}
		return []remediation.OwnerChain{{Owners: []remediation.DeployOwner{native.Owner}}}
	}

	chains := make([]remediation.OwnerChain, 0, len(finals))
	for _, f := range finals {
		owners := []remediation.DeployOwner{native.Owner}
		if helmOK {
			owners = append(owners, helm)
		}
		owners = append(owners, f)
		chains = append(chains, remediation.OwnerChain{Owners: owners})
	}
	return chains
}

// DeployBindings returns one remediation.DeployBinding per running
// container, using the same running-container criteria RunningContainers
// documents (main containers with state.running, plus native sidecars). It
// is a separate LIST cycle from RunningContainers — Observe reads both from
// one cycle. Chains is nil when the Pod's owner-reference chain didn't
// resolve to a known workload; otherwise see buildOwnerChains for how it's
// populated. Intended is left at its zero value on every chain: what a
// management chain's final owner declares as its image is not something this
// package reads.
func (c *Client) DeployBindings(ctx context.Context) ([]remediation.DeployBinding, error) {
	l, err := c.list(ctx, true)
	if err != nil {
		return nil, err
	}
	return bindingsOf(l, time.Now().UTC()), nil
}

// bindingsOf builds the bindings of every running container of l.
func bindingsOf(l listing, observedAt time.Time) []remediation.DeployBinding {
	var out []remediation.DeployBinding
	for _, pod := range l.pods {
		namespace, name := pod.Metadata.Namespace, pod.Metadata.Name
		platform := l.platformByNode[pod.Spec.NodeName]
		native := resolveNativeOwner(pod, l.rsByKey, l.jobByKey)
		chains := buildOwnerChains(native, l.idx, observedAt)
		workload := native.workload()

		initSpecByName := make(map[string]specContainer, len(pod.Spec.InitContainers))
		for _, sc := range pod.Spec.InitContainers {
			initSpecByName[sc.Name] = sc
		}

		for _, cs := range pod.Status.ContainerStatuses {
			if cs.State.Running == nil {
				continue
			}
			out = append(out, buildDeployBinding(namespace, name, cs, platform, workload, chains))
		}
		for _, cs := range pod.Status.InitContainerStatuses {
			if cs.State.Running == nil {
				continue
			}
			sc, ok := initSpecByName[cs.Name]
			if !ok || sc.RestartPolicy != "Always" {
				continue
			}
			out = append(out, buildDeployBinding(namespace, name, cs, platform, workload, chains))
		}
	}
	sortDeployBindings(out)
	return out
}

// buildDeployBinding converts one running container status into a
// remediation.DeployBinding, deriving Subject exactly as buildContainer
// derives a Container's Image: the status-reported image and imageID are
// the only source, never spec's intent.
func buildDeployBinding(namespace, pod string, cs containerStatus, platform inventory.Platform, workload inventory.Workload, chains []remediation.OwnerChain) remediation.DeployBinding {
	img, _ := runningImageOf(cs, platform)
	key, resolved := inventory.EntityKeyOf(img)
	return remediation.DeployBinding{
		Workload:    workload,
		Container:   namespace + "/" + pod + "/" + cs.Name,
		Subject:     inventory.ImageSubject{Ref: img.Ref, Key: key, Resolved: resolved},
		Chains:      chains,
		Conflicting: len(chains) > 1,
	}
}

// sortDeployBindings orders bindings deterministically: (Subject.Ref,
// Subject.Key.Digest.Kind, Subject.Key.Digest.Hex, Subject.Key.Platform.OS,
// Subject.Key.Platform.Architecture, Subject.Key.Platform.Variant,
// Workload.Group, Workload.Name, Container) — the same tiers sortContainers
// uses, with Subject.Key standing in for the Image fields DeployBinding
// doesn't carry directly.
func sortDeployBindings(bindings []remediation.DeployBinding) {
	sort.Slice(bindings, func(i, j int) bool {
		a, b := bindings[i], bindings[j]
		if a.Subject.Ref != b.Subject.Ref {
			return a.Subject.Ref < b.Subject.Ref
		}
		if a.Subject.Key.Digest.Kind != b.Subject.Key.Digest.Kind {
			return a.Subject.Key.Digest.Kind < b.Subject.Key.Digest.Kind
		}
		if a.Subject.Key.Digest.Hex != b.Subject.Key.Digest.Hex {
			return a.Subject.Key.Digest.Hex < b.Subject.Key.Digest.Hex
		}
		if a.Subject.Key.Platform.OS != b.Subject.Key.Platform.OS {
			return a.Subject.Key.Platform.OS < b.Subject.Key.Platform.OS
		}
		if a.Subject.Key.Platform.Architecture != b.Subject.Key.Platform.Architecture {
			return a.Subject.Key.Platform.Architecture < b.Subject.Key.Platform.Architecture
		}
		if a.Subject.Key.Platform.Variant != b.Subject.Key.Platform.Variant {
			return a.Subject.Key.Platform.Variant < b.Subject.Key.Platform.Variant
		}
		if a.Workload.Group != b.Workload.Group {
			return a.Workload.Group < b.Workload.Group
		}
		if a.Workload.Name != b.Workload.Name {
			return a.Workload.Name < b.Workload.Name
		}
		return a.Container < b.Container
	})
}
