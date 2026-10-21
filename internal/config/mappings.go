package config

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// ParseWorkloadKey splits a compose/<project>/<service> workload key. Project
// and service follow the rule the Docker adapter applies to Compose labels,
// and neither may contain a slash.
func ParseWorkloadKey(key string) (project, service string, err error) {
	parts := strings.Split(key, "/")
	if len(parts) != 3 || parts[0] != string(inventory.WorkloadCompose) {
		return "", "", fmt.Errorf("must be compose/<project>/<service>")
	}
	if !inventory.ValidComposeName(parts[1]) {
		return "", "", fmt.Errorf("has an invalid project name")
	}
	if !inventory.ValidComposeName(parts[2]) {
		return "", "", fmt.Errorf("has an invalid service name")
	}
	return parts[1], parts[2], nil
}

// manifestObjectKinds are the Kind spellings of the objects that define each
// kind of workload in a manifest.
var manifestObjectKinds = map[inventory.WorkloadKind]string{
	inventory.WorkloadDeployment:  "Deployment",
	inventory.WorkloadStatefulSet: "StatefulSet",
	inventory.WorkloadDaemonSet:   "DaemonSet",
	inventory.WorkloadJob:         "Job",
	inventory.WorkloadCronJob:     "CronJob",
	inventory.WorkloadPod:         "Pod",
}

// KubernetesWorkload is a parsed <kind>/<namespace>/<name>/<container> key.
type KubernetesWorkload = inventory.KubernetesWorkload

// ParseKubernetesWorkloadKey splits a Kubernetes workload key; see
// inventory.ParseKubernetesWorkloadKey.
func ParseKubernetesWorkloadKey(key string) (KubernetesWorkload, error) {
	return inventory.ParseKubernetesWorkloadKey(key)
}

// validateMappings checks every mapping on its own and then the mappings
// against each other. kubernetes says which adapter the keys are for: the
// Compose form with Docker, the Kubernetes form otherwise. A Compose mapping
// belongs to Docker, a manifest mapping to Kubernetes; dependency and
// Dockerfile mappings to both. The checks are:
//   - a workload has at most one entry of each source, and at most one of
//     Compose and Manifest, since two places would decide its image tag;
//   - a manifest object of a namespace is edited on behalf of one workload
//     container only (mappings that differ in namespace are told apart here;
//     a document without a namespace that two of them resolve to is refused
//     when the file is edited);
//   - a Compose service of a file is edited on behalf of one workload only;
//   - a dependency root is always read from the same branch, so several
//     workloads may share it only when they agree on that;
//   - a Dockerfile is likewise always read from the same branch, while
//     several workloads may name the same Dockerfile and stage.
//
// Repository names are compared case-insensitively, as GitHub does.
func validateMappings(ms []RemediationMapping, kubernetes bool) error {
	type composeKey struct{ repo, path, service string }
	type manifestKey struct{ repo, path, kind, namespace, name, container string }
	type depKey struct{ repo, dir string }
	type dockerfileKey struct{ repo, path string }
	routes := map[routeKey]int{}
	composes := map[composeKey]int{}
	manifests := map[manifestKey]int{}
	deps := map[depKey]int{}
	depBranch := map[depKey]string{}
	dockerfiles := map[dockerfileKey]int{}
	dockerfileBranch := map[dockerfileKey]string{}
	tagRoutes := map[string]int{}
	editPoints := editPointIndex{set: map[editPoint][]string{}, of: map[string]editPoint{}, at: map[string]string{}}
	kustBranch := map[string]kustBranchEntry{}

	for i, m := range ms {
		at := fmt.Sprintf("remediation.mappings[%d]", i)
		var kw KubernetesWorkload
		var keyErr error
		if kubernetes {
			kw, keyErr = ParseKubernetesWorkloadKey(m.Workload)
		} else {
			_, _, keyErr = ParseWorkloadKey(m.Workload)
		}
		if keyErr != nil {
			return fmt.Errorf("config: %s.workload %q %v", at, m.Workload, keyErr)
		}
		if kubernetes && m.Compose != nil {
			return fmt.Errorf("config: %s sets a compose mapping, which belongs to the Docker adapter; use manifest with kubernetes.enabled", at)
		}
		if !kubernetes && m.Manifest != nil {
			return fmt.Errorf("config: %s sets a manifest mapping, which requires kubernetes.enabled", at)
		}
		if !kubernetes && m.Kustomize != nil {
			return fmt.Errorf("config: %s sets a kustomize mapping, which requires kubernetes.enabled", at)
		}
		repo, err := github.ParseRepo(m.Repository)
		if err != nil {
			return fmt.Errorf("config: %s.repository %q must be a GitHub owner/name", at, m.Repository)
		}
		if !github.ValidBranch(m.BaseBranch) {
			return fmt.Errorf("config: %s.base_branch %q is not a valid branch name", at, m.BaseBranch)
		}
		set := 0
		for _, present := range []bool{m.Compose != nil, m.Manifest != nil, m.Kustomize != nil, m.Dependencies != nil, m.Dockerfile != nil} {
			if present {
				set++
			}
		}
		if set != 1 {
			return fmt.Errorf("config: %s must set exactly one of compose, manifest, kustomize, dependencies and dockerfile", at)
		}
		repoKey := strings.ToLower(repo.String())
		switch {
		case m.Compose != nil:
			if !github.ValidPath(m.Compose.Path, false) {
				return fmt.Errorf("config: %s.compose.path %q must be a normalized path inside the repository (no leading /, no ./ or .., no backslashes)", at, m.Compose.Path)
			}
			if !inventory.ValidComposeName(m.Compose.Service) || strings.Contains(m.Compose.Service, "/") {
				return fmt.Errorf("config: %s.compose.service %q is not a valid service name", at, m.Compose.Service)
			}
			rk := routeKey{m.Workload, "compose"}
			if j, dup := routes[rk]; dup {
				return fmt.Errorf("config: %s repeats the compose mapping of workload %q already set by remediation.mappings[%d]", at, m.Workload, j)
			}
			routes[rk] = i
			ck := composeKey{repoKey, m.Compose.Path, m.Compose.Service}
			if j, dup := composes[ck]; dup {
				return fmt.Errorf("config: %s maps service %q of %s in %s, already mapped by remediation.mappings[%d] for another workload", at, m.Compose.Service, m.Compose.Path, m.Repository, j)
			}
			composes[ck] = i
		case m.Manifest != nil:
			if !github.ValidPath(m.Manifest.Path, false) {
				return fmt.Errorf("config: %s.manifest.path %q must be a normalized path inside the repository (no leading /, no ./ or .., no backslashes)", at, m.Manifest.Path)
			}
			wantKind := manifestObjectKinds[kw.Kind]
			if k := m.Manifest.ObjectKind; k != "" && k != wantKind {
				return fmt.Errorf("config: %s.manifest.object.kind %q must be %q, the kind of workload %q", at, k, wantKind, m.Workload)
			}
			if n := m.Manifest.ObjectName; n != "" && !inventory.ValidDNS1123Subdomain(n) {
				return fmt.Errorf("config: %s.manifest.object.name %q is not a valid object name", at, n)
			}
			objName := m.Manifest.ObjectName
			if objName == "" {
				objName = kw.Name
			}
			rk := routeKey{m.Workload, "manifest"}
			if j, dup := routes[rk]; dup {
				return fmt.Errorf("config: %s repeats the manifest mapping of workload %q already set by remediation.mappings[%d]", at, m.Workload, j)
			}
			routes[rk] = i
			mk := manifestKey{repoKey, m.Manifest.Path, wantKind, kw.Namespace, objName, kw.Container}
			if j, dup := manifests[mk]; dup {
				return fmt.Errorf("config: %s maps container %q of %s %q of namespace %s in %s of %s, already mapped by remediation.mappings[%d] for another workload", at, kw.Container, wantKind, objName, kw.Namespace, m.Manifest.Path, m.Repository, j)
			}
			manifests[mk] = i
			if j, dup := tagRoutes[m.Workload]; dup {
				return fmt.Errorf("config: %s sets a manifest mapping for workload %q, whose image tag remediation.mappings[%d] already sets", at, m.Workload, j)
			}
			tagRoutes[m.Workload] = i
			if err := editPoints.add(at, m.Workload, nil, editPoint{kind: "manifest", repo: repoKey, path: m.Manifest.Path, item: wantKind + "/" + kw.Namespace + "/" + objName + "/" + kw.Container}); err != nil {
				return err
			}
		case m.Kustomize != nil:
			if err := validateKustomize(at, m, repoKey, kw, routes, i, tagRoutes, editPoints, kustBranch); err != nil {
				return err
			}
		case m.Dockerfile != nil:
			if !github.ValidPath(m.Dockerfile.Path, false) {
				return fmt.Errorf("config: %s.dockerfile.path %q must be a normalized path inside the repository (no leading /, no ./ or .., no backslashes)", at, m.Dockerfile.Path)
			}
			if m.Dockerfile.Target != "" && !ValidStageName(m.Dockerfile.Target) {
				return fmt.Errorf("config: %s.dockerfile.target %q is not a valid build stage name", at, m.Dockerfile.Target)
			}
			rk := routeKey{m.Workload, "dockerfile"}
			if j, dup := routes[rk]; dup {
				return fmt.Errorf("config: %s repeats the dockerfile mapping of workload %q already set by remediation.mappings[%d]", at, m.Workload, j)
			}
			routes[rk] = i
			fk := dockerfileKey{repoKey, m.Dockerfile.Path}
			if first, seen := dockerfiles[fk]; seen && dockerfileBranch[fk] != m.BaseBranch {
				return fmt.Errorf("config: %s maps Dockerfile %q of %s to base_branch %q, but remediation.mappings[%d] maps it to %q", at, m.Dockerfile.Path, m.Repository, m.BaseBranch, first, dockerfileBranch[fk])
			}
			if _, seen := dockerfiles[fk]; !seen {
				dockerfiles[fk] = i
				dockerfileBranch[fk] = m.BaseBranch
			}
		default:
			if !github.ValidPath(m.Dependencies.Directory, true) {
				return fmt.Errorf("config: %s.dependencies.directory %q must be \".\" or a normalized path inside the repository (no leading /, no ./ or .., no backslashes)", at, m.Dependencies.Directory)
			}
			rk := routeKey{m.Workload, "dependencies"}
			if j, dup := routes[rk]; dup {
				return fmt.Errorf("config: %s repeats the dependencies mapping of workload %q already set by remediation.mappings[%d]", at, m.Workload, j)
			}
			routes[rk] = i
			dk := depKey{repoKey, m.Dependencies.Directory}
			if first, seen := deps[dk]; seen && depBranch[dk] != m.BaseBranch {
				return fmt.Errorf("config: %s maps dependency root %q of %s to base_branch %q, but remediation.mappings[%d] maps it to %q", at, m.Dependencies.Directory, m.Repository, m.BaseBranch, first, depBranch[dk])
			}
			if _, seen := deps[dk]; !seen {
				deps[dk] = i
				depBranch[dk] = m.BaseBranch
			}
		}
	}
	return nil
}

// routeKey identifies one source route of a workload.
type routeKey struct{ workload, route string }

// editPoint is a place in the repository that decides the image of the
// containers it acts on. For a manifest it is the container's own image field;
// for a Kustomize images entry it is the entry, which acts on every container
// that is rendered with its image name.
type editPoint struct {
	kind string
	repo string
	path string
	item string
}

// editPointIndex checks that an edit point is declared with one set of
// containers by every mapping that names it, and that a container belongs to
// one edit point only: two places deciding one container's tag would produce
// conflicting pull requests.
type editPointIndex struct {
	set map[editPoint][]string // the sorted set each edit point was first declared with
	of  map[string]editPoint   // the edit point of each container
	at  map[string]string      // where the container was first declared
}

// add records that the mapping at (the workload plus affects) is an edit of
// point.
func (x *editPointIndex) add(at, workload string, affects []string, point editPoint) error {
	members := append([]string{workload}, affects...)
	sort.Strings(members)
	if first, seen := x.set[point]; seen {
		if strings.Join(first, "\x00") != strings.Join(members, "\x00") {
			return fmt.Errorf("config: %s declares the containers %s for %s of %s, but another mapping of it declares %s: every mapping of one edit point must declare the same set (the mapped workload and its affects)",
				at, strings.Join(members, ", "), point.item, point.path, strings.Join(first, ", "))
		}
	} else {
		x.set[point] = members
	}
	for _, w := range members {
		if prev, ok := x.of[w]; ok && prev != point {
			return fmt.Errorf("config: %s puts %s under %s of %s, but %s (%s) already puts it under %s of %s: the container's tag would be decided in two places",
				at, w, point.item, point.path, x.at[w], w, prev.item, prev.path)
		}
		x.of[w] = point
		if _, ok := x.at[w]; !ok {
			x.at[w] = at
		}
	}
	return nil
}

type kustBranchEntry struct {
	at     string
	branch string
}

// kustomizationFileNames are the names a kustomization file can have.
var kustomizationFileNames = map[string]bool{"kustomization.yaml": true, "kustomization.yml": true, "Kustomization": true}

// validateKustomize checks one kustomize mapping.
func validateKustomize(at string, m RemediationMapping, repoKey string, kw KubernetesWorkload, routes map[routeKey]int, i int,
	tagRoutes map[string]int, idx editPointIndex, branches map[string]kustBranchEntry) error {
	k := m.Kustomize
	if !github.ValidPath(k.Path, false) {
		return fmt.Errorf("config: %s.kustomize.path %q must be a normalized path inside the repository (no leading /, no ./ or .., no backslashes)", at, k.Path)
	}
	if !kustomizationFileNames[path.Base(k.Path)] {
		return fmt.Errorf("config: %s.kustomize.path %q must be a kustomization.yaml, kustomization.yml or Kustomization file", at, k.Path)
	}
	if !validKustomizeImageName(k.Image) {
		return fmt.Errorf("config: %s.kustomize.image %q must be the name of an images entry: an image name without a tag or a digest", at, k.Image)
	}
	rk := routeKey{m.Workload, "kustomize"}
	if j, dup := routes[rk]; dup {
		return fmt.Errorf("config: %s repeats the kustomize mapping of workload %q already set by remediation.mappings[%d]", at, m.Workload, j)
	}
	routes[rk] = i
	if j, dup := tagRoutes[m.Workload]; dup {
		return fmt.Errorf("config: %s sets a kustomize mapping for workload %q, whose image tag remediation.mappings[%d] already sets", at, m.Workload, j)
	}
	tagRoutes[m.Workload] = i
	seen := map[string]bool{m.Workload: true}
	for _, a := range k.Affects {
		if _, err := ParseKubernetesWorkloadKey(a); err != nil {
			return fmt.Errorf("config: %s.kustomize.affects %q %v", at, a, err)
		}
		if seen[a] {
			return fmt.Errorf("config: %s.kustomize.affects lists %q more than once or lists the mapped workload itself", at, a)
		}
		seen[a] = true
	}
	// A file is always read from one branch.
	fk := repoKey + "\x00" + k.Path
	if b, ok := branches[fk]; ok && b.branch != m.BaseBranch {
		return fmt.Errorf("config: %s maps %s of %s to base_branch %q, but %s maps it to %q", at, k.Path, m.Repository, m.BaseBranch, b.at, b.branch)
	}
	if _, ok := branches[fk]; !ok {
		branches[fk] = kustBranchEntry{at, m.BaseBranch}
	}
	return idx.add(at, m.Workload, k.Affects, editPoint{kind: "kustomize", repo: repoKey, path: k.Path, item: "images[" + k.Image + "]"})
}

// validKustomizeImageName reports whether s can be the name of an images
// entry: an image reference without a tag or a digest.
func validKustomizeImageName(s string) bool {
	if s == "" || len(s) > 255 || strings.ContainsAny(s, " \t\r\n$@{}") {
		return false
	}
	if _, ok := inventory.RepositoryOf(s); !ok {
		return false
	}
	return inventory.TagOf(s) == "" && inventory.DigestOf(s) == ""
}

// ValidStageName reports whether s can name a Dockerfile build stage: a
// letter followed by letters, digits, "_", "." and "-", at most 128 bytes.
// Docker compares stage names without regard to case.
func ValidStageName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// MappingsOutsideScope lists the workload keys of the mappings whose namespace
// is outside kubernetes.namespaces: the scan never sees those workloads, so
// their mappings have no effect. It is empty unless Kubernetes is enabled with
// a namespace list. A mapping like that is a likely mistake, not an invalid
// configuration, so the caller warns instead of failing.
func (c Config) MappingsOutsideScope() []string {
	if !c.Kubernetes.Enabled || len(c.Kubernetes.Namespaces) == 0 {
		return nil
	}
	scoped := map[string]bool{}
	for _, ns := range c.Kubernetes.Namespaces {
		scoped[ns] = true
	}
	var out []string
	for _, m := range c.Remediation.Mappings {
		w, err := ParseKubernetesWorkloadKey(m.Workload)
		if err != nil || scoped[w.Namespace] {
			continue
		}
		out = append(out, m.Workload)
	}
	return out
}
