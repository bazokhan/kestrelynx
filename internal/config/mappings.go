package config

import (
	"fmt"
	"regexp"
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

// KubernetesWorkload is a parsed <kind>/<namespace>/<name>/<container> key.
type KubernetesWorkload struct {
	Kind      inventory.WorkloadKind
	Namespace string
	Name      string
	Container string
}

var (
	dns1123Label     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	dns1123Subdomain = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
)

// kubernetesWorkloadKinds are the kinds the Kubernetes adapter reports.
var kubernetesWorkloadKinds = map[string]inventory.WorkloadKind{
	"deployment":  inventory.WorkloadDeployment,
	"statefulset": inventory.WorkloadStatefulSet,
	"daemonset":   inventory.WorkloadDaemonSet,
	"job":         inventory.WorkloadJob,
	"cronjob":     inventory.WorkloadCronJob,
	"pod":         inventory.WorkloadPod,
}

// ParseKubernetesWorkloadKey splits a <kind>/<namespace>/<name>/<container>
// workload key, the form notifications and the webhook show for a Kubernetes
// container. The container is part of the key: one Pod's containers can come
// from different images and different sources. Names follow the Kubernetes
// rules (a DNS-1123 label for namespace and container, a DNS-1123 subdomain
// of at most 253 bytes for the workload name).
func ParseKubernetesWorkloadKey(key string) (KubernetesWorkload, error) {
	parts := strings.Split(key, "/")
	if len(parts) != 4 {
		return KubernetesWorkload{}, fmt.Errorf("must be <kind>/<namespace>/<name>/<container>")
	}
	kind, ok := kubernetesWorkloadKinds[parts[0]]
	if !ok {
		return KubernetesWorkload{}, fmt.Errorf("has an unknown kind %q (allowed: deployment, statefulset, daemonset, job, cronjob, pod)", parts[0])
	}
	if !dns1123Label.MatchString(parts[1]) {
		return KubernetesWorkload{}, fmt.Errorf("has an invalid namespace")
	}
	if len(parts[2]) > 253 || !dns1123Subdomain.MatchString(parts[2]) {
		return KubernetesWorkload{}, fmt.Errorf("has an invalid workload name")
	}
	if !dns1123Label.MatchString(parts[3]) {
		return KubernetesWorkload{}, fmt.Errorf("has an invalid container name")
	}
	return KubernetesWorkload{Kind: kind, Namespace: parts[1], Name: parts[2], Container: parts[3]}, nil
}

// validateMappings checks every mapping on its own and then the mappings
// against each other. kubernetes says which adapter the keys are for: the
// Compose form with Docker, the Kubernetes form otherwise. With Kubernetes
// only dependency mappings are accepted. The checks are:
//   - a workload has at most one Compose entry, at most one Dependencies
//     entry and at most one Dockerfile entry;
//   - a Compose service of a file is edited on behalf of one workload only;
//   - a dependency root is always read from the same branch, so several
//     workloads may share it only when they agree on that;
//   - a Dockerfile is likewise always read from the same branch, while
//     several workloads may name the same Dockerfile and stage.
//
// Repository names are compared case-insensitively, as GitHub does.
func validateMappings(ms []RemediationMapping, kubernetes bool) error {
	type routeKey struct{ workload, route string }
	type composeKey struct{ repo, path, service string }
	type depKey struct{ repo, dir string }
	type dockerfileKey struct{ repo, path string }
	routes := map[routeKey]int{}
	composes := map[composeKey]int{}
	deps := map[depKey]int{}
	depBranch := map[depKey]string{}
	dockerfiles := map[dockerfileKey]int{}
	dockerfileBranch := map[dockerfileKey]string{}

	for i, m := range ms {
		at := fmt.Sprintf("remediation.mappings[%d]", i)
		var keyErr error
		if kubernetes {
			_, keyErr = ParseKubernetesWorkloadKey(m.Workload)
		} else {
			_, _, keyErr = ParseWorkloadKey(m.Workload)
		}
		if keyErr != nil {
			return fmt.Errorf("config: %s.workload %q %v", at, m.Workload, keyErr)
		}
		if kubernetes && (m.Compose != nil || m.Dockerfile != nil) {
			kind := "compose"
			if m.Compose == nil {
				kind = "dockerfile"
			}
			return fmt.Errorf("config: %s sets a %s mapping, which is not supported with kubernetes.enabled; only dependencies mappings are", at, kind)
		}
		repo, err := github.ParseRepo(m.Repository)
		if err != nil {
			return fmt.Errorf("config: %s.repository %q must be a GitHub owner/name", at, m.Repository)
		}
		if !github.ValidBranch(m.BaseBranch) {
			return fmt.Errorf("config: %s.base_branch %q is not a valid branch name", at, m.BaseBranch)
		}
		set := 0
		for _, present := range []bool{m.Compose != nil, m.Dependencies != nil, m.Dockerfile != nil} {
			if present {
				set++
			}
		}
		if set != 1 {
			return fmt.Errorf("config: %s must set exactly one of compose, dependencies and dockerfile", at)
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
