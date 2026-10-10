package config

import (
	"fmt"
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

// validateMappings checks every mapping on its own and then the mappings
// against each other:
//   - a workload has at most one Compose entry, at most one Dependencies
//     entry and at most one Dockerfile entry;
//   - a Compose service of a file is edited on behalf of one workload only;
//   - a dependency root is always read from the same branch, so several
//     workloads may share it only when they agree on that;
//   - a Dockerfile is likewise always read from the same branch, while
//     several workloads may name the same Dockerfile and stage.
//
// Repository names are compared case-insensitively, as GitHub does.
func validateMappings(ms []RemediationMapping) error {
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
		if _, _, err := ParseWorkloadKey(m.Workload); err != nil {
			return fmt.Errorf("config: %s.workload %q %v", at, m.Workload, err)
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
