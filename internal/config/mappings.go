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
//   - a workload has at most one Compose entry and at most one Dependencies
//     entry;
//   - a Compose service of a file is edited on behalf of one workload only;
//   - a dependency root is always read from the same branch, so several
//     workloads may share it only when they agree on that.
//
// Repository names are compared case-insensitively, as GitHub does.
func validateMappings(ms []RemediationMapping) error {
	type routeKey struct{ workload, route string }
	type composeKey struct{ repo, path, service string }
	type depKey struct{ repo, dir string }
	routes := map[routeKey]int{}
	composes := map[composeKey]int{}
	deps := map[depKey]int{}
	depBranch := map[depKey]string{}

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
		if (m.Compose == nil) == (m.Dependencies == nil) {
			return fmt.Errorf("config: %s must set exactly one of compose and dependencies", at)
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
