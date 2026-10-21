package runner

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

// The chains the pull request stage gets cover every Kubernetes container of
// the cycle's observation, whether or not the plan has an item for it, and
// each workload once.
func TestObservedManagementCoversWorkloadsWithoutPlanItems(t *testing.T) {
	c := func(pod string) inventory.Container {
		return inventory.Container{
			Name:     "shop/" + pod + "/app",
			Workload: inventory.Workload{Kind: inventory.WorkloadDeployment, Group: "shop", Name: "web"},
			Declared: &inventory.Declared{Ref: "nginx:1"},
		}
	}
	chain := []remediation.OwnerChain{{Owners: []remediation.DeployOwner{{Kind: remediation.OwnerFlux, ResourceID: remediation.ResourceIDFluxKustomization, Name: "apps", Scope: "flux-system"}}}}
	containers := []inventory.Container{
		c("web-1"), c("web-2"),
		{Name: "shop/db-1/db", Workload: inventory.Workload{Kind: inventory.WorkloadStatefulSet, Group: "shop", Name: "db"}, Declared: &inventory.Declared{Ref: "pg:1"}},
		{Name: "compose-1", Workload: inventory.Workload{Kind: inventory.WorkloadCompose, Group: "p", Name: "s"}},
	}
	bindings := []remediation.DeployBinding{
		{Container: "shop/web-1/app", Chains: chain},
		{Container: "shop/web-2/app", Chains: chain},
		{Container: "compose-1", Chains: chain},
	}
	got := observedManagement(containers, bindings)
	if len(got) != 1 || got[0].Workload != "deployment/shop/web/app" || len(got[0].Chains) != 1 {
		t.Errorf("chains = %+v, want the one workload with a chain, once", got)
	}
}
