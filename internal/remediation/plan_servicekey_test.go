package remediation

import "testing"

func TestServiceRef_WorkloadKey(t *testing.T) {
	for name, tc := range map[string]struct {
		ref  ServiceRef
		want string
	}{
		"compose":                        {ServiceRef{Project: "shop", Service: "web", Container: "shop-web-1"}, "compose/shop/web"},
		"kubernetes":                     {ServiceRef{Workload: "deployment/shop/web/app"}, "deployment/shop/web/app"},
		"container started outside":      {ServiceRef{Container: "shop-api"}, "container/shop-api"},
		"project without service":        {ServiceRef{Project: "shop", Container: "shop-api"}, "container/shop-api"},
		"service without project":        {ServiceRef{Service: "web", Container: "shop-api"}, "container/shop-api"},
		"empty":                          {ServiceRef{}, ""},
		"name Docker would not accept":   {ServiceRef{Container: "a"}, ""},
		"name of a pod's container":      {ServiceRef{Container: "shop/pod/app"}, ""},
		"workload wins over a container": {ServiceRef{Workload: "deployment/shop/web/app", Container: "shop-api"}, "deployment/shop/web/app"},
	} {
		if got := tc.ref.WorkloadKey(); got != tc.want {
			t.Errorf("%s: WorkloadKey() = %q, want %q", name, got, tc.want)
		}
	}
}
