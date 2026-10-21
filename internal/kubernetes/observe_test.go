package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

// The testdata/k3s lists were recorded from a K3s v1.31.5 (containerd 1.7)
// cluster: the Pods, ReplicaSets, Deployments and StatefulSet of one
// namespace, and its Node, as the API server returned them. Only
// metadata.managedFields and a node environment annotation were removed.
// Workloads in them:
//   - pinned: two Pods, nginx:1.25.4, annotated with an Argo CD tracking id;
//   - web-demo: a Helm release, nginx:1.25.4;
//   - stale-ifnotpresent, stale-never: spec nginx:1.26 (IfNotPresent, Never)
//     over content that the registry's tag no longer points at;
//   - aliased: spec nginx:mainline, which containerd reports as the other
//     name of the same content, docker.io/library/nginx:1.25.4.

const k3sNamespace = "shop"

// k3sList reads a recorded list.
func k3sList(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "k3s", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// k3sLists are the recorded lists by resource, as bodies of list requests.
func k3sLists(t *testing.T) map[string][]byte {
	t.Helper()
	m := map[string][]byte{}
	for _, r := range []string{"pods", "replicasets", "jobs", "deployments", "statefulsets", "daemonsets", "cronjobs", "nodes"} {
		m[r] = k3sList(t, r)
	}
	return m
}

// serveK3s scripts the fake server with the given lists, for a client whose
// namespaces are [shop].
func serveK3s(f *fakeServer, lists map[string][]byte) {
	f.on("/api/v1/nodes", ok(lists["nodes"]))
	f.on("/api/v1/namespaces/"+k3sNamespace+"/pods", ok(lists["pods"]))
	f.on("/apis/apps/v1/namespaces/"+k3sNamespace+"/replicasets", ok(lists["replicasets"]))
	f.on("/apis/apps/v1/namespaces/"+k3sNamespace+"/deployments", ok(lists["deployments"]))
	f.on("/apis/apps/v1/namespaces/"+k3sNamespace+"/statefulsets", ok(lists["statefulsets"]))
	f.on("/apis/apps/v1/namespaces/"+k3sNamespace+"/daemonsets", ok(lists["daemonsets"]))
	f.on("/apis/batch/v1/namespaces/"+k3sNamespace+"/jobs", ok(lists["jobs"]))
	f.on("/apis/batch/v1/namespaces/"+k3sNamespace+"/cronjobs", ok(lists["cronjobs"]))
}

// editItems decodes a recorded list, lets edit change its items, and encodes
// it again.
func editItems(t *testing.T, list []byte, edit func(items []map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(list, &doc); err != nil {
		t.Fatal(err)
	}
	var items []map[string]any
	for _, it := range doc["items"].([]any) {
		items = append(items, it.(map[string]any))
	}
	edit(items)
	out := make([]any, len(items))
	for i, it := range items {
		out[i] = it
	}
	doc["items"] = out
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func itemNamed(t *testing.T, items []map[string]any, name string) map[string]any {
	t.Helper()
	for _, it := range items {
		if it["metadata"].(map[string]any)["name"] == name {
			return it
		}
	}
	t.Fatalf("no item named %q", name)
	return nil
}

func containerByName(t *testing.T, cs []inventory.Container, name string) inventory.Container {
	t.Helper()
	for _, c := range cs {
		if strings.HasSuffix(c.Name, name) {
			return c
		}
	}
	t.Fatalf("no container %q in %d containers", name, len(cs))
	return inventory.Container{}
}

func TestObserve_K3sRecording(t *testing.T) {
	f := newFakeServer(t)
	serveK3s(f, k3sLists(t))
	srv := f.start()
	c := newTestClient(t, srv, []string{k3sNamespace})

	containers, bindings, err := c.Observe(context.Background())
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if len(containers) != 6 || len(bindings) != 6 {
		t.Fatalf("got %d containers and %d bindings, want 6 and 6", len(containers), len(bindings))
	}

	for _, tc := range []struct {
		container string
		declared  inventory.Declared
		running   string
	}{
		{"/web", inventory.Declared{Ref: "nginx:1.26", PullPolicy: "Never"}, "docker.io/library/nginx:1.26"},
		{"stale-ifnotpresent-85d5c7b696-hldhb/app", inventory.Declared{Ref: "nginx:1.26", PullPolicy: "IfNotPresent"}, "docker.io/library/nginx:1.26"},
		{"aliased-dfd96f5c5-4kd7z/app", inventory.Declared{Ref: "nginx:mainline", PullPolicy: "Never"}, "docker.io/library/nginx:1.25.4"},
		{"web-demo-547c7c9cf7-44p5f/demo", inventory.Declared{Ref: "nginx:1.25.4", PullPolicy: "IfNotPresent"}, "docker.io/library/nginx:1.25.4"},
	} {
		got := containerByName(t, containers, tc.container)
		if got.Declared == nil || *got.Declared != tc.declared {
			t.Errorf("%s: Declared = %+v, want %+v", tc.container, got.Declared, tc.declared)
		}
		if got.Image.Ref != tc.running {
			t.Errorf("%s: running ref = %q, want %q (the status image, never the spec's)", tc.container, got.Image.Ref, tc.running)
		}
	}

	// The two replicas of pinned share one workload and one chain.
	chainOf := func(container string) []remediation.OwnerChain {
		for _, b := range bindings {
			if b.Container == container {
				return b.Chains
			}
		}
		t.Fatalf("no binding for %s", container)
		return nil
	}
	pinned := chainOf("shop/pinned-54776c966b-mbcs2/app")
	if len(pinned) != 1 || len(pinned[0].Owners) != 2 || pinned[0].Final().Kind != remediation.OwnerArgoCD || pinned[0].Final().Name != "pinned-app" {
		t.Errorf("pinned chains = %+v, want deployment -> Argo CD app pinned-app", pinned)
	}
	helm := chainOf("shop/web-demo-547c7c9cf7-44p5f/demo")
	if len(helm) != 1 || helm[0].Final().Kind != remediation.OwnerHelm || helm[0].Final().Name != "web" || helm[0].Final().Scope != "shop" {
		t.Errorf("helm chains = %+v, want deployment -> Helm release web in shop", helm)
	}
	plain := chainOf("shop/stale-never-0/web")
	if len(plain) != 1 || len(plain[0].Owners) != 1 || plain[0].Owners[0].Resource != remediation.ResourceStatefulSet {
		t.Errorf("unmanaged statefulset chains = %+v, want the statefulset alone", plain)
	}

	// One listing: every resource is listed once, by GET only.
	seen := map[string]int{}
	for _, r := range f.requests {
		seen[strings.SplitN(r, "?", 2)[0]]++
	}
	for path, n := range seen {
		if n != 1 {
			t.Errorf("%s listed %d times, want once", path, n)
		}
	}
	if len(seen) != 8 {
		t.Errorf("listed %d resources, want 8: %v", len(seen), seen)
	}
	for _, m := range f.methods {
		if m != http.MethodGet {
			t.Errorf("request method %s, want GET only", m)
		}
	}
}

// RunningContainers keeps its own set of LIST calls: the resources that only
// carry markers are not listed for it.
func TestRunningContainers_DoesNotListMarkerKinds(t *testing.T) {
	f := newFakeServer(t)
	serveK3s(f, k3sLists(t))
	srv := f.start()
	c := newTestClient(t, srv, []string{k3sNamespace})

	cs, err := c.RunningContainers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 6 {
		t.Fatalf("got %d containers, want 6", len(cs))
	}
	for _, kind := range []string{"deployments", "statefulsets", "daemonsets", "cronjobs"} {
		if f.requestedPathPrefix("/apis/apps/v1/namespaces/shop/"+kind) || f.requestedPathPrefix("/apis/batch/v1/namespaces/shop/"+kind) {
			t.Errorf("%s were listed for RunningContainers", kind)
		}
	}
}

// The spec and status arrays of a Pod need not share an order; containers are
// matched by name.
func TestObserve_SpecAndStatusOrderDiffer(t *testing.T) {
	lists := k3sLists(t)
	lists["pods"] = editItems(t, lists["pods"], func(items []map[string]any) {
		pod := itemNamed(t, items, "pinned-54776c966b-mbcs2")
		spec := pod["spec"].(map[string]any)
		status := pod["status"].(map[string]any)
		first := spec["containers"].([]any)[0].(map[string]any)
		second := map[string]any{}
		for k, v := range first {
			second[k] = v
		}
		second["name"], second["image"], second["imagePullPolicy"] = "sidecar", "busybox:1.36.1", "Always"
		spec["containers"] = []any{first, second}
		fs := status["containerStatuses"].([]any)[0].(map[string]any)
		ss := map[string]any{}
		for k, v := range fs {
			ss[k] = v
		}
		ss["name"], ss["image"] = "sidecar", "docker.io/library/busybox:1.36.1"
		// Status lists the sidecar first, spec lists it second.
		status["containerStatuses"] = []any{ss, fs}
	})
	f := newFakeServer(t)
	serveK3s(f, lists)
	c := newTestClient(t, f.start(), []string{k3sNamespace})

	cs, _, err := c.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	side := containerByName(t, cs, "pinned-54776c966b-mbcs2/sidecar")
	if side.Declared == nil || side.Declared.Ref != "busybox:1.36.1" || side.Declared.PullPolicy != "Always" {
		t.Errorf("sidecar declared = %+v, want busybox:1.36.1 Always", side.Declared)
	}
	app := containerByName(t, cs, "pinned-54776c966b-mbcs2/app")
	if app.Declared == nil || app.Declared.Ref != "nginx:1.25.4" || app.Declared.PullPolicy != "IfNotPresent" {
		t.Errorf("app declared = %+v, want nginx:1.25.4 IfNotPresent", app.Declared)
	}
}

// A container without a spec entry (or with a duplicated one) has no declared
// reference; the running one is not put in its place.
func TestObserve_MissingDeclaredInfoIsEmpty(t *testing.T) {
	for name, edit := range map[string]func(spec map[string]any){
		"no entry": func(spec map[string]any) { spec["containers"] = []any{} },
		"renamed":  func(spec map[string]any) { spec["containers"].([]any)[0].(map[string]any)["name"] = "other" },
		"duplicate": func(spec map[string]any) {
			spec["containers"] = append(spec["containers"].([]any), spec["containers"].([]any)[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			lists := k3sLists(t)
			lists["pods"] = editItems(t, lists["pods"], func(items []map[string]any) {
				edit(itemNamed(t, items, "stale-never-0")["spec"].(map[string]any))
			})
			f := newFakeServer(t)
			serveK3s(f, lists)
			c := newTestClient(t, f.start(), []string{k3sNamespace})

			cs, _, err := c.Observe(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			got := containerByName(t, cs, "stale-never-0/web")
			if got.Declared == nil {
				t.Fatal("Declared = nil, want a value with an empty Ref (nil means the adapter has no declarations)")
			}
			if got.Declared.Ref != "" || got.Declared.PullPolicy != "" {
				t.Errorf("Declared = %+v, want it empty", *got.Declared)
			}
			if got.Image.Ref != "docker.io/library/nginx:1.26" {
				t.Errorf("running ref = %q, want the status image", got.Image.Ref)
			}
		})
	}
}

// An owner reference whose UID is not the listed ReplicaSet's leaves the
// workload unknown, and a Deployment whose UID differs from the one the chain
// led to carries no tool markers: nothing is taken from an object that is not
// the owner.
func TestObserve_OwnerUIDMismatch(t *testing.T) {
	t.Run("replica set uid", func(t *testing.T) {
		lists := k3sLists(t)
		lists["pods"] = editItems(t, lists["pods"], func(items []map[string]any) {
			pod := itemNamed(t, items, "pinned-54776c966b-mbcs2")
			pod["metadata"].(map[string]any)["ownerReferences"].([]any)[0].(map[string]any)["uid"] = "00000000-0000-0000-0000-000000000000"
		})
		f := newFakeServer(t)
		serveK3s(f, lists)
		c := newTestClient(t, f.start(), []string{k3sNamespace})
		cs, bindings, err := c.Observe(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		got := containerByName(t, cs, "pinned-54776c966b-mbcs2/app")
		if got.Workload.Known() {
			t.Errorf("Workload = %+v, want unknown for a stale owner reference", got.Workload)
		}
		if got.Declared == nil || got.Declared.Ref != "nginx:1.25.4" {
			t.Errorf("Declared = %+v, want it read regardless of the owner", got.Declared)
		}
		for _, b := range bindings {
			if b.Container == "shop/pinned-54776c966b-mbcs2/app" && len(b.Chains) != 0 {
				t.Errorf("chains = %+v, want none without a resolved owner", b.Chains)
			}
		}
	})
	t.Run("deployment uid", func(t *testing.T) {
		lists := k3sLists(t)
		lists["deployments"] = editItems(t, lists["deployments"], func(items []map[string]any) {
			itemNamed(t, items, "pinned")["metadata"].(map[string]any)["uid"] = "11111111-1111-1111-1111-111111111111"
		})
		f := newFakeServer(t)
		serveK3s(f, lists)
		c := newTestClient(t, f.start(), []string{k3sNamespace})
		_, bindings, err := c.Observe(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range bindings {
			if b.Container != "shop/pinned-54776c966b-mbcs2/app" {
				continue
			}
			if len(b.Chains) != 1 || len(b.Chains[0].Owners) != 1 {
				t.Errorf("chains = %+v, want the deployment alone: its marker object has another UID", b.Chains)
			}
		}
	})
}

// A LIST that fails fails the observation: neither containers nor chains are
// returned from a partial listing.
func TestObserve_ListFailure(t *testing.T) {
	for _, resource := range []string{"pods", "replicasets", "deployments", "cronjobs"} {
		t.Run(resource, func(t *testing.T) {
			f := newFakeServer(t)
			serveK3s(f, k3sLists(t))
			group := "/apis/apps/v1"
			switch resource {
			case "pods":
				group = "/api/v1"
			case "cronjobs":
				group = "/apis/batch/v1"
			}
			f.on(group+"/namespaces/"+k3sNamespace+"/"+resource, repeatedServerErrors(10)...)
			c := newTestClient(t, f.start(), []string{k3sNamespace})

			cs, bindings, err := c.Observe(context.Background())
			if err == nil {
				t.Fatal("Observe succeeded although a LIST failed")
			}
			if !strings.Contains(err.Error(), resource) {
				t.Errorf("err = %v, want it to name %s", err, resource)
			}
			if cs != nil || bindings != nil {
				t.Errorf("got %d containers and %d bindings from a failed listing", len(cs), len(bindings))
			}
			for _, m := range f.methods {
				if m != http.MethodGet {
					t.Errorf("request method %s, want GET only", m)
				}
			}
		})
	}
}

// DeployBindings, which Observe now shares its listing with, is unchanged.
func TestDeployBindings_SameAsObserve(t *testing.T) {
	f1, f2 := newFakeServer(t), newFakeServer(t)
	serveK3s(f1, k3sLists(t))
	serveK3s(f2, k3sLists(t))
	c1 := newTestClient(t, f1.start(), []string{k3sNamespace})
	c2 := newTestClient(t, f2.start(), []string{k3sNamespace})

	want, err := c1.DeployBindings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, got, err := c2.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("Observe returned %d bindings, DeployBindings %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Container != want[i].Container || got[i].Subject != want[i].Subject || len(got[i].Chains) != len(want[i].Chains) {
			t.Errorf("binding %d differs: %+v vs %+v", i, got[i], want[i])
		}
	}
}
