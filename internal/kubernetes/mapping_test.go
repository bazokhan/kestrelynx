package kubernetes

import (
	"context"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

func TestRunningContainers_NodeMissing_PlatformZero_EntityUnresolved(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	f.on("/api/v1/pods", ok(envelope("", loadFixture(t, "pod_no_node.json"))))
	srv := f.start()
	c := newTestClient(t, srv, nil)

	cs, err := c.RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	if len(cs) != 1 {
		t.Fatalf("got %d containers, want 1", len(cs))
	}

	if cs[0].Image.Platform.Known() {
		t.Errorf("Platform = %+v, want zero value (pod's nodeName has no matching Node)", cs[0].Image.Platform)
	}
	if _, ok := inventory.EntityKeyOf(cs[0].Image); ok {
		t.Error("EntityKeyOf ok = true, want false: a registry digest with unknown Platform must not resolve to an entity")
	}
}

func TestRunningContainers_MixedArchitecture_DistinctEntities(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("",
		loadFixture(t, "node_amd64.json"),
		loadFixture(t, "node_arm64.json"),
	)))
	f.on("/api/v1/pods", ok(envelope("",
		loadFixture(t, "pod_mixed_arch_amd64.json"),
		loadFixture(t, "pod_mixed_arch_arm64.json"),
	)))
	srv := f.start()
	c := newTestClient(t, srv, nil)

	cs, err := c.RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	if len(cs) != 2 {
		t.Fatalf("got %d containers, want 2", len(cs))
	}
	if cs[0].Image.Registry.Digest.Hex == "" || cs[0].Image.Registry.Digest.Hex != cs[1].Image.Registry.Digest.Hex {
		t.Fatalf("test setup broken: both pods must share the same index digest, got %+v and %+v", cs[0].Image, cs[1].Image)
	}
	if cs[0].Image.Platform == cs[1].Image.Platform {
		t.Fatalf("test setup broken: the two pods must resolve to different Platforms, both got %+v", cs[0].Image.Platform)
	}

	images := inventory.DistinctImages(cs)
	if len(images) != 2 {
		t.Errorf("DistinctImages len = %d, want 2: the same index digest under two different running platforms is two entities, not one", len(images))
	}
}

func TestRunningContainers_NativeSidecarIncluded_OrdinaryInitExcluded(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	f.on("/api/v1/pods", ok(envelope("", loadFixture(t, "pod_native_sidecar.json"))))
	srv := f.start()
	c := newTestClient(t, srv, nil)

	cs, err := c.RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}

	names := map[string]bool{}
	for _, ct := range cs {
		names[ct.Name] = true
	}
	const (
		mainName          = "default/app-with-sidecar-1/app"
		nativeSidecarName = "default/app-with-sidecar-1/envoy-proxy"
		ordinaryInitName  = "default/app-with-sidecar-1/wait-for-db"
	)
	if !names[mainName] {
		t.Errorf("missing main container %q; got %v", mainName, cs)
	}
	if !names[nativeSidecarName] {
		t.Errorf("missing native sidecar %q (restartPolicy Always, running); got %v", nativeSidecarName, cs)
	}
	if names[ordinaryInitName] {
		t.Errorf("ordinary init container %q must be excluded even though its status reports running; got %v", ordinaryInitName, cs)
	}
	if len(cs) != 2 {
		t.Errorf("got %d containers, want 2 (main + native sidecar); got %v", len(cs), cs)
	}
}

// The ordinary init containers of a Pod are carried on its running containers
// as observations: matched to their spec by name, left without a declared
// reference or a digest when the Pod does not show them reliably, and never
// listed as running containers.
func TestRunningContainers_OrdinaryInitContainersAreObservedNotListed(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	f.on("/api/v1/pods", ok(envelope("", loadFixture(t, "pod_init_containers.json"))))
	srv := f.start()
	c := newTestClient(t, srv, nil)

	cs, err := c.RunningContainers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, c := range cs {
		names[c.Name] = true
	}
	if len(cs) != 2 || !names["shop/api-1/app"] || !names["shop/api-1/proxy"] {
		t.Fatalf("running containers = %v, want the main container and the native sidecar only", names)
	}
	for _, c := range cs {
		by := map[string]inventory.InitObservation{}
		if c.PodInit == nil {
			t.Fatalf("%s: no init observations", c.Name)
		}
		for _, o := range c.PodInit.Containers {
			by[o.Name] = o
		}
		if _, ok := by["proxy"]; ok {
			t.Errorf("%s: the native sidecar is listed as an ordinary init container", c.Name)
		}
		m := by["migrate"]
		if m.Declared.Ref != "docker.io/library/api:1.0" || m.Declared.PullPolicy != "IfNotPresent" || m.Image.Ref != "docker.io/library/api:1.0" ||
			m.Image.Registry.Digest.Hex == "" || !m.Image.Platform.Known() {
			t.Errorf("%s: migrate = %+v", c.Name, m)
		}
		if _, ok := inventory.EntityKeyOf(m.Image); !ok {
			t.Errorf("%s: migrate has no entity key", c.Name)
		}
		if d := by["dup"]; d.Declared.Ref != "" || d.Image.Ref != "" || d.Image.Registry.Digest.Hex != "" {
			t.Errorf("%s: a repeated name is %+v, want it empty", c.Name, d)
		}
		if b := by["badid"]; b.Image.Registry.Digest.Hex != "" || b.Declared.Ref != "" {
			t.Errorf("%s: an imageID that is not a digest gave %+v", c.Name, b)
		}
		if n := by["noid"]; n.Image.Registry.Digest.Hex != "" {
			t.Errorf("%s: a missing imageID gave %+v", c.Name, n)
		}
		if n := by["nospecstatus"]; n.Declared.Ref != "docker.io/library/api:1.0" || n.HasStatus || n.Image.Ref != "" {
			t.Errorf("%s: an init container the status does not show is %+v, want its declaration and no status", c.Name, n)
		}
		if m := by["migrate"]; !m.HasStatus {
			t.Errorf("%s: migrate has a status entry", c.Name)
		}
		kinds := map[string]inventory.SpecKind{}
		for _, sc := range c.PodInit.Spec {
			kinds[sc.Name+"|"+sc.Ref] = sc.Kind
		}
		for key, want := range map[string]inventory.SpecKind{
			"app|docker.io/library/api:1.0":          inventory.SpecMain,
			"proxy|docker.io/library/envoy:1.0":      inventory.SpecSidecar,
			"migrate|docker.io/library/api:1.0":      inventory.SpecInit,
			"nospecstatus|docker.io/library/api:1.0": inventory.SpecInit,
			"dup|docker.io/library/api:2.0":          inventory.SpecInit,
		} {
			if kinds[key] != want {
				t.Errorf("%s: spec entry %s is %q, want %q", c.Name, key, kinds[key], want)
			}
		}
		if s := by["stranger"]; s.Declared.Ref != "" {
			t.Errorf("%s: a status without a spec entry was given the declaration %+v", c.Name, s.Declared)
		}
	}
}
