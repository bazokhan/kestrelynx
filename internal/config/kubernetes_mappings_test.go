package config

import (
	"strings"
	"testing"
)

const k8sHeader = "\nkubernetes:\n  enabled: true\nremediation:\n  enabled: true\n  mappings:\n"

func k8sMapping(workload, source string) string {
	return "    - workload: " + workload + "\n      repository: example/app\n      base_branch: main\n" + source
}

const depSource = "      dependencies:\n        directory: .\n"

func TestParseKubernetesWorkloadKey(t *testing.T) {
	w, err := ParseKubernetesWorkloadKey("deployment/shop/web.api/app-1")
	if err != nil {
		t.Fatal(err)
	}
	if w.Kind != "deployment" || w.Namespace != "shop" || w.Name != "web.api" || w.Container != "app-1" {
		t.Errorf("parsed = %+v", w)
	}
	for _, kind := range []string{"deployment", "statefulset", "daemonset", "job", "cronjob", "pod"} {
		if _, err := ParseKubernetesWorkloadKey(kind + "/ns/n/c"); err != nil {
			t.Errorf("kind %s: %v", kind, err)
		}
	}
	long := strings.Repeat("a", 254)
	for name, key := range map[string]string{
		"three parts (no container)": "deployment/shop/web",
		"five parts":                 "deployment/shop/web/app/x",
		"unknown kind":               "replicaset/shop/web/app",
		"compose form":               "compose/shop/web",
		"upper-case namespace":       "deployment/Shop/web/app",
		"underscore namespace":       "deployment/sh_op/web/app",
		"long namespace":             "deployment/" + strings.Repeat("a", 64) + "/web/app",
		"empty name":                 "deployment/shop//app",
		"name with underscore":       "deployment/shop/we_b/app",
		"name too long":              "deployment/shop/" + long + "/app",
		"dotted container":           "deployment/shop/web/app.x",
		"empty container":            "deployment/shop/web/",
		"empty":                      "",
	} {
		if _, err := ParseKubernetesWorkloadKey(key); err == nil {
			t.Errorf("%s: %q accepted", name, key)
		}
	}
}

func TestParse_KubernetesMappings(t *testing.T) {
	c, err := Parse([]byte(minimal + k8sHeader + k8sMapping("deployment/shop/web/app", depSource) + k8sMapping("cronjob/shop/report/job", depSource)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(c.Remediation.Mappings) != 2 || c.Remediation.Mappings[0].Workload != "deployment/shop/web/app" {
		t.Errorf("mappings = %+v", c.Remediation.Mappings)
	}
}

func TestParse_KubernetesMappingsRejected(t *testing.T) {
	composeSource := "      compose:\n        path: compose.yaml\n        service: web\n"
	for name, tc := range map[string]struct{ mapping, want string }{
		"compose key":       {k8sMapping("compose/shop/web", depSource), "workload"},
		"container missing": {k8sMapping("deployment/shop/web", depSource), "<kind>/<namespace>/<name>/<container>"},
		"unknown kind":      {k8sMapping("replicaset/shop/web/app", depSource), "unknown kind"},
		"compose mapping":   {k8sMapping("deployment/shop/web/app", composeSource), "compose mapping, which belongs to the Docker adapter"},
		"repeated route":    {k8sMapping("deployment/shop/web/app", depSource) + k8sMapping("deployment/shop/web/app", depSource), "repeats the dependencies mapping"},
	} {
		_, err := Parse([]byte(minimal + k8sHeader + tc.mapping))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, tc.want)
		}
	}
	// Validated whether or not the plan is enabled, as the Docker form is.
	_, err := Parse([]byte(minimal + "\nkubernetes:\n  enabled: true\nremediation:\n  mappings:\n" + k8sMapping("compose/shop/web", depSource)))
	if err == nil {
		t.Error("a mapping of the wrong form was accepted with the plan off")
	}
}

// The Docker-mode forms are as they were: a Kubernetes key is refused there.
func TestParse_DockerModeKeepsComposeKeys(t *testing.T) {
	docker := "\nremediation:\n  enabled: true\n  mappings:\n"
	if _, err := Parse([]byte(minimal + docker + k8sMapping("compose/shop/web", depSource))); err != nil {
		t.Fatalf("compose key: %v", err)
	}
	_, err := Parse([]byte(minimal + docker + k8sMapping("deployment/shop/web/app", depSource)))
	if err == nil || !strings.Contains(err.Error(), "compose/<project>/<service>") {
		t.Errorf("err = %v, want a Kubernetes key refused in Docker mode", err)
	}
	if _, err := Parse([]byte(minimal + docker + k8sMapping("compose/shop/web", "      dockerfile:\n        path: Dockerfile\n"))); err != nil {
		t.Errorf("dockerfile mapping in Docker mode: %v", err)
	}
}

func TestMappingsOutsideScope(t *testing.T) {
	body := k8sHeader + k8sMapping("deployment/shop/web/app", depSource) + k8sMapping("deployment/other/web/app", depSource)
	c, err := Parse([]byte(minimal + body))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.MappingsOutsideScope(); len(got) != 0 {
		t.Errorf("without a namespace list: %v, want none", got)
	}
	c, err = Parse([]byte(minimal + "\nkubernetes:\n  enabled: true\n  namespaces: [shop]\nremediation:\n  enabled: true\n  mappings:\n" + k8sMapping("deployment/shop/web/app", depSource) + k8sMapping("deployment/other/web/app", depSource)))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.MappingsOutsideScope(); len(got) != 1 || got[0] != "deployment/other/web/app" {
		t.Errorf("outside scope = %v, want the other namespace's workload", got)
	}
}

const manifestSource = "      manifest:\n        path: apps/web/deployment.yaml\n"

func TestParse_KubernetesRoutes(t *testing.T) {
	routes := k8sMapping("deployment/shop/web/app", manifestSource) +
		k8sMapping("deployment/shop/web/app", "      dockerfile:\n        path: Dockerfile\n") +
		k8sMapping("deployment/shop/web/app", depSource)
	c, err := Parse([]byte(minimal + k8sHeader + routes))
	if err != nil {
		t.Fatalf("manifest, dockerfile and dependencies of one workload: %v", err)
	}
	if m := c.Remediation.Mappings[0]; m.Manifest == nil || m.Manifest.Path != "apps/web/deployment.yaml" || m.Manifest.ObjectKind != "" {
		t.Errorf("manifest mapping = %+v", m.Manifest)
	}
	obj := "      manifest:\n        path: apps/web/deployment.yaml\n        object:\n          kind: Deployment\n          name: prod-web\n"
	c, err = Parse([]byte(minimal + k8sHeader + k8sMapping("deployment/shop/web/app", obj)))
	if err != nil {
		t.Fatalf("object override: %v", err)
	}
	if m := c.Remediation.Mappings[0].Manifest; m.ObjectKind != "Deployment" || m.ObjectName != "prod-web" {
		t.Errorf("object = %+v", m)
	}
}

func TestParse_ManifestMappingsRejected(t *testing.T) {
	obj := func(kind, name string) string {
		return "      manifest:\n        path: web.yaml\n        object:\n          kind: " + kind + "\n          name: " + name + "\n"
	}
	for name, tc := range map[string]struct{ mapping, want string }{
		"absolute path":               {k8sMapping("deployment/shop/web/app", "      manifest:\n        path: /web.yaml\n"), "manifest.path"},
		"dotdot path":                 {k8sMapping("deployment/shop/web/app", "      manifest:\n        path: ../web.yaml\n"), "manifest.path"},
		"no path":                     {k8sMapping("deployment/shop/web/app", "      manifest:\n        path: \"\"\n"), "manifest.path"},
		"wrong kind":                  {k8sMapping("deployment/shop/web/app", obj("StatefulSet", "web")), "object.kind"},
		"lower-case kind":             {k8sMapping("deployment/shop/web/app", obj("deployment", "web")), "object.kind"},
		"bad object name":             {k8sMapping("deployment/shop/web/app", obj("Deployment", "Web_1")), "object.name"},
		"repeated":                    {k8sMapping("deployment/shop/web/app", manifestSource) + k8sMapping("deployment/shop/web/app", manifestSource), "repeats the manifest mapping"},
		"same object, same namespace": {k8sMapping("deployment/shop/web/app", manifestSource) + k8sMapping("deployment/shop/web2/app", "      manifest:\n        path: apps/web/deployment.yaml\n        object:\n          name: web\n"), "already mapped"},
		"unknown key":                 {k8sMapping("deployment/shop/web/app", "      manifest:\n        path: web.yaml\n        affects: []\n"), "affects"},
		"two sources at once":         {k8sMapping("deployment/shop/web/app", manifestSource+depSource), "exactly one"},
	} {
		_, err := Parse([]byte(minimal + k8sHeader + tc.mapping))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, tc.want)
		}
	}
	// The same object name in two namespaces of one file is two edit points.
	ns := k8sMapping("deployment/shop/web/app", manifestSource) + k8sMapping("deployment/prod/web/app", manifestSource)
	if _, err := Parse([]byte(minimal + k8sHeader + ns)); err != nil {
		t.Errorf("one object name in two namespaces: %v", err)
	}
	// The same object edited for two containers is fine.
	two := k8sMapping("deployment/shop/web/app", manifestSource) + k8sMapping("deployment/shop/web/log", manifestSource)
	if _, err := Parse([]byte(minimal + k8sHeader + two)); err != nil {
		t.Errorf("two containers of one object: %v", err)
	}
	// A manifest mapping needs Kubernetes, and a compose one needs Docker.
	_, err := Parse([]byte(minimal + "\nremediation:\n  mappings:\n" + k8sMapping("compose/shop/web", manifestSource)))
	if err == nil || !strings.Contains(err.Error(), "requires kubernetes.enabled") {
		t.Errorf("manifest in Docker mode: %v", err)
	}
}

func TestParse_KubernetesDockerfileMappingAccepted(t *testing.T) {
	c, err := Parse([]byte(minimal + k8sHeader + k8sMapping("deployment/shop/web/app", "      dockerfile:\n        path: Dockerfile\n        target: build\n")))
	if err != nil {
		t.Fatalf("dockerfile mapping with kubernetes.enabled: %v", err)
	}
	if m := c.Remediation.Mappings[0]; m.Dockerfile == nil || m.Dockerfile.Target != "build" {
		t.Errorf("mapping = %+v", m)
	}
}
