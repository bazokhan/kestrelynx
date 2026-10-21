package config

import (
	"strings"
	"testing"
)

func helmSource(path, key string, affects ...string) string {
	s := "      helm_values:\n        path: " + path + "\n"
	if key != "" {
		s += "        key: " + key + "\n"
	}
	if len(affects) > 0 {
		s += "        affects:\n"
		for _, a := range affects {
			s += "          - " + a + "\n"
		}
	}
	return s
}

const helmPath = "releases/db/values-prod.yaml"

func TestParse_HelmValuesMapping(t *testing.T) {
	cfg := k8sMapping("statefulset/shop/db/postgres", helmSource(helmPath, "primary.image", "statefulset/shop/db/init-permissions", "cronjob/shop/db-backup/backup"))
	c, err := Parse([]byte(minimal + k8sHeader + cfg))
	if err != nil {
		t.Fatal(err)
	}
	h := c.Remediation.Mappings[0].HelmValues
	if h == nil || h.Path != helmPath || h.Key != "primary.image" || len(h.Affects) != 2 {
		t.Errorf("helm_values = %+v", h)
	}
	for _, key := range []string{"image", "app_1.image-2", "a.b.c.d"} {
		if _, err := Parse([]byte(minimal + k8sHeader + k8sMapping("deployment/shop/web/app", helmSource("values.yml", key)))); err != nil {
			t.Errorf("key %q: %v", key, err)
		}
	}
	// With dockerfile and dependencies, and both sides of one key.
	combo := k8sMapping("deployment/shop/web/app", helmSource(helmPath, "image", "deployment/shop/web/log")) +
		k8sMapping("deployment/shop/web/log", helmSource(helmPath, "image", "deployment/shop/web/app")) +
		k8sMapping("deployment/shop/web/app", depSource)
	if _, err := Parse([]byte(minimal + k8sHeader + combo)); err != nil {
		t.Errorf("combination: %v", err)
	}
}

func TestParse_HelmValuesMappingsRejected(t *testing.T) {
	web := "deployment/shop/web/app"
	for name, tc := range map[string]struct{ mapping, want string }{
		"no key":                    {k8sMapping(web, helmSource(helmPath, "")), "helm_values.key"},
		"key with a leading dot":    {k8sMapping(web, helmSource(helmPath, ".image")), "helm_values.key"},
		"key with an empty segment": {k8sMapping(web, helmSource(helmPath, "a..b")), "helm_values.key"},
		"key with a slash":          {k8sMapping(web, helmSource(helmPath, "a/b")), "helm_values.key"},
		"key with a bracket":        {k8sMapping(web, "      helm_values:\n        path: "+helmPath+"\n        key: \"a[0]\"\n"), "helm_values.key"},
		"key with a space":          {k8sMapping(web, "      helm_values:\n        path: "+helmPath+"\n        key: \"a b\"\n"), "helm_values.key"},
		"not a yaml file":           {k8sMapping(web, helmSource("values.json", "image")), "values file"},
		"absolute path":             {k8sMapping(web, helmSource("/values.yaml", "image")), "helm_values.path"},
		"dotdot path":               {k8sMapping(web, helmSource("../values.yaml", "image")), "helm_values.path"},
		"affects: bad key":          {k8sMapping(web, helmSource(helmPath, "image", "deployment/shop/web")), "affects"},
		"affects: self":             {k8sMapping(web, helmSource(helmPath, "image", web)), "affects"},
		"affects: duplicate":        {k8sMapping(web, helmSource(helmPath, "image", "job/shop/a/b", "job/shop/a/b")), "affects"},
		"repeated":                  {k8sMapping(web, helmSource(helmPath, "image")) + k8sMapping(web, helmSource(helmPath, "image")), "repeats the helm_values mapping"},
		"two sources at once":       {k8sMapping(web, helmSource(helmPath, "image")+manifestSource), "exactly one"},
		"unknown key":               {k8sMapping(web, "      helm_values:\n        path: "+helmPath+"\n        key: image\n        image: x\n"), "image"},
		"helm_values and kustomize of one workload": {
			k8sMapping(web, helmSource(helmPath, "image")) + k8sMapping(web, kustSource(kustPath, "api")), "already sets"},
		"helm_values and manifest of one workload": {
			k8sMapping(web, helmSource(helmPath, "image")) + k8sMapping(web, manifestSource), "already sets"},
		"same key, other set": {
			k8sMapping(web, helmSource(helmPath, "image", "deployment/shop/web/log")) + k8sMapping("deployment/shop/web/log", helmSource(helmPath, "image")), "same set"},
		"workload under two keys": {
			k8sMapping(web, helmSource(helmPath, "image")) + k8sMapping("deployment/shop/web/b", helmSource(helmPath, "worker.image", web)), "decided in two places"},
		"affects-only container under two keys": {
			k8sMapping(web, helmSource(helmPath, "image", "job/shop/x/c")) + k8sMapping("deployment/shop/web/b", helmSource(helmPath, "worker.image", "job/shop/x/c")), "decided in two places"},
		"affects-only container under a Kustomize entry and a key": {
			k8sMapping(web, helmSource(helmPath, "image", "job/shop/x/c")) + k8sMapping("deployment/shop/web/b", kustSource(kustPath, "api", "job/shop/x/c")), "decided in two places"},
		"affects a container that has a manifest mapping": {
			k8sMapping(web, helmSource(helmPath, "image", "deployment/shop/web/b")) + k8sMapping("deployment/shop/web/b", manifestSource), "decided in two places"},
		"one file on two branches": {
			k8sMapping(web, helmSource(helmPath, "image")) +
				"    - workload: deployment/shop/web/b\n      repository: example/app\n      base_branch: dev\n" + helmSource(helmPath, "worker.image"), "base_branch"},
	} {
		_, err := Parse([]byte(minimal + k8sHeader + tc.mapping))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, tc.want)
		}
	}
	_, err := Parse([]byte(minimal + "\nremediation:\n  mappings:\n" + k8sMapping("compose/shop/web", helmSource(helmPath, "image"))))
	if err == nil || !strings.Contains(err.Error(), "requires kubernetes.enabled") {
		t.Errorf("helm_values in Docker mode: %v", err)
	}
	ok := k8sMapping(web, helmSource(helmPath, "image")) + k8sMapping("deployment/shop/web/b", helmSource(helmPath, "worker.image"))
	if _, err := Parse([]byte(minimal + k8sHeader + ok)); err != nil {
		t.Errorf("two keys of one file: %v", err)
	}
}
