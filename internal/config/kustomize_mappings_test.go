package config

import (
	"strings"
	"testing"
)

func kustSource(path, image string, affects ...string) string {
	s := "      kustomize:\n        path: " + path + "\n"
	if image != "" {
		s += "        image: " + image + "\n"
	}
	if len(affects) > 0 {
		s += "        affects:\n"
		for _, a := range affects {
			s += "          - " + a + "\n"
		}
	}
	return s
}

const kustPath = "apps/api/overlays/prod/kustomization.yaml"

func TestParse_KustomizeMapping(t *testing.T) {
	cfg := k8sMapping("deployment/shop/api/api", kustSource(kustPath, "api", "deployment/shop/api/sidecar", "cronjob/shop/report/job"))
	c, err := Parse([]byte(minimal + k8sHeader + cfg))
	if err != nil {
		t.Fatal(err)
	}
	k := c.Remediation.Mappings[0].Kustomize
	if k == nil || k.Path != kustPath || k.Image != "api" || len(k.Affects) != 2 || k.Affects[1] != "cronjob/shop/report/job" {
		t.Errorf("kustomize = %+v", k)
	}
	// Without affects the entry acts on the mapped container only.
	if _, err := Parse([]byte(minimal + k8sHeader + k8sMapping("deployment/shop/api/api", kustSource("kustomization.yml", "ghcr.io/example/api")))); err != nil {
		t.Errorf("no affects, a registry name, kustomization.yml: %v", err)
	}
	// A kustomize mapping combines with the dockerfile and dependencies routes.
	combo := k8sMapping("deployment/shop/api/api", kustSource(kustPath, "api")) +
		k8sMapping("deployment/shop/api/api", "      dockerfile:\n        path: Dockerfile\n") +
		k8sMapping("deployment/shop/api/api", depSource)
	if _, err := Parse([]byte(minimal + k8sHeader + combo)); err != nil {
		t.Errorf("kustomize with dockerfile and dependencies: %v", err)
	}
	// Two mappings of the one edit point that declare the same set.
	same := k8sMapping("deployment/shop/api/api", kustSource(kustPath, "api", "deployment/shop/api/sidecar")) +
		k8sMapping("deployment/shop/api/sidecar", kustSource(kustPath, "api", "deployment/shop/api/api"))
	if _, err := Parse([]byte(minimal + k8sHeader + same)); err != nil {
		t.Errorf("the same set from both sides: %v", err)
	}
}

func TestParse_KustomizeMappingsRejected(t *testing.T) {
	web := "deployment/shop/api/api"
	for name, tc := range map[string]struct{ mapping, want string }{
		"no image":                 {k8sMapping(web, kustSource(kustPath, "")), "kustomize.image"},
		"image with a tag":         {k8sMapping(web, kustSource(kustPath, "api:1.2")), "kustomize.image"},
		"image with a digest":      {k8sMapping(web, kustSource(kustPath, "api@sha256:"+strings.Repeat("a", 64))), "kustomize.image"},
		"image with a space":       {k8sMapping(web, "      kustomize:\n        path: "+kustPath+"\n        image: \"a b\"\n"), "kustomize.image"},
		"not a kustomization file": {k8sMapping(web, kustSource("apps/api/deploy.yaml", "api")), "kustomization"},
		"absolute path":            {k8sMapping(web, kustSource("/kustomization.yaml", "api")), "kustomize.path"},
		"dotdot path":              {k8sMapping(web, kustSource("../kustomization.yaml", "api")), "kustomize.path"},
		"affects: bad key":         {k8sMapping(web, kustSource(kustPath, "api", "deployment/shop/api")), "affects"},
		"affects: compose key":     {k8sMapping(web, kustSource(kustPath, "api", "compose/shop/api")), "affects"},
		"affects: self":            {k8sMapping(web, kustSource(kustPath, "api", web)), "affects"},
		"affects: duplicate":       {k8sMapping(web, kustSource(kustPath, "api", "job/shop/a/b", "job/shop/a/b")), "affects"},
		"repeated":                 {k8sMapping(web, kustSource(kustPath, "api")) + k8sMapping(web, kustSource(kustPath, "api")), "repeats the kustomize mapping"},
		"two sources at once":      {k8sMapping(web, kustSource(kustPath, "api")+manifestSource), "exactly one"},
		"unknown key":              {k8sMapping(web, "      kustomize:\n        path: "+kustPath+"\n        image: api\n        key: x\n"), "key"},
		"kustomize and manifest of one workload": {
			k8sMapping(web, kustSource(kustPath, "api")) + k8sMapping(web, manifestSource), "already sets",
		},
		"same edit point, other set": {
			k8sMapping(web, kustSource(kustPath, "api", "deployment/shop/api/sidecar")) +
				k8sMapping("deployment/shop/api/sidecar", kustSource(kustPath, "api")), "same set",
		},
		"same edit point, set from one side only": {
			k8sMapping(web, kustSource(kustPath, "api")) + k8sMapping("deployment/shop/api/b", kustSource(kustPath, "api")), "same set",
		},
		"workload under two entries": {
			k8sMapping(web, kustSource(kustPath, "api")) + k8sMapping("deployment/shop/api/b", kustSource(kustPath, "worker", web)), "decided in two places",
		},
		"affects-only container under two entries": {
			k8sMapping(web, kustSource(kustPath, "api", "job/shop/x/c")) + k8sMapping("deployment/shop/api/b", kustSource(kustPath, "worker", "job/shop/x/c")), "decided in two places",
		},
		"affects-only container under two files": {
			k8sMapping(web, kustSource(kustPath, "api", "job/shop/x/c")) + k8sMapping("deployment/shop/api/b", kustSource("other/kustomization.yaml", "api", "job/shop/x/c")), "decided in two places",
		},
		"affects a container that has a manifest mapping": {
			k8sMapping(web, kustSource(kustPath, "api", "deployment/shop/api/b")) + k8sMapping("deployment/shop/api/b", manifestSource), "decided in two places",
		},
		"one file on two branches": {
			k8sMapping(web, kustSource(kustPath, "api")) +
				"    - workload: deployment/shop/api/b\n      repository: example/app\n      base_branch: dev\n" + kustSource(kustPath, "worker"), "base_branch",
		},
	} {
		_, err := Parse([]byte(minimal + k8sHeader + tc.mapping))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, tc.want)
		}
	}
	// A kustomize mapping needs Kubernetes.
	_, err := Parse([]byte(minimal + "\nremediation:\n  mappings:\n" + k8sMapping("compose/shop/web", kustSource(kustPath, "api"))))
	if err == nil || !strings.Contains(err.Error(), "requires kubernetes.enabled") {
		t.Errorf("kustomize in Docker mode: %v", err)
	}
	// Two entries of one file with their own sets are fine.
	ok := k8sMapping(web, kustSource(kustPath, "api")) + k8sMapping("deployment/shop/api/b", kustSource(kustPath, "worker"))
	if _, err := Parse([]byte(minimal + k8sHeader + ok)); err != nil {
		t.Errorf("two entries of one file: %v", err)
	}
}
