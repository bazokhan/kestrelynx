package config

import (
	"strings"
	"testing"
)

func TestParse_ContainerMappingsValid(t *testing.T) {
	cases := map[string][]string{
		"dockerfile and dependencies": {
			mapping("container/web", "ex/app", "main", dockerfileRoute),
			mapping("container/web", "ex/app", "main", depsRoute),
		},
		"name with dot, underscore, dash and capitals": {
			mapping("container/Shop_api-1.x", "ex/app", "main", dockerfileRoute),
		},
		"two characters": {
			mapping("container/ab", "ex/app", "main", dockerfileRoute),
		},
		"longest name": {
			mapping("container/"+strings.Repeat("a", 253), "ex/app", "main", dockerfileRoute),
		},
		"sharing a Dockerfile with a Compose service": {
			mapping("compose/p/web", "ex/app", "main", dockerfileRoute),
			mapping("container/web", "EX/App", "main", dockerfileRoute),
		},
		"sharing a dependency root with a Compose service": {
			mapping("compose/p/web", "ex/app", "main", depsRoute),
			mapping("container/web", "ex/app", "main", depsRoute),
		},
		"next to a Compose mapping of a service": {
			mapping("compose/p/web", "ex/deploy", "main", composeRoute),
			mapping("container/web", "ex/app", "main", dockerfileRoute),
		},
	}
	for name, ms := range cases {
		c, err := Parse(remediationWith(ms...))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(c.Remediation.Mappings) != len(ms) {
			t.Errorf("%s: mappings = %d", name, len(c.Remediation.Mappings))
		}
	}
}

func TestParse_ContainerMappingsInvalid(t *testing.T) {
	cases := map[string][]string{
		"empty name":           {mapping("container/", "ex/app", "main", dockerfileRoute)},
		"one character":        {mapping("container/a", "ex/app", "main", dockerfileRoute)},
		"leading dash":         {mapping("container/-web", "ex/app", "main", dockerfileRoute)},
		"leading dot":          {mapping("container/.web", "ex/app", "main", dockerfileRoute)},
		"slash in name":        {mapping("container/a/b", "ex/app", "main", dockerfileRoute)},
		"space in name":        {mapping("\"container/a b\"", "ex/app", "main", dockerfileRoute)},
		"control character":    {mapping("\"container/web\\u0007x\"", "ex/app", "main", dockerfileRoute)},
		"newline":              {mapping("\"container/web\\nx\"", "ex/app", "main", dockerfileRoute)},
		"too long":             {mapping("container/"+strings.Repeat("a", 254), "ex/app", "main", dockerfileRoute)},
		"non-ASCII letter":     {mapping("container/wéb", "ex/app", "main", dockerfileRoute)},
		"no prefix separator":  {mapping("container", "ex/app", "main", dockerfileRoute)},
		"duplicate dockerfile": {mapping("container/web", "ex/a", "main", dockerfileRoute), mapping("container/web", "ex/b", "main", dockerfileRoute)},
		"duplicate dependencies": {
			mapping("container/web", "ex/a", "main", depsRoute),
			mapping("container/web", "ex/a", "main", depsRoute),
		},
		"Dockerfile with two branches": {
			mapping("container/web", "ex/a", "main", dockerfileRoute),
			mapping("container/api", "ex/a", "dev", dockerfileRoute),
		},
		"Dockerfile with two branches against a Compose service": {
			mapping("compose/p/web", "ex/a", "main", dockerfileRoute),
			mapping("container/web", "ex/a", "dev", dockerfileRoute),
		},
		"dependency root with two branches against a Compose service": {
			mapping("compose/p/web", "ex/a", "main", depsRoute),
			mapping("container/web", "ex/a", "dev", depsRoute),
		},
		"manifest route": {mapping("container/web", "ex/app", "main", "      manifest:\n        path: k.yaml\n")},
	}
	for name, ms := range cases {
		_, err := Parse(remediationWith(ms...))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), "remediation.mappings[") {
			t.Errorf("%s: err = %v, want it to name the mapping", name, err)
		}
	}
}

func TestParse_ContainerMappingWithComposeRoutePointsToComposeKey(t *testing.T) {
	_, err := Parse(remediationWith(mapping("container/web", "ex/app", "main", composeRoute)))
	if err == nil {
		t.Fatal("accepted")
	}
	if !strings.Contains(err.Error(), "compose/<project>/<service>") || !strings.Contains(err.Error(), "remediation.mappings[0]") {
		t.Errorf("err = %v", err)
	}
}

func TestParse_ContainerMappingRefusedInKubernetesMode(t *testing.T) {
	_, err := Parse([]byte(minimal + k8sHeader + k8sMapping("container/web", depSource)))
	if err == nil {
		t.Fatal("accepted")
	}
	if !strings.Contains(err.Error(), "remediation.mappings[0].workload") {
		t.Errorf("err = %v", err)
	}
}

func TestParse_ContainerMappingCheckedWhileDisabled(t *testing.T) {
	// remediation is off unless enabled: true is set, as here.
	if _, err := Parse(remediationWith(mapping("container/a/b", "ex/app", "main", dockerfileRoute))); err == nil {
		t.Error("accepted while remediation is disabled")
	}
}
