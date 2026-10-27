package notify

import (
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

// The rebuild guidance for a floating base follows the origin of the
// Dockerfile and the kinds of workloads that build from it.
func TestPlanMessage_DockerfileRebuildMixed(t *testing.T) {
	compose := map[Language]string{
		LanguageJA: "稼働中のイメージの作成元のベースを確認できない。`docker compose build --pull` で再ビルドすると現在のベースが入る",
		LanguageEN: "rebuilding with `docker compose build --pull` picks up the current base",
	}
	mapping := map[Language]string{
		LanguageJA: "ベースを取り直して再ビルドし(`docker build --pull` など)、デプロイし直す",
		LanguageEN: "pull the base again, rebuild the image (for example with `docker build --pull`) and deploy it again",
	}
	mixed := map[Language]string{
		LanguageJA: "Compose のサービスは `docker compose build --pull` で、`docker run` のコンテナは `docker build --pull` などで再ビルドし、それぞれコンテナを作り直す",
		LanguageEN: "rebuild with `docker compose build --pull` for the Compose services and with `docker build --pull` or the like for the `docker run` containers, then recreate the containers",
	}
	cases := []struct {
		name      string
		origin    remediation.DockerfileOrigin
		workloads []string
		want      map[Language]string
	}{
		{"shared by Compose build and a container", remediation.DockerfileFromBoth, []string{"compose/shop/web", "container/shop-api"}, mixed},
		{"a container alone, in the mapping", remediation.DockerfileFromMapping, []string{"container/shop-api"}, mapping},
		{"the mapping and the build of Compose services", remediation.DockerfileFromBoth, []string{"compose/shop/web", "compose/shop/api"}, compose},
		{"Compose build only", remediation.DockerfileFromCompose, []string{"compose/shop/web"}, compose},
		{"mapping of a Compose service", remediation.DockerfileFromMapping, []string{"compose/shop/web"}, mapping},
	}
	for _, c := range cases {
		for _, lang := range []Language{LanguageJA, LanguageEN} {
			it := runtimeRebuildItem(c.origin)
			it.Workloads = c.workloads
			got := rebuildPlanText(t, it, lang)
			if !strings.Contains(got, c.want[lang]) {
				t.Errorf("%s/%s: missing %q in\n%s", c.name, lang, c.want[lang], got)
			}
			for _, other := range []map[Language]string{compose, mapping, mixed} {
				if other[lang] != c.want[lang] && strings.Contains(got, other[lang]) {
					t.Errorf("%s/%s: has other guidance %q", c.name, lang, other[lang])
				}
			}
		}
	}
}

// A container started outside Compose is found by its workload key among the
// running images, and is shown by its name when no image is known for it.
func TestPlanMessage_ContainerWorkloadImages(t *testing.T) {
	r, _, _ := planCycleFixture()
	build := func(withImage bool) string {
		p := dockerfileFixture()
		p.Items = nil
		if withImage {
			p.Items = []remediation.Item{{
				Key: "shop-api:1|x", Category: remediation.CategoryNoCandidate, Reason: remediation.ReasonNoNewerTag,
				Services: []remediation.ServiceRef{{Container: "shop-api"}},
				Current:  remediation.ImageState{Ref: "shop-api:1"},
			}}
		}
		it := runtimeRebuildItem(remediation.DockerfileFromMapping)
		it.Workloads = []string{"container/shop-api"}
		p.DockerfileItems = []remediation.DockerfileItem{it}
		return slackPlanText(r, &PlanInfo{Plan: &p, Changed: true}, LanguageEN)
	}
	if got := build(true); !strings.Contains(got, "shop-api:1") {
		t.Errorf("the running image of the container is not shown:\n%s", got)
	}
	got := build(false)
	if !strings.Contains(got, "shop-api") || strings.Contains(got, "container/shop-api") {
		t.Errorf("the container is not shown by its name:\n%s", got)
	}
}
