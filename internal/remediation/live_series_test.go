//go:build live

package remediation

import (
	"context"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/registry"
)

// These tests talk to public registries. Run them by hand:
//
//	go test -tags live -run TestLiveSeries -v ./internal/remediation

func liveSeries(t *testing.T, repo, tag string, allowance int) (Selection, registry.TagList, time.Duration, int) {
	t.Helper()
	budget := registry.NewBudget(500)
	c := registry.New(registry.Options{Budget: budget})
	cur, ok := ParseTagVersion(tag)
	if !ok {
		t.Fatalf("%s is not a pinned tag", tag)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	start := time.Now()
	list, err := listPinnedSeries(ctx, c, repo, cur, allowance)
	took := time.Since(start)
	if err != nil {
		t.Fatalf("%s:%s: %v (after %d requests, %s)", repo, tag, err, budget.Used(), took)
	}
	return SelectPinned(cur, list), list, took, budget.Used()
}

func TestLiveSeriesElasticsearch(t *testing.T) {
	sel, list, took, used := liveSeries(t, "docker.elastic.co/elasticsearch/elasticsearch", "8.19.16", 20)
	t.Logf("selection = %+v; series tags = %d; truncated = %v; tag requests = %d; http requests = %d; took %s", sel, len(list.Tags), list.Truncated, list.Pages, used, took)
	if list.Truncated {
		t.Fatalf("the walk did not finish within the allowance: %+v", list)
	}
}

func TestLiveSeriesDockerHubMatchesFullListing(t *testing.T) {
	for _, tag := range []string{"1.25.3", "1.25.3-alpine", "1.24.0"} {
		sel, list, took, used := liveSeries(t, "nginx", tag, 20)
		t.Logf("nginx:%s series walk: selection = %+v; series tags = %d; truncated = %v; tag requests = %d; http requests = %d; took %s", tag, sel, len(list.Tags), list.Truncated, list.Pages, used, took)

		c := registry.New(registry.Options{Budget: registry.NewBudget(100)})
		start := time.Now()
		full, err := c.ListTags(context.Background(), "nginx")
		if err != nil {
			t.Fatal(err)
		}
		cur, _ := ParseTagVersion(tag)
		want := SelectPinned(cur, full)
		t.Logf("nginx:%s full listing: selection = %+v; tags = %d; truncated = %v; pages = %d; took %s", tag, want, len(full.Tags), full.Truncated, full.Pages, time.Since(start))
		if full.Truncated {
			continue
		}
		if sel != want {
			t.Errorf("nginx:%s: series walk selected %+v, full listing %+v", tag, sel, want)
		}
	}
}
