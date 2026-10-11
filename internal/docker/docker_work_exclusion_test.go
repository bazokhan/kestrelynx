package docker

import (
	"context"
	"testing"
)

// A work container of the update stage never reaches the inventory, whatever
// the rest of the listing holds, while a container that only borrows part of
// its identity does.
func TestRunningContainers_WorkContainersAreExcluded(t *testing.T) {
	id := func(c string) string { return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + c }
	work := map[string]string{labelWork: "1", labelInstance: "0123456789abcdef0123456789abcdef", labelJob: "lang-1-0", labelImage: validID1}
	srv := serveContainers(t, []rawContainer{
		{Id: id("1"), Image: "app:1", ImageID: validID1, Names: []string{"/shop-web-1"}, Labels: composeLabels("shop", "web")},
		{Id: id("2"), Image: "worker@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", ImageID: validID2, Names: []string{"/" + workNamePfx + "01234567-lang-1-0"}, Labels: work},
		// The label alone, or the name alone, is not a work container.
		{Id: id("3"), Image: "app:2", ImageID: validID1, Names: []string{"/shop-api-1"}, Labels: map[string]string{labelWork: "1"}},
		{Id: id("4"), Image: "app:3", ImageID: validID1, Names: []string{"/" + workNamePfx + "lookalike"}, Labels: composeLabels("shop", "cron")},
		{Id: id("5"), Image: "app:4", ImageID: validID1, Names: []string{"/other"}, Labels: map[string]string{labelWork: "0"}},
	})
	cs, err := newTestClient(srv).RunningContainers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range cs {
		names = append(names, c.Name)
		if c.Image.Ref == "" || c.Name == workNamePfx+"01234567-lang-1-0" {
			t.Errorf("work container in the inventory: %+v", c)
		}
	}
	if len(cs) != 4 {
		t.Errorf("containers = %v, want the four that are not work containers", names)
	}
}
