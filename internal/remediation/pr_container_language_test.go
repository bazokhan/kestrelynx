package remediation

import (
	"strings"
	"testing"
)

// A language pull request for a container started outside Compose has the
// keys and the marker of the same unit for a Compose service, a branch named
// after the container and the note on the source.
func TestPRStageLanguageContainerWorkload(t *testing.T) {
	fx := langFixtures()["npm"]
	run := func(workload string) (string, string) {
		h := langHarness(t, fx)
		it := h.langItem(fx)
		it.Workloads = []string{workload}
		u := onlyUnit(t, h.run(prLangPlan(it)))
		wantStatus(t, u, PRStatusCreated, "")
		pulls := h.gh.pulls(testRepo)
		if len(pulls) != 1 {
			t.Fatalf("pulls = %d", len(pulls))
		}
		return pulls[0].HeadRef, pulls[0].Body
	}
	_, cbody := run("compose/app/web")
	head, body := run("container/shop-api")

	if !strings.HasPrefix(head, "kestrelynx/language/shop-api-npm-") {
		t.Errorf("branch = %q", head)
	}
	mc, err := parsePRMarker(cbody)
	if err != nil {
		t.Fatal(err)
	}
	m, err := parsePRMarker(body)
	if err != nil {
		t.Fatal(err)
	}
	if m.Kind != "language" || m.verify(testRepoID) != nil || !m.branchMatches(head) {
		t.Errorf("marker %+v", m)
	}
	if m.TargetKey != mc.TargetKey || m.UpdateKey != mc.UpdateKey {
		t.Errorf("keys differ from the Compose unit's: target %q / %q, update %q / %q", m.TargetKey, mc.TargetKey, m.UpdateKey, mc.UpdateKey)
	}
	if !strings.Contains(body, "`container/shop-api`") || !strings.Contains(body, textFor(BodyEN).SourceNote) {
		t.Errorf("the body lacks the workload or the note:\n%s", body)
	}
	if strings.Contains(cbody, textFor(BodyEN).SourceNote) {
		t.Error("the Compose body has the note")
	}
}
