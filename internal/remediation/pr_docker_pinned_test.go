package remediation

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

// The keys, markers, branch names and pull request bodies of Compose and
// Dockerfile updates are pinned to the values the program produced before
// Kubernetes updates existed: a stored record or an open pull request made
// then must still be recognized, byte for byte.
func TestDockerModeOutputIsPinned(t *testing.T) {
	m := sampleMarker()
	d := sampleMarker()
	d.Kind = "dockerfile"
	d.Locations = []string{"stages[0]"}
	d.TargetKey = TargetKeyOf("dockerfile", d.RepoID, d.BaseBranch, d.Path, d.Locations)
	d.UpdateKey = UpdateKey(d.TargetKey, d.CurrentRef, d.CandidateTag, d.CandidateDigest)
	d.AttemptKey = AttemptKey(d.UpdateKey, d.BaseSHA, d.InputBlobSHA, d.Changes)
	for name, got := range map[string]string{
		"compose target key":    m.TargetKey,
		"compose update key":    m.UpdateKey,
		"compose attempt key":   m.AttemptKey,
		"compose marker":        encodeMarker(m),
		"dockerfile target key": d.TargetKey,
		"dockerfile update key": d.UpdateKey,
		"dockerfile marker":     encodeMarker(d),
	} {
		if want := pinnedDockerOutput[name]; got != want {
			t.Errorf("%s changed:\n got %s\nwant %s", name, got, want)
		}
	}

	h := newPRHarness(t)
	h.run(testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, []string{"CVE-2"})))
	pr := h.gh.pulls(testRepo)[0]
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(pr.Body))); got != pinnedDockerOutput["compose body"] || pr.HeadRef != pinnedDockerOutput["compose branch"] {
		t.Errorf("the Compose pull request changed: body %s branch %s", got, pr.HeadRef)
	}
	df := newDFPRHarness(t)
	df.run(dfPlan(dfPlanItem("3.12.5-slim", '5', []string{"CVE-1", "CVE-2"}, []string{"CVE-3"})))
	pr = df.gh.pulls(testRepo)[0]
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(pr.Body))); got != pinnedDockerOutput["dockerfile body"] || pr.HeadRef != pinnedDockerOutput["dockerfile branch"] {
		t.Errorf("the Dockerfile pull request changed: body %s branch %s", got, pr.HeadRef)
	}
}

var pinnedDockerOutput = map[string]string{
	"compose target key":    `d596a66a37dc307e942721c34ab9e199f77f040025dd35c89eca19f67f63a6ca`,
	"compose update key":    `e513bca69279da9566db0a06ac85a0a173b88d9bf1a0a76acc455a31016fe979`,
	"compose attempt key":   `e17763c925cde9702bea370d076aec40d211b1d0658f6a78f56fbf450df9d39d`,
	"compose marker":        `<!-- kestrelynx:{"v":1,"repo_id":7,"base_branch":"main","path":"compose.yml","locations":["services.web.image"],"current_ref":"nginx:1.25.3","candidate_tag":"1.25.4","candidate_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","input_blob_sha":"3333333333333333333333333333333333333333","changes":[{"path":"compose.yml","mode":"100644","blob_sha":"4444444444444444444444444444444444444444"}],"target_key":"d596a66a37dc307e942721c34ab9e199f77f040025dd35c89eca19f67f63a6ca","update_key":"e513bca69279da9566db0a06ac85a0a173b88d9bf1a0a76acc455a31016fe979","attempt_key":"e17763c925cde9702bea370d076aec40d211b1d0658f6a78f56fbf450df9d39d","fix_targets":[{"location":"services.web.image","vuln_id":"CVE-1","package":{"ecosystem":"debian","class":"os","name":"libc"}}]} -->`,
	"dockerfile target key": `5c448b4f278d4a2481a845f965b5ce76a89070ae18d9e6ae83aafaa9b8f3d596`,
	"dockerfile update key": `b7a920004dd05498aa57899b1f37c3891a91e19dc5a5f6c63af243a6d7fd4edf`,
	"dockerfile marker":     `<!-- kestrelynx:{"v":1,"kind":"dockerfile","repo_id":7,"base_branch":"main","path":"compose.yml","locations":["stages[0]"],"current_ref":"nginx:1.25.3","candidate_tag":"1.25.4","candidate_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","input_blob_sha":"3333333333333333333333333333333333333333","changes":[{"path":"compose.yml","mode":"100644","blob_sha":"4444444444444444444444444444444444444444"}],"target_key":"5c448b4f278d4a2481a845f965b5ce76a89070ae18d9e6ae83aafaa9b8f3d596","update_key":"b7a920004dd05498aa57899b1f37c3891a91e19dc5a5f6c63af243a6d7fd4edf","attempt_key":"117b981accecc3874dc5415822215efbb4583305a4268668c143808affa1ba0b","fix_targets":[{"location":"services.web.image","vuln_id":"CVE-1","package":{"ecosystem":"debian","class":"os","name":"libc"}}]} -->`,
	"compose body":          `1f66d81027071db87569e270e5ed340b6ff188ccec53e0d9d04652e139e2d540`,
	"compose branch":        `kestrelynx/compose/web-and-1-1.25.4-8f0682d96b0d`,
	"dockerfile body":       `05fd65beddc1bee99be7aff417ffd67070028ba59ac88aba37e38c51b3c05f7f`,
	"dockerfile branch":     `kestrelynx/dockerfile/svc-3.12.5-slim-eba10fdf3a60`,
}
