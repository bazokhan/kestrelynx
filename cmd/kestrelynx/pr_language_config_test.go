package main

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

// TestBuildPlanConfig_PullRequestLanguage checks that notify.language reaches
// the pull request stage and so the wording of the pull request bodies.
func TestBuildPlanConfig_PullRequestLanguage(t *testing.T) {
	for _, tc := range []struct {
		notify string
		want   remediation.BodyLanguage
	}{{"", remediation.BodyEN}, {"en", remediation.BodyEN}, {"ja", remediation.BodyJA}} {
		cfg := config.Config{
			Notify: config.NotifyConfig{Language: tc.notify},
			Remediation: config.RemediationConfig{
				Enabled: true, StorageDir: "/data/remediation", PullRequests: config.RemediationPullRequestsConfig{Enabled: true},
				GitHub: config.RemediationGitHubConfig{Token: "ghp_exampletoken"},
				Limits: config.RemediationLimits{NewPRsPerCycle: 2, OpenPRs: 5},
			},
		}
		pc := buildPlanConfig(cfg)
		if pc.PullRequests == nil {
			t.Fatal("no pull request stage")
		}
		st, err := pc.PullRequests.NewStage(fakeResolver{})
		if err != nil {
			t.Fatal(err)
		}
		stage, ok := st.(*remediation.PRStage)
		if !ok {
			t.Fatalf("stage is %T", st)
		}
		if stage.Language() != tc.want {
			t.Errorf("notify.language %q: stage language %q, want %q", tc.notify, stage.Language(), tc.want)
		}
	}
}
