package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

const minimal = `
notify:
  slack_webhook_url: "https://hooks.slack.test/abc"
`

func TestParse_Defaults(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := c.Scan.Severity; len(got) != 2 || got[0] != "HIGH" || got[1] != "CRITICAL" {
		t.Errorf("default Severity = %v, want [HIGH CRITICAL]", got)
	}
	if c.Docker.Socket != "/var/run/docker.sock" {
		t.Errorf("default Socket = %q", c.Docker.Socket)
	}
	if !c.Schedule.RunOnStart {
		t.Errorf("default RunOnStart = false, want true")
	}
	if c.Notify.Mode != "diff" {
		t.Errorf("default Mode = %q, want diff", c.Notify.Mode)
	}
	if c.Notify.FullReportDay != "monday" {
		t.Errorf("default FullReportDay = %q, want monday", c.Notify.FullReportDay)
	}
	if c.State.Path != "/var/lib/kestrelynx/state.json" {
		t.Errorf("default State.Path = %q", c.State.Path)
	}
}

func TestParse_NotifyModeAndFullReportDay(t *testing.T) {
	c, err := Parse([]byte(`
notify:
  slack_webhook_url: "https://x.test"
  mode: "FULL"
  full_report_day: "Friday"
state:
  path: "/data/state.json"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Notify.Mode != "full" {
		t.Errorf("Mode = %q, want normalized full", c.Notify.Mode)
	}
	if day, ok := c.Notify.FullReportWeekday(); !ok || day.String() != "Friday" {
		t.Errorf("FullReportWeekday = %v ok=%v, want Friday true", day, ok)
	}
	if c.State.Path != "/data/state.json" {
		t.Errorf("State.Path = %q", c.State.Path)
	}
}

func TestParse_EnvironmentName(t *testing.T) {
	c, err := Parse([]byte(minimal + "\nenvironment:\n  name: \"prod-vps\"\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Environment.Name != "prod-vps" {
		t.Errorf("Environment.Name = %q, want prod-vps", c.Environment.Name)
	}
}

func TestParse_EnvironmentNameEmptyByDefault(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Environment.Name != "" {
		t.Errorf("default Environment.Name = %q, want empty (unnamed default environment)", c.Environment.Name)
	}
}

func TestParse_InvalidEnvironmentNameRejected(t *testing.T) {
	invalid := []string{
		"Prod",                  // uppercase
		"prod.vps",              // dot
		"prod_vps",              // underscore
		"prod\x1fvps",           // US control character
		strings.Repeat("a", 64), // over 63 bytes
	}
	for _, name := range invalid {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(minimal + "\nenvironment:\n  name: \"" + name + "\"\n"))
			if err == nil {
				t.Fatalf("Parse: expected error for invalid environment.name %q", name)
			}
		})
	}
}

func TestParse_FullReportDayNever(t *testing.T) {
	c, err := Parse([]byte(`
notify:
  slack_webhook_url: "https://x.test"
  full_report_day: "never"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, ok := c.Notify.FullReportWeekday(); ok {
		t.Error("never should disable the weekly full report")
	}
}

func TestParse_InvalidModeAndDay(t *testing.T) {
	if _, err := Parse([]byte("notify: { slack_webhook_url: \"https://x.test\", mode: \"delta\" }")); err == nil {
		t.Fatal("expected error for invalid notify.mode")
	}
	if _, err := Parse([]byte("notify: { slack_webhook_url: \"https://x.test\", full_report_day: \"noday\" }")); err == nil {
		t.Fatal("expected error for invalid notify.full_report_day")
	}
}

func TestParse_NotifyLanguageDefault(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Notify.Language != "en" {
		t.Errorf("default Notify.Language = %q, want en", c.Notify.Language)
	}
}

func TestParse_NotifyLanguageJA(t *testing.T) {
	c, err := Parse([]byte(`
notify:
  slack_webhook_url: "https://x.test"
  language: "JA"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Notify.Language != "ja" {
		t.Errorf("Notify.Language = %q, want normalized ja", c.Notify.Language)
	}
}

func TestParse_InvalidNotifyLanguageRejected(t *testing.T) {
	if _, err := Parse([]byte("notify: { slack_webhook_url: \"https://x.test\", language: \"fr\" }")); err == nil {
		t.Fatal("expected error for invalid notify.language")
	}
}

func TestParse_FullOverride(t *testing.T) {
	yaml := `
schedule:
  daily_at: "06:30"
  run_on_start: false
scan:
  severity: [CRITICAL]
notify:
  slack_webhook_url: "https://hooks.slack.test/x"
  generic_webhook_url: "https://example.test/hook"
  notify_on_clean: true
docker:
  socket: "/run/docker.sock"
`
	c, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Schedule.DailyAt != "06:30" || c.Schedule.RunOnStart {
		t.Errorf("schedule = %+v", c.Schedule)
	}
	if len(c.Scan.Severity) != 1 || c.Scan.Severity[0] != "CRITICAL" {
		t.Errorf("severity = %v", c.Scan.Severity)
	}
	if !c.Notify.NotifyOnClean || c.Notify.GenericWebhookURL == "" {
		t.Errorf("notify = %+v", c.Notify)
	}
	if c.Docker.Socket != "/run/docker.sock" {
		t.Errorf("socket = %q", c.Docker.Socket)
	}
}

func TestParse_RequiresNotifyTarget(t *testing.T) {
	_, err := Parse([]byte(`scan: { severity: [HIGH] }`))
	if err == nil {
		t.Fatal("expected error when no notify target configured")
	}
	if !strings.Contains(err.Error(), "notify") {
		t.Errorf("error should mention notify target: %v", err)
	}
}

func TestParse_NormalizesSeverityCase(t *testing.T) {
	c, err := Parse([]byte(`
scan:
  severity: [high, Critical]
notify:
  slack_webhook_url: "https://x.test"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Scan.Severity[0] != "HIGH" || c.Scan.Severity[1] != "CRITICAL" {
		t.Errorf("severity not normalized: %v", c.Scan.Severity)
	}
}

func TestParse_InvalidSeverity(t *testing.T) {
	_, err := Parse([]byte(`
scan:
  severity: [HIGH, BOGUS]
notify:
  slack_webhook_url: "https://x.test"
`))
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
}

func TestParse_InvalidDailyAt(t *testing.T) {
	_, err := Parse([]byte(`
schedule:
  daily_at: "9am"
notify:
  slack_webhook_url: "https://x.test"
`))
	if err == nil {
		t.Fatal("expected error for malformed daily_at")
	}
}

func TestParse_BadYAML(t *testing.T) {
	if _, err := Parse([]byte("notify: [unclosed")); err == nil {
		t.Fatal("expected error for malformed YAML")
	}
}

func TestDailyTime(t *testing.T) {
	c, _ := Parse([]byte(`
schedule:
  daily_at: "06:30"
notify:
  slack_webhook_url: "https://x.test"
`))
	h, m, ok := c.Schedule.DailyTime()
	if !ok || h != 6 || m != 30 {
		t.Errorf("DailyTime = %d:%d ok=%v, want 6:30 true", h, m, ok)
	}

	noTime, _ := Parse([]byte(minimal))
	if _, _, ok := noTime.Schedule.DailyTime(); ok {
		t.Errorf("empty daily_at should yield ok=false")
	}
}

func TestParse_TriageDefaults(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !c.Triage.Enabled {
		t.Error("default Triage.Enabled = false, want true")
	}
	if c.Triage.ActNowEPSS != 0.10 || c.Triage.WatchEPSS != 0.01 {
		t.Errorf("default thresholds = %v/%v, want 0.10/0.01", c.Triage.ActNowEPSS, c.Triage.WatchEPSS)
	}
	if c.Triage.KEVURL != "" || c.Triage.EPSSURL != "" {
		t.Errorf("default URLs should be empty (library defaults apply): %q %q", c.Triage.KEVURL, c.Triage.EPSSURL)
	}
}

func TestParse_TriageOverrides(t *testing.T) {
	c, err := Parse([]byte(`
notify:
  slack_webhook_url: "https://x.test"
triage:
  enabled: true
  act_now_epss: 0.5
  watch_epss: 0.05
  kev_url: "https://mirror.test/kev.json"
  epss_url: "https://mirror.test/epss.csv.gz"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Triage.ActNowEPSS != 0.5 || c.Triage.WatchEPSS != 0.05 {
		t.Errorf("thresholds = %v/%v, want 0.5/0.05", c.Triage.ActNowEPSS, c.Triage.WatchEPSS)
	}
	if c.Triage.KEVURL != "https://mirror.test/kev.json" {
		t.Errorf("KEVURL = %q", c.Triage.KEVURL)
	}
}

func TestParse_TriageDisabled(t *testing.T) {
	c, err := Parse([]byte(`
notify:
  slack_webhook_url: "https://x.test"
triage:
  enabled: false
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Triage.Enabled {
		t.Error("Triage.Enabled = true, want false")
	}
}

func TestParse_TriageInvalidThresholds(t *testing.T) {
	for _, body := range []string{
		"act_now_epss: 0.005\n  watch_epss: 0.01", // watch > act_now
		"watch_epss: 0",     // watch must be > 0
		"act_now_epss: 1.5", // above 1
	} {
		_, err := Parse([]byte("notify:\n  slack_webhook_url: \"https://x.test\"\ntriage:\n  " + body + "\n"))
		if err == nil || !strings.Contains(err.Error(), "triage") {
			t.Errorf("thresholds %q: err = %v, want triage validation error", body, err)
		}
	}
}

func TestParse_KubernetesDefaults(t *testing.T) {
	// A config file predating the kubernetes: section (the whole existing
	// corpus) must still parse under KnownFields(true) and get an adapter
	// that stays off.
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Kubernetes.Enabled {
		t.Error("default Kubernetes.Enabled = true, want false")
	}
	if c.Kubernetes.APIServer != "" || c.Kubernetes.TokenFile != "" || c.Kubernetes.CAFile != "" || c.Kubernetes.TLSServerName != "" {
		t.Errorf("default Kubernetes fields should be empty, got %+v", c.Kubernetes)
	}
	if len(c.Kubernetes.Namespaces) != 0 {
		t.Errorf("default Kubernetes.Namespaces = %v, want empty", c.Kubernetes.Namespaces)
	}
	// docker.socket keeps applying its usual default, unaffected by the
	// rawConfig.Docker.Socket pointer change.
	if c.Docker.Socket != "/var/run/docker.sock" {
		t.Errorf("default Socket = %q", c.Docker.Socket)
	}
}

func TestParse_KubernetesAllKeys(t *testing.T) {
	c, err := Parse([]byte(minimal + `
kubernetes:
  enabled: true
  api_server: "https://10.0.0.1:443"
  token_file: "/var/run/secrets/kubernetes.io/serviceaccount/token"
  ca_file: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
  tls_server_name: "kubernetes.default.svc"
  namespaces: ["default", "kube-system"]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := KubernetesConfig{
		Enabled:       true,
		APIServer:     "https://10.0.0.1:443",
		TokenFile:     "/var/run/secrets/kubernetes.io/serviceaccount/token",
		CAFile:        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
		TLSServerName: "kubernetes.default.svc",
		Namespaces:    []string{"default", "kube-system"},
	}
	if c.Kubernetes.Enabled != want.Enabled ||
		c.Kubernetes.APIServer != want.APIServer ||
		c.Kubernetes.TokenFile != want.TokenFile ||
		c.Kubernetes.CAFile != want.CAFile ||
		c.Kubernetes.TLSServerName != want.TLSServerName ||
		len(c.Kubernetes.Namespaces) != 2 || c.Kubernetes.Namespaces[0] != "default" || c.Kubernetes.Namespaces[1] != "kube-system" {
		t.Errorf("Kubernetes = %+v, want %+v", c.Kubernetes, want)
	}
}

func TestParse_KubernetesEnabledWithoutExplicitDockerSocket(t *testing.T) {
	// docker.socket left out entirely (not even the docker: section) must not
	// trip the mutual-exclusion check: Config.Docker.Socket still ends up
	// non-empty (the default fills in), but that's not "explicitly set".
	c, err := Parse([]byte(minimal + "\nkubernetes:\n  enabled: true\n"))
	if err != nil {
		t.Fatalf("Parse: %v, want kubernetes.enabled alone to succeed", err)
	}
	if !c.Kubernetes.Enabled {
		t.Error("Kubernetes.Enabled = false, want true")
	}
	if c.Docker.Socket != "/var/run/docker.sock" {
		t.Errorf("Docker.Socket = %q, want default to still apply", c.Docker.Socket)
	}
}

func TestParse_KubernetesEnabledWithExplicitDockerSocketRejected(t *testing.T) {
	for _, body := range []string{
		`docker:
  socket: "/var/run/docker.sock"`, // explicit, even matching the default value
		`docker:
  socket: "/custom/docker.sock"`,
		`docker:
  socket: ""`, // explicit empty string still counts as "set"
	} {
		_, err := Parse([]byte(minimal + "\nkubernetes:\n  enabled: true\n" + body + "\n"))
		if err == nil {
			t.Errorf("body %q: expected mutual-exclusion error", body)
			continue
		}
		if !strings.Contains(err.Error(), "docker.socket") || !strings.Contains(err.Error(), "kubernetes.enabled") {
			t.Errorf("body %q: err = %v, want it to name both docker.socket and kubernetes.enabled", body, err)
		}
	}
}

func TestParse_KubernetesInvalidNamespaceRejected(t *testing.T) {
	invalid := []string{
		"Default",               // uppercase
		"kube_system",           // underscore
		"kube.system",           // dot
		"",                      // empty entry
		strings.Repeat("a", 64), // over 63 bytes
	}
	for _, ns := range invalid {
		t.Run(ns, func(t *testing.T) {
			_, err := Parse([]byte(minimal + "\nkubernetes:\n  namespaces: [\"" + ns + "\"]\n"))
			if err == nil {
				t.Fatalf("Parse: expected error for invalid namespace %q", ns)
			}
			if !strings.Contains(err.Error(), "namespaces") {
				t.Errorf("err = %v, want it to mention namespaces", err)
			}
		})
	}
}

func TestParse_KubernetesAPIServerRequiresHTTPS(t *testing.T) {
	_, err := Parse([]byte(minimal + "\nkubernetes:\n  api_server: \"http://10.0.0.1:443\"\n"))
	if err == nil {
		t.Fatal("Parse: expected error for http:// api_server")
	}
	if !strings.Contains(err.Error(), "api_server") {
		t.Errorf("err = %v, want it to mention api_server", err)
	}
}

func TestParse_TriageDisabledSkipsThresholdValidation(t *testing.T) {
	// A nonsensical threshold must not block someone turning the feature off.
	_, err := Parse([]byte(`
notify:
  slack_webhook_url: "https://x.test"
triage:
  enabled: false
  watch_epss: 0
`))
	if err != nil {
		t.Errorf("Parse: %v, want disabled triage to skip threshold validation", err)
	}
}

func TestParse_RemediationDefaults(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := c.Remediation
	if r.Enabled || r.PullRequests.Enabled {
		t.Errorf("Remediation enabled flags = %v/%v, want both false by default", r.Enabled, r.PullRequests.Enabled)
	}
	if r.GitHub.Token != "" || len(r.Mappings) != 0 {
		t.Errorf("token/mappings = %q/%v, want none", r.GitHub.Token, r.Mappings)
	}
	if r.StorageDir != "/var/lib/kestrelynx/remediation" {
		t.Errorf("StorageDir = %q", r.StorageDir)
	}
	want := RemediationLimits{CandidateScansPerCycle: 10, BaselineRescansPerCycle: 10, RegistryRequestsPerCycle: 200, TagPagesPerRepository: 20, CycleTimeout: 30 * time.Minute, NewPRsPerCycle: 3, OpenPRs: 10, DependencyJobsPerCycle: 3, JobTimeout: 6 * time.Minute}
	if r.Limits != want {
		t.Errorf("Remediation.Limits = %+v, want %+v", r.Limits, want)
	}
}

func TestParse_RemediationExplicit(t *testing.T) {
	c, err := Parse([]byte(minimal + `
remediation:
  enabled: true
  github:
    token: ghp_exampletoken
  storage_dir: /data/remediation
  mappings:
    - workload: compose/shop/web
      repository: example/deployment
      base_branch: release/1.x
      compose:
        path: deploy/compose.yml
        service: web
    - workload: compose/shop/api
      repository: example/application
      base_branch: main
      dependencies:
        directory: .
  limits:
    candidate_scans_per_cycle: 3
    baseline_rescans_per_cycle: 4
    registry_requests_per_cycle: 50
    tag_pages_per_repository: 5
    cycle_timeout: 45m
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := c.Remediation
	if !r.Enabled {
		t.Error("Remediation.Enabled = false, want true")
	}
	if r.GitHub.Token.Value() != "ghp_exampletoken" || r.StorageDir != "/data/remediation" {
		t.Errorf("token/storage = %q/%q", r.GitHub.Token.Value(), r.StorageDir)
	}
	want := RemediationLimits{CandidateScansPerCycle: 3, BaselineRescansPerCycle: 4, RegistryRequestsPerCycle: 50, TagPagesPerRepository: 5, CycleTimeout: 45 * time.Minute, NewPRsPerCycle: 3, OpenPRs: 10, DependencyJobsPerCycle: 3, JobTimeout: 6 * time.Minute}
	if r.Limits != want {
		t.Errorf("Remediation.Limits = %+v, want %+v", r.Limits, want)
	}
	if len(r.Mappings) != 2 {
		t.Fatalf("mappings = %+v", r.Mappings)
	}
	m0, m1 := r.Mappings[0], r.Mappings[1]
	if m0.Workload != "compose/shop/web" || m0.Repository != "example/deployment" || m0.BaseBranch != "release/1.x" ||
		m0.Compose == nil || m0.Compose.Path != "deploy/compose.yml" || m0.Compose.Service != "web" || m0.Dependencies != nil {
		t.Errorf("mapping 0 = %+v", m0)
	}
	if m1.Dependencies == nil || m1.Dependencies.Directory != "." || m1.Compose != nil {
		t.Errorf("mapping 1 = %+v", m1)
	}
}

func TestParse_RemediationAllowedInBothModes(t *testing.T) {
	for _, mode := range []string{"diff", "full"} {
		_, err := Parse([]byte(`
notify:
  slack_webhook_url: "https://x.test"
  mode: ` + mode + `
remediation:
  enabled: true
`))
		if err != nil {
			t.Errorf("mode %s: %v", mode, err)
		}
	}
}

func TestParse_RemediationLimitsMustBePositive(t *testing.T) {
	for _, key := range []string{"candidate_scans_per_cycle", "baseline_rescans_per_cycle", "registry_requests_per_cycle", "tag_pages_per_repository", "cycle_timeout", "new_prs_per_cycle", "open_prs"} {
		for _, v := range []string{"-1", "0"} {
			if key == "cycle_timeout" {
				v += "s"
			}
			_, err := Parse([]byte(minimal + "\nremediation:\n  limits:\n    " + key + ": " + v + "\n"))
			if err == nil {
				t.Errorf("%s: %s accepted", key, v)
				continue
			}
			if !strings.Contains(err.Error(), key) {
				t.Errorf("%s: err = %v, want it to name the key", key, err)
			}
		}
	}
	if _, err := Parse([]byte(minimal + "\nremediation:\n  limits:\n    cycle_timeout: soon\n")); err == nil {
		t.Error("unparseable cycle_timeout accepted")
	}
}

func TestParse_RemediationPullRequests(t *testing.T) {
	c, err := Parse([]byte(minimal + "\nremediation:\n  enabled: true\n  github:\n    token: ghp_exampletoken\n  pull_requests:\n    enabled: true\n  limits:\n    new_prs_per_cycle: 2\n    open_prs: 5\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !c.Remediation.PullRequests.Enabled || c.Remediation.Limits.NewPRsPerCycle != 2 || c.Remediation.Limits.OpenPRs != 5 {
		t.Errorf("pull requests = %+v, limits = %+v", c.Remediation.PullRequests, c.Remediation.Limits)
	}
	if _, err := Parse([]byte(minimal + "\nremediation:\n  enabled: true\n  pull_requests:\n    enabled: false\n")); err != nil {
		t.Errorf("explicit false: %v", err)
	}
}

func TestParse_RemediationPullRequestsRejected(t *testing.T) {
	tok := "  github:\n    token: ghp_exampletoken\n"
	for name, tc := range map[string]struct{ body, want string }{
		"plan off":      {"remediation:\n" + tok + "  pull_requests:\n    enabled: true\n", "requires remediation.enabled"},
		"no token":      {"remediation:\n  enabled: true\n  pull_requests:\n    enabled: true\n", "remediation.github.token"},
		"blank token":   {"remediation:\n  enabled: true\n  github:\n    token: \"\"\n  pull_requests:\n    enabled: true\n", "remediation.github.token"},
		"kubernetes pr": {"kubernetes:\n  enabled: true\nremediation:\n" + tok + "  pull_requests:\n    enabled: true\n", "remediation.pull_requests.enabled"},
	} {
		_, err := Parse([]byte(minimal + "\n" + tc.body))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, tc.want)
		}
	}
}

func TestParse_RemediationStorageDirMustBeAbsolute(t *testing.T) {
	_, err := Parse([]byte(minimal + "\nremediation:\n  storage_dir: relative/dir\n"))
	if err == nil || !strings.Contains(err.Error(), "remediation.storage_dir") {
		t.Errorf("err = %v", err)
	}
}

func TestParse_RemediationPlanWithKubernetes(t *testing.T) {
	c, err := Parse([]byte(minimal + "\nkubernetes:\n  enabled: true\nremediation:\n  enabled: true\n"))
	if err != nil {
		t.Fatalf("Parse: %v, want the fix plan accepted with kubernetes.enabled", err)
	}
	if !c.Remediation.Enabled || !c.Kubernetes.Enabled {
		t.Errorf("remediation.enabled = %v, kubernetes.enabled = %v", c.Remediation.Enabled, c.Kubernetes.Enabled)
	}
	if _, err := Parse([]byte(minimal + "\nkubernetes:\n  enabled: true\nremediation:\n  enabled: false\n")); err != nil {
		t.Errorf("Parse: %v, want a disabled plan to be accepted with kubernetes", err)
	}
	// Pull requests are allowed with the plan on Kubernetes, and still need it.
	pr := "\nkubernetes:\n  enabled: true\nremediation:\n  enabled: true\n  github:\n    token: ghp_exampletoken\n  pull_requests:\n    enabled: true\n"
	if c, err := Parse([]byte(minimal + pr)); err != nil || !c.Remediation.PullRequests.Enabled {
		t.Errorf("pull requests with kubernetes.enabled: %v", err)
	}
	// Docker mode is as it was.
	if _, err := Parse([]byte(minimal + "\nremediation:\n  enabled: true\n  github:\n    token: ghp_exampletoken\n  pull_requests:\n    enabled: true\n")); err != nil {
		t.Errorf("Docker mode with pull requests: %v", err)
	}
}

func TestParse_RemediationUnknownKeyRejected(t *testing.T) {
	for _, body := range []string{
		"remediation:\n  plan:\n    enabled: true\n",
		"remediation:\n  limits:\n    max_candidates: 1\n",
		"remediation:\n  mappings:\n    - workload: compose/a/b\n      repository: x/y\n      base_branch: main\n      dockerfile:\n        path: Dockerfile\n        stage: x\n",
		"remediation:\n  mappings:\n    - workload: compose/a/b\n      repository: x/y\n      base_branch: main\n      dependencies:\n        dir: .\n",
	} {
		if _, err := Parse([]byte(minimal + "\n" + body)); err == nil {
			t.Errorf("%q: expected an unknown-key error", body)
		}
	}
}

func TestParse_RemediationTokenIsRedacted(t *testing.T) {
	const tok = "ghp_supersecretvalue"
	c, err := Parse([]byte(minimal + "\nremediation:\n  github:\n    token: " + tok + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	slog.New(slog.NewTextHandler(&buf, nil)).Info("cfg", "token", c.Remediation.GitHub.Token, "remediation", c.Remediation)
	for _, out := range []string{
		fmt.Sprint(c), fmt.Sprintf("%v", c.Remediation), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c.Remediation), buf.String(),
	} {
		if strings.Contains(out, tok) {
			t.Errorf("token leaked in %q", out)
		}
	}
	if c.Remediation.GitHub.Token.Value() != tok {
		t.Error("Value() must return the token")
	}
	for _, bad := range []string{"\"a b\"", "\"a\\nb\""} {
		_, err := Parse([]byte(minimal + "\nremediation:\n  github:\n    token: " + bad + "\n"))
		if err == nil || strings.Contains(err.Error(), "a b") {
			t.Errorf("token %s: err = %v", bad, err)
		}
	}
}

func mapping(workload, repo, branch, route string) string {
	return "    - workload: " + workload + "\n      repository: " + repo + "\n      base_branch: " + branch + "\n" + route
}

const (
	composeRoute = "      compose:\n        path: compose.yml\n        service: web\n"
	depsRoute    = "      dependencies:\n        directory: app\n"
)

func remediationWith(mappings ...string) []byte {
	return []byte(minimal + "\nremediation:\n  mappings:\n" + strings.Join(mappings, ""))
}

func TestParse_RemediationMappingValid(t *testing.T) {
	cases := map[string][]string{
		"both routes for one workload": {
			mapping("compose/p/web", "ex/deploy", "main", composeRoute),
			mapping("compose/p/web", "ex/app", "main", depsRoute),
		},
		"workloads sharing a dependency root": {
			mapping("compose/p/web", "ex/app", "main", depsRoute),
			mapping("compose/p/api", "Ex/App", "main", depsRoute),
		},
		"root directory": {mapping("compose/p/web", "ex/app", "main", "      dependencies:\n        directory: .\n")},
		"nested branch":  {mapping("compose/p/web", "ex/app", "release/v1.2", depsRoute)},
		"unicode names":  {mapping("compose/プロジェクト/web-1", "ex/app", "main", depsRoute)},
	}
	for name, ms := range cases {
		if _, err := Parse(remediationWith(ms...)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParse_RemediationMappingInvalid(t *testing.T) {
	long := strings.Repeat("p", 254)
	cases := map[string][]string{
		"wrong kind":             {mapping("deployment/p/web", "ex/app", "main", depsRoute)},
		"two segments":           {mapping("compose/web", "ex/app", "main", depsRoute)},
		"four segments":          {mapping("compose/p/web/x", "ex/app", "main", depsRoute)},
		"empty project":          {mapping("compose//web", "ex/app", "main", depsRoute)},
		"project too long":       {mapping("compose/"+long+"/web", "ex/app", "main", depsRoute)},
		"control char":           {mapping("\"compose/p\\t/web\"", "ex/app", "main", depsRoute)},
		"repo without owner":     {mapping("compose/p/web", "app", "main", depsRoute)},
		"repo with url":          {mapping("compose/p/web", "https://github.com/ex/app", "main", depsRoute)},
		"repo with .git":         {mapping("compose/p/web", "ex/app.git", "main", depsRoute)},
		"empty branch":           {mapping("compose/p/web", "ex/app", "\"\"", depsRoute)},
		"branch dot dot":         {mapping("compose/p/web", "ex/app", "a..b", depsRoute)},
		"branch leading dash":    {mapping("compose/p/web", "ex/app", "-main", depsRoute)},
		"branch with space":      {mapping("compose/p/web", "ex/app", "\"a b\"", depsRoute)},
		"no route":               {mapping("compose/p/web", "ex/app", "main", "")},
		"both routes":            {mapping("compose/p/web", "ex/app", "main", composeRoute+depsRoute)},
		"compose no path":        {mapping("compose/p/web", "ex/app", "main", "      compose:\n        service: web\n")},
		"compose no service":     {mapping("compose/p/web", "ex/app", "main", "      compose:\n        path: compose.yml\n")},
		"compose root path":      {mapping("compose/p/web", "ex/app", "main", "      compose:\n        path: .\n        service: web\n")},
		"absolute path":          {mapping("compose/p/web", "ex/app", "main", "      compose:\n        path: /etc/compose.yml\n        service: web\n")},
		"parent path":            {mapping("compose/p/web", "ex/app", "main", "      compose:\n        path: ../compose.yml\n        service: web\n")},
		"unnormalized path":      {mapping("compose/p/web", "ex/app", "main", "      compose:\n        path: ./x/../y.yml\n        service: web\n")},
		"backslash path":         {mapping("compose/p/web", "ex/app", "main", "      compose:\n        path: 'a\\b.yml'\n        service: web\n")},
		"control char in path":   {mapping("compose/p/web", "ex/app", "main", "      compose:\n        path: \"a\\nb.yml\"\n        service: web\n")},
		"service with slash":     {mapping("compose/p/web", "ex/app", "main", "      compose:\n        path: c.yml\n        service: a/b\n")},
		"dir parent":             {mapping("compose/p/web", "ex/app", "main", "      dependencies:\n        directory: ../x\n")},
		"dir dot slash":          {mapping("compose/p/web", "ex/app", "main", "      dependencies:\n        directory: ./app\n")},
		"dir trailing slash":     {mapping("compose/p/web", "ex/app", "main", "      dependencies:\n        directory: app/\n")},
		"dir absolute":           {mapping("compose/p/web", "ex/app", "main", "      dependencies:\n        directory: /app\n")},
		"dir empty":              {mapping("compose/p/web", "ex/app", "main", "      dependencies:\n        directory: \"\"\n")},
		"duplicate compose":      {mapping("compose/p/web", "ex/a", "main", composeRoute), mapping("compose/p/web", "ex/b", "main", composeRoute)},
		"duplicate dependencies": {mapping("compose/p/web", "ex/a", "main", depsRoute), mapping("compose/p/web", "ex/a", "main", depsRoute)},
		"service claimed twice":  {mapping("compose/p/web", "ex/a", "main", composeRoute), mapping("compose/p/other", "EX/A", "main", composeRoute)},
		"root with two branches": {mapping("compose/p/web", "ex/a", "main", depsRoute), mapping("compose/p/api", "ex/a", "dev", depsRoute)},
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

const dockerfileRoute = "      dockerfile:\n        path: Dockerfile\n        target: runtime\n"

func TestParse_RemediationDockerfileMapping(t *testing.T) {
	c, err := Parse(remediationWith(
		mapping("compose/p/web", "ex/app", "main", dockerfileRoute),
		mapping("compose/p/web", "ex/app", "main", depsRoute),
		mapping("compose/p/api", "ex/app", "main", "      dockerfile:\n        path: services/api/Dockerfile\n"),
	))
	if err != nil {
		t.Fatal(err)
	}
	ms := c.Remediation.Mappings
	if ms[0].Dockerfile == nil || ms[0].Dockerfile.Path != "Dockerfile" || ms[0].Dockerfile.Target != "runtime" || ms[0].Compose != nil || ms[0].Dependencies != nil {
		t.Errorf("mapping 0 = %+v", ms[0])
	}
	if ms[2].Dockerfile == nil || ms[2].Dockerfile.Path != "services/api/Dockerfile" || ms[2].Dockerfile.Target != "" {
		t.Errorf("mapping 2 = %+v", ms[2])
	}
}

func TestParse_RemediationDockerfileMappingValid(t *testing.T) {
	cases := map[string][]string{
		"all three routes for one workload": {
			mapping("compose/p/web", "ex/deploy", "main", composeRoute),
			mapping("compose/p/web", "ex/app", "main", depsRoute),
			mapping("compose/p/web", "ex/app", "main", dockerfileRoute),
		},
		"workloads sharing a Dockerfile and stage": {
			mapping("compose/p/web", "ex/app", "main", dockerfileRoute),
			mapping("compose/p/api", "EX/App", "main", dockerfileRoute),
		},
		"workloads sharing a Dockerfile, other stages": {
			mapping("compose/p/web", "ex/app", "main", dockerfileRoute),
			mapping("compose/p/api", "ex/app", "main", "      dockerfile:\n        path: Dockerfile\n        target: Api-1.x\n"),
		},
		"same path in another repository and branch": {
			mapping("compose/p/web", "ex/app", "main", dockerfileRoute),
			mapping("compose/p/api", "ex/other", "dev", dockerfileRoute),
		},
	}
	for name, ms := range cases {
		if _, err := Parse(remediationWith(ms...)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParse_RemediationDockerfileMappingInvalid(t *testing.T) {
	df := func(body string) string { return "      dockerfile:\n" + body }
	cases := map[string][]string{
		"no path":             {mapping("compose/p/web", "ex/app", "main", df("        target: runtime\n"))},
		"empty dockerfile":    {mapping("compose/p/web", "ex/app", "main", "      dockerfile: {}\n")},
		"root path":           {mapping("compose/p/web", "ex/app", "main", df("        path: .\n"))},
		"absolute path":       {mapping("compose/p/web", "ex/app", "main", df("        path: /Dockerfile\n"))},
		"parent path":         {mapping("compose/p/web", "ex/app", "main", df("        path: ../Dockerfile\n"))},
		"unnormalized path":   {mapping("compose/p/web", "ex/app", "main", df("        path: ./Dockerfile\n"))},
		"backslash path":      {mapping("compose/p/web", "ex/app", "main", df("        path: 'a\\Dockerfile'\n"))},
		"control char path":   {mapping("compose/p/web", "ex/app", "main", df("        path: \"a\\nDockerfile\"\n"))},
		"target with space":   {mapping("compose/p/web", "ex/app", "main", df("        path: Dockerfile\n        target: \"a b\"\n"))},
		"target with dollar":  {mapping("compose/p/web", "ex/app", "main", df("        path: Dockerfile\n        target: $T\n"))},
		"target leading dash": {mapping("compose/p/web", "ex/app", "main", df("        path: Dockerfile\n        target: -x\n"))},
		"with compose":        {mapping("compose/p/web", "ex/app", "main", composeRoute+dockerfileRoute)},
		"with dependencies":   {mapping("compose/p/web", "ex/app", "main", depsRoute+dockerfileRoute)},
		"duplicate dockerfile": {
			mapping("compose/p/web", "ex/a", "main", dockerfileRoute),
			mapping("compose/p/web", "ex/b", "main", dockerfileRoute),
		},
		"Dockerfile with two branches": {
			mapping("compose/p/web", "ex/a", "main", dockerfileRoute),
			mapping("compose/p/api", "ex/a", "dev", dockerfileRoute),
		},
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

func TestValidStageName(t *testing.T) {
	for _, ok := range []string{"a", "build", "Runtime", "go-1.22_x", strings.Repeat("a", 128)} {
		if !ValidStageName(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "1a", "-a", ".a", "_a", "a b", "a$b", "a/b", "a:b", "é", strings.Repeat("a", 129)} {
		if ValidStageName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParse_RemediationMappingsUnusedWhenDisabled(t *testing.T) {
	c, err := Parse(remediationWith(mapping("compose/p/web", "ex/app", "main", depsRoute)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Remediation.Enabled || len(c.Remediation.Mappings) != 1 {
		t.Errorf("remediation = %+v", c.Remediation)
	}
}

func TestExampleConfig_RemediationBlockParses(t *testing.T) {
	data, err := os.ReadFile("../../config.example.yml")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	// Uncomment the remediation example (the trailing block of "# " lines)
	// and parse it on its own: the file's other keys are examples of theirs.
	var block []string
	in := false
	for _, line := range strings.Split(string(data), "\n") {
		if line == "# remediation:" {
			in = true
		}
		if !in {
			continue
		}
		if strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "#   #") {
			line = strings.TrimPrefix(strings.TrimPrefix(line, "#"), " ")
		}
		block = append(block, line)
	}
	if len(block) == 0 {
		t.Fatal("config.example.yml has no commented remediation block")
	}
	c, err := Parse([]byte(minimal + "\n" + strings.Join(block, "\n")))
	if err != nil {
		t.Fatalf("Parse uncommented example: %v", err)
	}
	if !c.Remediation.Enabled {
		t.Error("uncommented example: Remediation.Enabled = false, want true")
	}
	if c.Remediation.Limits != (RemediationLimits{10, 10, 200, 20, 30 * time.Minute, 3, 10, 3, 6 * time.Minute}) {
		t.Errorf("uncommented example limits = %+v", c.Remediation.Limits)
	}
	if len(c.Remediation.Mappings) == 0 {
		t.Error("uncommented example has no mappings")
	}
}

func TestParse_RemediationTokenDecodeErrorsDoNotEchoIt(t *testing.T) {
	const tok = "ghp_supersecretvalue"
	for name, val := range map[string]string{
		"tagged int":    "!!int " + tok,
		"tagged float":  "!!float " + tok,
		"tagged bool":   "!!bool " + tok,
		"tagged null":   "!!null " + tok,
		"tagged seq":    "!!seq " + tok,
		"tagged map":    "!!map " + tok,
		"tagged ts":     "!!timestamp " + tok,
		"tagged binary": "!!binary " + tok,
		"custom tag":    "!custom " + tok,
		"list":          "[" + tok + "]",
		"map":           "{k: " + tok + "}",
		"number":        "12345678",
		"bool":          "true",
	} {
		_, err := Parse([]byte(minimal + "\nremediation:\n  github:\n    token: " + val + "\n"))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), tok) || strings.Contains(err.Error(), "12345678") {
			t.Errorf("%s: error echoes the value: %v", name, err)
		}
	}
	// An unset token stays unset.
	for _, val := range []string{"", "~", "null", "!!null"} {
		c, err := Parse([]byte(minimal + "\nremediation:\n  github:\n    token: " + val + "\n"))
		if err != nil || c.Remediation.GitHub.Token != "" {
			t.Errorf("%q: token = %q, err = %v", val, c.Remediation.GitHub.Token.Value(), err)
		}
	}
	// A tagged string and a quoted string are fine.
	for _, val := range []string{"!!str " + tok, `"` + tok + `"`, "'" + tok + "'", tok} {
		c, err := Parse([]byte(minimal + "\nremediation:\n  github:\n    token: " + val + "\n"))
		if err != nil || c.Remediation.GitHub.Token.Value() != tok {
			t.Errorf("%s: token = %q, err = %v", val, c.Remediation.GitHub.Token.Value(), err)
		}
	}
}

func TestParse_NodeRuntimeDefaults(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if want := (NodeRuntimeConfig{Enabled: true}); c.Scan.NodeRuntime != want {
		t.Errorf("default NodeRuntime = %+v, want %+v", c.Scan.NodeRuntime, want)
	}
}

func TestParse_NodeRuntimeOverrides(t *testing.T) {
	c, err := Parse([]byte(`
notify:
  slack_webhook_url: "https://x.test"
scan:
  node_runtime:
    security_wg_url: "https://mirror.test/index.json"
    blog_feed_url: "https://mirror.test/feed.xml"
    blog_post_base_url: "https://mirror.test/posts/"
    releases_url: "https://mirror.test/dist.json"
    schedule_url: "https://mirror.test/schedule.json"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := NodeRuntimeConfig{
		Enabled:         true,
		SecurityWGURL:   "https://mirror.test/index.json",
		BlogFeedURL:     "https://mirror.test/feed.xml",
		BlogPostBaseURL: "https://mirror.test/posts/",
		ReleasesURL:     "https://mirror.test/dist.json",
		ScheduleURL:     "https://mirror.test/schedule.json",
	}
	if c.Scan.NodeRuntime != want {
		t.Errorf("NodeRuntime = %+v, want %+v", c.Scan.NodeRuntime, want)
	}
}

func TestParse_NodeRuntimeDisabled(t *testing.T) {
	c, err := Parse([]byte(`
notify:
  slack_webhook_url: "https://x.test"
scan:
  node_runtime:
    enabled: false
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Scan.NodeRuntime.Enabled {
		t.Error("node_runtime.enabled: false was not honoured")
	}
}
