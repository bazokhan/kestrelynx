package config

import (
	"os"
	"strings"
	"testing"
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
	if c.Remediation.Plan.Enabled {
		t.Error("Remediation.Plan.Enabled = true, want false by default")
	}
	want := RemediationLimits{MaxCandidateScans: 10, MaxBaselineRescans: 10, MaxRegistryRequests: 200, MaxTagPages: 20}
	if c.Remediation.Limits != want {
		t.Errorf("Remediation.Limits = %+v, want %+v", c.Remediation.Limits, want)
	}
}

func TestParse_RemediationExplicit(t *testing.T) {
	c, err := Parse([]byte(minimal + `
remediation:
  plan:
    enabled: true
  limits:
    max_candidate_scans: 3
    max_baseline_rescans: 0
    max_registry_requests: 50
    max_tag_pages: 5
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !c.Remediation.Plan.Enabled {
		t.Error("Remediation.Plan.Enabled = false, want true")
	}
	// An explicit 0 stays 0 (it allows none of that work); it is not replaced
	// by the default.
	want := RemediationLimits{MaxCandidateScans: 3, MaxBaselineRescans: 0, MaxRegistryRequests: 50, MaxTagPages: 5}
	if c.Remediation.Limits != want {
		t.Errorf("Remediation.Limits = %+v, want %+v", c.Remediation.Limits, want)
	}
}

func TestParse_RemediationPlanAllowedInBothModes(t *testing.T) {
	for _, mode := range []string{"diff", "full"} {
		_, err := Parse([]byte(`
notify:
  slack_webhook_url: "https://x.test"
  mode: ` + mode + `
remediation:
  plan:
    enabled: true
`))
		if err != nil {
			t.Errorf("mode %s: %v", mode, err)
		}
	}
}

func TestParse_RemediationNegativeLimitRejected(t *testing.T) {
	for _, key := range []string{"max_candidate_scans", "max_baseline_rescans", "max_registry_requests", "max_tag_pages"} {
		_, err := Parse([]byte(minimal + "\nremediation:\n  limits:\n    " + key + ": -1\n"))
		if err == nil {
			t.Errorf("%s: expected an error for a negative limit", key)
			continue
		}
		if !strings.Contains(err.Error(), key) {
			t.Errorf("%s: err = %v, want it to name the key", key, err)
		}
	}
}

func TestParse_RemediationPlanWithKubernetesRejected(t *testing.T) {
	_, err := Parse([]byte(minimal + "\nkubernetes:\n  enabled: true\nremediation:\n  plan:\n    enabled: true\n"))
	if err == nil {
		t.Fatal("Parse: expected an error for remediation.plan.enabled with kubernetes.enabled")
	}
	if !strings.Contains(err.Error(), "remediation.plan.enabled") || !strings.Contains(err.Error(), "kubernetes.enabled") {
		t.Errorf("err = %v, want it to name both keys", err)
	}
	// Disabled plan next to Kubernetes stays valid.
	if _, err := Parse([]byte(minimal + "\nkubernetes:\n  enabled: true\nremediation:\n  plan:\n    enabled: false\n")); err != nil {
		t.Errorf("Parse: %v, want a disabled plan to be accepted with kubernetes", err)
	}
}

func TestParse_RemediationUnknownKeyRejected(t *testing.T) {
	for _, body := range []string{
		"remediation:\n  enabled: true\n",
		"remediation:\n  plan:\n    enable: true\n",
		"remediation:\n  limits:\n    max_candidates: 1\n",
	} {
		if _, err := Parse([]byte(minimal + "\n" + body)); err == nil {
			t.Errorf("%q: expected an unknown-key error", body)
		}
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
	if !c.Remediation.Plan.Enabled {
		t.Error("uncommented example: Remediation.Plan.Enabled = false, want true")
	}
	if c.Remediation.Limits != (RemediationLimits{10, 10, 200, 20}) {
		t.Errorf("uncommented example limits = %+v", c.Remediation.Limits)
	}
}
