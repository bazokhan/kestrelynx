// Package config loads and validates KestreLynx's single YAML config file
// (docs/ARCHITECTURE.md §5). Parsing applies defaults so a minimal file — just
// one notify target — is enough to run.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"gopkg.in/yaml.v3"
)

// Config is the validated runtime configuration.
type Config struct {
	Schedule    ScheduleConfig
	Scan        ScanConfig
	Notify      NotifyConfig
	Docker      DockerConfig
	Kubernetes  KubernetesConfig
	State       StateConfig
	Triage      TriageConfig
	Environment EnvironmentConfig
	Runtime     RuntimeConfig
	Remediation RemediationConfig
}

// EnvironmentConfig names the environment this instance is watching
// (docs/development/environment-workload-model.md). Name is the only
// user-facing key; Kind is not configurable — it's set by the composition
// root to match whichever Runtime Adapter it wired up.
type EnvironmentConfig struct {
	Name string // "" = the unnamed default environment; current single-host behavior, unchanged.
}

type ScheduleConfig struct {
	DailyAt    string // "HH:MM" local time; empty means run every 24h from start
	RunOnStart bool   // run one scan immediately on startup
}

// DailyTime parses DailyAt into hour and minute. ok is false when DailyAt is
// empty (i.e. interval mode rather than wall-clock mode).
func (s ScheduleConfig) DailyTime() (hour, min int, ok bool) {
	if s.DailyAt == "" {
		return 0, 0, false
	}
	t, err := time.Parse("15:04", s.DailyAt)
	if err != nil {
		return 0, 0, false
	}
	return t.Hour(), t.Minute(), true
}

type ScanConfig struct {
	Severity []string // Trivy severities to report, e.g. HIGH, CRITICAL
}

type NotifyConfig struct {
	SlackWebhookURL string
	// Slack Web API delivery: a bot token (chat:write) plus destination
	// channel. Replaces the webhook and additionally posts the full report to
	// the summary's thread.
	SlackBotToken     string
	SlackChannel      string
	GenericWebhookURL string
	NotifyOnClean     bool   // also notify when nothing was found
	Mode              string // "diff" (default) or "full"
	FullReportDay     string // diff mode: weekday of the weekly full report; "never" disables
	// Language selects the wording dictionary the Slack channel message and
	// thread report render from ("en" or "ja"). Never affects the generic
	// webhook payload, which is always English (it's consumed
	// programmatically, not read in Slack). Defaults to "en".
	Language string
}

// FullReportWeekday parses FullReportDay into a time.Weekday. ok is false when
// the weekly full report is disabled ("never").
func (n NotifyConfig) FullReportWeekday() (time.Weekday, bool) {
	day, ok := weekdays[strings.ToLower(n.FullReportDay)]
	return day, ok
}

type DockerConfig struct {
	Socket string
}

// KubernetesConfig selects and configures the Kubernetes Runtime Adapter,
// mutually exclusive with Docker (validate rejects enabling this alongside an
// explicitly set docker.socket). The field shapes mirror kubernetes.Options
// (internal/kubernetes/kubernetes.go): every field left empty falls back to
// that package's in-cluster default.
type KubernetesConfig struct {
	Enabled       bool
	APIServer     string   // "" = build from KUBERNETES_SERVICE_HOST/PORT
	TokenFile     string   // "" = the projected ServiceAccount token's default path
	CAFile        string   // "" = the projected cluster CA's default path
	TLSServerName string   // "" = don't override; validate against APIServer as-is
	Namespaces    []string // empty = every namespace
}

type StateConfig struct {
	Path string // where diff-mode scan state is persisted
}

// TriageConfig controls the Phase 1+ triage layer (docs/TRIAGE_SPEC.md §7).
// Disabling it also stops the KEV/EPSS feed downloads — the explicit way out
// for users who don't want the extra egress.
type TriageConfig struct {
	Enabled    bool
	ActNowEPSS float64 // EPSS probability at or above which a CVE is act_now
	WatchEPSS  float64 // EPSS probability at or above which a CVE is at least watch
	KEVURL     string  // override for air-gapped mirrors; empty = CISA
	EPSSURL    string  // override for air-gapped mirrors; empty = FIRST/Empirical Security
	// DiscussionLinks looks up the HN discussion for act-now CVEs. Unlike the
	// bulk feeds this sends those CVE IDs (only) as search queries; off = zero
	// CVE egress (docs/TRIAGE_SPEC.md §8).
	DiscussionLinks bool
}

// RuntimeConfig controls the optional runtime-usage overlay: an opt-in
// Sensor companion process observes which packages are actually exercised
// by a running container, and this main body reads what it wrote to show
// usage alongside the ordinary vulnerability findings. Disabled by
// default — with no Sensor deployed there is nothing at EvidenceDir to read,
// and the main body must not fail a scan cycle over a directory nobody asked
// it to look at.
type RuntimeConfig struct {
	Enabled bool
	// EvidenceDir is where the Sensor writes its evidence file
	// (evidence.FileName inside it). Always an absolute path — Load resolves
	// it once at startup, and it is shared with the Sensor container only
	// through a mounted volume, never a relative path meaningful to just one
	// of the two containers.
	EvidenceDir string
	// MuteUnfixableNotInUse hides (from Slack rows only — the generic
	// webhook always keeps everything) a package finding with no fix coming
	// (affected or will_not_fix) that nothing has used for at least 7 days
	// of Sensor observation and that isn't act_now, replacing it with a
	// single count. Meaningful only when Enabled is also true; false is
	// simply inert otherwise (no runtime verdict exists to judge against),
	// not a configuration error.
	MuteUnfixableNotInUse bool
}

// RemediationConfig controls the optional fix plan: for each running image
// with a fixed vulnerability, it looks for a newer image in the registry,
// rescans it and reports whether it would resolve the findings. The plan is
// read-only — nothing is pulled, changed or created. Disabled by default.
type RemediationConfig struct {
	Plan   RemediationPlanConfig
	Limits RemediationLimits
}

// RemediationPlanConfig switches the read-only plan on.
type RemediationPlanConfig struct {
	Enabled bool
}

// RemediationLimits caps the work of one plan. A limit of zero allows none of
// that work; work past a limit is reported as deferred, never dropped.
type RemediationLimits struct {
	MaxCandidateScans   int // candidate image scans per cycle
	MaxBaselineRescans  int // rescans of a running image to match the plan's scan conditions
	MaxRegistryRequests int // registry HTTP requests per cycle, token exchanges included
	MaxTagPages         int // tag listing pages per cycle
}

// rawConfig mirrors the YAML shape. Pointers are used where "absent" must be
// distinguished from a zero value (booleans whose default is true).
type rawConfig struct {
	Schedule struct {
		DailyAt    string `yaml:"daily_at"`
		RunOnStart *bool  `yaml:"run_on_start"`
	} `yaml:"schedule"`
	Scan struct {
		Severity []string `yaml:"severity"`
	} `yaml:"scan"`
	Notify struct {
		SlackWebhookURL   string `yaml:"slack_webhook_url"`
		SlackBotToken     string `yaml:"slack_bot_token"`
		SlackChannel      string `yaml:"slack_channel"`
		GenericWebhookURL string `yaml:"generic_webhook_url"`
		NotifyOnClean     bool   `yaml:"notify_on_clean"`
		Mode              string `yaml:"mode"`
		FullReportDay     string `yaml:"full_report_day"`
		Language          string `yaml:"language"`
	} `yaml:"notify"`
	Docker struct {
		// Socket is a pointer so validate can tell "explicitly set" (including
		// an explicit empty string) apart from "omitted" — the mutual
		// exclusion check with kubernetes.enabled needs that distinction,
		// since Config.Docker.Socket itself always ends up non-empty (the
		// default fills in either way).
		Socket *string `yaml:"socket"`
	} `yaml:"docker"`
	Kubernetes struct {
		Enabled       *bool    `yaml:"enabled"`
		APIServer     string   `yaml:"api_server"`
		TokenFile     string   `yaml:"token_file"`
		CAFile        string   `yaml:"ca_file"`
		TLSServerName string   `yaml:"tls_server_name"`
		Namespaces    []string `yaml:"namespaces"`
	} `yaml:"kubernetes"`
	State struct {
		Path string `yaml:"path"`
	} `yaml:"state"`
	Triage struct {
		Enabled         *bool    `yaml:"enabled"`
		ActNowEPSS      *float64 `yaml:"act_now_epss"`
		WatchEPSS       *float64 `yaml:"watch_epss"`
		KEVURL          string   `yaml:"kev_url"`
		EPSSURL         string   `yaml:"epss_url"`
		DiscussionLinks *bool    `yaml:"discussion_links"`
	} `yaml:"triage"`
	Environment struct {
		Name string `yaml:"name"`
	} `yaml:"environment"`
	Runtime struct {
		Enabled               *bool  `yaml:"enabled"`
		EvidenceDir           string `yaml:"evidence_dir"`
		MuteUnfixableNotInUse *bool  `yaml:"mute_unfixable_not_in_use"`
	} `yaml:"runtime"`
	Remediation struct {
		Plan struct {
			Enabled *bool `yaml:"enabled"`
		} `yaml:"plan"`
		// The limits are pointers so an explicit 0 ("allow none") is told
		// apart from an omitted key.
		Limits struct {
			MaxCandidateScans   *int `yaml:"max_candidate_scans"`
			MaxBaselineRescans  *int `yaml:"max_baseline_rescans"`
			MaxRegistryRequests *int `yaml:"max_registry_requests"`
			MaxTagPages         *int `yaml:"max_tag_pages"`
		} `yaml:"limits"`
	} `yaml:"remediation"`
}

const (
	defaultSocket        = "/var/run/docker.sock"
	defaultStatePath     = "/var/lib/kestrelynx/state.json"
	defaultFullReportDay = "monday"
	// defaultNotifyLanguage is the wording every deployment saw before
	// notify.language existed.
	defaultNotifyLanguage = "en"
	// Default EPSS thresholds (docs/TRIAGE_SPEC.md §4): 10% predicted
	// exploitation probability is act_now territory, 1% is worth watching.
	defaultActNowEPSS = 0.10
	defaultWatchEPSS  = 0.01
	// defaultEvidenceDir mirrors the Sensor's own --evidence-dir default
	// (internal/sensor), so an unconfigured runtime.evidence_dir and an
	// unconfigured Sensor flag agree on the volume path without either side
	// having to spell it out.
	defaultEvidenceDir = "/var/lib/kestrelynx-runtime"
)

// Provisional defaults for the fix plan's per-cycle limits. They are
// deliberately small so a first run stays cheap for registries and for the
// host; they are to be revisited once real runs show what a cycle costs.
const (
	defaultMaxCandidateScans   = 10
	defaultMaxBaselineRescans  = 10
	defaultMaxRegistryRequests = 200
	defaultMaxTagPages         = 20
)

var validSeverities = map[string]bool{
	"UNKNOWN": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true,
}

var weekdays = map[string]time.Weekday{
	"sunday": time.Sunday, "monday": time.Monday, "tuesday": time.Tuesday,
	"wednesday": time.Wednesday, "thursday": time.Thursday,
	"friday": time.Friday, "saturday": time.Saturday,
}

// Load reads and parses the config file at path.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	return Parse(data)
}

// Parse parses YAML bytes, applies defaults, and validates.
func Parse(data []byte) (Config, error) {
	var raw rawConfig
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	c := Config{
		Schedule: ScheduleConfig{
			DailyAt:    raw.Schedule.DailyAt,
			RunOnStart: boolOr(raw.Schedule.RunOnStart, true),
		},
		Scan:   ScanConfig{Severity: raw.Scan.Severity},
		Notify: NotifyConfig(raw.Notify),
		Docker: DockerConfig{Socket: stringOr(raw.Docker.Socket, "")},
		Kubernetes: KubernetesConfig{
			Enabled:       boolOr(raw.Kubernetes.Enabled, false),
			APIServer:     raw.Kubernetes.APIServer,
			TokenFile:     raw.Kubernetes.TokenFile,
			CAFile:        raw.Kubernetes.CAFile,
			TLSServerName: raw.Kubernetes.TLSServerName,
			Namespaces:    raw.Kubernetes.Namespaces,
		},
		State: StateConfig{Path: raw.State.Path},
		Triage: TriageConfig{
			Enabled:         boolOr(raw.Triage.Enabled, true),
			ActNowEPSS:      floatOr(raw.Triage.ActNowEPSS, defaultActNowEPSS),
			WatchEPSS:       floatOr(raw.Triage.WatchEPSS, defaultWatchEPSS),
			KEVURL:          raw.Triage.KEVURL,
			EPSSURL:         raw.Triage.EPSSURL,
			DiscussionLinks: boolOr(raw.Triage.DiscussionLinks, true),
		},
		Environment: EnvironmentConfig{Name: raw.Environment.Name},
		Runtime: RuntimeConfig{
			Enabled:               boolOr(raw.Runtime.Enabled, false),
			EvidenceDir:           raw.Runtime.EvidenceDir,
			MuteUnfixableNotInUse: boolOr(raw.Runtime.MuteUnfixableNotInUse, false),
		},
		Remediation: RemediationConfig{
			Plan: RemediationPlanConfig{Enabled: boolOr(raw.Remediation.Plan.Enabled, false)},
			Limits: RemediationLimits{
				MaxCandidateScans:   intOr(raw.Remediation.Limits.MaxCandidateScans, defaultMaxCandidateScans),
				MaxBaselineRescans:  intOr(raw.Remediation.Limits.MaxBaselineRescans, defaultMaxBaselineRescans),
				MaxRegistryRequests: intOr(raw.Remediation.Limits.MaxRegistryRequests, defaultMaxRegistryRequests),
				MaxTagPages:         intOr(raw.Remediation.Limits.MaxTagPages, defaultMaxTagPages),
			},
		},
	}

	applyDefaults(&c)
	if err := validate(&c, raw.Docker.Socket != nil); err != nil {
		return Config{}, err
	}
	return c, nil
}

func applyDefaults(c *Config) {
	// schedule.daily_at intentionally has no default: empty means interval mode
	// (run every 24h from start), per docs/ARCHITECTURE.md §5.
	if len(c.Scan.Severity) == 0 {
		c.Scan.Severity = []string{"HIGH", "CRITICAL"}
	}
	if c.Docker.Socket == "" {
		c.Docker.Socket = defaultSocket
	}
	if c.Notify.Mode == "" {
		c.Notify.Mode = "diff"
	}
	if c.Notify.FullReportDay == "" {
		c.Notify.FullReportDay = defaultFullReportDay
	}
	if c.Notify.Language == "" {
		c.Notify.Language = defaultNotifyLanguage
	}
	if c.State.Path == "" {
		c.State.Path = defaultStatePath
	}
	if c.Runtime.EvidenceDir == "" {
		c.Runtime.EvidenceDir = defaultEvidenceDir
	}
}

// namespacePattern matches a DNS-1123 label, the syntax Kubernetes namespace
// names use. It mirrors inventory.environmentNamePattern's rule (lowercase
// alphanumerics and hyphens, 1-63 bytes, alphanumeric ends) but is kept as its
// own regexp since it validates an unrelated config key.
var namespacePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func validate(c *Config, dockerSocketExplicit bool) error {
	if c.Kubernetes.Enabled && dockerSocketExplicit {
		return fmt.Errorf("config: configure either docker.socket or kubernetes.enabled, not both")
	}
	for _, ns := range c.Kubernetes.Namespaces {
		if !namespacePattern.MatchString(ns) {
			return fmt.Errorf("config: invalid kubernetes.namespaces entry %q: must be 1-63 bytes of lowercase alphanumerics and hyphens, starting and ending with an alphanumeric", ns)
		}
	}
	if c.Kubernetes.APIServer != "" && !strings.HasPrefix(c.Kubernetes.APIServer, "https://") {
		return fmt.Errorf("config: kubernetes.api_server must use https, got %q", c.Kubernetes.APIServer)
	}
	if (c.Notify.SlackBotToken == "") != (c.Notify.SlackChannel == "") {
		return fmt.Errorf("config: slack_bot_token and slack_channel must be set together")
	}
	if c.Notify.SlackBotToken != "" && c.Notify.SlackWebhookURL != "" {
		return fmt.Errorf("config: configure either slack_webhook_url or slack_bot_token, not both")
	}
	if c.Notify.SlackWebhookURL == "" && c.Notify.SlackBotToken == "" && c.Notify.GenericWebhookURL == "" {
		return fmt.Errorf("config: at least one notify target (slack_webhook_url, slack_bot_token, or generic_webhook_url) is required")
	}
	for i, s := range c.Scan.Severity {
		up := strings.ToUpper(strings.TrimSpace(s))
		if !validSeverities[up] {
			return fmt.Errorf("config: invalid scan.severity %q (allowed: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL)", s)
		}
		c.Scan.Severity[i] = up
	}
	// Empty daily_at is valid (interval mode). Only a non-empty, unparseable
	// value is an error.
	if _, _, ok := c.Schedule.DailyTime(); !ok && c.Schedule.DailyAt != "" {
		return fmt.Errorf("config: schedule.daily_at %q is not a valid HH:MM time", c.Schedule.DailyAt)
	}
	m := strings.ToLower(c.Notify.Mode)
	if m != "diff" && m != "full" {
		return fmt.Errorf("config: invalid notify.mode %q (allowed: diff, full)", c.Notify.Mode)
	}
	c.Notify.Mode = m
	if day := strings.ToLower(c.Notify.FullReportDay); day != "never" {
		if _, ok := weekdays[day]; !ok {
			return fmt.Errorf("config: invalid notify.full_report_day %q (a weekday name or \"never\")", c.Notify.FullReportDay)
		}
	}
	lang := strings.ToLower(c.Notify.Language)
	if lang != "en" && lang != "ja" {
		return fmt.Errorf("config: invalid notify.language %q (allowed: en, ja)", c.Notify.Language)
	}
	c.Notify.Language = lang
	if c.Triage.Enabled {
		if c.Triage.WatchEPSS <= 0 || c.Triage.WatchEPSS > c.Triage.ActNowEPSS || c.Triage.ActNowEPSS > 1 {
			return fmt.Errorf("config: triage thresholds must satisfy 0 < watch_epss (%v) <= act_now_epss (%v) <= 1", c.Triage.WatchEPSS, c.Triage.ActNowEPSS)
		}
	}
	if err := inventory.ValidateEnvironmentName(c.Environment.Name); err != nil {
		return fmt.Errorf("config: environment.name: %w", err)
	}
	if c.Runtime.Enabled {
		if c.Kubernetes.Enabled {
			return fmt.Errorf("config: runtime.enabled is not supported with kubernetes.enabled")
		}
		if !filepath.IsAbs(c.Runtime.EvidenceDir) {
			return fmt.Errorf("config: runtime.evidence_dir %q must be an absolute path", c.Runtime.EvidenceDir)
		}
	}
	for _, l := range []struct {
		key string
		val int
	}{
		{"max_candidate_scans", c.Remediation.Limits.MaxCandidateScans},
		{"max_baseline_rescans", c.Remediation.Limits.MaxBaselineRescans},
		{"max_registry_requests", c.Remediation.Limits.MaxRegistryRequests},
		{"max_tag_pages", c.Remediation.Limits.MaxTagPages},
	} {
		if l.val < 0 {
			return fmt.Errorf("config: remediation.limits.%s must not be negative, got %d", l.key, l.val)
		}
	}
	if c.Remediation.Plan.Enabled && c.Kubernetes.Enabled {
		return fmt.Errorf("config: remediation.plan.enabled is not supported with kubernetes.enabled")
	}
	return nil
}

func boolOr(p *bool, def bool) bool {
	if p != nil {
		return *p
	}
	return def
}

func stringOr(p *string, def string) string {
	if p != nil {
		return *p
	}
	return def
}

func intOr(p *int, def int) int {
	if p != nil {
		return *p
	}
	return def
}

func floatOr(p *float64, def float64) float64 {
	if p != nil {
		return *p
	}
	return def
}
