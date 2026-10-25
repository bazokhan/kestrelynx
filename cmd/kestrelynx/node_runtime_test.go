package main

import (
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/config"
)

func TestBuildNodeRuntime_CacheDirNextToStateAndOverrides(t *testing.T) {
	cfg := config.Config{}
	cfg.State.Path = "/var/lib/kestrelynx/state.json"
	cfg.Triage.Enabled = false
	cfg.Scan.NodeRuntime = config.NodeRuntimeConfig{Enabled: true, ReleasesURL: "https://mirror.test/dist.json"}

	advisor, refresher := buildNodeRuntime(cfg, slog.Default())
	if advisor == nil || refresher.Advisor != advisor {
		t.Fatal("the refresher must load into the advisor the scanners share")
	}
	if want := filepath.Join("/var/lib/kestrelynx", "nodejs"); refresher.Source.CacheDir != want {
		t.Errorf("CacheDir = %q, want %q", refresher.Source.CacheDir, want)
	}
	if refresher.Source.ReleasesURL != "https://mirror.test/dist.json" || refresher.Source.SecurityWGURL != "" {
		t.Errorf("URL overrides not passed through: %+v", refresher.Source)
	}
}
