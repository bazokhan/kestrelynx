package main

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/nodecore"
	"github.com/kitsunetrail/kestrelynx/internal/pycore"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
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

func TestBuildPythonRuntime_CacheDirNextToStateAndOverrides(t *testing.T) {
	cfg := config.Config{}
	cfg.State.Path = "/var/lib/kestrelynx/state.json"
	cfg.Scan.PythonRuntime = config.PythonRuntimeConfig{
		Enabled:          true,
		AdvisoryDBURL:    "https://mirror.test/db.tar.gz",
		CVERecordBaseURL: "https://mirror.test/cves/",
		ReleasesURL:      "https://mirror.test/releases.json",
		ReleaseCycleURL:  "https://mirror.test/cycle.json",
	}

	advisor, refresher := buildPythonRuntime(cfg, slog.Default())
	if advisor == nil || refresher.Advisor != advisor {
		t.Fatal("the refresher must load into the advisor the scanners share")
	}
	src := refresher.Source
	if want := filepath.Join("/var/lib/kestrelynx", "python"); src.CacheDir != want {
		t.Errorf("CacheDir = %q, want %q", src.CacheDir, want)
	}
	if src.AdvisoryDBURL != "https://mirror.test/db.tar.gz" || src.CVERecordBaseURL != "https://mirror.test/cves/" ||
		src.ReleasesURL != "https://mirror.test/releases.json" || src.ReleaseCycleURL != "https://mirror.test/cycle.json" {
		t.Errorf("URL overrides not passed through: %+v", src)
	}
}

func TestBuildRuntimes(t *testing.T) {
	cases := []struct {
		name         string
		node, python bool
		want         []string // advisor types in order
	}{
		{"both", true, true, []string{"*nodecore.Advisor", "*pycore.Advisor"}},
		{"node only", true, false, []string{"*nodecore.Advisor"}},
		{"python only", false, true, []string{"*pycore.Advisor"}},
		{"neither", false, false, nil},
	}
	for _, c := range cases {
		cfg := config.Config{}
		cfg.State.Path = "/var/lib/kestrelynx/state.json"
		cfg.Scan.NodeRuntime.Enabled = c.node
		cfg.Scan.PythonRuntime.Enabled = c.python

		advisors, refreshers := buildRuntimes(cfg, slog.Default())
		var got, gotRefreshers []string
		for _, a := range advisors {
			got = append(got, fmt.Sprintf("%T", a))
		}
		for _, r := range refreshers {
			gotRefreshers = append(gotRefreshers, fmt.Sprintf("%T", r))
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: advisors = %v, want %v", c.name, got, c.want)
		}
		if len(gotRefreshers) != len(c.want) {
			t.Errorf("%s: refreshers = %v, want one per advisor", c.name, gotRefreshers)
		}

		// The normal scanner and the plan scanner carry the same instances.
		normal := withRuntimes(scanner.Trivy{}, advisors)
		plan := withRuntimes(scanner.Trivy{SkipDBUpdate: true}, advisors)
		if len(normal.Runtimes) != len(c.want) || len(plan.Runtimes) != len(c.want) {
			t.Fatalf("%s: scanners carry %d and %d advisors, want %d", c.name, len(normal.Runtimes), len(plan.Runtimes), len(c.want))
		}
		for i := range normal.Runtimes {
			if normal.Runtimes[i] != advisors[i] || plan.Runtimes[i] != advisors[i] {
				t.Errorf("%s: scanner %d does not share advisor %d", c.name, i, i)
			}
		}
	}
}

func TestBuildRuntimes_RefreshersLoadIntoTheSharedAdvisors(t *testing.T) {
	cfg := config.Config{}
	cfg.State.Path = "/var/lib/kestrelynx/state.json"
	cfg.Scan.NodeRuntime.Enabled = true
	cfg.Scan.PythonRuntime.Enabled = true

	advisors, refreshers := buildRuntimes(cfg, slog.Default())
	if nr, ok := refreshers[0].(nodecore.Refresher); !ok || scanner.RuntimeAdvisor(nr.Advisor) != advisors[0] {
		t.Errorf("refresher 0 = %#v, want the Node.js refresher of advisor 0", refreshers[0])
	}
	if pr, ok := refreshers[1].(pycore.Refresher); !ok || scanner.RuntimeAdvisor(pr.Advisor) != advisors[1] {
		t.Errorf("refresher 1 = %#v, want the CPython refresher of advisor 1", refreshers[1])
	}
}
