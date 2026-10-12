package remediation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/toolfetch"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// The integration tests of the update stage run against the official Node.js
// and Python images the build pins by digest, a real Docker daemon, the work
// program built from this source, package manager releases fetched and
// checked by the fetching package of the main process, the real registries and
// a real Trivy with its database cached. They run only when
// KESTRELYNX_WORKER_IT=1. Optional settings:
//
//	KESTRELYNX_DOCKER_SOCK  the Docker socket (default /var/run/docker.sock)
//	KESTRELYNX_TRIVY_BIN    the trivy executable (default ~/.local/bin/trivy)
//	KESTRELYNX_TRIVY_CACHE  its cache directory (default ~/.cache/trivy)
//	KESTRELYNX_IT_PLATFORM  the platform to run on (default linux/<GOARCH>)
//	KESTRELYNX_IT_MIN_RELEASE_AGE  how old a package manager release has to be
//	                        (default 1h, so that a release of the day can be used)
//	KESTRELYNX_IT_DUMP_JOBS a directory to keep the files of every job in

// itEnv is what an integration test of the update stage runs with.
type itEnv struct {
	ctx      context.Context
	set      *docker.WorkSet
	instance string
	trivy    scanner.Trivy
	prepared scanner.ScanConditions
	image    ImageEnv
	platform string
	program  func() ([]byte, error)
	tools    ToolProvider
	// dumpDir, when set, is where the files of every job are kept, to run it
	// again under a tracer (see dumpingWork).
	dumpDir string
}

// itDefaultToolVersions are the releases the integration tests run when a
// project names none; they are the ones the fetching package defaults to.
var itDefaultToolVersions = map[DependencyManager]string{
	ManagerNpm:  "11.21.0",
	ManagerPnpm: "11.28.5",
	ManagerUv:   "0.13.0",
}

func itSetup(t *testing.T) *itEnv {
	t.Helper()
	if os.Getenv("KESTRELYNX_WORKER_IT") != "1" {
		t.Skip("set KESTRELYNX_WORKER_IT=1 to run the update stage against the pinned official images")
	}
	sock := os.Getenv("KESTRELYNX_DOCKER_SOCK")
	if sock == "" {
		sock = "/var/run/docker.sock"
	}
	home, _ := os.UserHomeDir()
	trivyBin := os.Getenv("KESTRELYNX_TRIVY_BIN")
	if trivyBin == "" {
		trivyBin = filepath.Join(home, ".local", "bin", "trivy")
	}
	cache := os.Getenv("KESTRELYNX_TRIVY_CACHE")
	if cache == "" {
		cache = filepath.Join(home, ".cache", "trivy")
	}
	platform := os.Getenv("KESTRELYNX_IT_PLATFORM")
	if platform == "" {
		platform = "linux/" + runtime.GOARCH
	}
	_, goarch, _ := strings.Cut(platform, "/")

	var idb [16]byte
	if _, err := rand.Read(idb[:]); err != nil {
		t.Fatal(err)
	}
	instance := hex.EncodeToString(idb[:])
	limits := docker.TransferLimits{
		MaxInputBytes: 8 << 20, MaxInputTarBytes: 128 << 20, MaxInputFiles: 16, MaxInputPathBytes: 256,
		MaxToolBytes: worker.MaxToolArchiveBytes, MaxProgramBytes: 16 << 20,
		LogMaxBytes: 8 << 20, MaxStdoutBytes: 8 << 20,
	}
	set := docker.NewWorkSet()
	for _, rid := range DefaultRuntimeIDs() {
		spec, _ := worker.LookupRuntime(rid)
		wc, err := docker.NewWork(sock, docker.WorkConfig{
			Image: spec.ImageRef(), Platform: platform,
			ExpectEnv:      map[string]string{spec.VersionEnv(): spec.Version},
			Entrypoint:     []string{worker.ProgramPath, "run", worker.JobFile},
			Env:            []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + worker.HomeDir},
			AllowedEnvKeys: []string{"PATH", "HOME"},
			InstanceID:     instance, Limits: limits,
			PullTimeout: 15 * time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := set.Add(rid, wc); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	t.Cleanup(func() {
		if _, err := set.CleanupStale(ctx); err != nil {
			t.Errorf("cleanup: %v", err)
		}
		out, err := exec.Command("docker", "ps", "-a", "-q", "--filter", "label=io.kestrelynx.work.instance="+instance).Output()
		if err == nil && strings.TrimSpace(string(out)) != "" {
			t.Errorf("work containers left behind: %s", out)
		}
	})

	tr := scanner.Trivy{BinPath: trivyBin, Severity: []string{"HIGH", "CRITICAL"}, CacheDir: cache, SkipDBUpdate: true}
	prepared, err := tr.CurrentConditions(ctx)
	if err != nil {
		t.Fatalf("trivy conditions: %v", err)
	}
	minAge := time.Hour
	if v := os.Getenv("KESTRELYNX_IT_MIN_RELEASE_AGE"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("KESTRELYNX_IT_MIN_RELEASE_AGE: %v", err)
		}
		minAge = d
	}
	e := &itEnv{
		ctx: ctx, set: set, instance: instance, trivy: tr, prepared: prepared, platform: platform,
		image:   ImageEnv{Platform: inventory.Platform{OS: "linux", Architecture: goarch}, OSFamily: "debian", OSName: "12.5"},
		program: itProgram(t, goarch),
	}
	e.useFetchedTools(t, minAge)
	if dir := os.Getenv("KESTRELYNX_IT_DUMP_JOBS"); dir != "" {
		e.dumpDir = dir
	}
	return e
}

// useFetchedTools makes the environment get the package managers the way the
// main process does, from the public registries through the fetching package
// (with the waiting period of a release shortened to minAge, which
// KESTRELYNX_IT_MIN_RELEASE_AGE sets), so that every release a project can
// name is one the run can have, pnpm 12 included.
func (e *itEnv) useFetchedTools(t *testing.T, minAge time.Duration) {
	t.Helper()
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("kestrelynx-it-storage-%d", os.Getuid()))
	p, err := toolfetch.New(toolfetch.Config{StorageDir: dir, MinReleaseAge: minAge})
	if err != nil {
		t.Fatal(err)
	}
	e.tools = fetchCycle{p: p, ToolProvider: NewToolProvider(p)}
}

// fetchCycle starts a fetch budget for every release asked for, so that a test
// that asks for many is not stopped by the budget of one cycle.
type fetchCycle struct {
	ToolProvider
	p *toolfetch.Provider
}

func (f fetchCycle) Provide(ctx context.Context, req ToolRequest) (ToolArtifact, error) {
	f.p.NewCycle()
	return f.ToolProvider.Provide(ctx, req)
}

// config completes a configuration of the update stage with the clients, the
// package manager provider and the work program of the environment.
func (e *itEnv) config(cfg LangUpdateConfig) LangUpdateConfig {
	cfg.Work, cfg.Scanner, cfg.Prepared = WorkRunner(e.set), e.trivy, e.prepared
	if e.dumpDir != "" {
		cfg.Work = &dumpingWork{inner: e.set, dir: e.dumpDir}
	}
	cfg.Tools = e.tools
	cfg.DefaultToolVersion = func(m DependencyManager, _ string) string { return itDefaultToolVersions[m] }
	cfg.Platform, cfg.Program = e.platform, e.program
	if cfg.PyPI == nil {
		cfg.PyPI = &PyPIClient{}
	}
	if cfg.Npm == nil {
		cfg.Npm = &NpmClient{}
	}
	return cfg
}

var (
	itProgramOnce sync.Map // goarch -> *itProgramBuild
)

type itProgramBuild struct {
	once sync.Once
	path string
	err  error
}

// itProgram builds the work program for the architecture from this source, once
// per test binary, and returns a loader of its bytes.
func itProgram(t *testing.T, goarch string) func() ([]byte, error) {
	t.Helper()
	v, _ := itProgramOnce.LoadOrStore(goarch, &itProgramBuild{})
	b := v.(*itProgramBuild)
	b.once.Do(func() {
		dir, err := os.MkdirTemp("", "kestrelynx-it-program-")
		if err != nil {
			b.err = err
			return
		}
		b.path = filepath.Join(dir, "kestrelynx-worker")
		cmd := exec.Command("go", "build", "-trimpath", "-o", b.path, "./cmd/kestrelynx-worker")
		cmd.Dir = filepath.Join("..", "..")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+goarch)
		if out, err := cmd.CombinedOutput(); err != nil {
			b.err = fmt.Errorf("build the work program: %v\n%s", err, out)
		}
	})
	if b.err != nil {
		t.Fatal(b.err)
	}
	return func() ([]byte, error) { return os.ReadFile(b.path) }
}

// dumpingWork keeps the files of every job it runs under dir/<job id>/, as the
// container is given them, and runs the job with the real client.
type dumpingWork struct {
	inner WorkRunner
	dir   string
}

func (d *dumpingWork) RunJob(ctx context.Context, spec docker.JobSpec) (docker.JobResult, error) {
	base := filepath.Join(d.dir, spec.JobID)
	for _, in := range spec.Inputs {
		p := filepath.Join(base, filepath.FromSlash(in.Path))
		mode := os.FileMode(0o644)
		if in.Executable {
			mode = 0o755
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return docker.JobResult{}, err
		}
		if err := os.WriteFile(p, in.Content, mode); err != nil {
			return docker.JobResult{}, err
		}
	}
	rt, ok := worker.LookupRuntime(spec.Runtime)
	if !ok {
		return docker.JobResult{}, fmt.Errorf("no runtime %q", spec.Runtime)
	}
	if err := os.WriteFile(filepath.Join(base, "image"), []byte(rt.ImageRef()), 0o644); err != nil {
		return docker.JobResult{}, err
	}
	return d.inner.RunJob(ctx, spec)
}
