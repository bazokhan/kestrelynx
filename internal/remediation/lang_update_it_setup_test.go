package remediation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// The integration tests of the update stage run against the official Node.js
// and Python images the build pins by digest, a real Docker daemon, the work
// program built from this source, package manager releases downloaded and
// checked here, the real registries and a real Trivy with its database
// cached. They run only when KESTRELYNX_WORKER_IT=1. Optional settings:
//
//	KESTRELYNX_DOCKER_SOCK  the Docker socket (default /var/run/docker.sock)
//	KESTRELYNX_TRIVY_BIN    the trivy executable (default ~/.local/bin/trivy)
//	KESTRELYNX_TRIVY_CACHE  its cache directory (default ~/.cache/trivy)
//	KESTRELYNX_IT_PLATFORM  the platform to run on (default linux/<GOARCH>)

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
	tools    *itTools
}

// itDefaultToolVersions are the releases the integration tests run.
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
	return &itEnv{
		ctx: ctx, set: set, instance: instance, trivy: tr, prepared: prepared, platform: platform,
		image:   ImageEnv{Platform: inventory.Platform{OS: "linux", Architecture: goarch}, OSFamily: "debian", OSName: "12.5"},
		program: itProgram(t, goarch),
		tools:   &itTools{dir: itToolCache(t), platform: platform},
	}
}

// config completes a configuration of the update stage with the clients, the
// package manager provider and the work program of the environment.
func (e *itEnv) config(cfg LangUpdateConfig) LangUpdateConfig {
	cfg.Work, cfg.Scanner, cfg.Prepared = e.set, e.trivy, e.prepared
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

func itToolCache(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("kestrelynx-it-tools-%d", os.Getuid()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// itTools downloads package manager releases from the public registries, checks
// them against the integrity the registry publishes, and keeps them in a
// directory. It stands in for the provider of the main process.
type itTools struct {
	dir      string
	platform string
	mu       sync.Mutex
}

func (f *itTools) Provide(ctx context.Context, req ToolRequest) (ToolArtifact, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch req.Manager {
	case ManagerNpm, ManagerPnpm:
		return f.npm(ctx, req)
	case ManagerUv:
		return f.uv(ctx, req)
	}
	return ToolArtifact{}, &ToolError{Category: CategoryFailed, Reason: ReasonUpdateInputInvalid, Detail: "no such manager " + string(req.Manager)}
}

func itGet(ctx context.Context, url string, limit int64) ([]byte, error) {
	rq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(rq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

func (f *itTools) finish(req ToolRequest, name, format, entry string, runWithNode bool, content []byte) (ToolArtifact, error) {
	h256, h512 := sha256.Sum256(content), sha512.Sum512(content)
	path := filepath.Join(f.dir, fmt.Sprintf("%s-%s-%s.%s", name, req.Version, strings.ReplaceAll(req.Platform, "/", "_"), strings.ReplaceAll(format, "-", ".")))
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return ToolArtifact{}, err
	}
	return ToolArtifact{
		Manager: req.Manager, Version: req.Version, Format: format, Path: path, Size: int64(len(content)),
		SHA256: hex.EncodeToString(h256[:]), SHA512: hex.EncodeToString(h512[:]), Entry: entry, RunWithNode: runWithNode,
	}, nil
}

func (f *itTools) npm(ctx context.Context, req ToolRequest) (ToolArtifact, error) {
	doc, err := itGet(ctx, "https://registry.npmjs.org/"+string(req.Manager)+"/"+req.Version, 2<<20)
	if err != nil {
		return ToolArtifact{}, err
	}
	var v struct {
		Dist struct {
			Tarball   string `json:"tarball"`
			Integrity string `json:"integrity"`
		} `json:"dist"`
	}
	if err := json.Unmarshal(doc, &v); err != nil {
		return ToolArtifact{}, err
	}
	content, err := itGet(ctx, v.Dist.Tarball, worker.MaxToolArchiveBytes+1)
	if err != nil {
		return ToolArtifact{}, err
	}
	want, ok := strings.CutPrefix(v.Dist.Integrity, "sha512-")
	h512 := sha512.Sum512(content)
	if !ok || base64.StdEncoding.EncodeToString(h512[:]) != want {
		return ToolArtifact{}, fmt.Errorf("%s %s does not match the registry's integrity", req.Manager, req.Version)
	}
	entry := "bin/npm-cli.js"
	if req.Manager == ManagerPnpm {
		entry = "bin/pnpm.cjs"
	}
	return f.finish(req, string(req.Manager), "npm-tgz", entry, true, content)
}

func (f *itTools) uv(ctx context.Context, req ToolRequest) (ToolArtifact, error) {
	doc, err := itGet(ctx, "https://pypi.org/pypi/uv/"+req.Version+"/json", 4<<20)
	if err != nil {
		return ToolArtifact{}, err
	}
	var v struct {
		URLs []struct {
			Filename string            `json:"filename"`
			URL      string            `json:"url"`
			Digests  map[string]string `json:"digests"`
		} `json:"urls"`
	}
	if err := json.Unmarshal(doc, &v); err != nil {
		return ToolArtifact{}, err
	}
	tag := "manylinux_2_17_x86_64"
	if req.Platform == "linux/arm64" {
		tag = "manylinux_2_28_aarch64"
	}
	for _, u := range v.URLs {
		if !strings.HasSuffix(u.Filename, ".whl") || !strings.Contains(u.Filename, tag) || strings.Contains(u.Filename, "musllinux") {
			continue
		}
		content, err := itGet(ctx, u.URL, worker.MaxToolArchiveBytes+1)
		if err != nil {
			return ToolArtifact{}, err
		}
		h := sha256.Sum256(content)
		if hex.EncodeToString(h[:]) != u.Digests["sha256"] {
			return ToolArtifact{}, fmt.Errorf("uv %s does not match the registry's sha256", req.Version)
		}
		return f.finish(req, "uv", "wheel", "uv-"+req.Version+".data/scripts/uv", false, content)
	}
	return ToolArtifact{}, fmt.Errorf("no wheel of uv %s for %s", req.Version, req.Platform)
}
