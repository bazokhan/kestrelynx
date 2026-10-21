package remediation

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/kubework"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/toolfetch"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
	"github.com/kitsunetrail/kestrelynx/internal/workexec"
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
//	KESTRELYNX_IT_K8S_API   run the jobs in work Pods of a Kubernetes cluster
//	                        instead of Docker containers: the API server URL,
//	                        with KESTRELYNX_IT_K8S_TOKEN and KESTRELYNX_IT_K8S_CA
//	                        (files) and KESTRELYNX_IT_K8S_RECEIVER (the receiving
//	                        image, pinned by digest); the namespace and the
//	                        policy of deploy/kubernetes/work must be applied

// itEnv is what an integration test of the update stage runs with.
type itEnv struct {
	ctx context.Context
	set *docker.WorkSet
	// work runs the jobs: the Docker set, or work Pods.
	work     WorkRunner
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
	var work WorkRunner = set
	if api := os.Getenv("KESTRELYNX_IT_K8S_API"); api != "" {
		work = itKubernetesWork(t, api, instance, goarch)
	}
	for _, rid := range DefaultRuntimeIDs() {
		spec, _ := worker.LookupRuntime(rid)
		if work != WorkRunner(set) {
			break
		}
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
		ctx: ctx, set: set, work: work, instance: instance, trivy: tr, prepared: prepared, platform: platform,
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
	cfg.Work, cfg.Scanner, cfg.Prepared = e.work, e.trivy, e.prepared
	if e.dumpDir != "" {
		cfg.Work = &dumpingWork{inner: e.work, dir: e.dumpDir}
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

// itKubernetesWork builds the executor that runs the jobs in work Pods of the
// cluster named by the environment, after it has proved the admission policy
// of the work namespace is in force.
func itKubernetesWork(t *testing.T, api, instance, goarch string) WorkRunner {
	t.Helper()
	c, err := kubework.New(kubework.Options{
		APIServer: api, TokenFile: os.Getenv("KESTRELYNX_IT_K8S_TOKEN"), CAFile: os.Getenv("KESTRELYNX_IT_K8S_CA"),
		Namespace: "kestrelynx-work",
	})
	if err != nil {
		t.Fatal(err)
	}
	images := map[string]string{}
	for _, rid := range DefaultRuntimeIDs() {
		spec, _ := worker.LookupRuntime(rid)
		images[rid] = "docker.io/library/" + spec.ImageRef()
	}
	var sb [8]byte
	if _, err := rand.Read(sb[:]); err != nil {
		t.Fatal(err)
	}
	var cli kubework.API = c
	if node := os.Getenv("KESTRELYNX_IT_K8S_NODE"); node != "" {
		cli = &leakCheckAPI{API: c, t: t, node: node}
	}
	r, err := kubework.NewRunner(kubework.Config{
		API: cli, Namespace: "kestrelynx-work", ServiceAccount: "kestrelynx-work", PriorityClass: "kestrelynx-work", Arch: goarch,
		ReceiverImage: os.Getenv("KESTRELYNX_IT_K8S_RECEIVER"), Images: images,
		Entrypoint: []string{worker.ProgramPath, "run-kubernetes", worker.JobFile},
		Env:        []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + worker.HomeDir},
		InstanceID: instance, SessionID: hex.EncodeToString(sb[:]), MaxConcurrent: 4,
		Limits: workexec.TransferLimits{
			MaxInputBytes: 8 << 20, MaxInputTarBytes: 128 << 20, MaxInputFiles: 16, MaxInputPathBytes: 256,
			MaxToolBytes: worker.MaxToolArchiveBytes, MaxProgramBytes: 16 << 20,
		},
		MaxResultTarBytes: worker.DefaultResultLimits().MaxTarBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if p := r.VerifyAdmission(context.Background()); p != nil {
		t.Fatalf("the admission policy of the work namespace is not in force: %v", p)
	}
	t.Cleanup(func() {
		// A deleted Pod is listed until its grace period ends.
		selector := kubework.LabelWork + "=" + kubework.LabelWorkValue + "," + kubework.LabelInstance + "=" + instance
		var left int
		for i := 0; i < 60; i++ {
			pods, err := c.ListPods(context.Background(), selector)
			if err != nil {
				t.Errorf("list the work Pods: %v", err)
				return
			}
			if left = len(pods); left == 0 {
				return
			}
			time.Sleep(time.Second)
		}
		t.Errorf("work Pods left behind: %d", left)
		r.Collect(context.Background(), time.Now().Add(24*time.Hour))
	})
	return r
}

// leakCheckAPI looks for what a job handled in everything the cluster keeps
// about its Pod, just before the Pod is deleted: the container logs and the
// termination message files on the node (node is the name of the Docker
// container that is the node, kubectl being run in it), the Pod object and its
// events. Neither the plain result nor the input may be there. The input is
// searched for by its paths and by lines of its files, taken from the tar that
// is sent. The check fails when it cannot look: a missing directory, no log
// file, a search that errors, a kubectl that fails, or a control search for
// the sealed frame that finds nothing.
type leakCheckAPI struct {
	kubework.API
	t    *testing.T
	node string

	mu    sync.Mutex
	marks map[string][]string // by Pod name
}

// plainResultMarks are texts the plain result block and result.json hold and
// the sealed log does not.
var plainResultMarks = []string{"KESTRELYNX-WORKER-RESULT", "KESTRELYNX-WORKER-END", `"status":"completed"`, `"duration_ms"`, `"argv"`}

// inputMarks derives the strings to look for from the input tar: every path
// under src/ and replace/, and up to five distinctive lines of each file there.
func inputMarks(data []byte) []string {
	var marks []string
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		if h.Typeflag != tar.TypeReg || !(strings.HasPrefix(h.Name, "src/") || strings.HasPrefix(h.Name, "replace/")) {
			continue
		}
		marks = append(marks, h.Name)
		body, _ := io.ReadAll(io.LimitReader(tr, 4<<20))
		var lines []string
		for _, l := range strings.Split(string(body), "\n") {
			if l = strings.TrimSpace(l); len(l) >= 24 && len(l) <= 200 && !strings.ContainsAny(l, "'\x00") {
				lines = append(lines, l)
			}
		}
		for i := 0; i < 5 && len(lines) > 0; i++ {
			marks = append(marks, lines[i*len(lines)/5])
		}
	}
	return marks
}

func (l *leakCheckAPI) AttachInput(ctx context.Context, name string, data []byte) error {
	l.mu.Lock()
	if l.marks == nil {
		l.marks = map[string][]string{}
	}
	l.marks[name] = inputMarks(data)
	l.mu.Unlock()
	return l.API.AttachInput(ctx, name, data)
}

func (l *leakCheckAPI) DeletePod(ctx context.Context, name, uid string) error {
	l.t.Helper()
	l.mu.Lock()
	marks := append(append([]string(nil), plainResultMarks...), l.marks[name]...)
	l.mu.Unlock()
	// KESTRELYNX_IT_K8S_LEAK_CANARY adds a string known to be in the logs, to
	// show that the check fails when it finds something.
	if c := os.Getenv("KESTRELYNX_IT_K8S_LEAK_CANARY"); c != "" {
		marks = append(marks, c)
	}
	if len(marks) == len(plainResultMarks) {
		l.t.Errorf("leak check of %s: no input was sent, so there is nothing input-specific to look for", name)
	}
	if out, err := l.search(name, uid, marks); err != nil {
		l.t.Errorf("leak check of %s: %v\n%s", name, err, out)
	} else {
		l.t.Logf("no result or input (%d strings) in the logs, termination files, Pod object or events of %s", len(marks), name)
	}
	return l.API.DeletePod(ctx, name, uid)
}

// search runs the searches on the node and checks that each could be made.
func (l *leakCheckAPI) search(name, uid string, marks []string) (string, error) {
	pats := "/tmp/kw-pats-" + uid
	logs := "/var/log/pods/kestrelynx-work_" + name + "_" + uid
	term := "/var/lib/kubelet/pods/" + uid + "/containers"
	script := fmt.Sprintf(`set -u
trap 'rm -f %[1]s %[1]s.pod %[1]s.ev' EXIT
cat > %[1]s || { echo "ERR writing %[1]s"; exit 0; }
test "$(wc -l < %[1]s)" -eq %[5]d || { echo "ERR %[1]s holds $(wc -l < %[1]s) of %[5]d patterns"; exit 0; }
test -d %[2]s || { echo "ERR missing %[2]s"; exit 0; }
test -d %[3]s || { echo "ERR missing %[3]s"; exit 0; }
echo "LOGFILES $(find %[2]s -type f | wc -l)"
grep -rF -e KESTRELYNX-SEALED %[2]s >/dev/null 2>&1; echo "CONTROL $?"
grep -rF -f %[1]s %[2]s %[3]s >/dev/null 2>&1; echo "DISK $?"
kubectl -n kestrelynx-work get pod %[4]s -o json > %[1]s.pod || echo "ERR kubectl pod"
grep -F -f %[1]s %[1]s.pod >/dev/null 2>&1; echo "POD $?"
kubectl -n kestrelynx-work get events -o json > %[1]s.ev || echo "ERR kubectl events"
grep -F -f %[1]s %[1]s.ev >/dev/null 2>&1; echo "EVENTS $?"
`, pats, logs, term, name, len(marks))
	cmd := exec.Command("docker", "exec", "-i", l.node, "sh", "-c", script)
	cmd.Stdin = strings.NewReader(strings.Join(marks, "\n") + "\n")
	raw, err := cmd.CombinedOutput()
	out := string(raw)
	if err != nil {
		return out, fmt.Errorf("the search could not run: %w", err)
	}
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		k, v, _ := strings.Cut(line, " ")
		if k == "ERR" {
			return out, fmt.Errorf("the search could not be made: %s", line)
		}
		got[k] = v
	}
	if n, _ := strconv.Atoi(got["LOGFILES"]); n < 2 {
		return out, fmt.Errorf("fewer than two container log files were found")
	}
	if got["CONTROL"] != "0" {
		return out, fmt.Errorf("the control search for the sealed frame in the logs found nothing, so the logs were not searched")
	}
	for _, k := range []string{"DISK", "POD", "EVENTS"} {
		switch got[k] {
		case "1":
		case "0":
			return out, fmt.Errorf("the %s search found the result or the input", k)
		default:
			return out, fmt.Errorf("the %s search failed (status %q)", k, got[k])
		}
	}
	return out, nil
}
