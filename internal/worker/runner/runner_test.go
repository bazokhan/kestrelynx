//go:build unix

package runner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

type env struct {
	t      *testing.T
	cfg    Config
	bin    string
	stdout bytes.Buffer
	files  map[string][]byte // decoded result of the last run
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{t: t, bin: filepath.Join(root, "bin")}
	e.cfg = Config{
		WorkDir: filepath.Join(root, "work"),
		TmpDir:  filepath.Join(root, "tmp"),
		HomeDir: filepath.Join(root, "home"),
		Path:    e.bin + ":/usr/bin:/bin",
		Stdout:  &e.stdout,
	}
	for _, d := range []string{e.bin, filepath.Join(e.cfg.WorkDir, "src"), e.cfg.TmpDir, e.cfg.HomeDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e *env) write(path, content string) {
	e.t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

// program installs a fake package manager script.
func (e *env) program(name, script string) {
	e.t.Helper()
	p := filepath.Join(e.bin, name)
	e.write(p, "#!/bin/sh\n"+script)
	if err := os.Chmod(p, 0o755); err != nil {
		e.t.Fatal(err)
	}
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// npmJob writes the two npm input files and returns a job for them.
func (e *env) npmJob() *worker.Job {
	e.t.Helper()
	files := map[string]string{"package.json": `{"name":"x"}`, "package-lock.json": `{"v":1}`}
	job := &worker.Job{
		Protocol: worker.ProtocolVersion, Manager: worker.ManagerNpm,
		Outputs:         []string{"package.json", "package-lock.json"},
		DeadlineSeconds: 30,
	}
	for _, name := range []string{"package.json", "package-lock.json"} {
		e.write(filepath.Join(e.cfg.WorkDir, "src", name), files[name])
		job.Inputs = append(job.Inputs, worker.Input{Path: name, Size: int64(len(files[name])), SHA256: sum(files[name])})
	}
	return job
}

func (e *env) run(job any) (*worker.Result, error) {
	e.t.Helper()
	var data []byte
	switch v := job.(type) {
	case []byte:
		data = v
	default:
		var err error
		if data, err = json.Marshal(job); err != nil {
			e.t.Fatal(err)
		}
	}
	jobPath := filepath.Join(e.cfg.WorkDir, "job.json")
	e.write(jobPath, string(data))
	e.stdout.Reset()
	runErr := Run(e.cfg, jobPath)
	files, err := worker.DecodeResult(e.stdout.Bytes(), worker.DefaultResultLimits())
	if err != nil {
		return nil, runErr
	}
	e.files = files
	raw := files["result.json"]
	var res worker.Result
	if err := json.Unmarshal(raw, &res); err != nil {
		e.t.Fatalf("result.json: %v", err)
	}
	return &res, runErr
}

func (e *env) read(rel ...string) string {
	e.t.Helper()
	b, ok := e.files[strings.Join(rel, "/")]
	if !ok {
		e.t.Fatalf("no %s in the result", strings.Join(rel, "/"))
	}
	return string(b)
}

func TestCompletedScratchAndMainSteps(t *testing.T) {
	e := newEnv(t)
	e.program("npm", `
case "$1" in
  install) echo '{"v":"relocked"}' > package-lock.json ;;
  update) echo '{"v":"updated"}' > package-lock.json ;;
esac
echo "ran $*"
`)
	job := e.npmJob()
	job.Steps = []worker.Step{
		{ID: "probe", Op: worker.OpNpmUpdate, Scratch: true, Packages: []worker.Package{{Name: "minimist"}}},
		{ID: "relock", Op: worker.OpNpmRelock},
	}
	res, err := e.run(job)
	if err != nil || res == nil {
		t.Fatalf("run: %v", err)
	}
	if res.Status != worker.StatusCompleted {
		t.Fatalf("status %s: %s", res.Status, res.Error)
	}
	if len(res.Steps) != 2 || res.Steps[0].ID != "probe" || res.Steps[1].ID != "relock" {
		t.Fatalf("steps: %+v", res.Steps)
	}
	if got := strings.Join(res.Steps[0].Argv, " "); got != "npm update minimist --package-lock-only --ignore-scripts --no-save --no-audit --no-fund" {
		t.Errorf("argv %q", got)
	}
	if !strings.Contains(res.Steps[0].Stdout, "ran update minimist") {
		t.Errorf("stdout %q", res.Steps[0].Stdout)
	}
	// the scratch step's copy shows its change; the main tree did not get it
	if got := e.read("steps", "probe", "package-lock.json"); !strings.Contains(got, "updated") {
		t.Errorf("probe copy %q", got)
	}
	if got := e.read("steps", "relock", "package-lock.json"); !strings.Contains(got, "relocked") {
		t.Errorf("relock copy %q", got)
	}
	if got := e.read("final", "package-lock.json"); !strings.Contains(got, "relocked") {
		t.Errorf("final %q", got)
	}
	if got := e.read("final", "package.json"); got != `{"name":"x"}` {
		t.Errorf("final package.json %q", got)
	}
	if len(res.Final) != 2 || res.Final[1].SHA256 != sum(e.read("final", "package-lock.json")) {
		t.Errorf("final list %+v", res.Final)
	}
	// the source directory is never modified
	if b, _ := os.ReadFile(filepath.Join(e.cfg.WorkDir, "src", "package-lock.json")); string(b) != `{"v":1}` {
		t.Errorf("src changed: %q", b)
	}
	if res.Steps[0].Outputs[0].Path != "package.json" || res.Steps[0].Outputs[0].Size != int64(len(`{"name":"x"}`)) {
		t.Errorf("step outputs %+v", res.Steps[0].Outputs)
	}
}

func TestScratchStepDoesNotChangeMainTree(t *testing.T) {
	e := newEnv(t)
	e.program("npm", `echo '{"v":"scratch"}' > package-lock.json`)
	job := e.npmJob()
	job.Steps = []worker.Step{{ID: "only", Op: worker.OpNpmRelock, Scratch: true}}
	res, _ := e.run(job)
	if res == nil || res.Status != worker.StatusCompleted {
		t.Fatalf("result %+v", res)
	}
	if got := e.read("final", "package-lock.json"); got != `{"v":1}` {
		t.Errorf("final reflects a scratch step: %q", got)
	}
	if got := e.read("steps", "only", "package-lock.json"); !strings.Contains(got, "scratch") {
		t.Errorf("step copy %q", got)
	}
}

func TestStopsAtFirstFailedStep(t *testing.T) {
	e := newEnv(t)
	e.program("npm", `echo boom >&2; exit 7`)
	job := e.npmJob()
	job.Steps = []worker.Step{
		{ID: "one", Op: worker.OpNpmRelock},
		{ID: "two", Op: worker.OpNpmRelock},
	}
	res, err := e.run(job)
	if err != nil || res == nil {
		t.Fatalf("run: %v", err)
	}
	if res.Status != worker.StatusStepFailed {
		t.Fatalf("status %s", res.Status)
	}
	if len(res.Steps) != 1 || res.Steps[0].ExitCode != 7 || !strings.Contains(res.Steps[0].Stderr, "boom") {
		t.Fatalf("steps %+v", res.Steps)
	}
	if len(res.Final) != 0 {
		t.Errorf("final listed after failure: %+v", res.Final)
	}
	for name := range e.files {
		if strings.HasPrefix(name, "final/") {
			t.Errorf("%s in the result after a failure", name)
		}
	}
}

func TestMissingProgramIsStepFailure(t *testing.T) {
	e := newEnv(t)
	job := e.npmJob()
	job.Steps = []worker.Step{{ID: "one", Op: worker.OpNpmRelock}}
	res, _ := e.run(job)
	if res == nil || res.Status != worker.StatusStepFailed || res.Steps[0].Error == "" {
		t.Fatalf("result %+v", res)
	}
}

func TestStepTimeoutKillsProcessGroup(t *testing.T) {
	e := newEnv(t)
	pidFile := filepath.Join(e.cfg.TmpDir, "child.pid")
	e.program("npm", `
sleep 60 &
echo $! > `+pidFile+`
wait
`)
	job := e.npmJob()
	job.StepTimeoutSeconds = 1
	job.Steps = []worker.Step{{ID: "slow", Op: worker.OpNpmRelock}}
	start := time.Now()
	res, err := e.run(job)
	if err != nil || res == nil {
		t.Fatalf("run: %v", err)
	}
	if time.Since(start) > 15*time.Second {
		t.Errorf("took %s", time.Since(start))
	}
	if res.Status != worker.StatusTimedOut || !res.Steps[0].TimedOut {
		t.Fatalf("result %+v", res)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid := strings.TrimSpace(string(b))
	// the grandchild is gone (reaped, or at least no longer a live process)
	deadline := time.Now().Add(3 * time.Second)
	for {
		stat, err := os.ReadFile("/proc/" + pid + "/stat")
		if err != nil || strings.Contains(string(stat), ") Z ") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("grandchild %s still running", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestOverallDeadline(t *testing.T) {
	e := newEnv(t)
	e.program("npm", `sleep 30`)
	job := e.npmJob()
	job.DeadlineSeconds = 1
	job.Steps = []worker.Step{{ID: "slow", Op: worker.OpNpmRelock}}
	res, _ := e.run(job)
	if res == nil || res.Status != worker.StatusTimedOut {
		t.Fatalf("result %+v", res)
	}
}

func TestChildEnvironmentIsFixed(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "secret-token")
	t.Setenv("NPM_TOKEN", "secret-npm")
	t.Setenv("HTTPS_PROXY", "http://evil")
	e := newEnv(t)
	e.program("npm", `env`)
	job := e.npmJob()
	job.Steps = []worker.Step{{ID: "env", Op: worker.OpNpmRelock}}
	res, _ := e.run(job)
	if res == nil || res.Status != worker.StatusCompleted {
		t.Fatalf("result %+v", res)
	}
	out := res.Steps[0].Stdout
	for _, bad := range []string{"secret-token", "secret-npm", "evil"} {
		if strings.Contains(out, bad) {
			t.Errorf("child environment leaks %q", bad)
		}
	}
	for _, want := range []string{
		"HOME=" + e.cfg.HomeDir, "npm_config_registry=https://registry.npmjs.org/",
		"npm_config_userconfig=" + e.cfg.TmpDir + "/kestrelynx-cache/npmrc-user",
		"npm_config_globalconfig=" + e.cfg.TmpDir + "/kestrelynx-cache/npmrc-global",
		"npm_config_update_notifier=false", "npm_config_fund=false", "npm_config_audit=false",
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("child environment lacks %q", want)
		}
	}
}

func TestEnvPerManager(t *testing.T) {
	c := Config{TmpDir: "/tmp", HomeDir: "/home/worker", Path: "/usr/bin"}
	has := func(env []string, kv string) bool {
		for _, e := range env {
			if e == kv {
				return true
			}
		}
		return false
	}
	pnpm := c.childEnv(worker.ManagerPnpm)
	for _, kv := range []string{"pnpm_config_pm_on_fail=warn", "pnpm_config_store_dir=/tmp/kestrelynx-cache/pnpm-store",
		"pnpm_config_cache_dir=/tmp/kestrelynx-cache/pnpm-cache", "pnpm_config_registry=https://registry.npmjs.org/"} {
		if !has(pnpm, kv) {
			t.Errorf("pnpm env lacks %s", kv)
		}
	}
	uv := c.childEnv(worker.ManagerUv)
	for _, kv := range []string{"UV_NO_CONFIG=1", "UV_PYTHON_DOWNLOADS=never", "UV_CACHE_DIR=/tmp/kestrelynx-cache/uv"} {
		if !has(uv, kv) {
			t.Errorf("uv env lacks %s", kv)
		}
	}
	pip := c.childEnv(worker.ManagerPip)
	if !has(pip, "PIP_CONFIG_FILE=/dev/null") {
		t.Errorf("pip env lacks PIP_CONFIG_FILE")
	}
	for _, e := range uv {
		if strings.HasPrefix(e, "npm_config_") {
			t.Errorf("uv env has npm setting %s", e)
		}
	}
}

func TestStreamTailIsBoundedAndClean(t *testing.T) {
	e := newEnv(t)
	e.program("npm", `
i=0
while [ $i -lt 3000 ]; do echo "line $i padding padding padding"; i=$((i+1)); done
printf 'esc\033[31mred\033[0m nul\000 bell\007\n'
echo "last line"
`)
	job := e.npmJob()
	job.Steps = []worker.Step{{ID: "noisy", Op: worker.OpNpmRelock}}
	res, _ := e.run(job)
	if res == nil || res.Status != worker.StatusCompleted {
		t.Fatalf("result %+v", res)
	}
	s := res.Steps[0]
	if !s.OutputTruncated || len(s.Stdout) > worker.MaxStreamTail {
		t.Errorf("truncated=%v len=%d", s.OutputTruncated, len(s.Stdout))
	}
	if !strings.HasSuffix(s.Stdout, "last line\n") {
		t.Errorf("tail lost the end: %q", s.Stdout[len(s.Stdout)-40:])
	}
	for _, r := range s.Stdout {
		if r < 0x20 && r != '\n' && r != '\t' {
			t.Fatalf("control character %q kept", r)
		}
	}
	if strings.Contains(s.Stdout, "\x1b") {
		t.Error("escape kept")
	}
}

func TestInputRejections(t *testing.T) {
	cases := map[string]func(e *env, job *worker.Job) any{
		"undeclared file": func(e *env, job *worker.Job) any {
			e.write(filepath.Join(e.cfg.WorkDir, "src", ".npmrc"), "registry=http://evil")
			return job
		},
		"hash mismatch": func(e *env, job *worker.Job) any {
			e.write(filepath.Join(e.cfg.WorkDir, "src", "package.json"), `{"name":"y"}`)
			return job
		},
		"size mismatch": func(e *env, job *worker.Job) any {
			job.Inputs[0].Size++
			return job
		},
		"symlink": func(e *env, job *worker.Job) any {
			p := filepath.Join(e.cfg.WorkDir, "src", "package.json")
			os.Remove(p)
			if err := os.Symlink("/etc/hostname", p); err != nil {
				t.Fatal(err)
			}
			return job
		},
		"hard link": func(e *env, job *worker.Job) any {
			if err := os.Link(filepath.Join(e.cfg.WorkDir, "src", "package.json"), filepath.Join(e.cfg.TmpDir, "alias")); err != nil {
				t.Skip("hard links unavailable")
			}
			return job
		},
		"directory in src": func(e *env, job *worker.Job) any {
			if err := os.Mkdir(filepath.Join(e.cfg.WorkDir, "src", "node_modules"), 0o755); err != nil {
				t.Fatal(err)
			}
			return job
		},
		"fifo": func(e *env, job *worker.Job) any {
			p := filepath.Join(e.cfg.WorkDir, "src", "package.json")
			os.Remove(p)
			if err := mkfifo(p); err != nil {
				t.Skip("mkfifo unavailable")
			}
			return job
		},
		"missing declared file": func(e *env, job *worker.Job) any {
			os.Remove(filepath.Join(e.cfg.WorkDir, "src", "package-lock.json"))
			return job
		},
		"unknown op": func(e *env, job *worker.Job) any {
			return json.RawMessage(strings.Replace(mustJSON(job), `"npm.relock"`, `"npm.exec"`, 1))
		},
		"dash name": func(e *env, job *worker.Job) any {
			job.Steps = []worker.Step{{ID: "u", Op: worker.OpNpmUpdate, Packages: []worker.Package{{Name: "--userconfig=/x"}}}}
			return job
		},
		"unknown field": func(e *env, job *worker.Job) any {
			return json.RawMessage(strings.Replace(mustJSON(job), `"manager"`, `"command":["sh"],"manager"`, 1))
		},
		"wrong protocol": func(e *env, job *worker.Job) any {
			job.Protocol = 99
			return job
		},
		"trailing data": func(e *env, job *worker.Job) any {
			return json.RawMessage(mustJSON(job) + `{}`)
		},
		"not json": func(e *env, job *worker.Job) any { return json.RawMessage(`not json`) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			ran := filepath.Join(e.cfg.TmpDir, "ran")
			e.program("npm", `touch `+ran)
			job := e.npmJob()
			job.Steps = []worker.Step{{ID: "relock", Op: worker.OpNpmRelock}}
			arg := mutate(e, job)
			if raw, ok := arg.(json.RawMessage); ok {
				arg = []byte(raw)
			}
			res, err := e.run(arg)
			if res == nil {
				t.Fatalf("no result.json (err %v)", err)
			}
			if res.Status != worker.StatusInputRejected || res.Error == "" {
				t.Fatalf("status %s error %q", res.Status, res.Error)
			}
			if len(res.Steps) != 0 {
				t.Errorf("steps ran: %+v", res.Steps)
			}
			if _, err := os.Stat(ran); err == nil {
				t.Errorf("the program ran for a rejected job")
			}
			if err != nil {
				t.Errorf("rejection returned error %v", err)
			}
		})
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestJobFileProblems(t *testing.T) {
	e := newEnv(t)
	if err := Run(e.cfg, filepath.Join(e.cfg.WorkDir, "missing.json")); err == nil {
		t.Error("missing job.json returned success")
	}
	files, err := worker.DecodeResult(e.stdout.Bytes(), worker.DefaultResultLimits())
	if err != nil || !strings.Contains(string(files["result.json"]), "input_rejected") {
		t.Errorf("no rejection result printed: %v", err)
	}
	// oversized job
	e2 := newEnv(t)
	big := filepath.Join(e2.cfg.WorkDir, "job.json")
	e2.write(big, strings.Repeat(" ", worker.MaxJobBytes+1))
	if err := Run(e2.cfg, big); err == nil {
		t.Error("oversized job accepted")
	}
}

func TestOutputThatIsNotAPlainFileFails(t *testing.T) {
	e := newEnv(t)
	e.program("npm", `rm package-lock.json; ln -s /etc/hostname package-lock.json`)
	job := e.npmJob()
	job.Steps = []worker.Step{{ID: "link", Op: worker.OpNpmRelock}}
	res, _ := e.run(job)
	if res == nil || res.Status != worker.StatusStepFailed {
		t.Fatalf("result %+v", res)
	}
}

func TestTailBufferKeepsTheEnd(t *testing.T) {
	// only the last max bytes are kept
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tail := newTailBuffer(8)
			tail.Write([]byte("0123456789"))
			if tail.String() != "23456789" || !tail.truncated {
				t.Errorf("tail %q", tail.String())
			}
		}()
	}
	wg.Wait()
}

func TestUnexpectedEntriesFailTheStep(t *testing.T) {
	cases := map[string]string{
		"file":      `echo x > pnpm-workspace.yaml`,
		"directory": `mkdir node_modules`,
		"symlink":   `ln -s /etc/hostname link`,
		"hidden":    `echo x > .npmrc`,
	}
	for name, script := range cases {
		for _, scratch := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/scratch=%v", name, scratch), func(t *testing.T) {
				e := newEnv(t)
				e.program("npm", script)
				job := e.npmJob()
				job.Steps = []worker.Step{
					{ID: "one", Op: worker.OpNpmRelock, Scratch: scratch},
					{ID: "two", Op: worker.OpNpmRelock},
				}
				res, err := e.run(job)
				if err != nil || res == nil {
					t.Fatalf("run: %v", err)
				}
				if res.Status != worker.StatusStepFailed || len(res.Steps) != 1 {
					t.Fatalf("status %s, %d steps", res.Status, len(res.Steps))
				}
				s := res.Steps[0]
				if s.Reason != worker.ReasonUnexpectedFiles || s.UnexpectedCount != 1 || len(s.UnexpectedPaths) != 1 {
					t.Fatalf("step %+v", s)
				}
				for name := range e.files {
					if strings.HasPrefix(name, "final/") {
						t.Errorf("%s in the result after a failed step", name)
					}
				}
			})
		}
	}
}

func TestUnexpectedEntryListIsBounded(t *testing.T) {
	e := newEnv(t)
	long := strings.Repeat("n", 200)
	e.program("npm", `
i=0
while [ $i -lt 50 ]; do : > "extra$i"; i=$((i+1)); done
: > `+long)
	job := e.npmJob()
	job.Steps = []worker.Step{{ID: "one", Op: worker.OpNpmRelock}}
	res, _ := e.run(job)
	if res == nil || len(res.Steps) != 1 {
		t.Fatalf("result %+v", res)
	}
	s := res.Steps[0]
	if s.UnexpectedCount != 51 || len(s.UnexpectedPaths) != worker.MaxUnexpectedPaths {
		t.Errorf("count %d, listed %d", s.UnexpectedCount, len(s.UnexpectedPaths))
	}
	for _, p := range s.UnexpectedPaths {
		if len(p) > worker.MaxUnexpectedPathLen {
			t.Errorf("path of %d bytes listed", len(p))
		}
	}
}

func TestDeclaredFilesOnlyIsNotUnexpected(t *testing.T) {
	e := newEnv(t)
	e.program("npm", `echo '{"v":2}' > package-lock.json`)
	job := e.npmJob()
	job.Steps = []worker.Step{{ID: "one", Op: worker.OpNpmRelock}}
	res, _ := e.run(job)
	if res == nil || res.Status != worker.StatusCompleted || res.Steps[0].Reason != "" {
		t.Fatalf("result %+v", res)
	}
}

func TestReleaseAgeReason(t *testing.T) {
	// the marker is at the start of a stderr far longer than the tail kept,
	// and a second case splits it across writes
	e := newEnv(t)
	e.program("npm", `
echo "Error: ERR_PNPM_MINIMUM_RELEASE_AGE_VIOLATION" >&2
i=0
while [ $i -lt 2000 ]; do echo "pkg$i was published at a time within the cutoff" >&2; i=$((i+1)); done
exit 1
`)
	job := e.npmJob()
	job.Steps = []worker.Step{{ID: "one", Op: worker.OpNpmRelock}}
	res, _ := e.run(job)
	if res == nil || res.Status != worker.StatusStepFailed {
		t.Fatalf("result %+v", res)
	}
	s := res.Steps[0]
	if s.Reason != worker.ReasonReleaseAgeViolation || s.ExitCode != 1 {
		t.Errorf("step %+v", s)
	}
	if strings.Contains(s.Stderr, "ERR_PNPM_MINIMUM") {
		t.Error("test is meant to lose the marker from the kept tail")
	}

	b := newMarkedTailBuffer(16, releaseAgeMarker)
	half := len(releaseAgeMarker) / 2
	b.Write([]byte("xx" + releaseAgeMarker[:half]))
	if b.found {
		t.Fatal("found early")
	}
	b.Write([]byte(releaseAgeMarker[half:] + "yy"))
	if !b.found {
		t.Error("marker split across writes not found")
	}

	e2 := newEnv(t)
	e2.program("npm", `echo "plain failure" >&2; exit 1`)
	job2 := e2.npmJob()
	job2.Steps = []worker.Step{{ID: "one", Op: worker.OpNpmRelock}}
	res2, _ := e2.run(job2)
	if res2 == nil || res2.Steps[0].Reason != "" {
		t.Errorf("reason set without the marker: %+v", res2)
	}
}

func TestChildrenRunInTheTmpTreeNotInWork(t *testing.T) {
	e := newEnv(t)
	e.program("npm", `pwd`)
	job := e.npmJob()
	job.Steps = []worker.Step{{ID: "one", Op: worker.OpNpmRelock}, {ID: "two", Op: worker.OpNpmRelock, Scratch: true}}
	res, _ := e.run(job)
	if res == nil || res.Status != worker.StatusCompleted {
		t.Fatalf("result %+v", res)
	}
	for _, s := range res.Steps {
		dir := strings.TrimSpace(s.Stdout)
		if !strings.HasPrefix(dir, e.cfg.TmpDir+"/") || strings.HasPrefix(dir, e.cfg.WorkDir) {
			t.Errorf("step %s ran in %s", s.ID, dir)
		}
	}
}

func TestChildFileSizeLimit(t *testing.T) {
	// The limit is applied to the whole process and cannot be raised again, so
	// this runs in a child of the test binary.
	if os.Getenv("KX_FSIZE_CHILD") == "1" {
		e := newEnv(t)
		e.cfg.FileSizeLimit = 64 << 20
		e.program("npm", `ulimit -f; ulimit -Hf; echo core=$(ulimit -c); dd if=/dev/zero of=big bs=1M count=100 >/dev/null 2>&1; wc -c < big`)
		job := e.npmJob()
		job.Steps = []worker.Step{{ID: "one", Op: worker.OpNpmRelock, Scratch: true}}
		res, _ := e.run(job)
		if res == nil || len(res.Steps) == 0 {
			t.Fatalf("result %+v", res)
		}
		fmt.Printf("STDOUT:%q\n", res.Steps[0].Stdout)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestChildFileSizeLimit$")
	cmd.Env = append(os.Environ(), "KX_FSIZE_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// ulimit -f counts 512-byte blocks in dash, 1024-byte blocks in bash
	if !strings.Contains(string(out), "131072") && !strings.Contains(string(out), "65536") {
		t.Errorf("limit not visible in the child:\n%s", out)
	}
	if !strings.Contains(string(out), "core=0") {
		t.Errorf("core files not disabled:\n%s", out)
	}
	if !strings.Contains(string(out), "67108864") {
		t.Errorf("write past the limit was not stopped:\n%s", out)
	}
}

func TestOutputBudget(t *testing.T) {
	e := newEnv(t)
	job := e.npmJob()
	var budget int64 = 5
	tree := filepath.Join(e.cfg.WorkDir, "src")
	if _, err := collect(tree, "final", job.Outputs, &budget, map[string][]byte{}); err == nil {
		t.Error("outputs over the budget accepted")
	}
}

// snapshot lists every entry under dir with its size and modification time.
func snapshot(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil {
			info, _ := d.Info()
			out = append(out, fmt.Sprintf("%s %d %d", p, info.Size(), info.ModTime().UnixNano()))
		}
		return nil
	})
	return out
}

func TestNothingIsWrittenUnderWork(t *testing.T) {
	e := newEnv(t)
	e.program("npm", `echo '{"v":2}' > package-lock.json`)
	job := e.npmJob()
	job.Steps = []worker.Step{{ID: "one", Op: worker.OpNpmRelock}, {ID: "two", Op: worker.OpNpmRelock, Scratch: true}}
	jobPath := filepath.Join(e.cfg.WorkDir, "job.json")
	data, _ := json.Marshal(job)
	e.write(jobPath, string(data))
	before := snapshot(t, e.cfg.WorkDir)
	if err := Run(e.cfg, jobPath); err != nil {
		t.Fatal(err)
	}
	after := snapshot(t, e.cfg.WorkDir)
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Errorf("work directory changed:\nbefore %q\nafter  %q", before, after)
	}
}

func TestStdoutHoldsOnlyTheResultBlock(t *testing.T) {
	e := newEnv(t)
	// a child that prints to its own stdout and stderr, and tries the
	// descriptors it might have inherited
	e.program("npm", `echo "child says hello"; echo "child error" >&2; ls /proc/self/fd | tr '\n' ' '; echo`)
	job := e.npmJob()
	job.Steps = []worker.Step{{ID: "one", Op: worker.OpNpmRelock}}
	res, _ := e.run(job)
	if res == nil || res.Status != worker.StatusCompleted {
		t.Fatalf("result %+v", res)
	}
	out := e.stdout.String()
	if !strings.HasPrefix(out, worker.ResultBlockStart+" ") || !strings.HasSuffix(out, worker.ResultBlockEnd+"\n") || strings.Contains(out, "child says hello") {
		t.Errorf("standard output is not just the block: %.200q", out)
	}
	if !strings.Contains(res.Steps[0].Stdout, "child says hello") {
		t.Errorf("child output not captured: %q", res.Steps[0].Stdout)
	}
	// the child sees 0, 1, 2 and the descriptor ls itself opens for the listing
	fds := strings.Fields(strings.Split(res.Steps[0].Stdout, "\n")[1])
	for _, fd := range fds {
		if fd != "0" && fd != "1" && fd != "2" && fd != "3" {
			t.Errorf("child inherited descriptor %s (all: %v)", fd, fds)
		}
	}
}

func TestHardenMakesTheProcessNonDumpable(t *testing.T) {
	if err := Harden(); err != nil {
		t.Fatal(err)
	}
	// A non-dumpable process's /proc entries belong to root.
	info, err := os.Stat("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		t.Errorf("/proc/self/fd owned by uid %d after Harden", st.Uid)
	}
}

// A descriptor the job runner inherited without close-on-exec (as a CI
// runner or a supervisor may leave open) must not reach the package
// managers it starts.
func TestChildrenDoNotReceiveInheritedDescriptors(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	inherited, err := syscall.Dup(int(f.Fd())) // dup does not set close-on-exec
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(inherited)

	e := newEnv(t)
	e.program("npm", `ls /proc/self/fd | tr '\n' ' '; echo`)
	job := e.npmJob()
	job.Steps = []worker.Step{{ID: "one", Op: worker.OpNpmRelock}}
	res, _ := e.run(job)
	if res == nil || res.Status != worker.StatusCompleted {
		t.Fatalf("result %+v", res)
	}
	fds := strings.Fields(res.Steps[0].Stdout)
	listed := strings.Join(fds, " ")
	for _, std := range []string{"0", "1", "2"} {
		if !strings.Contains(" "+listed+" ", " "+std+" ") {
			t.Fatalf("the child's descriptors were not listed: %q", res.Steps[0].Stdout)
		}
	}
	for _, fd := range fds {
		if fd == fmt.Sprint(inherited) {
			t.Errorf("child received inherited descriptor %d (all: %s)", inherited, res.Steps[0].Stdout)
		}
	}
}
