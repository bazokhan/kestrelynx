package kubework

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
	"github.com/kitsunetrail/kestrelynx/internal/workexec"
)

func wantUnavailable(t *testing.T, err error, manual bool, reason string) {
	t.Helper()
	var u *workexec.Unavailable
	if !errors.As(err, &u) || u.Reason != reason || u.Manual != manual {
		t.Fatalf("error = %v, want unavailable %s (manual %v)", err, reason, manual)
	}
}

func TestRunJobReturnsTheSealedResult(t *testing.T) {
	f := newFake()
	r := testRunner(t, f)
	verified(t, r)
	res, err := r.RunJob(context.Background(), testSpec("job-1"))
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Stdout) != string(worker.ResultBlockOfTar([]byte("result tar"))) || res.ExitCode != 0 {
		t.Errorf("result = %d %q", res.ExitCode, res.Stdout)
	}
	if len(f.pods) != 0 || len(f.deleted) != 1 || f.deleteUID[0] == "" {
		t.Errorf("Pod left or deleted without a UID: %v %v %v", f.pods, f.deleted, f.deleteUID)
	}
	if len(f.attached) != 1 || strings.Contains(string(f.sealed), "result tar") {
		t.Error("input not sent once, or the log holds the plain result")
	}
}

func TestRunJobNeedsVerifiedAdmission(t *testing.T) {
	f := newFake()
	r := testRunner(t, f)
	_, err := r.RunJob(context.Background(), testSpec("job-1"))
	wantUnavailable(t, err, true, ReasonAdmissionUnverified)
	if f.creates != 0 {
		t.Error("a Pod was created before the policy was checked")
	}
}

func TestRunJobRefusesAnAlteredCreatedPod(t *testing.T) {
	mutations := map[string]func(p map[string]any){
		"annotation": func(p map[string]any) { p["metadata"].(pm)["annotations"] = pm{"injected": "x"} },
		"sidecar": func(p map[string]any) {
			s := specOf(p)
			s["containers"] = append(s["containers"].([]any), pm{"name": "side"})
		},
		"command": func(p map[string]any) { workOf(p)["command"] = []any{"sh"} },
		"image":   func(p map[string]any) { workOf(p)["image"] = "docker.io/library/x@sha256:" + strings.Repeat("3", 64) },
		"volume": func(p map[string]any) {
			specOf(p)["volumes"] = append(specOf(p)["volumes"].([]any), pm{"name": "extra"})
		},
		"hostnetwork": func(p map[string]any) { specOf(p)["hostNetwork"] = true },
		"nodename":    func(p map[string]any) { specOf(p)["nodeName"] = "node-9" },
		"env": func(p map[string]any) {
			workOf(p)["env"] = append(workOf(p)["env"].([]any), pm{"name": "A", "value": "b"})
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			f := newFake()
			f.mutateCreated = mutate
			r := testRunner(t, f)
			verified(t, r)
			_, err := r.RunJob(context.Background(), testSpec("job-1"))
			if err == nil || !strings.Contains(err.Error(), "not the one asked for") {
				t.Fatalf("error = %v", err)
			}
			if len(f.attached) != 0 {
				t.Error("input was sent to an altered Pod")
			}
			if len(f.deleted) != 1 {
				t.Errorf("deleted = %v", f.deleted)
			}
		})
	}
}

func TestRunJobStopsWhenThePodChangesLater(t *testing.T) {
	cases := map[string]func(n int, p map[string]any){
		"uid":  func(n int, p map[string]any) { p["metadata"].(pm)["uid"] = testUID(901) },
		"node": func(n int, p map[string]any) { specOf(p)["nodeName"] = []string{"node-1", "node-2"}[n%2] },
		"form": func(n int, p map[string]any) {
			workOf(p)["image"] = "docker.io/library/x@sha256:" + strings.Repeat("4", 64)
		},
		"annotations": func(n int, p map[string]any) { p["metadata"].(pm)["annotations"] = pm{"a": "b"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake()
			f.mutateRead = func(n int, p map[string]any) {
				if n >= 2 {
					mutate(n, p)
				}
			}
			r := testRunner(t, f)
			verified(t, r)
			res, err := r.RunJob(context.Background(), testSpec("job-1"))
			if err == nil || res.Stdout != nil {
				t.Fatalf("result %q error %v", res.Stdout, err)
			}
			if len(f.pods) != 0 {
				t.Error("Pod not deleted")
			}
		})
	}
}

func TestRunJobUIDChangeAfterTheLogIsRead(t *testing.T) {
	f := newFake()
	f.mutateRead = func(n int, p map[string]any) {
		// The last read, which follows the log read, answers with another Pod.
		if f.sealed != nil && f.lastLog != nil {
			p["metadata"].(pm)["uid"] = testUID(901)
		}
	}
	r := testRunner(t, f)
	verified(t, r)
	res, err := r.RunJob(context.Background(), testSpec("job-1"))
	if err == nil || res.Stdout != nil || !strings.Contains(err.Error(), "UID changed") {
		t.Fatalf("result %q error %v", res.Stdout, err)
	}
}

func TestRunJobRefusesWhatIsNotSealedToThisAttempt(t *testing.T) {
	other, _ := worker.NewSealKey()
	binding := func(job string, attempt uint32, uid string) worker.SealBinding {
		return worker.SealBinding{Instance: testInstance, Session: testSession, Job: JobLabel(job), Attempt: attempt, PodUID: uid}
	}
	seal := func(b worker.SealBinding, key *worker.SealKey) []byte {
		file, _ := worker.SealFileBytes(key.PublicKey(), b)
		pub, _, _ := worker.ParseSealFile(file)
		out, err := worker.SealFrame(pub, b, []byte("forged"))
		if err != nil {
			panic(err)
		}
		return out
	}
	plain := string(worker.ResultBlockOfTar([]byte("plain result")))
	cases := map[string]func(real []byte) []byte{
		"another key":        func([]byte) []byte { return seal(binding("job-1", 1, testUID(1)), other) },
		"another Pod":        func([]byte) []byte { return seal(binding("job-1", 1, testUID(2)), other) },
		"replayed attempt":   func(real []byte) []byte { return real }, // reused below by a second run
		"plaintext fallback": func([]byte) []byte { return []byte(plain) },
		"nothing":            func([]byte) []byte { return nil },
	}
	for name, fn := range cases {
		if name == "replayed attempt" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			f := newFake()
			f.logFn = func(real []byte, _ worker.SealBinding) []byte { return fn(real) }
			r := testRunner(t, f)
			verified(t, r)
			res, err := r.RunJob(context.Background(), testSpec("job-1"))
			if !errors.Is(err, workexec.ErrResultInvalid) || res.Stdout != nil {
				t.Fatalf("result %q error %v", res.Stdout, err)
			}
		})
	}
	t.Run("replayed from an earlier attempt", func(t *testing.T) {
		f := newFake()
		r := testRunner(t, f)
		verified(t, r)
		if _, err := r.RunJob(context.Background(), testSpec("job-1")); err != nil {
			t.Fatal(err)
		}
		first := f.sealed
		f.logFn = func([]byte, worker.SealBinding) []byte { return first }
		res, err := r.RunJob(context.Background(), testSpec("job-1"))
		if !errors.Is(err, workexec.ErrResultInvalid) || res.Stdout != nil {
			t.Fatalf("result %q error %v", res.Stdout, err)
		}
	})
}

func TestRunJobLogOverTheLimit(t *testing.T) {
	f := newFake()
	r := testRunner(t, f)
	verified(t, r)
	f.logFn = func(real []byte, _ worker.SealBinding) []byte {
		return append(real, make([]byte, worker.SealedLogLimit(r.cfg.MaxResultTarBytes))...)
	}
	_, err := r.RunJob(context.Background(), testSpec("job-1"))
	if !errors.Is(err, workexec.ErrResultInvalid) || !strings.Contains(err.Error(), "containerLogMaxSize") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunJobLogThatLostItsBeginning(t *testing.T) {
	f := newFake()
	r := testRunner(t, f)
	verified(t, r)
	f.logFn = func(real []byte, _ worker.SealBinding) []byte {
		// The node rotated the log: the start of the frame is gone.
		i := bytes.Index(real, []byte(worker.SealedStart))
		j := i + bytes.IndexByte(real[i:], '\n')
		return append(append([]byte{}, real[:i]...), real[j+1:]...)
	}
	_, err := r.RunJob(context.Background(), testSpec("job-1"))
	if !errors.Is(err, workexec.ErrResultInvalid) || !strings.Contains(err.Error(), "cut or rotated") ||
		!strings.Contains(err.Error(), fmt.Sprint(worker.SealedLogNodeBytes(r.cfg.MaxResultTarBytes))) {
		t.Fatalf("error = %v", err)
	}
}

func TestRunJobExitCodeWithoutResult(t *testing.T) {
	f := newFake()
	f.workExit = 3
	f.logFn = func([]byte, worker.SealBinding) []byte { return []byte("KESTRELYNX-STATUS environment rejected\n") }
	r := testRunner(t, f)
	verified(t, r)
	res, err := r.RunJob(context.Background(), testSpec("job-1"))
	if err != nil || res.ExitCode != 3 || res.Stdout != nil {
		t.Fatalf("result %+v error %v", res, err)
	}
}

func TestRunJobWrongImage(t *testing.T) {
	f := newFake()
	f.workImageID = "docker.io/library/node@sha256:" + strings.Repeat("9", 64)
	r := testRunner(t, f)
	verified(t, r)
	res, err := r.RunJob(context.Background(), testSpec("job-1"))
	if err == nil || res.Stdout != nil || !strings.Contains(err.Error(), "not the pinned image") {
		t.Fatalf("result %q error %v", res.Stdout, err)
	}
}

func TestRunJobPodNeverStarts(t *testing.T) {
	f := newFake()
	f.neverStarts = true
	r := testRunner(t, f)
	verified(t, r)
	spec := testSpec("job-1")
	spec.Timeout = 50 * time.Millisecond
	_, err := r.RunJob(context.Background(), spec)
	wantUnavailable(t, err, false, ReasonPodNotStarted)
	if len(f.pods) != 0 {
		t.Error("Pod not deleted")
	}
}

func TestRunJobQuotaAndConcurrency(t *testing.T) {
	t.Run("quota", func(t *testing.T) {
		f := newFake()
		r := testRunner(t, f)
		verified(t, r)
		f.createErr = func(dry bool, n int) error {
			return &APIError{Code: 403, Message: `pods "x" is forbidden: exceeded quota: work, requested: count/pods=1`}
		}
		_, err := r.RunJob(context.Background(), testSpec("job-1"))
		wantUnavailable(t, err, false, ReasonPodLimit)
	})
	t.Run("max concurrent", func(t *testing.T) {
		f := newFake()
		r := testRunner(t, f)
		verified(t, r)
		f.pods["kestrelynx-work-other"] = pm{"metadata": pm{"name": "kestrelynx-work-other"}}
		_, err := r.RunJob(context.Background(), testSpec("job-1"))
		wantUnavailable(t, err, false, ReasonPodLimit)
		if f.creates != 0 && len(f.attached) != 0 {
			t.Error("a Pod was made over the limit")
		}
	})
	t.Run("lost answer removes our Pod and defers", func(t *testing.T) {
		f := newFake()
		r := testRunner(t, f)
		verified(t, r)
		params := r.params(testSpec("job-1"), testNodeImg)
		f.createErr = func(dry bool, n int) error {
			// The Pod is created, the answer is lost.
			pod := BuildPod(params)
			pod["metadata"].(pm)["uid"] = testUID(900)
			f.pods[params.Name()] = pod
			return errors.New("connection reset")
		}
		_, err := r.RunJob(context.Background(), testSpec("job-1"))
		wantUnavailable(t, err, false, ReasonPodLimit)
		if len(f.deleted) != 1 || f.deleteUID[0] != testUID(900) {
			t.Errorf("deleted %v %v", f.deleted, f.deleteUID)
		}
	})
	t.Run("name taken by a Pod that is not ours stays", func(t *testing.T) {
		f := newFake()
		r := testRunner(t, f)
		verified(t, r)
		params := r.params(testSpec("job-1"), testNodeImg)
		f.createErr = func(bool, int) error { return &APIError{Code: 409, Reason: "AlreadyExists", Message: "exists"} }
		foreign := BuildPod(params)
		foreign["metadata"].(pm)["uid"] = testUID(902)
		labelsOf(foreign)[LabelSession] = "ffffffffffffffff"
		f.pods[params.Name()] = foreign
		_, err := r.RunJob(context.Background(), testSpec("job-1"))
		wantUnavailable(t, err, false, ReasonPodLimit)
		if len(f.deleted) != 0 {
			t.Errorf("a Pod of another session was deleted: %v", f.deleted)
		}
	})
}

func TestRunJobDeletesWhenAttachFails(t *testing.T) {
	f := newFake()
	f.attachErr = errors.New("websocket closed")
	r := testRunner(t, f)
	verified(t, r)
	_, err := r.RunJob(context.Background(), testSpec("job-1"))
	if err == nil || len(f.pods) != 0 {
		t.Fatalf("error %v, pods %v", err, f.pods)
	}
}

func TestRunJobInputLimit(t *testing.T) {
	f := newFake()
	r := testRunner(t, f)
	verified(t, r)
	spec := testSpec("job-1")
	spec.Inputs = append(spec.Inputs, workexec.InputFile{Path: "src/big", Content: make([]byte, 2<<20)})
	_, err := r.RunJob(context.Background(), spec)
	if err == nil || len(f.attached) != 0 || len(f.pods) != 0 {
		t.Fatalf("error %v attached %d", err, len(f.attached))
	}
}

func TestRunJobAttemptsAreCounted(t *testing.T) {
	f := newFake()
	r := testRunner(t, f)
	verified(t, r)
	for i := 0; i < 2; i++ {
		if _, err := r.RunJob(context.Background(), testSpec("job-1")); err != nil {
			t.Fatal(err)
		}
	}
	if r.attempts["job-1"] != 2 {
		t.Errorf("attempts = %d", r.attempts["job-1"])
	}
}

func TestVerifyAdmission(t *testing.T) {
	t.Run("in force", func(t *testing.T) {
		f := newFake()
		r := testRunner(t, f)
		if p := r.VerifyAdmission(context.Background()); p != nil {
			t.Fatal(p)
		}
		if len(f.probes) != len(probes()) {
			t.Errorf("%d probes made, want %d", len(f.probes), len(probes()))
		}
	})
	t.Run("a rule that does not refuse", func(t *testing.T) {
		for _, pr := range probes() {
			f := newFake()
			f.refuse = func(id string, _ expectKind) *APIError {
				if id == pr.id {
					return nil
				}
				return refusalFor(pr)
			}
			// The fake answers every other probe with this probe's refusal, so
			// only the accepted one can be the cause.
			r := testRunner(t, f)
			p := r.VerifyAdmission(context.Background())
			if p == nil {
				t.Fatalf("%s: accepted probe not noticed", pr.id)
			}
			if !p.Manual && p.Reason != ReasonAdmissionUnverified {
				t.Errorf("%s: %+v", pr.id, p)
			}
		}
	})
	t.Run("a refusal by another rule", func(t *testing.T) {
		f := newFake()
		f.refuse = func(id string, kind expectKind) *APIError {
			return &APIError{Code: 422, Message: refusalPrefix() + "KRW-something-else"}
		}
		p := testRunner(t, f).VerifyAdmission(context.Background())
		if p == nil || p.Reason != ReasonAdmissionUnverified {
			t.Fatalf("%+v", p)
		}
	})
	t.Run("refused by Pod Security instead of the policy", func(t *testing.T) {
		f := newFake()
		f.refuse = func(id string, kind expectKind) *APIError {
			return &APIError{Code: 403, Message: `violates PodSecurity "restricted:latest"`}
		}
		if p := testRunner(t, f).VerifyAdmission(context.Background()); p == nil {
			t.Fatal("a policy that is not in force was accepted")
		}
	})
	t.Run("old cluster", func(t *testing.T) {
		f := newFake()
		f.version = [2]int{1, 29}
		p := testRunner(t, f).VerifyAdmission(context.Background())
		if p == nil || p.Reason != ReasonClusterTooOld || !p.Manual {
			t.Fatalf("%+v", p)
		}
	})
	t.Run("quota used up defers", func(t *testing.T) {
		f := newFake()
		f.createErr = func(dry bool, n int) error {
			return &APIError{Code: 403, Message: "exceeded quota: work"}
		}
		p := testRunner(t, f).VerifyAdmission(context.Background())
		if p == nil || p.Reason != ReasonPodLimit || p.Manual {
			t.Fatalf("%+v", p)
		}
	})
	t.Run("missing PriorityClass is manual", func(t *testing.T) {
		f := newFake()
		f.createErr = func(dry bool, n int) error {
			return &APIError{Code: 403, Message: `no PriorityClass with name kestrelynx-work was found`}
		}
		p := testRunner(t, f).VerifyAdmission(context.Background())
		if p == nil || p.Reason != ReasonPriorityClass || !p.Manual {
			t.Fatalf("%+v", p)
		}
	})
	t.Run("a server that changes the Pod", func(t *testing.T) {
		f := newFake()
		f.createErr = nil
		r := testRunner(t, f)
		// An admission step adds an annotation to the dry-run answer.
		wrapped := &mutatingDry{fakeAPI: f}
		r.cfg.API = wrapped
		p := r.VerifyAdmission(context.Background())
		if p == nil || p.Reason != ReasonAdmissionUnverified {
			t.Fatalf("%+v", p)
		}
	})
	t.Run("a failed check blocks jobs", func(t *testing.T) {
		f := newFake()
		f.version = [2]int{1, 20}
		r := testRunner(t, f)
		r.VerifyAdmission(context.Background())
		_, err := r.RunJob(context.Background(), testSpec("job-1"))
		wantUnavailable(t, err, true, ReasonClusterTooOld)
	})
}

type mutatingDry struct{ *fakeAPI }

func (m *mutatingDry) CreatePod(ctx context.Context, pod map[string]any, dry bool) (map[string]any, error) {
	out, err := m.fakeAPI.CreatePod(ctx, pod, dry)
	if err == nil && dry && m.fakeAPI.creates == 1 {
		out["metadata"].(pm)["annotations"] = pm{"sidecar.injected/x": "y"}
	}
	return out, err
}

func TestPolicyRulesMatchTheProbes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "kubernetes", "work", "50-validatingadmissionpolicy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	inPolicy := map[string]bool{}
	for _, m := range regexp.MustCompile(`KRW-([a-z]+)`).FindAllStringSubmatch(string(data), -1) {
		inPolicy[m[1]] = true
	}
	// The rules that need a running Pod or a RuntimeClass cannot be probed with
	// a creation.
	unprobed := map[string]bool{"update": true, "ephemeral": true, "runtime": true}
	// Probes of the policy's catch-all behaviour are not rules of their own.
	wantProbed := ProbeIDs()
	probed := map[string]bool{}
	for _, id := range wantProbed {
		probed[id] = true
		if !inPolicy[id] {
			t.Errorf("the probe %q has no rule in the policy", id)
		}
	}
	var missing []string
	for id := range inPolicy {
		if !probed[id] && !unprobed[id] {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("rules without a probe: %v", missing)
	}
}
