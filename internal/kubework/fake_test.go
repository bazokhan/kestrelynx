package kubework

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
	"github.com/kitsunetrail/kestrelynx/internal/workexec"
)

const (
	testInstance = "0123456789abcdef0123456789abcdef"
	testSession  = "0011223344556677"
	testNodeImg  = "docker.io/library/node@sha256:" + "1111111111111111111111111111111111111111111111111111111111111111"
	testRecvImg  = "docker.io/library/kestrelynx@sha256:" + "2222222222222222222222222222222222222222222222222222222222222222"
)

// fakeAPI is a cluster stand-in: it keeps Pods, runs the Pod through its
// phases as the runner reads it and, when the input arrives, "runs" the work
// by sealing a result to the key in the input.
type fakeAPI struct {
	mu   sync.Mutex
	pods map[string]map[string]any
	uids int

	// Hooks to make the cluster misbehave.
	mutateCreated func(pod map[string]any)        // changes the answer to the creation
	mutateRead    func(n int, pod map[string]any) // changes the n-th read of the Pod
	createErr     func(dry bool, n int) error     // fails the n-th creation
	version       [2]int
	listExtra     []map[string]any                                 // Pods that exist besides the created ones
	neverStarts   bool                                             // the receive container never runs
	workExit      int                                              // exit code of the work container
	logFn         func(sealed []byte, b worker.SealBinding) []byte // changes the log read
	result        []byte                                           // the result tar to seal
	workImageID   string
	attachErr     error

	// What happened.
	creates    int
	reads      int
	attached   [][]byte
	deleted    []string
	deleteUID  []string
	lastLog    []byte
	probes     []map[string]any // dry-run creations after the first
	refuse     func(id string, kind expectKind) *APIError
	good       map[string]any
	sealed     []byte
	attachedAt string
}

func newFake() *fakeAPI {
	return &fakeAPI{pods: map[string]map[string]any{}, version: [2]int{1, 31}, result: []byte("result tar"), workImageID: testNodeImg}
}

func (f *fakeAPI) ServerVersion(context.Context) (int, int, error) {
	return f.version[0], f.version[1], nil
}

func (f *fakeAPI) CreatePod(_ context.Context, pod map[string]any, dry bool) (map[string]any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates++
	if f.createErr != nil {
		if err := f.createErr(dry, f.creates); err != nil {
			return nil, err
		}
	}
	if dry {
		return f.dryRun(pod)
	}
	c := deepCopy(pod)
	f.uids++
	meta := c["metadata"].(pm)
	meta["uid"] = testUID(f.uids)
	meta["resourceVersion"] = "1"
	meta["creationTimestamp"] = time.Now().UTC().Format(time.RFC3339)
	specOf(c)["preemptionPolicy"] = "Never"
	f.pods[meta["name"].(string)] = c
	f.attachedAt = ""
	out := deepCopy(c)
	if f.mutateCreated != nil {
		f.mutateCreated(out)
	}
	return out, nil
}

// dryRun accepts the first Pod, which is the right one, and answers the ones
// after it as the policy would.
func (f *fakeAPI) dryRun(pod map[string]any) (map[string]any, error) {
	if f.good == nil {
		f.good = deepCopy(pod)
		out := deepCopy(pod)
		specOf(out)["preemptionPolicy"] = "Never"
		return out, nil
	}
	f.probes = append(f.probes, deepCopy(pod))
	got, _ := json.Marshal(normalized(pod))
	for _, pr := range probes() {
		want := deepCopy(f.good)
		pr.mutate(want)
		w, _ := json.Marshal(normalized(want))
		if !bytes.Equal(got, w) {
			continue
		}
		if f.refuse != nil {
			if e := f.refuse(pr.id, pr.expect); e != nil {
				return nil, e
			}
			return pod, nil
		}
		return nil, refusalFor(pr)
	}
	return nil, &APIError{Code: 500, Message: "unknown probe"}
}

func refusalFor(pr probe) *APIError {
	switch pr.expect {
	case expectPodSec:
		return &APIError{Code: 403, Message: `pods "x" is forbidden: violates PodSecurity "restricted:latest": x`}
	case expectAnyRule:
		return &APIError{Code: 422, Message: refusalPrefix() + "KRW-labels"}
	}
	return &APIError{Code: 422, Message: refusalPrefix() + RuleMessage(pr.id)}
}

func (f *fakeAPI) GetPod(_ context.Context, name string) (map[string]any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.pods[name]
	if !ok {
		return nil, &APIError{Code: 404, Reason: "NotFound", Message: "not found"}
	}
	f.reads++
	out := deepCopy(p)
	f.status(out, name)
	if f.mutateRead != nil {
		f.mutateRead(f.reads, out)
	}
	return out, nil
}

// status fills the Pod's status from how far it has come.
func (f *fakeAPI) status(p map[string]any, name string) {
	meta := p["metadata"].(pm)
	attached := f.attachedAt == name
	spec := specOf(p)
	spec["nodeName"] = "node-1"
	st := pm{"phase": "Pending"}
	recv := pm{"name": ReceiveContainer, "state": pm{"waiting": pm{"reason": "PodInitializing"}}}
	work := pm{"name": WorkContainer, "imageID": f.workImageID, "state": pm{"waiting": pm{"reason": "PodInitializing"}}}
	switch {
	case f.neverStarts:
	case !attached:
		recv["state"] = pm{"running": pm{}}
		st["phase"] = "Pending"
	default:
		recv["state"] = pm{"terminated": pm{"exitCode": float64(0), "reason": "Completed"}}
		work["state"] = pm{"terminated": pm{"exitCode": float64(f.workExit), "reason": "Completed"}}
		st["phase"] = "Succeeded"
	}
	st["initContainerStatuses"] = []any{recv}
	st["containerStatuses"] = []any{work}
	p["status"] = st
	_ = meta
}

func (f *fakeAPI) ListPods(context.Context, string) ([]map[string]any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]any
	for _, p := range f.pods {
		out = append(out, deepCopy(p))
	}
	for _, p := range f.listExtra {
		out = append(out, deepCopy(p))
	}
	return out, nil
}

func (f *fakeAPI) DeletePod(_ context.Context, name, uid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, name)
	f.deleteUID = append(f.deleteUID, uid)
	delete(f.pods, name)
	return nil
}

func (f *fakeAPI) PodLog(_ context.Context, name, container string, _ int64) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if container == ReceiveContainer {
		return []byte("KESTRELYNX-STATUS receive ok\n"), nil
	}
	log := f.sealed
	if f.logFn != nil {
		log = f.logFn(f.sealed, worker.SealBinding{})
	}
	f.lastLog = log
	return log, nil
}

// AttachInput takes the input, finds the seal file in it and seals the
// result to it, as the work program would.
func (f *fakeAPI) AttachInput(_ context.Context, name string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.attachErr != nil {
		return f.attachErr
	}
	f.attached = append(f.attached, data)
	f.attachedAt = name
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return errors.New("the input has no seal file")
		}
		if err != nil {
			return err
		}
		if strings.HasSuffix(h.Name, worker.SealInputName) {
			b, _ := io.ReadAll(tr)
			pub, binding, err := worker.ParseSealFile(b)
			if err != nil {
				return err
			}
			f.sealed, err = worker.SealFrame(pub, binding, f.result, [2]string{"job", "completed"})
			return err
		}
	}
}

func testRunner(t *testing.T, f *fakeAPI) *Runner {
	t.Helper()
	r, err := NewRunner(Config{
		API: f, Namespace: "kestrelynx-work", ServiceAccount: "kestrelynx-work", PriorityClass: "kestrelynx-work", Arch: "amd64",
		ReceiverImage: testRecvImg, Images: map[string]string{"node24": testNodeImg},
		Entrypoint: []string{"/work/bin/kestrelynx-worker", "run-kubernetes", "/work/job.json"},
		Env:        []string{"PATH=/usr/bin", "HOME=/home/worker"},
		InstanceID: testInstance, SessionID: testSession, MaxConcurrent: 1,
		Limits:            workexec.TransferLimits{MaxInputBytes: 1 << 20, MaxInputTarBytes: 4 << 20, MaxInputFiles: 12, MaxInputPathBytes: 256, MaxToolBytes: 1 << 20, MaxProgramBytes: 1 << 20},
		MaxResultTarBytes: 1 << 20, Poll: time.Millisecond,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func verified(t *testing.T, r *Runner) {
	t.Helper()
	if p := r.VerifyAdmission(context.Background()); p != nil {
		t.Fatalf("admission: %v", p)
	}
}

func testSpec(id string) workexec.JobSpec {
	return workexec.JobSpec{
		JobID: id, Runtime: "node24", Timeout: 10 * time.Second, Resources: probeResources(),
		Inputs: []workexec.InputFile{
			{Path: "job.json", Content: []byte(`{}`)},
			{Path: "bin/kestrelynx-worker", Content: []byte("program"), Kind: workexec.KindProgram, Executable: true},
		},
	}
}

// testUID makes the UUID the server would give the n-th Pod.
func testUID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func deepCopyList(l []any) []any { return normalized(l).([]any) }

// testRunnerNoT is testRunner for a caller without a *testing.T.
func testRunnerNoT(f *fakeAPI) *Runner {
	r, err := NewRunner(Config{
		API: f, Namespace: "kestrelynx-work", ServiceAccount: "kestrelynx-work", PriorityClass: "kestrelynx-work", Arch: "amd64",
		ReceiverImage: testRecvImg, Images: map[string]string{"node24": testNodeImg},
		Entrypoint: []string{"/work/bin/kestrelynx-worker", "run-kubernetes", "/work/job.json"},
		Env:        []string{"PATH=/usr/bin", "HOME=/home/worker"},
		InstanceID: testInstance, SessionID: testSession, MaxConcurrent: 1,
		MaxResultTarBytes: 1 << 20,
	})
	if err != nil {
		panic(err)
	}
	return r
}
