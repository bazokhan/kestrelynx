package kubework

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
	"github.com/kitsunetrail/kestrelynx/internal/workexec"
)

// API is the part of the client the runner uses.
type API interface {
	CreatePod(ctx context.Context, pod map[string]any, dryRun bool) (map[string]any, error)
	GetPod(ctx context.Context, name string) (map[string]any, error)
	ListPods(ctx context.Context, selector string) ([]map[string]any, error)
	DeletePod(ctx context.Context, name, uid string) error
	PodLog(ctx context.Context, name, container string, limitBytes int64) ([]byte, error)
	AttachInput(ctx context.Context, name string, data []byte) error
	ServerVersion(ctx context.Context) (major, minor int, err error)
}

var _ API = (*Client)(nil)

// Reasons of an executor that cannot run a job (see workexec.Unavailable).
const (
	ReasonPodLimit            = "work_pod_limit"
	ReasonAdmissionUnverified = "work_admission_unverified"
	ReasonPriorityClass       = "work_priority_class_missing"
	ReasonPodNotStarted       = "work_pod_not_started"
	ReasonClusterTooOld       = "work_cluster_too_old"
)

// Config is what a Runner needs.
type Config struct {
	API            API
	Namespace      string
	ServiceAccount string
	PriorityClass  string
	// Arch is the architecture of the nodes the Pods run on and the main
	// process's own ("amd64").
	Arch          string
	ReceiverImage string
	// Images maps a runtime key to its work image, "repository@sha256:...".
	Images     map[string]string
	Entrypoint []string
	Env        []string
	InstanceID string
	SessionID  string
	// MaxConcurrent is how many work Pods of this installation may exist at
	// once, not counting Pods already being deleted; the namespace's
	// ResourceQuota bounds the total including those.
	MaxConcurrent int
	// Limits bound the input; MaxResultTarBytes bounds the result tar.
	Limits            workexec.TransferLimits
	MaxResultTarBytes int64
	// PodMaxAge is how old a Pod of this start may be before the collector
	// removes it; zero means a little over the longest a job may run.
	PodMaxAge time.Duration
	// Poll is how often a Pod is read while waiting; zero means 500 ms.
	Poll time.Duration
	Log  *slog.Logger
}

// Runner runs jobs in work Pods. It implements the update stage's WorkRunner.
type Runner struct {
	cfg Config

	mu       sync.Mutex
	attempts map[string]uint32
	// admission is the result of the last check of the namespace's admission
	// policy; zero until VerifyAdmission has run.
	admission admissionState
}

type admissionState struct {
	checked bool
	problem *workexec.Unavailable
	at      time.Time
}

// NewRunner validates cfg and returns a Runner.
func NewRunner(cfg Config) (*Runner, error) {
	switch {
	case cfg.API == nil:
		return nil, errors.New("kubework: no API client")
	case cfg.MaxConcurrent <= 0:
		return nil, errors.New("kubework: the limit of concurrent Pods must be positive")
	case cfg.MaxResultTarBytes <= 0:
		return nil, errors.New("kubework: the result limit must be positive")
	case len(cfg.Images) == 0:
		return nil, errors.New("kubework: no work image")
	}
	base := Params{
		Namespace: cfg.Namespace, Instance: cfg.InstanceID, Session: cfg.SessionID, JobID: "probe",
		ServiceAccount: cfg.ServiceAccount, PriorityClass: cfg.PriorityClass, Arch: cfg.Arch,
		ReceiverImage: cfg.ReceiverImage, Entrypoint: cfg.Entrypoint, Env: cfg.Env,
		Resources:             workexec.Resources{MemoryBytes: 1, NanoCPUs: 1, TmpSizeBytes: 1, HomeSizeBytes: 1, ToolsSizeBytes: 1, ShmSizeBytes: 1},
		ActiveDeadlineSeconds: 60,
	}
	for key, img := range cfg.Images {
		p := base
		p.WorkImage = img
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("kubework: runtime %s: %w", key, err)
		}
	}
	if cfg.Poll <= 0 {
		cfg.Poll = 500 * time.Millisecond
	}
	return &Runner{cfg: cfg, attempts: map[string]uint32{}}, nil
}

func (r *Runner) log() *slog.Logger {
	if r.cfg.Log != nil {
		return r.cfg.Log
	}
	return slog.Default()
}

func (r *Runner) params(spec workexec.JobSpec, image string) Params {
	return Params{
		Namespace: r.cfg.Namespace, Instance: r.cfg.InstanceID, Session: r.cfg.SessionID, JobID: spec.JobID,
		ServiceAccount: r.cfg.ServiceAccount, PriorityClass: r.cfg.PriorityClass, Arch: r.cfg.Arch,
		ReceiverImage: r.cfg.ReceiverImage, WorkImage: image, Entrypoint: r.cfg.Entrypoint, Env: r.cfg.Env,
		Resources: spec.Resources, ActiveDeadlineSeconds: int64(spec.Timeout/time.Second) + 60,
	}
}

func (r *Runner) selector() string {
	return LabelWork + "=" + LabelWorkValue + "," + LabelInstance + "=" + r.cfg.InstanceID
}

func (r *Runner) nextAttempt(jobID string) uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempts[jobID]++
	return r.attempts[jobID]
}

// podView is the part of a Pod's status the runner reads.
type podView struct {
	Metadata struct {
		Name              string            `json:"name"`
		UID               string            `json:"uid"`
		Labels            map[string]string `json:"labels"`
		CreationTimestamp string            `json:"creationTimestamp"`
		DeletionTimestamp string            `json:"deletionTimestamp"`
	} `json:"metadata"`
	Spec struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
	Status struct {
		Phase                 string    `json:"phase"`
		Reason                string    `json:"reason"`
		StartTime             string    `json:"startTime"`
		InitContainerStatuses []cStatus `json:"initContainerStatuses"`
		ContainerStatuses     []cStatus `json:"containerStatuses"`
	} `json:"status"`
}

type cStatus struct {
	Name    string `json:"name"`
	ImageID string `json:"imageID"`
	State   struct {
		Waiting *struct {
			Reason string `json:"reason"`
		} `json:"waiting"`
		Running    *struct{} `json:"running"`
		Terminated *struct {
			ExitCode int    `json:"exitCode"`
			Reason   string `json:"reason"`
		} `json:"terminated"`
	} `json:"state"`
}

func viewOf(obj map[string]any) (podView, error) {
	var v podView
	b, err := json.Marshal(obj)
	if err != nil {
		return v, err
	}
	return v, json.Unmarshal(b, &v)
}

func (v podView) container(list []cStatus, name string) *cStatus {
	for i := range list {
		if list[i].Name == name {
			return &list[i]
		}
	}
	return nil
}

func unavailable(manual bool, reason, format string, args ...any) *workexec.Unavailable {
	return &workexec.Unavailable{Manual: manual, Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// RunJob runs one job in a work Pod and returns its result as the plain result
// block the update stage decodes. The Pod is deleted whatever happens.
func (r *Runner) RunJob(ctx context.Context, spec workexec.JobSpec) (res workexec.JobResult, err error) {
	image, ok := r.cfg.Images[spec.Runtime]
	if !ok {
		return workexec.JobResult{}, fmt.Errorf("no work image for runtime %q", spec.Runtime)
	}
	if spec.JobID == "" || spec.Timeout <= 0 {
		return workexec.JobResult{}, errors.New("a job needs an ID and a timeout")
	}
	if p := r.admissionProblem(); p != nil {
		return workexec.JobResult{}, p
	}
	params := r.params(spec, image)
	if err := params.Validate(); err != nil {
		return workexec.JobResult{}, err
	}
	// The job's whole time, from creation to deletion.
	jctx, cancel := context.WithTimeout(ctx, spec.Timeout)
	defer cancel()

	if u := r.checkConcurrency(jctx); u != nil {
		return workexec.JobResult{}, u
	}
	key, err := worker.NewSealKey()
	if err != nil {
		return workexec.JobResult{}, err
	}
	requested := BuildPod(params)
	created, err := r.cfg.API.CreatePod(jctx, requested, false)
	if err != nil {
		return workexec.JobResult{}, r.createFailed(ctx, params, err)
	}
	view, verr := viewOf(created)
	if verr != nil || view.Metadata.UID == "" || view.Metadata.Name != params.Name() {
		return workexec.JobResult{}, errors.New("the answer to the creation of the Pod does not identify it")
	}
	name, uid := view.Metadata.Name, view.Metadata.UID
	defer func() {
		if derr := r.deletePod(name, uid); derr != nil {
			err = errors.Join(err, fmt.Errorf("%w: %w", workexec.ErrCleanup, derr))
		}
	}()

	node, cerr := CheckPod(requested, created, false, "")
	if cerr != nil {
		return workexec.JobResult{}, fmt.Errorf("the created Pod is not the one asked for: %w", cerr)
	}
	_ = node
	binding := worker.SealBinding{
		Instance: r.cfg.InstanceID, Session: r.cfg.SessionID, Job: JobLabel(spec.JobID),
		Attempt: r.nextAttempt(spec.JobID), PodUID: uid,
	}
	sealFile, err := worker.SealFileBytes(key.PublicKey(), binding)
	if err != nil {
		return workexec.JobResult{}, err
	}
	inputs := append(append([]workexec.InputFile(nil), spec.Inputs...), workexec.InputFile{Path: worker.SealInputName, Content: sealFile})
	tarBytes, err := workexec.BuildInputTar(inputs, r.cfg.Limits, "")
	if err != nil {
		return workexec.JobResult{}, fmt.Errorf("build the input: %w", err)
	}

	w := &waiter{r: r, requested: requested, name: name, uid: uid}
	if err := w.untilReceiveRuns(jctx); err != nil {
		return workexec.JobResult{}, r.waitError(jctx, err, spec.Timeout)
	}
	if err := r.cfg.API.AttachInput(jctx, name, tarBytes); err != nil {
		return workexec.JobResult{}, fmt.Errorf("send the input to the Pod: %w", err)
	}
	final, err := w.untilWorkEnds(jctx)
	if err != nil {
		return workexec.JobResult{}, r.waitError(jctx, err, spec.Timeout)
	}
	if err := r.checkImage(final, image); err != nil {
		return workexec.JobResult{}, err
	}
	limit := worker.SealedLogLimit(r.cfg.MaxResultTarBytes)
	logBytes, err := r.cfg.API.PodLog(jctx, name, WorkContainer, limit+1)
	if err != nil {
		return workexec.JobResult{}, fmt.Errorf("read the log of the Pod: %w", err)
	}
	// The Pod must still be the one created when its output is taken.
	if err := w.sameUID(jctx); err != nil {
		return workexec.JobResult{}, err
	}
	exit := final.workExit
	tarOut, oerr := worker.OpenSealed(logBytes, limit, key, binding, r.cfg.MaxResultTarBytes)
	if oerr != nil {
		if exit != 0 {
			// The program ended without a result; its exit code is what there is.
			return workexec.JobResult{ExitCode: exit}, nil
		}
		// The log the API serves is at most limit bytes, but the node stores
		// every line with a prefix, and rotates the log (dropping its
		// beginning) past containerLogMaxSize; a result that was cut that way
		// shows as a missing or damaged frame.
		hint := fmt.Sprintf("if the node cut or rotated the container log, containerLogMaxSize must exceed %d bytes for the largest result (the API serves at most %d)",
			worker.SealedLogNodeBytes(r.cfg.MaxResultTarBytes), limit)
		return workexec.JobResult{}, fmt.Errorf("%w: %v (%s)", workexec.ErrResultInvalid, oerr, hint)
	}
	return workexec.JobResult{ExitCode: exit, Stdout: worker.ResultBlockOfTar(tarOut)}, nil
}

// admissionProblem is the reason no job runs, if the admission check found
// one or has not run.
func (r *Runner) admissionProblem() *workexec.Unavailable {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.admission.checked {
		return unavailable(true, ReasonAdmissionUnverified, "the admission policy of the work namespace has not been checked")
	}
	return r.admission.problem
}

// checkConcurrency defers the job when this installation already has as many
// work Pods as it may (finished ones count until they are collected). A Pod
// that is already being deleted does not count: it is on its way out, and
// counting it would defer jobs for the whole grace period after each job. The
// namespace's ResourceQuota still counts such a Pod until it is gone, so the
// quota can still refuse a create in that window; createFailed defers the job
// then, which is correct.
func (r *Runner) checkConcurrency(ctx context.Context) *workexec.Unavailable {
	pods, err := r.cfg.API.ListPods(ctx, r.selector())
	if err != nil {
		return unavailable(false, ReasonPodLimit, "the work Pods could not be counted: %v", clip(err.Error(), 200))
	}
	live := 0
	for _, obj := range pods {
		if v, err := viewOf(obj); err == nil && v.Metadata.DeletionTimestamp != "" {
			continue
		}
		live++
	}
	if live >= r.cfg.MaxConcurrent {
		return unavailable(false, ReasonPodLimit, "%d work Pods exist (limit %d)", live, r.cfg.MaxConcurrent)
	}
	return nil
}

// createFailed classifies a failure to create a Pod. A quota that is used up
// defers the job. When the answer is lost, the Pod may exist: it is looked for
// by name and removed if it is ours, and the job is deferred either way, so
// the same job is not created again in the same cycle.
func (r *Runner) createFailed(ctx context.Context, p Params, err error) error {
	var ae *APIError
	if errors.As(err, &ae) {
		if ae.Code == 403 && strings.Contains(ae.Message, "exceeded quota") {
			return unavailable(false, ReasonPodLimit, "the quota of the work namespace is used up: %s", clip(ae.Message, 200))
		}
		if ae.Code == 409 {
			r.removeIfOurs(p)
			return unavailable(false, ReasonPodLimit, "a Pod of the same name existed and was removed; the job is tried again later")
		}
		return fmt.Errorf("create the Pod: %w", err)
	}
	r.removeIfOurs(p)
	return unavailable(false, ReasonPodLimit, "the Pod may or may not have been created (%s); the job is tried again later", clip(err.Error(), 120))
}

// removeIfOurs deletes the Pod of the params' name if it carries this
// installation's labels and this session's.
func (r *Runner) removeIfOurs(p Params) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), 30*time.Second)
	defer cancel()
	obj, err := r.cfg.API.GetPod(ctx, p.Name())
	if err != nil {
		return
	}
	v, err := viewOf(obj)
	if err != nil || v.Metadata.UID == "" {
		return
	}
	l := v.Metadata.Labels
	if l[LabelWork] != LabelWorkValue || l[LabelInstance] != p.Instance || l[LabelSession] != p.Session {
		return
	}
	if err := r.deletePod(p.Name(), v.Metadata.UID); err != nil {
		r.logger().Warn("a work Pod could not be removed", "err", err)
	}
}

func (r *Runner) logger() *slog.Logger { return r.log() }

// deletePod deletes with the UID as a condition, on a context of its own so a
// cancelled job still removes its Pod.
func (r *Runner) deletePod(name, uid string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), 30*time.Second)
	defer cancel()
	return r.cfg.API.DeletePod(ctx, name, uid)
}

// checkImage requires the work container to have run the pinned image.
func (r *Runner) checkImage(f finalState, image string) error {
	_, digest, _ := strings.Cut(image, "@")
	if !strings.HasSuffix(f.workImageID, "@"+digest) && f.workImageID != digest {
		return fmt.Errorf("the work container ran %q, not the pinned image", clip(f.workImageID, 100))
	}
	return nil
}

// waitError turns the end of a wait into the error RunJob returns.
func (r *Runner) waitError(ctx context.Context, err error, timeout time.Duration) error {
	var u *workexec.Unavailable
	if errors.As(err, &u) {
		return u
	}
	if errors.Is(err, workexec.ErrImageUnavailable) || errors.Is(err, workexec.ErrJobTimeout) {
		return err
	}
	if ctx.Err() != nil {
		return fmt.Errorf("%w: %w", workexec.ErrJobTimeout, ctx.Err())
	}
	return err
}

// VerifyAdmission and the rest of the admission check are in admission.go.
