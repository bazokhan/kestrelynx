package kubework

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
	"github.com/kitsunetrail/kestrelynx/internal/workexec"
)

// The names of what a work Pod is made of. The admission policy of the work
// namespace and the check the main process makes of every Pod it gets back
// both rest on this one description, so a Pod that differs from it in any
// field they do not list as a default is not run.
const (
	// LabelWork and the labels after it are the only labels of a work Pod.
	LabelWork     = "io.kestrelynx.work"
	LabelInstance = "io.kestrelynx.work.instance"
	LabelSession  = "io.kestrelynx.work.session"
	LabelJob      = "io.kestrelynx.work.job"
	// LabelWorkValue is the value of LabelWork.
	LabelWorkValue = "v1"

	// ReceiveContainer is the init container that unpacks the input and
	// WorkContainer the container that runs the job.
	ReceiveContainer = "receive"
	WorkContainer    = "work"

	// ReceiverUID and WorkUID are the users of the two containers.
	ReceiverUID = worker.ReceiverUID
	WorkUID     = worker.UID

	// PodNamePrefix starts every work Pod's name.
	PodNamePrefix = "kestrelynx-work-"

	// terminationGraceSeconds is the grace period of a work Pod.
	terminationGraceSeconds = 5
	// MaxActiveDeadlineSeconds bounds how long a Pod may run.
	MaxActiveDeadlineSeconds = 3600 + 600

	// ReceiverProgram is the program the init container runs, and its argument.
	ReceiverProgram = "/usr/local/bin/kestrelynx"
	ReceiverArg     = "receive"
)

// The volumes of a work Pod, in the order they are listed.
const (
	volWork  = "work"
	volTmp   = "tmp"
	volHome  = "home"
	volTools = "tools"
	volShm   = "shm"
)

var (
	// nameRE is the shape of a work Pod's name.
	nameRE = regexp.MustCompile(`^kestrelynx-work-[0-9a-f]{32}-[0-9a-f]{16}$`)
	// hexRE are the shapes of the label values.
	instanceRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	sessionRE  = regexp.MustCompile(`^[0-9a-f]{16}$`)
	jobRE      = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// JobLabel is the label value (and the end of the Pod's name) for a job ID: the
// job ID may hold characters a Kubernetes name cannot, so the name holds a
// hash of it.
func JobLabel(jobID string) string {
	sum := sha256.Sum256([]byte(jobID))
	return hex.EncodeToString(sum[:8])
}

// PodName is the name of the Pod of a job of an installation.
func PodName(instance, jobID string) string {
	return PodNamePrefix + instance + "-" + JobLabel(jobID)
}

// Params is everything that varies in a work Pod. Everything else about it is
// fixed in this file.
type Params struct {
	Namespace      string
	Instance       string
	Session        string
	JobID          string
	ServiceAccount string
	PriorityClass  string
	// Arch is the node architecture the Pod is pinned to ("amd64").
	Arch string
	// ReceiverImage and WorkImage are references with a digest.
	ReceiverImage string
	WorkImage     string
	// Entrypoint is the command of the work container, Env its complete
	// environment ("KEY=value").
	Entrypoint []string
	Env        []string
	Resources  workexec.Resources
	// ActiveDeadlineSeconds bounds the Pod's run.
	ActiveDeadlineSeconds int64
}

// Validate checks the parts a Pod cannot be made without.
func (p Params) Validate() error {
	switch {
	case p.Namespace == "" || p.ServiceAccount == "" || p.PriorityClass == "" || p.Arch == "":
		return errors.New("a work Pod needs a namespace, a service account, a priority class and an architecture")
	case !instanceRE.MatchString(p.Instance) || !sessionRE.MatchString(p.Session):
		return errors.New("the instance or session identifier of a work Pod is malformed")
	case !strings.Contains(p.ReceiverImage, "@sha256:") || !strings.Contains(p.WorkImage, "@sha256:"):
		return errors.New("a work Pod's images are pinned by digest")
	case len(p.Entrypoint) < 2:
		return errors.New("a work Pod needs the command of its work container")
	case p.ActiveDeadlineSeconds <= 0 || p.ActiveDeadlineSeconds > MaxActiveDeadlineSeconds:
		return fmt.Errorf("the deadline of a work Pod is %d seconds, outside 1..%d", p.ActiveDeadlineSeconds, MaxActiveDeadlineSeconds)
	case p.Resources.MemoryBytes <= 0 || p.Resources.NanoCPUs <= 0 || p.Resources.TmpSizeBytes <= 0 ||
		p.Resources.HomeSizeBytes <= 0 || p.Resources.ToolsSizeBytes <= 0 || p.Resources.ShmSizeBytes <= 0:
		return errors.New("every resource value of a work Pod must be positive")
	}
	return nil
}

// Labels are the four labels of the Pod.
func (p Params) Labels() map[string]string {
	return map[string]string{
		LabelWork: LabelWorkValue, LabelInstance: p.Instance, LabelSession: p.Session, LabelJob: JobLabel(p.JobID),
	}
}

// Name is the Pod's name.
func (p Params) Name() string { return PodName(p.Instance, p.JobID) }

func quantity(n int64) string { return strconv.FormatInt(n, 10) }

func cpuQuantity(nano int64) string { return strconv.FormatInt(nano/1_000_000, 10) + "m" }

// Memory the receiving container needs: it writes the whole input into a
// memory volume.
const receiverMemoryBytes = 512 << 20

// workVolumeBytes is the size of the volume the input is unpacked into.
func workVolumeBytes() int64 {
	return int64(worker.MaxInputTotalBytes+worker.MaxToolArchiveBytes) + 16<<20 + 8<<20
}

// ephemeral storage the two containers may use: the logs the kubelet keeps
// count against it, and the largest sealed result is about 94 MiB.
const (
	workEphemeralLimit     int64 = 512 << 20
	workEphemeralRequest   int64 = 128 << 20
	receiveEphemeralLimit  int64 = 64 << 20
	receiveEphemeralReqest int64 = 16 << 20
)

// BuildPod renders the Pod as it is sent to create. Fields the API server
// fills in (the priority and preemption policy of the class, the scheduler's
// name, the service account's alias, the default tolerations, the image pull
// policy) are not in it.
func BuildPod(p Params) map[string]any {
	envs := make([]any, 0, len(p.Env))
	for _, kv := range p.Env {
		k, v, _ := strings.Cut(kv, "=")
		envs = append(envs, map[string]any{"name": k, "value": v})
	}
	resources := func(cpu, mem, eph, ephReq int64) map[string]any {
		return map[string]any{
			"requests": map[string]any{"cpu": cpuQuantity(cpu / 4), "memory": quantity(mem / 4), "ephemeral-storage": quantity(ephReq)},
			"limits":   map[string]any{"cpu": cpuQuantity(cpu), "memory": quantity(mem), "ephemeral-storage": quantity(eph)},
		}
	}
	secCtx := func(uid int64) map[string]any {
		return map[string]any{
			"runAsUser": uid, "runAsGroup": uid, "runAsNonRoot": true,
			"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
			"capabilities": map[string]any{"drop": []any{"ALL"}},
		}
	}
	mem := func(size int64) map[string]any {
		return map[string]any{"emptyDir": map[string]any{"medium": "Memory", "sizeLimit": quantity(size)}}
	}
	vol := func(name string, size int64) map[string]any {
		v := mem(size)
		v["name"] = name
		return v
	}
	receive := map[string]any{
		"name":                     ReceiveContainer,
		"image":                    p.ReceiverImage,
		"command":                  []any{ReceiverProgram, ReceiverArg},
		"stdin":                    true,
		"stdinOnce":                true,
		"securityContext":          secCtx(ReceiverUID),
		"terminationMessagePath":   worker.TerminationDir + "/" + ReceiveContainer,
		"terminationMessagePolicy": "File",
		"resources":                resources(1_000_000_000, receiverMemoryBytes, receiveEphemeralLimit, receiveEphemeralReqest),
		"volumeMounts":             []any{map[string]any{"name": volWork, "mountPath": worker.WorkDir}},
	}
	work := map[string]any{
		"name":                     WorkContainer,
		"image":                    p.WorkImage,
		"command":                  []any{p.Entrypoint[0]},
		"args":                     toAny(p.Entrypoint[1:]),
		"env":                      envs,
		"securityContext":          secCtx(WorkUID),
		"terminationMessagePath":   worker.TerminationDir + "/" + WorkContainer,
		"terminationMessagePolicy": "File",
		"resources":                resources(p.Resources.NanoCPUs, p.Resources.MemoryBytes, workEphemeralLimit, workEphemeralRequest),
		"volumeMounts": []any{
			map[string]any{"name": volWork, "mountPath": worker.WorkDir, "readOnly": true},
			map[string]any{"name": volTmp, "mountPath": worker.TmpDir},
			map[string]any{"name": volHome, "mountPath": worker.HomeDir},
			map[string]any{"name": volTools, "mountPath": worker.ToolsRoot},
			map[string]any{"name": volShm, "mountPath": "/dev/shm"},
		},
	}
	labels := map[string]any{}
	for k, v := range p.Labels() {
		labels[k] = v
	}
	spec := map[string]any{
		"restartPolicy":                 "Never",
		"automountServiceAccountToken":  false,
		"serviceAccountName":            p.ServiceAccount,
		"activeDeadlineSeconds":         p.ActiveDeadlineSeconds,
		"terminationGracePeriodSeconds": int64(terminationGraceSeconds),
		"dnsPolicy":                     "ClusterFirst",
		"enableServiceLinks":            false,
		"priorityClassName":             p.PriorityClass,
		"nodeSelector":                  map[string]any{"kubernetes.io/os": "linux", "kubernetes.io/arch": p.Arch},
		"securityContext": map[string]any{
			"runAsNonRoot": true, "seccompProfile": map[string]any{"type": "RuntimeDefault"},
		},
		"initContainers": []any{receive},
		"containers":     []any{work},
		"volumes": []any{
			vol(volWork, workVolumeBytes()),
			vol(volTmp, p.Resources.TmpSizeBytes),
			vol(volHome, p.Resources.HomeSizeBytes),
			vol(volTools, p.Resources.ToolsSizeBytes),
			vol(volShm, p.Resources.ShmSizeBytes),
		},
	}
	return map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": p.Name(), "namespace": p.Namespace, "labels": labels},
		"spec":     spec,
	}
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// normalized round-trips a value through JSON so that numbers are float64 and
// maps are map[string]any, as a decoded response is.
func normalized(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}
