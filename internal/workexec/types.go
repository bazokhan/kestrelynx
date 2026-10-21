// Package workexec holds the types a work executor and its caller share: the
// description of a job, its inputs and limits, and what comes back. The Docker
// executor and the Kubernetes one implement the same interface over them, so
// the update stage does not depend on either.
package workexec

import (
	"errors"
	"time"
)

// InputFile is one file placed under /work before the container starts.
// Path is relative to /work, for example "src/package.json".
type InputFile struct {
	Path    string
	Content []byte
	// Kind says what the file is, which decides the limits it counts against;
	// the zero value is an ordinary input.
	Kind InputKind
	// Executable makes the file mode 0755 instead of 0644 (the work program
	// only).
	Executable bool
}

// InputKind is the class of an input file. Package manager archives and the
// program have limits of their own, apart from the input files.
type InputKind int

const (
	KindInput   InputKind = iota // a file of the project
	KindTool                     // a package manager archive
	KindProgram                  // the program the container runs
)

// JobSpec describes one job.
type JobSpec struct {
	// JobID names the container (with the instance id) and labels it. It
	// must be unique among live jobs of this instance.
	JobID string
	// Inputs are written under /work before start.
	Inputs []InputFile
	// Timeout bounds the whole job, from container creation to deletion.
	Timeout time.Duration
	// Resources are the limits applied to the container.
	Resources Resources
	// Runtime names the client a set of executors runs the job with; a single
	// executor ignores it.
	Runtime string
}

// JobResult is what a finished job left behind. The client does not
// interpret Stdout; the job's own protocol decides what it means.
type JobResult struct {
	// ExitCode is the container's exit code.
	ExitCode int
	// Stdout is the container's standard output, exactly as logged. It is nil
	// when the job exited non-zero and its output could not be read.
	Stdout []byte
}

var (
	// ErrJobTimeout reports that the job's deadline passed; the container was
	// killed and deleted and there is no result.
	ErrJobTimeout = errors.New("work job deadline exceeded")
	// ErrCleanup wraps a failure to delete the job's container. The result,
	// if any, is still returned next to it.
	ErrCleanup = errors.New("work container cleanup failed")
)

// TransferLimits bound the tar streams in both directions.
type TransferLimits struct {
	MaxInputBytes     int64 // total input file bytes
	MaxInputTarBytes  int64 // whole input archive, headers included
	MaxInputFiles     int   // input files
	MaxInputPathBytes int   // longest input path
	// MaxToolBytes bounds the tool archives of a job together, and
	// MaxProgramBytes the program the container runs. They are limits of their
	// own so that neither takes from the room the input files have. Zero
	// allows none.
	MaxToolBytes    int64
	MaxProgramBytes int64
	LogMaxBytes     int64 // json-file max-size of the container log (one file, no rotation)
	MaxStdoutBytes  int64 // most stdout bytes read back; at least LogMaxBytes
}

// Resources are the per-job resource values; every field is required.
type Resources struct {
	MemoryBytes   int64 // memory limit; swap is set to the same value (no swap)
	NanoCPUs      int64
	PidsLimit     int64
	NofileLimit   int64
	ShmSizeBytes  int64 // size of /dev/shm
	TmpSizeBytes  int64 // size of the /tmp tmpfs
	HomeSizeBytes int64 // size of the /home/worker tmpfs
	// ToolsSizeBytes is the size of the tmpfs the package manager is unpacked
	// into.
	ToolsSizeBytes int64
}

// ErrImageUnavailable reports that the image a job needs could not be made
// ready: it could not be pulled, or the executor's copy is not the pinned image
// for the platform. Nothing was run.
var ErrImageUnavailable = errors.New("work image unavailable")

// Unavailable says that an executor cannot run a job for a reason that is not
// the job's: the update stage reports the item as manual (the setup needs a
// person) or deferred (the limit passes, or the next cycle may find it fixed).
type Unavailable struct {
	// Manual says the item needs a person; otherwise it is deferred.
	Manual bool
	// Reason is the reason code the item is shown with.
	Reason string
	Detail string
}

func (u *Unavailable) Error() string { return u.Reason + ": " + u.Detail }

// ErrResultInvalid reports that the executor got the job's output and it was
// not a result that could be used (sealed to another attempt, damaged, cut,
// over the size limit). The job's files were not used.
var ErrResultInvalid = errors.New("work job result invalid")
