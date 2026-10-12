// Package worker defines the job protocol between the main process and the
// program that runs inside a disposable work container. The main process
// writes /work/job.json (and the input files it names) before the container
// starts; the program in the container validates the job, runs a fixed list of
// package-manager operations and prints the result on its standard output.
// /work is read-only to it, and nothing is exchanged while the container runs. Both sides import this package, so the file names, the
// operation set and the validation rules cannot drift apart.
package worker

// ProtocolVersion is the version of the job and result formats. The program
// that runs in the container is shipped with the main process that starts it,
// built from the same source, and checks the version of every job and result.
const ProtocolVersion = 3

// Paths inside the work container. The program only reads /work.
const (
	WorkDir    = "/work"
	JobFile    = "/work/job.json"
	SrcDirName = "src"
	// ToolsDirName is the directory of /work that holds the package manager
	// archive, and ProgramPath is where the program itself is placed.
	ToolsDirName = "tools"
	ProgramPath  = "/work/bin/kestrelynx-worker"
	// ProgramInputPath is ProgramPath relative to /work, as an input file.
	ProgramInputPath = "bin/kestrelynx-worker"
	// ToolsRoot is the tmpfs the archive is unpacked into, and ToolsBinDir the
	// directory of it that holds the links the children find their programs
	// by: the interpreter and the package manager.
	ToolsRoot   = "/opt/kestrelynx-tools"
	ToolsBinDir = "/opt/kestrelynx-tools/bin"
	// HomeDir and TmpDir are the tmpfs mounts of the container.
	HomeDir = "/home/worker"
	TmpDir  = "/tmp"
	// ResultName, StepsDir and FinalDir are paths in the result tar.
	ResultName = "result.json"
	StepsDir   = "steps"
	FinalDir   = "final"
	// UID and GID the container runs as. /work is owned by root, so the job
	// can read it and cannot write it.
	UID = 10001
	GID = 10001
)

// Manager is the package manager a job is for.
type Manager string

const (
	ManagerNpm  Manager = "npm"
	ManagerPnpm Manager = "pnpm"
	ManagerUv   Manager = "uv"
	ManagerPip  Manager = "pip"
)

// Op is one fixed operation. The program turns it into a command line itself;
// a job never carries a command.
type Op string

const (
	OpNpmRelock  Op = "npm.relock"
	OpNpmUpdate  Op = "npm.update"
	OpPnpmFrozen Op = "pnpm.frozen_check"
	OpPnpmUpdate Op = "pnpm.update"
	OpPnpmRelock Op = "pnpm.relock"
	OpUvCheck    Op = "uv.check"
	OpUvUpgrade  Op = "uv.upgrade"
	OpPipDryRun  Op = "pip.dry_run"
)

// PipReportName is the file pip.dry_run writes its install report to, in the
// working tree.
const PipReportName = "pip-report.json"

// Limits on the size of the job and of what it carries.
const (
	MaxJobBytes        = 1 << 20
	MaxInputs          = 8
	MaxInputFileBytes  = 32 << 20
	MaxInputTotalBytes = 64 << 20
	MaxSteps           = 64
	MaxPackages        = 256
	MaxTargetList      = 32
	MaxDeadlineSeconds = 3600
	// MaxOutputFileBytes bounds one file copied to the result.
	MaxOutputFileBytes = 32 << 20
	// MaxStreamTail is how much of each of a step's stdout and stderr the
	// result keeps (the end of the stream).
	MaxStreamTail = 8 << 10
	// MaxResultBytes is the largest result.json the program writes.
	MaxResultBytes = 4 << 20
	// MaxOutTotalBytes bounds the collected copies in steps/ and final/
	// together. They are held in memory until the result is printed.
	MaxOutTotalBytes = 64 << 20
	// ChildMaxFileBytes is the largest single file a child process may
	// write (RLIMIT_FSIZE). It is well above any file a job collects, so a
	// large cached download still fits, while one runaway write cannot fill
	// a disk.
	ChildMaxFileBytes = 256 << 20
)

// Tool formats.
const (
	FormatNpmTgz = "npm-tgz"
	FormatWheel  = "wheel"
)

// Limits on the package manager archive the program unpacks.
const (
	MaxToolArchiveBytes  = 64 << 20
	MaxToolUnpackedBytes = 160 << 20
	MaxToolFiles         = 5000
)

// Tool is the package manager release a job runs. The main process fetched
// and checked the archive; it is placed at Path (relative to /work) and the
// program checks Size, SHA256 and SHA512 again before it unpacks it.
type Tool struct {
	// Name is the manager the tool is the release of.
	Name    Manager `json:"name"`
	Version string  `json:"version"`
	// Format is FormatNpmTgz or FormatWheel.
	Format string `json:"format"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512"`
	// Entry is the executable inside the unpacked archive, relative to the
	// unpacked root (after the leading "package/" of an npm archive is
	// dropped). RunWithNode says it is a JavaScript file started by node.
	Entry       string `json:"entry"`
	RunWithNode bool   `json:"run_with_node,omitempty"`
}

// Runtime is the runtime a job runs in: an id of the runtime table and the
// exact versions of the language and, for Python, of its pip. The program
// checks them against the executables it finds before it runs a step.
type Runtime struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Pip     string `json:"pip,omitempty"`
}

// Job is /work/job.json.
type Job struct {
	Protocol int     `json:"protocol"`
	Manager  Manager `json:"manager"`
	Runtime  Runtime `json:"runtime"`
	// Tool is the package manager release; pip is the one manager that has
	// none, because it is the one of the Python image.
	Tool *Tool `json:"tool,omitempty"`
	// Inputs are the files under /work/src, by name, with the size and
	// SHA-256 the main process computed. No other file may be present.
	Inputs []Input `json:"inputs"`
	Steps  []Step  `json:"steps"`
	// Outputs names the files copied after each step and into final/. Only
	// names the manager may produce are accepted.
	Outputs []string `json:"outputs"`
	// DeadlineSeconds is the limit for the whole job and StepTimeoutSeconds
	// for one step (0 means the whole-job limit only).
	DeadlineSeconds    int `json:"deadline_seconds"`
	StepTimeoutSeconds int `json:"step_timeout_seconds,omitempty"`
}

// Input is one declared input file.
type Input struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Step is one operation. Scratch steps run in a copy of the current working
// tree and leave it unchanged; other steps change the working tree that the
// next step and final/ see.
type Step struct {
	ID      string `json:"id"`
	Op      Op     `json:"op"`
	Scratch bool   `json:"scratch,omitempty"`
	// Packages are the update targets. npm.update takes names only;
	// uv.upgrade takes a name and a version; pnpm.update takes a name and
	// optionally a version (without one, the package moves within the range
	// its dependents declare, which is how a transitive dependency is updated).
	Packages []Package `json:"packages,omitempty"`
	// RequireHashes and Target are for pip.dry_run.
	RequireHashes bool    `json:"require_hashes,omitempty"`
	Target        *Target `json:"target,omitempty"`
}

// Package is a package name and, for the operations that pin one, a version.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Target is the environment pip resolves for.
type Target struct {
	PythonVersion  string   `json:"python_version,omitempty"`
	Platforms      []string `json:"platforms,omitempty"`
	Implementation string   `json:"implementation,omitempty"`
	ABIs           []string `json:"abis,omitempty"`
}

// Status is the overall outcome in result.json.
type Status string

const (
	StatusCompleted     Status = "completed"
	StatusInputRejected Status = "input_rejected"
	// StatusEnvironmentRejected: the container is not one the program runs
	// in (it is writable where it may not be, or the runtime is not the one
	// the job names).
	StatusEnvironmentRejected Status = "environment_rejected"
	StatusStepFailed          Status = "step_failed"
	StatusTimedOut            Status = "timed_out"
)

// Reason codes a step can carry besides its exit code.
const (
	// ReasonUnexpectedFiles: the step left entries in the working tree other
	// than the job's input and output files.
	ReasonUnexpectedFiles = "unexpected_files"
	// ReasonInputModified: the step changed an input file that is not one of
	// the job's outputs (a settings file the manager only reads).
	ReasonInputModified = "input_modified"
	// ReasonReleaseAgeViolation: the manager refused a package version
	// because it was published too recently (a string match on its error).
	ReasonReleaseAgeViolation = "release_age_violation"
)

// Limits on the list of unexpected paths a step reports.
const (
	MaxUnexpectedPaths   = 32
	MaxUnexpectedPathLen = 128
)

// Result is result.json in the result tar. The main process treats it, like every
// other file in the result, as untrusted output.
type Result struct {
	Protocol   int          `json:"protocol"`
	Status     Status       `json:"status"`
	Manager    Manager      `json:"manager,omitempty"`
	Error      string       `json:"error,omitempty"`
	DurationMS int64        `json:"duration_ms"`
	Steps      []StepResult `json:"steps"`
	// Final lists the files in final/.
	Final []OutputFile `json:"final,omitempty"`
}

// StepResult records one step that was started.
type StepResult struct {
	ID         string   `json:"id"`
	Op         Op       `json:"op"`
	Scratch    bool     `json:"scratch,omitempty"`
	Argv       []string `json:"argv"`
	ExitCode   int      `json:"exit_code"`
	DurationMS int64    `json:"duration_ms"`
	TimedOut   bool     `json:"timed_out,omitempty"`
	Error      string   `json:"error,omitempty"`
	Stdout     string   `json:"stdout,omitempty"`
	Stderr     string   `json:"stderr,omitempty"`
	// OutputTruncated is set when stdout or stderr was longer than the tail kept.
	OutputTruncated bool `json:"output_truncated,omitempty"`
	// Reason is a machine-readable cause (the Reason constants), set when the
	// step failed for one of them.
	Reason string `json:"reason,omitempty"`
	// UnexpectedPaths lists, for ReasonUnexpectedFiles, up to
	// MaxUnexpectedPaths of the entries found; UnexpectedCount is how many
	// there were in all.
	UnexpectedPaths []string     `json:"unexpected_paths,omitempty"`
	UnexpectedCount int          `json:"unexpected_count,omitempty"`
	Outputs         []OutputFile `json:"outputs,omitempty"`
}

// OutputFile is a file written under the result, by its name relative to the
// step or final directory.
type OutputFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
