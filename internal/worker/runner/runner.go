//go:build unix

// Package runner is the program that runs inside a work container: it checks
// /work/job.json and the input files, runs the job's fixed operations one at a
// time in working trees under the temporary directory, and prints the result
// on its standard output. It never writes under /work and never takes a
// command from the job.
package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// Config is where the program works and what its children may use. The zero
// value is not usable; DefaultConfig gives the container layout.
type Config struct {
	// WorkDir holds job.json and src/; it is only read.
	WorkDir string
	// TmpDir is the writable scratch space for working trees and caches.
	TmpDir string
	// HomeDir is HOME for the children.
	HomeDir string
	// BinDir is the only directory a step's program is found in, by the
	// absolute path it is started with, and Path is the PATH the children get.
	BinDir string
	Path   string
	// Environment, when set, makes the program check the container and
	// prepare the runtime and the tool before it runs a job. Without it the
	// caller has put the programs in BinDir itself.
	Environment *EnvironmentConfig
	// FileSizeLimit is RLIMIT_FSIZE for the children, in bytes (0 leaves it
	// and the core file limit alone); core files are turned off with it. It is lowered for this process too, hard limit included, so a
	// child cannot raise it again; this program itself never writes a larger
	// file.
	FileSizeLimit uint64
	// Stdout receives the result block and nothing else.
	Stdout io.Writer
}

// DefaultConfig is the layout inside the work image.
func DefaultConfig() Config {
	return Config{
		WorkDir: worker.WorkDir,
		TmpDir:  worker.TmpDir,
		HomeDir: worker.HomeDir,
		BinDir:  worker.ToolsBinDir,
		Path:    worker.ToolsBinDir + ":/usr/bin:/bin",

		Environment: DefaultEnvironment(),

		FileSizeLimit: worker.ChildMaxFileBytes,
		Stdout:        os.Stdout,
	}
}

// Run executes the job at jobPath and prints the result block to cfg.Stdout.
// It returns an error when the job file could not be read or no result could
// be printed; every other outcome, including a failed step, is a result with a
// status. A result is printed for an unreadable job file too.
func Run(cfg Config, jobPath string) error {
	start := time.Now()
	files := map[string][]byte{}
	finish := func(res *worker.Result) error {
		res.Protocol = worker.ProtocolVersion
		res.DurationMS = time.Since(start).Milliseconds()
		if res.Steps == nil {
			res.Steps = []worker.StepResult{}
		}
		return emit(cfg.Stdout, res, files)
	}
	reject := func(format string, args ...any) error {
		return finish(&worker.Result{Status: worker.StatusInputRejected, Error: sanitize(fmt.Sprintf(format, args...))})
	}
	// No child may receive a descriptor this program inherited; without this
	// step os/exec would pass every inherited descriptor that is not
	// close-on-exec to each package manager.
	if err := closeInheritedOnExec(); err != nil {
		return reject("cannot keep inherited descriptors from the children: %v", err)
	}

	// The container is checked before anything the job names is read.
	if cfg.Environment != nil {
		if err := cfg.Environment.selfCheck(); err != nil {
			return finish(&worker.Result{Status: worker.StatusEnvironmentRejected, Error: sanitize(err.Error())})
		}
	}

	job, err := readJob(jobPath)
	var bad *malformedError
	if errors.As(err, &bad) {
		return reject("%v", err)
	}
	if err != nil {
		if werr := finish(&worker.Result{Status: worker.StatusInputRejected, Error: sanitize(err.Error())}); werr != nil {
			return werr
		}
		return fmt.Errorf("read job: %w", err)
	}
	if err := job.Validate(); err != nil {
		return reject("%v", err)
	}
	if err := checkInputs(filepath.Join(cfg.WorkDir, worker.SrcDirName), job.Inputs); err != nil {
		return reject("%v", err)
	}
	if err := checkReplacements(filepath.Join(cfg.WorkDir, worker.ReplaceDirName), job.Replacements); err != nil {
		return reject("%v", err)
	}
	if cfg.Environment != nil {
		if err := cfg.prepareEnvironment(job); err != nil {
			status := worker.StatusInputRejected
			var env *environmentError
			if errors.As(err, &env) {
				status = worker.StatusEnvironmentRejected
			}
			return finish(&worker.Result{Status: status, Error: sanitize(err.Error())})
		}
	}

	base, err := os.MkdirTemp(cfg.TmpDir, "kestrelynx-worker-")
	if err != nil {
		return fmt.Errorf("create working directory: %w", err)
	}
	defer os.RemoveAll(base)

	res := execute(cfg, job, base, files, start)
	return finish(res)
}

// malformedError means job.json was read but is not a well-formed job. It is
// a rejection of the input, not a failure of the program, so the run still
// ends with a result.
type malformedError struct{ err error }

func (e *malformedError) Error() string { return e.err.Error() }
func (e *malformedError) Unwrap() error { return e.err }

// readJob reads and strictly decodes job.json. A file that cannot be read, is
// not a plain file or is too large is an error; content that does not parse as
// a job is a *malformedError.
func readJob(path string) (*worker.Job, error) {
	f, _, err := regularFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, worker.MaxJobBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > worker.MaxJobBytes {
		return nil, fmt.Errorf("job.json is larger than %d bytes", worker.MaxJobBytes)
	}
	job, err := DecodeJob(data)
	if err != nil {
		return nil, &malformedError{err}
	}
	return job, nil
}

// DecodeJob parses job.json bytes, refusing unknown fields and trailing data.
func DecodeJob(data []byte) (*worker.Job, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var job worker.Job
	if err := dec.Decode(&job); err != nil {
		return nil, fmt.Errorf("decode job.json: %w", err)
	}
	if dec.More() {
		return nil, errors.New("decode job.json: trailing data")
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode job.json: trailing data")
	}
	return &job, nil
}

// execute runs the steps of a validated job whose inputs have been checked.
func execute(cfg Config, job *worker.Job, base string, files map[string][]byte, start time.Time) *worker.Result {
	res := &worker.Result{Manager: job.Manager}
	fail := func(status worker.Status, format string, args ...any) *worker.Result {
		res.Status = status
		res.Error = sanitize(fmt.Sprintf(format, args...))
		return res
	}

	ctx, cancel := context.WithDeadline(context.Background(), start.Add(time.Duration(job.DeadlineSeconds)*time.Second))
	defer cancel()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigs)
	interrupted := make(chan struct{})
	go func() {
		select {
		case <-sigs:
			close(interrupted)
			cancel()
		case <-ctx.Done():
		}
	}()

	if cfg.FileSizeLimit > 0 {
		lim := syscall.Rlimit{Cur: cfg.FileSizeLimit, Max: cfg.FileSizeLimit}
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &lim); err != nil {
			return fail(worker.StatusStepFailed, "set file size limit: %v", err)
		}
		// A child killed by the file size limit would otherwise leave a core
		// file as large as its memory in its working directory.
		if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
			return fail(worker.StatusStepFailed, "disable core files: %v", err)
		}
	}
	if err := cfg.prepareCache(); err != nil {
		return fail(worker.StatusStepFailed, "prepare cache: %v", err)
	}
	// The working tree holds the job's outputs, the inputs it declared and
	// nothing else: a settings file the job did not carry is not allowed to
	// appear.
	names := worker.OutputNames(job.Manager)
	for _, in := range job.Inputs {
		if !contains(names, in.Path) {
			names = append(names, in.Path)
		}
	}
	outBudget := int64(worker.MaxOutTotalBytes)
	mainTree := filepath.Join(base, "main")
	if err := copyTree(filepath.Join(cfg.WorkDir, worker.SrcDirName), mainTree, names); err != nil {
		return fail(worker.StatusStepFailed, "prepare working tree: %v", err)
	}

	replacingStep := job.FirstReplacingStep()
	for i, step := range job.Steps {
		if i == replacingStep {
			if err := replaceFiles(filepath.Join(cfg.WorkDir, worker.ReplaceDirName), mainTree, job.Replacements); err != nil {
				return fail(worker.StatusStepFailed, "step %q: put the replacements in place: %v", step.ID, err)
			}
		}
		argv, err := worker.Argv(*job, step)
		if err != nil {
			return fail(worker.StatusInputRejected, "step %q: %v", step.ID, err)
		}
		tree := mainTree
		if step.Scratch {
			tree = filepath.Join(base, "scratch-"+step.ID)
			if err := copyTree(mainTree, tree, names); err != nil {
				return fail(worker.StatusStepFailed, "step %q: copy working tree: %v", step.ID, err)
			}
		}

		stepCtx, stepCancel := ctx, context.CancelFunc(func() {})
		if job.StepTimeoutSeconds > 0 {
			stepCtx, stepCancel = context.WithTimeout(ctx, time.Duration(job.StepTimeoutSeconds)*time.Second)
		}
		t0 := time.Now()
		pr := runProc(stepCtx, &cfg, job.Manager, argv, tree)
		stepCancel()

		sr := worker.StepResult{
			ID: step.ID, Op: step.Op, Scratch: step.Scratch, Argv: argv,
			ExitCode: pr.exitCode, DurationMS: time.Since(t0).Milliseconds(),
			TimedOut: pr.timedOut, Stdout: pr.stdout, Stderr: pr.stderr, OutputTruncated: pr.truncated,
		}
		if pr.err != nil {
			sr.Error = sanitize(pr.err.Error())
		}
		res.Steps = append(res.Steps, sr)
		last := &res.Steps[len(res.Steps)-1]

		select {
		case <-interrupted:
			return fail(worker.StatusStepFailed, "interrupted")
		default:
		}
		if pr.releaseAge {
			last.Reason = worker.ReasonReleaseAgeViolation
		}
		if pr.timedOut {
			return fail(worker.StatusTimedOut, "step %q exceeded its time limit", step.ID)
		}
		if pr.err != nil || pr.exitCode != 0 {
			return fail(worker.StatusStepFailed, "step %q failed", step.ID)
		}
		if name, err := changedSettings(tree, job); err != nil || name != "" {
			last.Reason = worker.ReasonInputModified
			if err != nil {
				last.Error = sanitize(err.Error())
			}
			return fail(worker.StatusStepFailed, "step %q changed the input file %q, which it may not", step.ID, name)
		}
		paths, count, err := unexpectedEntries(tree, names)
		if err != nil {
			return fail(worker.StatusStepFailed, "step %q: inspect working tree: %v", step.ID, err)
		}
		if count > 0 {
			last.Reason = worker.ReasonUnexpectedFiles
			last.UnexpectedPaths, last.UnexpectedCount = paths, count
			return fail(worker.StatusStepFailed, "step %q left %d unexpected entries in the working tree", step.ID, count)
		}
		files, err := collect(tree, worker.StepsDir+"/"+step.ID, job.Outputs, &outBudget, files)
		if err != nil {
			last.Error = sanitize(err.Error())
			return fail(worker.StatusStepFailed, "step %q: collect outputs: %v", step.ID, err)
		}
		last.Outputs = files
		if step.Scratch {
			os.RemoveAll(tree)
		}
	}

	final, err := collect(mainTree, worker.FinalDir, job.Outputs, &outBudget, files)
	if err != nil {
		return fail(worker.StatusStepFailed, "collect final outputs: %v", err)
	}
	res.Final = final
	res.Status = worker.StatusCompleted
	return res
}

// emit adds result.json to files, packs them and prints the block. Nothing
// else is ever written to out.
func emit(out io.Writer, res *worker.Result, files map[string][]byte) error {
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > worker.MaxResultBytes {
		return fmt.Errorf("result is %d bytes, over %d", len(data), worker.MaxResultBytes)
	}
	files[worker.ResultName] = append(data, '\n')
	block, err := worker.EncodeResult(files)
	if err != nil {
		return err
	}
	_, err = out.Write(block)
	return err
}
