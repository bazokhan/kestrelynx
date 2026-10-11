package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// Step ids of the update jobs. The id of a failed step says which part of the
// update failed.
const (
	stepBaseline = "baseline" // the original input checked as it is
	stepUpdate   = "update"   // the update itself
	// stepUpdateMore updates the targets whose specifier was not edited, after
	// the step that relocks against the edited manifest.
	stepUpdateMore = "update_more"
	stepCheck      = "check" // the updated input checked again
)

// jobOutput is a finished job whose result passed the structural checks: the
// files are exactly the declared ones, and the steps are the job's steps.
type jobOutput struct {
	result worker.Result
	files  map[string][]byte
}

// stepFile returns an output file a step collected.
func (o *jobOutput) stepFile(step, name string) ([]byte, bool) {
	b, ok := o.files[worker.StepsDir+"/"+step+"/"+name]
	return b, ok
}

// finalFile returns a file of the final tree.
func (o *jobOutput) finalFile(name string) ([]byte, bool) {
	b, ok := o.files[worker.FinalDir+"/"+name]
	return b, ok
}

// newJob builds a job for manager m. The deadline leaves the client time to
// collect the result before its own limit.
func (u *LangUpdater) newJob(m worker.Manager, inputs map[string][]byte, steps []worker.Step) worker.Job {
	deadline := jobDeadlineSeconds(u.cfg.JobTimeout)
	job := worker.Job{
		Protocol: worker.ProtocolVersion, Manager: m, Steps: steps,
		Outputs:         worker.OutputNames(m),
		DeadlineSeconds: deadline, StepTimeoutSeconds: deadline,
	}
	for _, name := range worker.InputNames(m) {
		content, ok := inputs[name]
		if !ok && !contains(worker.RequiredInputNames(m), name) {
			continue // a settings file the project does not have
		}
		job.Inputs = append(job.Inputs, worker.Input{Path: name, Size: int64(len(content)), SHA256: sha256Hex(content)})
	}
	return job
}

// execute runs a job in a work container and checks its result. Everything
// the container returned is untrusted: the block is decoded under the default
// limits, result.json must describe the job's own steps, the files must be
// exactly the ones the steps and the final tree declare with the sizes and
// hashes declared, and the outcome is mapped to a failure when the job did not
// complete. roles maps a failed step's id to the failure it stands for.
func (u *LangUpdater) execute(ctx context.Context, job worker.Job, inputs map[string][]byte, jobID string, upd *LanguageUpdate) (*jobOutput, *updateFailure) {
	if f := jobLimitFailure(job, inputs); f != nil {
		return nil, f
	}
	if err := job.Validate(); err != nil {
		return nil, manualFailure(ReasonUpdateInputInvalid, "the update job is not valid: %v", err)
	}
	jobJSON, err := json.Marshal(job)
	if err != nil {
		return nil, failedFailure(ReasonUpdateInputInvalid, "encode the update job: %v", err)
	}
	spec := docker.JobSpec{
		JobID:     jobID,
		Inputs:    []docker.InputFile{{Path: "job.json", Content: jobJSON}},
		Timeout:   u.cfg.JobTimeout,
		Resources: u.cfg.Resources,
	}
	for _, in := range job.Inputs {
		spec.Inputs = append(spec.Inputs, docker.InputFile{Path: worker.SrcDirName + "/" + in.Path, Content: inputs[in.Path]})
	}

	res, err := u.cfg.Work.RunJob(ctx, spec)
	if err != nil {
		switch {
		case errors.Is(err, docker.ErrCleanup) && res.Stdout != nil:
			upd.Notes = append(upd.Notes, "the work container could not be deleted after the job: "+clip(err.Error(), 200))
		case ctx.Err() != nil:
			return nil, &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
		case errors.Is(err, docker.ErrJobTimeout):
			return nil, failedFailure(ReasonUpdateJobTimedOut, "the job did not finish within %s", u.cfg.JobTimeout)
		default:
			return nil, failedFailure(ReasonUpdateJobFailed, "run the job: %v", clip(err.Error(), 300))
		}
	}
	if res.ExitCode != 0 {
		return nil, failedFailure(ReasonUpdateJobFailed, "the job program exited with code %d", res.ExitCode)
	}
	files, err := worker.DecodeResult(res.Stdout, worker.DefaultResultLimits())
	if err != nil {
		return nil, failedFailure(ReasonUpdateResultInvalid, "%v", err)
	}
	out, err := checkResultFiles(job, files)
	if err != nil {
		return nil, failedFailure(ReasonUpdateResultInvalid, "%v", err)
	}
	if f := outputSizeFailure(job, inputs, out.files); f != nil {
		return nil, f
	}
	for _, s := range out.result.Steps {
		upd.Steps = append(upd.Steps, UpdateStep{ID: s.ID, Op: string(s.Op), Scratch: s.Scratch, ExitCode: s.ExitCode, DurationMS: s.DurationMS})
		if job.Manager == worker.ManagerPnpm {
			upd.Notes = append(upd.Notes, pnpmWarnings(s.Stderr)...)
		}
	}
	return out, jobStatusFailure(out.result)
}

// jobLimitFailure defers a job that is over a limit of the job format: the
// work is not wrong, the work image cannot take it in one job.
func jobLimitFailure(job worker.Job, inputs map[string][]byte) *updateFailure {
	deferred := func(reason Reason, format string, args ...any) *updateFailure {
		return &updateFailure{category: CategoryDeferred, reason: reason, detail: fmt.Sprintf(format, args...)}
	}
	for _, s := range job.Steps {
		if len(s.Packages) > worker.MaxPackages {
			return deferred(ReasonUpdatePackageLimit, "the update names %d packages, more than the %d one job takes", len(s.Packages), worker.MaxPackages)
		}
	}
	if len(job.Steps) > worker.MaxSteps {
		return deferred(ReasonUpdateInputLimit, "the job has %d steps, more than the %d one job takes", len(job.Steps), worker.MaxSteps)
	}
	var total int64
	for name, c := range inputs {
		total += int64(len(c))
		if int64(len(c)) > worker.MaxInputFileBytes {
			return deferred(ReasonUpdateInputLimit, "%s is %d bytes, more than the %d one job takes", name, len(c), worker.MaxInputFileBytes)
		}
	}
	if total > worker.MaxInputTotalBytes {
		return deferred(ReasonUpdateInputLimit, "the inputs are %d bytes, more than the %d one job takes", total, worker.MaxInputTotalBytes)
	}
	return nil
}

// checkResultFiles decodes result.json and checks it against the job and the
// files that came with it.
func checkResultFiles(job worker.Job, files map[string][]byte) (*jobOutput, error) {
	raw, ok := files[worker.ResultName]
	if !ok {
		return nil, errors.New("the result has no result.json")
	}
	res, err := parseResultJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("result.json cannot be read: %w", err)
	}
	if res.Protocol != worker.ProtocolVersion {
		return nil, fmt.Errorf("result.json has protocol %d", res.Protocol)
	}
	switch res.Status {
	case worker.StatusCompleted, worker.StatusStepFailed, worker.StatusTimedOut, worker.StatusInputRejected:
	default:
		return nil, fmt.Errorf("result.json has the unknown status %q", res.Status)
	}
	if res.Manager != "" && res.Manager != job.Manager {
		return nil, fmt.Errorf("result.json is for the manager %q", res.Manager)
	}
	if err := checkStatusAgainstSteps(job, res); err != nil {
		return nil, err
	}

	declared := map[string]worker.OutputFile{} // path in the result tar
	addOutputs := func(prefix string, list []worker.OutputFile) error {
		for _, f := range list {
			if !contains(job.Outputs, f.Path) {
				return fmt.Errorf("result.json declares the undeclared output %q", f.Path)
			}
			p := prefix + "/" + f.Path
			if _, dup := declared[p]; dup {
				return fmt.Errorf("result.json declares %q twice", p)
			}
			declared[p] = f
		}
		return nil
	}
	for i, s := range res.Steps {
		want := job.Steps[i]
		argv, err := worker.Argv(job.Manager, want)
		if err != nil {
			return nil, err
		}
		if s.ID != want.ID || s.Op != want.Op || s.Scratch != want.Scratch || !sameArgv(s.Argv, argv) {
			return nil, fmt.Errorf("step %d of result.json is not the job's step %q", i+1, want.ID)
		}
		// A step that did not succeed has no outputs in the result.
		if stepSucceeded(s) {
			if err := addOutputs(worker.StepsDir+"/"+s.ID, s.Outputs); err != nil {
				return nil, err
			}
		} else if len(s.Outputs) != 0 {
			return nil, fmt.Errorf("step %q failed and still lists outputs", s.ID)
		}
	}
	if res.Status == worker.StatusCompleted {
		if err := addOutputs(worker.FinalDir, res.Final); err != nil {
			return nil, err
		}
	}
	out := &jobOutput{result: res, files: map[string][]byte{}}
	for name, content := range files {
		if name == worker.ResultName {
			continue
		}
		d, ok := declared[name]
		if !ok {
			return nil, fmt.Errorf("the result holds the undeclared file %q", name)
		}
		if int64(len(content)) != d.Size || sha256Hex(content) != d.SHA256 {
			return nil, fmt.Errorf("the result file %q is not what result.json declares", name)
		}
		out.files[name] = content
	}
	for name := range declared {
		if _, ok := files[name]; !ok {
			return nil, fmt.Errorf("the result lacks the declared file %q", name)
		}
	}
	return out, nil
}

// stepSucceeded reports whether a step ended cleanly: exit code 0, within its
// time, with no error and no machine-readable cause of failure.
func stepSucceeded(s worker.StepResult) bool {
	return s.ExitCode == 0 && !s.TimedOut && s.Error == "" && s.Reason == "" && len(s.UnexpectedPaths) == 0 && s.UnexpectedCount == 0
}

// expectedOutputs are the files a successful step of the job returns: the
// manager's own files, and the install report of a pip step.
func expectedOutputs(m worker.Manager, op worker.Op) []string {
	out := worker.RequiredInputNames(m)
	if op == worker.OpPipDryRun {
		out = append(out, worker.PipReportName)
	}
	sort.Strings(out)
	return out
}

func sameOutputs(want []string, got []worker.OutputFile) bool {
	if len(want) != len(got) {
		return false
	}
	names := make([]string, len(got))
	for i, f := range got {
		names[i] = f.Path
	}
	sort.Strings(names)
	for i := range want {
		if want[i] != names[i] {
			return false
		}
	}
	return true
}

// checkStatusAgainstSteps requires the overall status to be what the steps
// show. A job is completed only when every step the job declares was run and
// ended cleanly with its files; a failed or timed out job has run the steps
// before the last one cleanly and ended on a step that did not; a rejected
// job ran nothing. Anything else is a result that contradicts itself.
func checkStatusAgainstSteps(job worker.Job, res worker.Result) error {
	n := len(res.Steps)
	if n > len(job.Steps) {
		return errors.New("result.json lists more steps than the job has")
	}
	for i, s := range res.Steps {
		if i < n-1 || res.Status == worker.StatusCompleted {
			if !stepSucceeded(s) {
				return fmt.Errorf("step %q did not end cleanly, but a later step or the job is reported as done", s.ID)
			}
			if !sameOutputs(expectedOutputs(job.Manager, s.Op), s.Outputs) {
				return fmt.Errorf("step %q does not list the files it should return", s.ID)
			}
		}
	}
	switch res.Status {
	case worker.StatusCompleted:
		if n != len(job.Steps) {
			return errors.New("result.json says completed but lists fewer steps than the job has")
		}
		if res.Error != "" {
			return errors.New("result.json says completed and carries an error")
		}
		if !sameOutputs(sortedNames(worker.RequiredInputNames(job.Manager)), res.Final) {
			return errors.New("result.json says completed but does not list the final files")
		}
	case worker.StatusStepFailed:
		if n == 0 || stepSucceeded(res.Steps[n-1]) || res.Steps[n-1].TimedOut {
			return errors.New("result.json says a step failed but its last step did not")
		}
	case worker.StatusTimedOut:
		if n == 0 || !res.Steps[n-1].TimedOut {
			return errors.New("result.json says timed out but its last step did not time out")
		}
	case worker.StatusInputRejected:
		if n != 0 {
			return errors.New("result.json says the input was rejected but lists steps")
		}
	}
	if res.Status != worker.StatusCompleted && len(res.Final) != 0 {
		return errors.New("result.json lists final files for a job that did not complete")
	}
	return nil
}

func sortedNames(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// jobStatusFailure maps a job that did not complete to a failure. A step
// that left unexpected files or was refused for the age of a release has its
// own reason; any other failed step is named by its role.
func jobStatusFailure(res worker.Result) *updateFailure {
	switch res.Status {
	case worker.StatusCompleted:
		return nil
	case worker.StatusInputRejected:
		return failedFailure(ReasonUpdateJobInputRefused, "the job program refused the input: %s", clip(res.Error, 300))
	case worker.StatusTimedOut:
		return failedFailure(ReasonUpdateJobTimedOut, "%s", clip(res.Error, 300))
	}
	if len(res.Steps) == 0 {
		return failedFailure(ReasonUpdateJobFailed, "the job failed before its first step: %s", clip(res.Error, 300))
	}
	s := res.Steps[len(res.Steps)-1]
	detail := fmt.Sprintf("step %s (%s) exited with %d", s.ID, s.Op, s.ExitCode)
	if tail := lastLines(s.Stderr, 3); tail != "" {
		detail += ": " + clip(tail, 300)
	}
	switch {
	case s.Reason == worker.ReasonUnexpectedFiles:
		return manualFailure(ReasonUnexpectedFiles, "step %s left %d unexpected entries in the working tree: %s", s.ID, s.UnexpectedCount, clip(strings.Join(s.UnexpectedPaths, ", "), 300))
	case s.Reason == worker.ReasonInputModified:
		return manualFailure(ReasonWorkInputModified, "step %s changed a settings file that it only reads", s.ID)
	case s.Reason == worker.ReasonReleaseAgeViolation:
		return manualFailure(ReasonReleaseAgeViolation, "%s", detail)
	}
	switch s.ID {
	case stepBaseline:
		return manualFailure(ReasonLockfileInconsistent, "the original input does not pass %s: %s", s.Op, detail)
	case stepUpdate, stepUpdateMore:
		return manualFailure(ReasonUpdateStepFailed, "%s", detail)
	}
	return manualFailure(ReasonPostUpdateCheckFailed, "%s", detail)
}

// pnpmWarnings returns the warnings pnpm printed about the pnpm version the
// project declares in packageManager. The work image runs its own pnpm
// whatever the project declares, and says so ("[WARN] This project is
// configured to use 9.0.0 of pnpm. Your current pnpm is v12.10.1"); the update
// goes on and the difference is kept as a note.
func pnpmWarnings(stderr string) []string {
	var out []string
	for _, l := range strings.Split(stderr, "\n") {
		l = strings.TrimSpace(l)
		low := strings.ToLower(l)
		if strings.Contains(low, "warn") && (strings.Contains(low, "packagemanager") || strings.Contains(low, "configured to use")) && len(out) < 3 {
			out = append(out, "pnpm: "+clip(l, 200))
		}
	}
	return out
}

// lastLines returns the last n non-empty lines of s.
func lastLines(s string, n int) string {
	var ls []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			ls = append(ls, l)
		}
	}
	if len(ls) > n {
		ls = ls[len(ls)-n:]
	}
	return strings.Join(ls, " | ")
}

// clip shortens s to at most n bytes at a rune boundary and replaces control
// characters, so text that came from a tool's output can sit in a detail.
func clip(s string, n int) string {
	if len(s) > n {
		s = strings.ToValidUTF8(s[:n], "") + "..."
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, ""))
}

// uniqueSorted returns the distinct elements of s in order.
func uniqueSorted(s []string) []string {
	m := map[string]bool{}
	for _, x := range s {
		m[x] = true
	}
	out := make([]string, 0, len(m))
	for x := range m {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

func sameArgv(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// reqInt reads a number member that must be there.
func reqInt(m map[string]json.RawMessage, key string) (int64, error) {
	raw, ok := m[key]
	if !ok || string(bytes.TrimSpace(raw)) == "null" {
		return 0, fmt.Errorf("%q is missing", key)
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, fmt.Errorf("%q is not an integer", key)
	}
	return n, nil
}

func reqString(m map[string]json.RawMessage, key string) (string, error) {
	if raw, ok := m[key]; !ok || string(bytes.TrimSpace(raw)) == "null" {
		return "", fmt.Errorf("%q is missing", key)
	}
	return optString(m, key)
}

func optInt(m map[string]json.RawMessage, key string) (int64, error) {
	if _, ok := m[key]; !ok {
		return 0, nil
	}
	return reqInt(m, key)
}

func stringList(m map[string]json.RawMessage, key string, required bool) ([]string, error) {
	raw, ok := m[key]
	if !ok {
		if required {
			return nil, fmt.Errorf("%q is missing", key)
		}
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil || (out == nil && required) {
		return nil, fmt.Errorf("%q is not a list of strings", key)
	}
	return out, nil
}

func readOutputFiles(m map[string]json.RawMessage, key string) ([]worker.OutputFile, error) {
	raw, ok := m[key]
	if !ok {
		return nil, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("%q is not a list", key)
	}
	if len(items) > worker.MaxResultEntries {
		return nil, fmt.Errorf("%q lists more than %d files", key, worker.MaxResultEntries)
	}
	var out []worker.OutputFile
	for _, it := range items {
		om, err := strictObject(it)
		if err != nil {
			return nil, fmt.Errorf("%q: %v", key, err)
		}
		var f worker.OutputFile
		if f.Path, err = reqString(om, "path"); err != nil {
			return nil, fmt.Errorf("%q: %v", key, err)
		}
		if f.Size, err = reqInt(om, "size"); err != nil {
			return nil, fmt.Errorf("%q: %v", key, err)
		}
		if f.SHA256, err = reqString(om, "sha256"); err != nil {
			return nil, fmt.Errorf("%q: %v", key, err)
		}
		out = append(out, f)
	}
	return out, nil
}

// parseResultJSON reads result.json, which the work container wrote and so
// cannot be trusted, by the exact spelling of its keys (a repeated key, or two
// that differ only in case, is refused) and requires what the format requires:
// the protocol, the status and the duration, every step's id, op, argv, exit
// code and duration. A required member that is missing, null or of another
// type is an error and never the zero value, which for an exit code would be
// success.
func parseResultJSON(raw []byte) (worker.Result, error) {
	var res worker.Result
	if len(raw) > worker.MaxResultBytes {
		return res, fmt.Errorf("it is over %d bytes", worker.MaxResultBytes)
	}
	top, err := strictObject(raw)
	if err != nil {
		return res, err
	}
	n, err := reqInt(top, "protocol")
	if err != nil {
		return res, err
	}
	res.Protocol = int(n)
	status, err := reqString(top, "status")
	if err != nil {
		return res, err
	}
	res.Status = worker.Status(status)
	mgr, err := optString(top, "manager")
	if err != nil {
		return res, err
	}
	res.Manager = worker.Manager(mgr)
	if res.Error, err = optString(top, "error"); err != nil {
		return res, err
	}
	if res.DurationMS, err = reqInt(top, "duration_ms"); err != nil {
		return res, err
	}
	stepsRaw, ok := top["steps"]
	if !ok {
		return res, errors.New(`"steps" is missing`)
	}
	var steps []json.RawMessage
	if err := json.Unmarshal(stepsRaw, &steps); err != nil || steps == nil {
		return res, errors.New(`"steps" is not a list`)
	}
	if len(steps) > worker.MaxSteps {
		return res, fmt.Errorf("it lists more than %d steps", worker.MaxSteps)
	}
	for i, sr := range steps {
		sm, err := strictObject(sr)
		if err != nil {
			return res, fmt.Errorf("step %d: %v", i+1, err)
		}
		var s worker.StepResult
		wrap := func(err error) error { return fmt.Errorf("step %d: %v", i+1, err) }
		if s.ID, err = reqString(sm, "id"); err != nil {
			return res, wrap(err)
		}
		op, err := reqString(sm, "op")
		if err != nil {
			return res, wrap(err)
		}
		s.Op = worker.Op(op)
		if s.Scratch, err = optBool(sm, "scratch"); err != nil {
			return res, wrap(err)
		}
		if s.Argv, err = stringList(sm, "argv", true); err != nil {
			return res, wrap(err)
		}
		code, err := reqInt(sm, "exit_code")
		if err != nil {
			return res, wrap(err)
		}
		s.ExitCode = int(code)
		if s.DurationMS, err = reqInt(sm, "duration_ms"); err != nil {
			return res, wrap(err)
		}
		if s.TimedOut, err = optBool(sm, "timed_out"); err != nil {
			return res, wrap(err)
		}
		for key, dst := range map[string]*string{"error": &s.Error, "stdout": &s.Stdout, "stderr": &s.Stderr, "reason": &s.Reason} {
			if *dst, err = optString(sm, key); err != nil {
				return res, wrap(err)
			}
		}
		if s.OutputTruncated, err = optBool(sm, "output_truncated"); err != nil {
			return res, wrap(err)
		}
		if s.UnexpectedPaths, err = stringList(sm, "unexpected_paths", false); err != nil {
			return res, wrap(err)
		}
		cnt, err := optInt(sm, "unexpected_count")
		if err != nil {
			return res, wrap(err)
		}
		s.UnexpectedCount = int(cnt)
		if s.Outputs, err = readOutputFiles(sm, "outputs"); err != nil {
			return res, wrap(err)
		}
		res.Steps = append(res.Steps, s)
	}
	if res.Final, err = readOutputFiles(top, "final"); err != nil {
		return res, err
	}
	return res, nil
}

// Bounds on what the container may return, in terms of what it was given. An
// honest update changes a lockfile a little; a file much larger than its input
// is not an update, and the checks that follow would be spent on it.
const (
	outputGrowthNum   = 5 // outputs may be 1.25 times their input...
	outputGrowthDen   = 4
	outputGrowthSlack = 512 << 10 // ...plus this much
	reportBase        = 4 << 20   // a pip report: this much...
	reportPerLine     = 1 << 20   // ...plus this much per line of the requirements
)

// outputSizeFailure refuses a returned file that is larger than its bound:
// the manager's own files by the size of the file of that name that was sent,
// the pip report by the number of lines of the requirements. The absolute
// bound of the job format applies to all of them.
func outputSizeFailure(job worker.Job, inputs map[string][]byte, files map[string][]byte) *updateFailure {
	for path, content := range files {
		name := path[strings.LastIndex(path, "/")+1:]
		limit := int64(worker.MaxOutputFileBytes)
		switch in, isInput := inputs[name]; {
		case isInput:
			if l := int64(len(in))*outputGrowthNum/outputGrowthDen + outputGrowthSlack; l < limit {
				limit = l
			}
		case name == worker.PipReportName:
			lines := int64(bytes.Count(inputs["requirements.txt"], []byte("\n")) + 1)
			if l := reportBase + reportPerLine*lines; l < limit {
				limit = l
			}
		}
		if int64(len(content)) > limit {
			return manualFailure(ReasonOutputFilesInvalid, "%s is %d bytes, over the %d bytes an update of the file it was made from can come to", path, len(content), limit)
		}
	}
	return nil
}
