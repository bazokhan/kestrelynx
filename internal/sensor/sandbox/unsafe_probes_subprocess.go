package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// unsafeProbeEnvVar, when set to "1" in this process's environment,
// diverts it — via this file's init(), before main() ever runs — into
// running the two RunUnsafeProbes checks and reporting their outcome as
// its own exit code, then exiting. Any binary that imports this package
// gains this hidden mode; RunUnsafeProbesInSubprocess is what sets the
// variable and execs a fresh copy of the running binary to reach it, which
// is what makes the probes safe to run from a long-lived caller (see
// RunUnsafeProbes's doc comment for exactly what is unsafe about running
// them inline).
const unsafeProbeEnvVar = "KL_SANDBOX_RUN_UNSAFE_PROBES"

func init() {
	if os.Getenv(unsafeProbeEnvVar) == "1" {
		runUnsafeProbeChild()
	}
}

// unsafeProbeTimeout bounds how long RunUnsafeProbesInSubprocess waits for
// its child: both probes complete in microseconds under every outcome this
// package accounts for (denied, allowed-then-immediately-exited-via-exec,
// or allowed-and-about-to-be-stopped-by-a-signal), so a generous multi-
// second bound only ever matters for the one case that has no other
// safeguard — PTRACE_TRACEME succeeding and the child then stopping before
// it reaches its own exit call. Without this, that case hangs
// RunUnsafeProbesInSubprocess (and therefore the caller's own self-check)
// indefinitely instead of surfacing as an error.
const unsafeProbeTimeout = 5 * time.Second

// exitCodeSetupFailed is runUnsafeProbeChild's exit code for a failure
// during its own setup (SetNoNewPrivsAll/ObserverFilter/InstallFilter) —
// before either probe was even attempted. It is chosen to sit outside
// reportCode's whole output range (100-122) so it can never be confused
// with a real probe report.
const exitCodeSetupFailed = 99

// reportBase anchors runUnsafeProbeChild's normal-completion exit codes
// (reportCode's output, 100-122) in a range that cannot collide with the
// exit code of whatever execve replaces this process with on a successful
// (i.e. not denied) exec attempt — see reportCode's doc comment for why
// that collision is exactly the bug this constant exists to avoid.
const reportBase = 100

// probeOutcome values, encoded into the low two decimal digits of
// runUnsafeProbeChild's exit code by reportCode.
const (
	probeOutcomeDenied     = 0 // errno was EPERM
	probeOutcomeAllowed    = 1 // the attempt succeeded
	probeOutcomeUnexpected = 2 // some other errno
)

// reportCode encodes both probes' outcomes into one process exit code:
// reportBase + execOutcome*10 + ptraceOutcome. This is the only reporting
// channel runUnsafeProbeChild can safely use once it has attempted
// ptrace(PTRACE_TRACEME) — see its doc comment for why it does not, e.g.,
// write a result to a pipe afterward instead.
//
// Without reportBase's offset, a successful (execOutcome == allowed)
// execve would exit via /bin/true replacing this process entirely, never
// reaching this call at all — and /bin/true's own exit code, 0, is
// indistinguishable from reportCode(probeOutcomeDenied, probeOutcomeDenied)
// (= 0) without the offset, which is exactly the collision the offset
// prevents: a successful exec would otherwise decode as "both denied".
// With the offset, any exit code RunUnsafeProbesInSubprocess sees outside
// [reportBase, reportBase+22] can only have come from whatever execve
// exec'd into, not from this function, however the day, reportOK
// upper-bounds it in decodeReportCode to be sure of the range.
func reportCode(execOutcome, ptraceOutcome int) int {
	return reportBase + execOutcome*10 + ptraceOutcome
}

// decodeReportCode reverses reportCode, and reports ok=false for any code
// that could not have come from it (including 0, /bin/true's own exit
// code) — see reportCode's doc comment.
func decodeReportCode(code int) (execOutcome, ptraceOutcome int, ok bool) {
	rel := code - reportBase
	if rel < 0 || rel > 22 {
		return 0, 0, false
	}
	execOutcome, ptraceOutcome = rel/10, rel%10
	if execOutcome > probeOutcomeUnexpected || ptraceOutcome > probeOutcomeUnexpected {
		return 0, 0, false
	}
	return execOutcome, ptraceOutcome, true
}

func classifyProbeErr(err error) int {
	switch {
	case err == nil:
		return probeOutcomeAllowed
	case err == unix.EPERM:
		return probeOutcomeDenied
	default:
		return probeOutcomeUnexpected
	}
}

// runUnsafeProbeChild is this process's entire job once unsafeProbeEnvVar
// is set: apply the same restrictions the real observer applies to itself
// (NO_NEW_PRIVS, then ObserverFilter — the (b) layer condition 3's probes
// exist to check), then run the two unsafe probes and exit with their
// combined result.
//
// The two probes are attempted in a specific order for a specific reason.
// execve first: if it is not denied, this process is immediately replaced
// by /bin/true and none of this function's own code runs again, so there
// is nothing to protect. ptrace(PTRACE_TRACEME) last, with nothing but the
// exit call after it: per ptrace(2), a successful PTRACE_TRACEME does not
// itself stop the caller — the *next* signal delivery or execve does — so
// the only way to keep that from happening here is to do as close to
// nothing as possible between the probe and calling syscall.Exit directly
// (not os.Exit, which runs registered exit hooks first; every extra
// instruction here is a wider window for some unrelated signal, such as
// the Go runtime's own async-preemption signal to another goroutine, to
// arrive and trigger exactly the permanent stop this package's own tests
// hit before this ordering existed). RunUnsafeProbesInSubprocess starts
// this child with asynchronous preemption turned off, which removes that
// runtime signal, and its own timeout is the backstop for the residual
// risk that some other signal arrives in that narrow window anyway.
func runUnsafeProbeChild() {
	if err := SetNoNewPrivsAll(); err != nil {
		syscall.Exit(exitCodeSetupFailed)
	}
	filter, err := ObserverFilter(int32(os.Getpid()))
	if err != nil {
		syscall.Exit(exitCodeSetupFailed)
	}
	if err := InstallFilter(filter); err != nil {
		syscall.Exit(exitCodeSetupFailed)
	}

	execErr := unix.Exec("/bin/true", []string{"/bin/true"}, nil)
	execOutcome := classifyProbeErr(execErr)

	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_TRACEME, 0, 0, 0, 0, 0)
	var ptraceErr error
	if errno != 0 {
		ptraceErr = errno
	}
	ptraceOutcome := classifyProbeErr(ptraceErr)

	syscall.Exit(reportCode(execOutcome, ptraceOutcome))
}

// asyncPreemptOff returns the GODEBUG setting of the probe child: the
// caller's own settings with asynchronous preemption turned off, so the Go
// runtime sends no preemption signal that could stop the child between a
// successful PTRACE_TRACEME and its exit.
func asyncPreemptOff(godebug string) string {
	if godebug == "" {
		return "asyncpreemptoff=1"
	}
	return godebug + ",asyncpreemptoff=1"
}

// RunUnsafeProbesInSubprocess runs RunUnsafeProbes (execve,
// ptrace(PTRACE_TRACEME)) safely by re-executing the current binary with
// unsafeProbeEnvVar set, so the two probes that can irrecoverably change a
// process's own state run in a disposable child instead of the caller. It
// waits at most unsafeProbeTimeout before killing that child and returning
// an error, so a child that PTRACE_TRACEME left permanently stopped cannot
// hang the caller indefinitely.
//
// Callers must invoke this before installing their own ObserverFilter, not
// after: once that filter is active, execve is denied unconditionally
// (by condition 3), so the calling process could no longer start
// this subprocess at all — the same reason the parser has to be spawned
// before the observer's own filter goes live. The child applies
// ObserverFilter to itself regardless, so the results reflect what the
// real observer's filter does, independent of when the caller happens to
// invoke this.
func RunUnsafeProbesInSubprocess() ([]Probe, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("sandbox: run unsafe probes: locate executable: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), unsafeProbeTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, exe)
	cmd.Env = append(os.Environ(), unsafeProbeEnvVar+"=1", "GODEBUG="+asyncPreemptOff(os.Getenv("GODEBUG")))
	cmd.Stderr = os.Stderr

	runErr := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("sandbox: run unsafe probes: subprocess did not exit within %s (ptrace(PTRACE_TRACEME) likely succeeded and left it stopped; killed)", unsafeProbeTimeout)
	}

	code := 0
	if runErr != nil {
		exitErr, ok := runErr.(*exec.ExitError)
		if !ok {
			return nil, fmt.Errorf("sandbox: run unsafe probes: start subprocess: %w", runErr)
		}
		code = exitErr.ExitCode()
		if code == -1 {
			return nil, fmt.Errorf("sandbox: run unsafe probes: subprocess terminated by a signal instead of exiting (%v)", exitErr)
		}
	}

	if code == exitCodeSetupFailed {
		return nil, fmt.Errorf("sandbox: run unsafe probes: subprocess failed its own setup before attempting either probe")
	}

	return probesFromExitCode(code), nil
}

// probesFromExitCode turns runUnsafeProbeChild's exit code into the two
// Probe results, split out from RunUnsafeProbesInSubprocess so the
// exec/report-code decoding logic — where a successful execve's exit
// code, 0, must not decode as "both probes denied" instead of "execve
// allowed" — can be checked
// directly against every code value that matters (0, the setup-failure
// code, each valid report code, and an arbitrary other exit code) without
// needing a live subprocess for each case.
func probesFromExitCode(code int) []Probe {
	if execOutcome, ptraceOutcome, ok := decodeReportCode(code); ok {
		return []Probe{
			{Name: "execve", Err: outcomeToProbeErr(execOutcome)},
			{Name: "ptrace(PTRACE_TRACEME)", Err: outcomeToProbeErr(ptraceOutcome)},
		}
	}

	// code is not one of runUnsafeProbeChild's own reserved report codes,
	// so it can only be the exit code of whatever execve succeeded in
	// running (/bin/true, exiting 0, in the normal case): execve was
	// allowed, and the process image was replaced before the
	// ptrace(PTRACE_TRACEME) probe — which runs after the exec attempt —
	// ever got a chance to run.
	return []Probe{
		{Name: "execve", Err: nil},
		{Name: "ptrace(PTRACE_TRACEME)", Err: fmt.Errorf("sandbox: not attempted: execve succeeded first (subprocess exited %d, running whatever it was exec'd into)", code)},
	}
}

func outcomeToProbeErr(outcome int) error {
	switch outcome {
	case probeOutcomeDenied:
		return unix.EPERM
	case probeOutcomeAllowed:
		return nil
	default:
		return fmt.Errorf("sandbox: unsafe probe subprocess reported outcome %d", outcome)
	}
}
