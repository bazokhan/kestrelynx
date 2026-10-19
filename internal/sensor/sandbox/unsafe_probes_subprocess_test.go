package sandbox

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestReportCode_RoundTrips covers every value reportCode can actually
// produce (execOutcome, ptraceOutcome each in {denied, allowed,
// unexpected}) decoding back to itself.
func TestReportCode_RoundTrips(t *testing.T) {
	outcomes := []int{probeOutcomeDenied, probeOutcomeAllowed, probeOutcomeUnexpected}
	for _, exec := range outcomes {
		for _, ptrace := range outcomes {
			code := reportCode(exec, ptrace)
			gotExec, gotPtrace, ok := decodeReportCode(code)
			if !ok {
				t.Errorf("decodeReportCode(reportCode(%d, %d)=%d) ok=false, want true", exec, ptrace, code)
				continue
			}
			if gotExec != exec || gotPtrace != ptrace {
				t.Errorf("decodeReportCode(%d) = (%d, %d), want (%d, %d)", code, gotExec, gotPtrace, exec, ptrace)
			}
		}
	}
}

// TestDecodeReportCode_RejectsCodesOutsideItsOwnRange is the regression
// test for an exit-code collision: exit code 0 —
// which is what /bin/true exits with after a successful (not denied)
// execve, and is also runUnsafeProbeChild's own reportCode(denied, denied)
// *before* reportBase's offset existed — must decode as "not one of ours"
// (ok=false), not silently as "both probes denied".
func TestDecodeReportCode_RejectsCodesOutsideItsOwnRange(t *testing.T) {
	for _, code := range []int{0, 1, 2, 42, exitCodeSetupFailed, reportBase - 1, reportBase + 23, 255} {
		if _, _, ok := decodeReportCode(code); ok {
			t.Errorf("decodeReportCode(%d) ok=true, want false (outside the reserved report range)", code)
		}
	}
}

// TestProbesFromExitCode covers the three shapes RunUnsafeProbesInSubprocess
// must tell apart from a bare exit code: a real report (both probes
// denied, the expected case under a working ObserverFilter), and an
// unreported code (standing in for execve having succeeded and replaced
// the process before ptrace(PTRACE_TRACEME) ever ran — see
// probesFromExitCode's doc comment for why any code outside the reserved
// range means exactly that).
func TestProbesFromExitCode(t *testing.T) {
	t.Run("both denied", func(t *testing.T) {
		probes := probesFromExitCode(reportCode(probeOutcomeDenied, probeOutcomeDenied))
		if len(probes) != 2 {
			t.Fatalf("got %d probes, want 2", len(probes))
		}
		for _, p := range probes {
			if !p.Denied() {
				t.Errorf("%s: Err = %v, want EPERM (denied)", p.Name, p.Err)
			}
		}
	})

	t.Run("execve allowed, ptrace unexpected errno", func(t *testing.T) {
		probes := probesFromExitCode(reportCode(probeOutcomeAllowed, probeOutcomeUnexpected))
		byName := map[string]Probe{}
		for _, p := range probes {
			byName[p.Name] = p
		}
		if err := byName["execve"].Err; err != nil {
			t.Errorf("execve.Err = %v, want nil (allowed)", err)
		}
		if !byName["ptrace(PTRACE_TRACEME)"].Unexpected() {
			t.Errorf("ptrace.Err = %v, want Unexpected()", byName["ptrace(PTRACE_TRACEME)"].Err)
		}
	})

	t.Run("exit code 0 means execve succeeded, not both denied", func(t *testing.T) {
		// The exact regression this test exists for: before reportBase's
		// offset, this decoded as reportCode(denied, denied) = 0.
		probes := probesFromExitCode(0)
		byName := map[string]Probe{}
		for _, p := range probes {
			byName[p.Name] = p
		}
		execProbe, ok := byName["execve"]
		if !ok {
			t.Fatalf("no execve probe in result: %+v", probes)
		}
		if execProbe.Err != nil {
			t.Errorf("execve.Err = %v, want nil (execve must be reported ALLOWED, not denied, for exit code 0)", execProbe.Err)
		}
		if execProbe.Denied() {
			t.Errorf("execve.Denied() = true for exit code 0, want false")
		}
		ptraceProbe, ok := byName["ptrace(PTRACE_TRACEME)"]
		if !ok {
			t.Fatalf("no ptrace probe in result: %+v", probes)
		}
		if ptraceProbe.Err == nil || ptraceProbe.Err == unix.EPERM {
			t.Errorf("ptrace.Err = %v, want a non-nil, non-EPERM error (never actually attempted)", ptraceProbe.Err)
		}
		if ptraceProbe.Denied() {
			t.Errorf("ptrace.Denied() = true when the probe was never attempted, want false")
		}
	})

	t.Run("some other arbitrary exit code also means execve succeeded", func(t *testing.T) {
		probes := probesFromExitCode(7) // whatever the exec'd program happened to exit with
		for _, p := range probes {
			if p.Name == "execve" && p.Err != nil {
				t.Errorf("execve.Err = %v, want nil", p.Err)
			}
		}
	})
}

// TestRunUnsafeProbesInSubprocess_Integration runs the real subprocess end
// to end (not just the exit-code decoding logic above). execve must come
// back denied: ObserverFilter denies it unconditionally by itself, with no
// dependency on the distributed container-wide profile (a). ptrace
// (PTRACE_TRACEME) is a different story — ObserverFilter does not restrict
// it at all, only (a) does, and this test runs with no (a) present (a raw
// process, not a Docker deployment; see scripts/gen_sensor_seccomp_profile.py)
// — so it is expected to come back *not* denied here. That is not a
// failure of this test: it is the known, already-documented gap
// TestSelfCheckProbes_WithoutContainerProfile_ReportsPossibleGaps and
// TestRunObserverSelfCheck_EndToEnd also exercise. What this test actually
// proves is the thing that used to hang before RunUnsafeProbesInSubprocess
// existed: PTRACE_TRACEME succeeding here does not stop the subprocess
// before it reports back, and RunUnsafeProbesInSubprocess returns promptly
// with a real, unambiguous result instead of blocking forever.
func TestRunUnsafeProbesInSubprocess_Integration(t *testing.T) {
	probes, err := RunUnsafeProbesInSubprocess()
	if err != nil {
		t.Fatalf("RunUnsafeProbesInSubprocess: %v", err)
	}
	if len(probes) != 2 {
		t.Fatalf("got %d probes, want 2: %+v", len(probes), probes)
	}
	byName := map[string]Probe{}
	for _, p := range probes {
		byName[p.Name] = p
	}
	if !byName["execve"].Denied() {
		t.Errorf("execve: Err = %v, want denied (ObserverFilter denies it unconditionally, independent of profile (a))", byName["execve"].Err)
	}
	if _, ok := byName["ptrace(PTRACE_TRACEME)"]; !ok {
		t.Fatalf("missing ptrace(PTRACE_TRACEME) result: %+v", probes)
	}
}

func TestAsyncPreemptOffKeepsTheCallersSettings(t *testing.T) {
	if got := asyncPreemptOff(""); got != "asyncpreemptoff=1" {
		t.Errorf("empty GODEBUG gives %q", got)
	}
	if got := asyncPreemptOff("madvdontneed=1"); got != "madvdontneed=1,asyncpreemptoff=1" {
		t.Errorf("existing GODEBUG gives %q", got)
	}
	// The setting added last wins over one the caller already had.
	if got := asyncPreemptOff("asyncpreemptoff=0"); got != "asyncpreemptoff=0,asyncpreemptoff=1" {
		t.Errorf("GODEBUG turning preemption on gives %q", got)
	}
}
