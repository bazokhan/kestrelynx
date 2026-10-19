// Command helpermain is the real, standalone process every sandbox package
// test that installs a seccomp filter or a Landlock ruleset execs as a
// child: not the `go test` binary re-exec'd on itself.
//
// This distinction matters and was found empirically, not assumed. A `go
// test` binary carries the testing package's own machinery, which installs
// a SIGQUIT handler via os/signal for the -test.timeout stack-dump feature;
// that alone initializes the Go runtime's epoll-based netpoller within the
// first instant of the process's life, before a test even gets to install
// its filter. A plain standalone binary defers that initialization until
// the runtime actually needs it — which, on Go 1.26, still happens to any
// sufficiently long-lived process (this package's own tests found this out
// by crashing): a forced GC or a timer eventually calls into
// runtime.netpollinit(), which needs epoll_create1, eventfd2, epoll_ctl and
// epoll_pwait, and runtime.netpollBreak() afterwards calls a bare write(2)
// on the poller's own wake-up fd. ParserFilter's allow-list accounts for
// all of that (see its doc comment for the acknowledged trade-off of
// allowing write(2) at all). Using this standalone binary instead of the
// test binary itself only changes *when* that initialization is forced to
// happen: later and only if the test actually keeps the process alive long
// enough (e.g. TestAsyncPreemption_SurvivesParserFilter, which forces a
// GC), not on every test regardless of what it is checking.
//
// Every role below mirrors what the startup order asks of the
// observer or the parser, run in isolation so a test can check one claim
// at a time. It reports results either by printing "name=OUTCOME" lines to
// stdout (roles that never install ParserFilter) or, once ParserFilter's
// allow-list is active, by sendmsg on fd 3 (see resultFD) — the same
// primitive the real parser uses to reply to the observer. write(2) to
// stdout would in fact still succeed once ParserFilter is installed (see
// its doc comment), but a helper standing in for the parser reports over
// the socket anyway, the same way the real parser always will.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/sensor/sandbox"
	"golang.org/x/sys/unix"
)

// parserResultFD is the fd number a role running under ParserFilter reports
// on once installed: index 0 of exec.Cmd.ExtraFiles always lands at fd 3 in
// the child (fds 0-2 being stdin/stdout/stderr; os/exec's documented
// behavior).
const parserResultFD = 3

func main() {
	role := os.Getenv("KL_SANDBOX_HELPER")
	switch role {
	case "observer-filter":
		observerFilter()
	case "parser-filter":
		parserFilter()
	case "landlock-all-threads":
		landlockAllThreads()
	case "async-preempt":
		asyncPreempt(role)
	case "async-preempt-parser":
		asyncPreempt(role)
	case "self-check-probes":
		selfCheckProbes()
	case "parser-longlived":
		parserLonglived()
	case "self-check-full":
		selfCheckFull()
	default:
		fmt.Fprintf(os.Stderr, "unknown role %q (set KL_SANDBOX_HELPER)\n", role)
		os.Exit(2)
	}
	os.Exit(3) // unreachable: every case above exits itself
}

func resultLine(name string, err error) string {
	switch {
	case err == nil:
		return fmt.Sprintf("%s=ALLOWED", name)
	case err == unix.EPERM || err == unix.EACCES:
		return fmt.Sprintf("%s=DENIED:%v", name, err)
	default:
		return fmt.Sprintf("%s=ERROR:%v", name, err)
	}
}

func result(name string, err error) { fmt.Println(resultLine(name, err)) }

func resultFD(fd int, name string, err error) {
	line := resultLine(name, err)
	if sendErr := unix.Sendmsg(fd, []byte(line), nil, nil, 0); sendErr != nil {
		fmt.Fprintf(os.Stderr, "resultFD sendmsg(%q): %v\n", line, sendErr)
	}
}

func die(step string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", step, err)
	os.Exit(1)
}

func observerFilter() {
	// Locked onto n real OS threads and parked *before* NO_NEW_PRIVS or the
	// seccomp filter exist, so releasing them afterward checks specific,
	// pre-existing TIDs by number — the actual guarantee TSYNC and
	// AllThreadsSyscall6 make — rather than only threads a caller happens
	// to create after setup, which would look identical even if thread
	// synchronization were silently broken (a freshly cloned thread
	// inherits NO_NEW_PRIVS/seccomp from its creator regardless of TSYNC).
	const nPre = 4
	preTIDs := make(chan int, nPre)
	proceed := make(chan struct{})
	preDone := make(chan string, nPre)
	for i := 0; i < nPre; i++ {
		i := i
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			preTIDs <- unix.Gettid()
			<-proceed
			_, err := unix.Openat(unix.AT_FDCWD, "/tmp/kl-sandbox-test-should-not-be-created-pre", unix.O_WRONLY|unix.O_CREAT, 0o600)
			preDone <- fmt.Sprintf("pre_existing_thread_%d=%s", i, resultOutcome(err))
		}()
	}
	collectedTIDs := make([]int, nPre)
	for i := 0; i < nPre; i++ {
		collectedTIDs[i] = <-preTIDs
	}

	pid := int32(os.Getpid())
	if err := sandbox.SetNonDumpable(); err != nil {
		die("SetNonDumpable", err)
	}
	if err := sandbox.SetNoNewPrivsAll(); err != nil {
		die("SetNoNewPrivsAll", err)
	}
	filter, err := sandbox.ObserverFilter(pid)
	if err != nil {
		die("ObserverFilter", err)
	}
	if err := sandbox.InstallFilter(filter); err != nil {
		die("InstallFilter", err)
	}
	close(proceed)
	for i := 0; i < nPre; i++ {
		fmt.Println(<-preDone)
	}
	statuses, err := sandbox.ReadTaskStatuses(os.Getpid())
	if err != nil {
		die("ReadTaskStatuses", err)
	}
	byTID := make(map[int]sandbox.TaskStatus, len(statuses))
	for _, st := range statuses {
		byTID[st.TID] = st
	}
	for _, tid := range collectedTIDs {
		st, ok := byTID[tid]
		if !ok {
			fmt.Printf("proc_status_pre_tid_%d=MISSING\n", tid)
			continue
		}
		fmt.Printf("proc_status_pre_tid_%d=NoNewPrivs:%d,Seccomp:%d\n", tid, st.NoNewPrivs, st.Seccomp)
	}

	// unix.Open is implemented on top of openat(2) on every architecture
	// (golang.org/x/sys/unix, syscall_linux.go), so this exercises the
	// same openat write-flags check as openat_wronly_creat below, not the
	// raw open(2) syscall number — see probeLegacyOpenCreat for that.
	_, errOpenWrite := unix.Open("/tmp/kl-sandbox-test-should-not-be-created", unix.O_WRONLY|unix.O_CREAT, 0o600)
	result("open_via_openat_wronly_creat", errOpenWrite)

	_, errOpenatWrite := unix.Openat(unix.AT_FDCWD, "/tmp/kl-sandbox-test-should-not-be-created2", unix.O_WRONLY|unix.O_CREAT, 0o600)
	result("openat_wronly_creat", errOpenatWrite)

	// The raw open(2)/creat(2) syscalls by number — a no-op on arm64,
	// where they don't exist (see legacy_arm64.go).
	probeLegacyOpenCreat()

	_, errOpenatRead := unix.Openat(unix.AT_FDCWD, "/dev/null", unix.O_RDONLY, 0)
	result("openat_rdonly", errOpenatRead)

	_, errOpenat2 := unix.Openat2(unix.AT_FDCWD, "/dev/null", &unix.OpenHow{Flags: unix.O_RDONLY})
	result("openat2", errOpenat2)

	errExec := unix.Exec("/bin/true", []string{"/bin/true"}, nil)
	result("execve", errExec)

	errKill := unix.Kill(os.Getpid(), unix.Signal(0))
	result("kill_self_sig0", errKill)

	runtime.LockOSThread()
	tid := unix.Gettid()
	errTgkillSelf := unix.Tgkill(os.Getpid(), tid, unix.Signal(0))
	result("tgkill_self", errTgkillSelf)
	errTgkillOther := unix.Tgkill(os.Getpid()+1, tid, unix.Signal(0))
	result("tgkill_other", errTgkillOther)
	runtime.UnlockOSThread()

	_, errSocketpair := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	result("socketpair", errSocketpair)

	os.Exit(0)
}

func parserFilter() {
	pid := int32(os.Getpid())
	if err := sandbox.SetNonDumpable(); err != nil {
		die("SetNonDumpable", err)
	}
	// landlock_restrict_self (like seccomp) requires the calling thread to
	// already have NO_NEW_PRIVS, or CAP_SYS_ADMIN (which the parser never
	// has): kernel v6.6 security/landlock/syscalls.c,
	// sys_landlock_restrict_self. Confirmed empirically by this package's
	// own tests before this call existed (RestrictAllFiles returned EPERM
	// on every thread without it).
	if err := sandbox.SetNoNewPrivsAll(); err != nil {
		die("SetNoNewPrivsAll", err)
	}
	abi, err := sandbox.RestrictAllFiles()
	if err != nil {
		die("RestrictAllFiles", err)
	}
	fmt.Printf("landlock_abi=%d\n", abi)

	filter, err := sandbox.ParserFilter(pid)
	if err != nil {
		die("ParserFilter", err)
	}
	if err := sandbox.InstallFilter(filter); err != nil {
		die("InstallFilter", err)
	}

	_, errOpenat := unix.Openat(unix.AT_FDCWD, "/etc/hostname", unix.O_RDONLY, 0)
	resultFD(parserResultFD, "openat_rdonly", errOpenat)

	_, errOpen := unix.Open("/etc/hostname", unix.O_RDONLY, 0)
	resultFD(parserResultFD, "open_rdonly", errOpen)

	os.Exit(0)
}

// landlockAllThreads proves RestrictAllFiles reaches OS threads that
// already existed *before* it was called, not just ones a caller happens
// to create afterward (which would pass even if AllThreadsSyscall6 were
// silently broken and Landlock only ever ended up on the calling thread,
// since a freshly cloned thread inherits Landlock's domain from whichever
// thread created it regardless). It does this by locking n goroutines onto
// n distinct OS threads and parking them on a channel receive *before*
// calling RestrictAllFiles, collecting each parked thread's real TID, then
// releasing them only after the restriction is in place — so every TID
// this test checks is one AllThreadsSyscall6 had to reach directly.
//
// It checks each of those TIDs twice: behaviorally (does an open attempt
// on that specific thread fail) and via /proc/self/task/<tid>/status
// (does NoNewPrivs read back as 1 for that same thread) — Landlock itself
// leaves no equivalent per-thread /proc field, so the open attempt is the
// only direct evidence of its domain, but NoNewPrivs corroborates that
// thread was reached by the *same* AllThreadsSyscall6 mechanism at all
// (SetNoNewPrivsAll is called with the same all-threads primitive
// immediately before RestrictAllFiles requires it).
func landlockAllThreads() {
	const n = 8
	tids := make(chan int, n)
	proceed := make(chan struct{})
	done := make(chan string, n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			tids <- unix.Gettid()
			<-proceed // parked on an already-existing OS thread, pre-restriction
			_, err := unix.Open("/etc/hostname", unix.O_RDONLY, 0)
			done <- fmt.Sprintf("thread_%d=%s", i, resultOutcome(err))
		}()
	}
	preTIDs := make([]int, n)
	for i := 0; i < n; i++ {
		preTIDs[i] = <-tids
	}

	if err := sandbox.SetNoNewPrivsAll(); err != nil {
		die("SetNoNewPrivsAll", err)
	}

	// /proc/self/task must be read here, between SetNoNewPrivsAll and
	// RestrictAllFiles: Landlock's own deny-all-by-default ruleset (no
	// rules are ever added to it) applies to *every* path once active,
	// /proc included, so reading it after RestrictAllFiles would itself
	// be denied — that's a consequence of Landlock working correctly, not
	// a way to inspect its effect on other threads.
	statuses, err := sandbox.ReadTaskStatuses(os.Getpid())
	if err != nil {
		die("ReadTaskStatuses", err)
	}
	byTID := make(map[int]sandbox.TaskStatus, len(statuses))
	for _, st := range statuses {
		byTID[st.TID] = st
	}

	if _, err := sandbox.RestrictAllFiles(); err != nil {
		die("RestrictAllFiles", err)
	}
	close(proceed)

	for i := 0; i < n; i++ {
		fmt.Println(<-done)
	}
	for _, tid := range preTIDs {
		st, ok := byTID[tid]
		if !ok {
			fmt.Printf("proc_status_tid_%d=MISSING\n", tid)
			continue
		}
		fmt.Printf("proc_status_tid_%d=NoNewPrivs:%d\n", tid, st.NoNewPrivs)
	}
	os.Exit(0)
}

func resultOutcome(err error) string {
	if err == nil {
		return "ALLOWED"
	}
	return fmt.Sprintf("DENIED:%v", err)
}

// asyncPreempt proves the Go runtime's async-preemption signal
// (tgkill(getpid(), tid, SIGURG), then rt_sigreturn from the handler) still
// works once the filter for role is installed: it runs more call-free busy
// loops than GOMAXPROCS and confirms runtime.GC() still completes.
//
// For the parser role, GOMAXPROCS is pinned to 1 first. clone/clone3 are
// deliberately not in ParserFilter's allow-list (a compromised parser
// should not be able to create new execution contexts), and this was
// confirmed the hard way: with the default GOMAXPROCS, spawning several
// CPU-bound goroutines makes the scheduler hand a P to a new M, which
// needs clone() and crashes the runtime outright once it is denied. With
// GOMAXPROCS(1) there is only ever one P, so the scheduler has no second P
// to hand off in the first place — matching the real parser, which is a
// single mostly-blocked-on-recvmsg goroutine with nothing else runnable
// for sysmon to hand its P to even when that syscall blocks.
func asyncPreempt(role string) {
	pid := int32(os.Getpid())

	// Locked onto their own OS threads and parked *before* the filter
	// exists, so the busy loops below are guaranteed to run on TIDs that
	// predate TSYNC/AllThreadsSyscall6, not threads the runtime happens to
	// create afterward (which would inherit the filter from whichever
	// existing thread clones them regardless of whether TSYNC itself
	// worked). This is what makes "GC completes" evidence that async
	// preemption reaches an existing thread specifically, not just new
	// ones.
	n := 3
	if role != "async-preempt-parser" {
		n = runtime.GOMAXPROCS(0) + 2
	}
	tids := make(chan int, n)
	proceed := make(chan struct{})
	stop := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			tids <- unix.Gettid()
			<-proceed
			x := 0
			for {
				select {
				case <-stop:
					return
				default:
				}
				for j := 0; j < 1<<28; j++ {
					x += j
				}
				_ = x
			}
		}()
	}
	preTIDs := make([]int, n)
	for i := 0; i < n; i++ {
		preTIDs[i] = <-tids
	}

	var filter []unix.SockFilter
	var err error
	if role == "async-preempt-parser" {
		// clone/clone3 are deliberately absent from ParserFilter (see its
		// doc comment); GOMAXPROCS(1) here matches how the real parser
		// runs, so the runtime never needs a thread beyond the n it
		// already has parked above.
		runtime.GOMAXPROCS(1)
		if err := sandbox.SetNonDumpable(); err != nil {
			die("SetNonDumpable", err)
		}
		if err := sandbox.SetNoNewPrivsAll(); err != nil {
			die("SetNoNewPrivsAll", err)
		}
		if _, err := sandbox.RestrictAllFiles(); err != nil {
			die("RestrictAllFiles", err)
		}
		filter, err = sandbox.ParserFilter(pid)
	} else {
		if err := sandbox.SetNoNewPrivsAll(); err != nil {
			die("SetNoNewPrivsAll", err)
		}
		filter, err = sandbox.ObserverFilter(pid)
	}
	if err != nil {
		die("build filter", err)
	}
	if err := sandbox.InstallFilter(filter); err != nil {
		die("InstallFilter", err)
	}
	close(proceed) // release the pre-existing, now-filtered threads into their busy loops

	gcDone := make(chan struct{})
	go func() {
		// The sleep is deliberate, not padding: a goroutine created via
		// `go func(){ runtime.GC() }()` with no delay can get the Go
		// scheduler's "runnext" slot and run immediately after whatever
		// goroutine created it yields, without ever actually needing the
		// busy loops above to be asynchronously preempted — they might
		// not even have started running yet. Sleeping first forces this
		// goroutine to actually park on a timer and be woken back up,
		// which (see sandbox.ParserFilter's doc comment on getpid) is the
		// same mechanism, and the same one this whole test exists to
		// check, that failed silently until getpid was added to the
		// allow-list: without it, this sleep would simply never end while
		// the busy loops kept the sole P occupied.
		time.Sleep(50 * time.Millisecond)
		runtime.GC()
		close(gcDone)
	}()

	report := func(line string) {
		if role == "async-preempt-parser" {
			if sendErr := unix.Sendmsg(parserResultFD, []byte(line), nil, nil, 0); sendErr != nil {
				fmt.Fprintf(os.Stderr, "sendmsg(%q): %v\n", line, sendErr)
			}
			return
		}
		fmt.Println(line)
	}

	select {
	case <-gcDone:
		report(fmt.Sprintf("pre_existing_threads=%d", len(preTIDs)))
		report("gc=COMPLETED")
	case <-time.After(20 * time.Second):
		report("gc=TIMEOUT")
		close(stop)
		os.Exit(1)
	}
	close(stop)
	os.Exit(0)
}

// selfCheckProbes runs sandbox.RunProbes() in this disposable process:
// execve and ptrace(PTRACE_TRACEME), two of the probes, permanently change
// process state in ways nothing should rely on continuing to work normally
// afterward, so they only ever run in a process about to exit anyway.
func selfCheckProbes() {
	// The two unsafe probes run in a disposable child, the way the observer
	// runs them: a PTRACE_TRACEME that succeeds stops its caller at the next
	// signal, which would hang this helper and the test waiting for it. The
	// child applies ObserverFilter to itself, and has to be started before
	// this process installs that filter, which denies execve.
	unsafeProbes, err := sandbox.RunUnsafeProbesInSubprocess()
	if err != nil {
		die("RunUnsafeProbesInSubprocess", err)
	}
	if os.Getenv("KL_SANDBOX_APPLY_FILTER") == "observer" {
		pid := int32(os.Getpid())
		if err := sandbox.SetNoNewPrivsAll(); err != nil {
			die("SetNoNewPrivsAll", err)
		}
		filter, err := sandbox.ObserverFilter(pid)
		if err != nil {
			die("ObserverFilter", err)
		}
		if err := sandbox.InstallFilter(filter); err != nil {
			die("InstallFilter", err)
		}
	}
	for _, p := range sandbox.RunProbes() {
		result(p.Name, p.Err)
	}
	for _, p := range unsafeProbes {
		result(p.Name, p.Err)
	}
	os.Exit(0)
}

// parserLonglived applies exactly the restrictions a real parser applies
// (dumpable, NNP, Landlock, seccomp allow-list) and then sleeps instead of
// exiting immediately, so a test acting as the observer has a real,
// stably-running restricted process to read /proc/<pid>/task/*/status from.
// It prints "ready" once every restriction is in place — write(2) is in
// ParserFilter's allow-list for reasons unrelated to this (see
// sandbox.ParserFilter's doc comment), so this plain print still works.
func parserLonglived() {
	pid := int32(os.Getpid())
	if err := sandbox.SetNonDumpable(); err != nil {
		die("SetNonDumpable", err)
	}
	if err := sandbox.SetNoNewPrivsAll(); err != nil {
		die("SetNoNewPrivsAll", err)
	}
	if _, err := sandbox.RestrictAllFiles(); err != nil {
		die("RestrictAllFiles", err)
	}
	filter, err := sandbox.ParserFilter(pid)
	if err != nil {
		die("ParserFilter", err)
	}
	if err := sandbox.InstallFilter(filter); err != nil {
		die("InstallFilter", err)
	}
	fmt.Println("ready")
	time.Sleep(2 * time.Second)
	os.Exit(0)
}

// selfCheckFull exercises sandbox.RunObserverSelfCheck end to end: it
// applies the observer's own filter to itself, spawns a real
// parser-longlived child, waits for that child to report itself ready, and
// then runs the full self-check — including the "parser's threads" half,
// which reads a genuinely separate process's /proc/<pid>/task entries, not
// a mock of them.
func selfCheckFull() {
	// Both the parser and the unsafe-probe subprocess must be started
	// before this process installs its own ObserverFilter: that filter
	// denies execve unconditionally, and starting either one is itself an
	// execve from this process's point of view. This mirrors the real
	// observer's own constraint, not just a convenience for this helper.
	exe, err := os.Executable()
	if err != nil {
		die("os.Executable", err)
	}
	child := exec.Command(exe)
	child.Env = append(os.Environ(), "KL_SANDBOX_HELPER=parser-longlived")
	stdout, err := child.StdoutPipe()
	if err != nil {
		die("StdoutPipe", err)
	}
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		die("start parser-longlived", err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "ready\n" {
		die("read child readiness", fmt.Errorf("got %q, err %v", line, err))
	}

	unsafeProbes, err := sandbox.RunUnsafeProbesInSubprocess()
	if err != nil {
		die("RunUnsafeProbesInSubprocess", err)
	}

	selfPID := int32(os.Getpid())
	if err := sandbox.SetNonDumpable(); err != nil {
		die("SetNonDumpable", err)
	}
	if err := sandbox.SetNoNewPrivsAll(); err != nil {
		die("SetNoNewPrivsAll", err)
	}
	filter, err := sandbox.ObserverFilter(selfPID)
	if err != nil {
		die("ObserverFilter", err)
	}
	if err := sandbox.InstallFilter(filter); err != nil {
		die("InstallFilter", err)
	}

	// CAP_BPF/CAP_PERFMON: the two capabilities the real observer holds
	// only transiently, and must have dropped by the time it reaches this
	// self-check. This process never had them in the first place (no file
	// capability set on this test binary), so GuardedCaps here is
	// exercising that the check *runs* and correctly finds nothing —
	// TestRunObserverSelfCheck_EndToEnd is what confirms it actually reads
	// CapEff/CapPrm rather than trusting an assumption.
	report, err := sandbox.RunObserverSelfCheck(sandbox.ObserverSelfCheckInput{
		ParserPID:    child.Process.Pid,
		GuardedCaps:  []uintptr{unix.CAP_BPF, unix.CAP_PERFMON},
		UnsafeProbes: unsafeProbes,
	})
	// child.Process.Kill() is expected to fail now: ObserverFilter denies
	// kill(2) unconditionally, for any target, once installed. This is
	// intentional (the observer never restarts or kills the parser itself;
	// a misbehaving parser is handled by the parser's own self-termination
	// or by Docker restarting the whole Sensor container), not a bug in
	// this helper — the error is ignored and the child is left to exit on
	// its own 2-second sleep.
	_ = child.Process.Kill()
	_ = child.Wait()
	if err != nil {
		die("RunObserverSelfCheck", err)
	}

	enc, err := json.Marshal(report)
	if err != nil {
		die("marshal report", err)
	}
	fmt.Println(string(enc))
	os.Exit(0)
}
