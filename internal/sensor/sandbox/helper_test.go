package sandbox

// This file drives the "helper process" side of every test that installs a
// seccomp filter or a Landlock ruleset: since both permanently change the
// calling process's own capabilities in ways a normal test cannot undo
// (there is no unseccomp(2)), every such test execs a small standalone
// binary as a throwaway child process and only ever inspects that child's
// stdout/socket messages/exit code, never the state of the test binary
// itself.
//
// The child is *not* the `go test` binary re-exec'd on itself (the usual
// os/exec_test.go pattern): see testdata/helpermain/main.go's package
// comment for why that does not work here. It is instead a real,
// dependency-free `package main` under testdata/helpermain, built once per
// test run and cached in a package-level sync.Once.

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const helperRoleEnv = "KL_SANDBOX_HELPER"

var (
	helperBinOnce sync.Once
	helperBinPath string
	helperBinErr  error
)

// buildHelperBin compiles testdata/helpermain into a temp binary the first
// time any test needs it, and reuses that binary for the rest of the test
// run.
func buildHelperBin(t *testing.T) string {
	t.Helper()
	helperBinOnce.Do(func() {
		// os.MkdirTemp (not t.TempDir()) because the binary needs to
		// outlive every individual test in this package, not just the one
		// that happened to build it first.
		outDir, err := os.MkdirTemp("", "kl-sandbox-helper-*")
		if err != nil {
			helperBinErr = err
			return
		}
		out := filepath.Join(outDir, "helpermain")
		cmd := exec.Command("go", "build", "-o", out, "./testdata/helpermain")
		cmd.Dir = "." // this package's directory; go.mod is found by walking up
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			helperBinErr = errJoin(err, stderr.String())
			return
		}
		helperBinPath = out
	})
	if helperBinErr != nil {
		t.Fatalf("build testdata/helpermain: %v", helperBinErr)
	}
	return helperBinPath
}

// errJoin folds a command's stderr into its error for one readable message
// (avoiding a dependency on errors.Join purely for a test-time build error).
func errJoin(err error, stderr string) error {
	if stderr == "" {
		return err
	}
	return &buildError{err: err, stderr: stderr}
}

type buildError struct {
	err    error
	stderr string
}

func (e *buildError) Error() string { return e.err.Error() + "\n" + e.stderr }
func (e *buildError) Unwrap() error { return e.err }

// helperCommand returns an *exec.Cmd invoking the compiled helper binary.
func helperCommand(t *testing.T) *exec.Cmd {
	t.Helper()
	return exec.Command(buildHelperBin(t))
}

// asExitError extracts a process exit code from err, if err is an
// *exec.ExitError (the child ran and exited non-zero) rather than some
// other failure to even start it.
func asExitError(err error) (code int, ok bool) {
	ee, ok := err.(*exec.ExitError)
	if !ok {
		return 0, false
	}
	return ee.ExitCode(), true
}

// helperTimeout bounds one run of the helper binary in reexecSelf.
const helperTimeout = 2 * time.Minute

// reexecSelf runs the helper binary with role passed via KL_SANDBOX_HELPER,
// plus any extra env, and returns its stdout and exit code.
func reexecSelf(t *testing.T, role string, extraEnv ...string) (stdout string, exitCode int) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}
	// A helper that never exits (left stopped by a signal, say) fails here
	// instead of holding the whole package until the test binary times out.
	ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, buildHelperBin(t))
	// A grandchild still holding the helper's stdout must not keep Output
	// waiting after the helper itself is killed.
	cmd.WaitDelay = 10 * time.Second
	cmd.Env = append(os.Environ(), helperRoleEnv+"="+role)
	cmd.Env = append(cmd.Env, extraEnv...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("helper %q did not exit within %s; stderr:\n%s", role, helperTimeout, stderr.String())
	}
	code := 0
	if err != nil {
		if ee, ok := asExitError(err); ok {
			code = ee
			if stderr.Len() > 0 {
				t.Logf("helper %q stderr:\n%s", role, stderr.String())
			}
		} else {
			t.Fatalf("run helper %q: %v; stderr:\n%s", role, err, stderr.String())
		}
	}
	return string(out), code
}

// reexecSelfWithSocket runs the helper binary the same way reexecSelf does,
// but additionally hands it one end of a SOCK_SEQPACKET socketpair as fd 3
// before starting it, and collects every message sent back on it. This is
// for roles that install ParserFilter on themselves: its allow-list has no
// write(2), only sendmsg/recvmsg on the socket the parser was born with, so
// a helper under that filter cannot just print its results to stdout — it
// has to report them the same way the real parser would report anything,
// over the socket. Lines printed to stdout *before* the filter installs
// (e.g. the detected Landlock ABI) are returned separately.
func reexecSelfWithSocket(t *testing.T, role string) (stdout string, socketLines []string, exitCode int) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	parentFD := fds[0]
	childFile := os.NewFile(uintptr(fds[1]), "child-result-sock")

	cmd := helperCommand(t)
	cmd.Env = append(os.Environ(), helperRoleEnv+"="+role)
	cmd.ExtraFiles = []*os.File{childFile}
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper %q: %v", role, err)
	}
	// The child has its own dup of this end now; the parent's copy (and the
	// SOCK_CLOEXEC original fds[1]) must be closed or the parent's read
	// loop below would never see EOF when the child exits.
	childFile.Close()

	// A receive timeout bounds how long the parent waits for the next
	// message: if the child hangs instead of exiting, this test fails
	// instead of blocking the test suite forever.
	if err := unix.SetsockoptTimeval(parentFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 10}); err != nil {
		t.Fatalf("set recv timeout: %v", err)
	}
	buf := make([]byte, 4096)
	for {
		n, _, _, _, err := unix.Recvmsg(parentFD, buf, nil, 0)
		if err != nil || n == 0 {
			break
		}
		socketLines = append(socketLines, string(buf[:n]))
	}
	unix.Close(parentFD)

	waitErr := cmd.Wait()
	code := 0
	if waitErr != nil {
		if ee, ok := asExitError(waitErr); ok {
			code = ee
		} else {
			t.Fatalf("wait helper %q: %v; stderr:\n%s", role, waitErr, stderrBuf.String())
		}
	}
	if stderrBuf.Len() > 0 {
		t.Logf("helper %q stderr:\n%s", role, stderrBuf.String())
	}
	return stdoutBuf.String(), socketLines, code
}
