//go:build unix

package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// releaseAgeMarker is the error code pnpm prints when a lockfile entry was
// published within its minimum release age.
const releaseAgeMarker = "ERR_PNPM_MINIMUM_RELEASE_AGE_VIOLATION"

// procResult is what one child process left behind.
type procResult struct {
	exitCode      int
	timedOut      bool
	stdout        string
	stderr        string
	truncated     bool
	quotaExceeded bool  // the space or entry count under /work went over its limit
	releaseAge    bool  // stderr carried the package manager's release-age error
	err           error // the program could not be started or waited for
}

// lookPath finds name in the colon-separated path list, never in the current
// directory and never through the program's own PATH.
func lookPath(path, name string) (string, error) {
	if strings.Contains(name, "/") {
		return "", fmt.Errorf("program name %q has a slash", name)
	}
	for _, dir := range filepath.SplitList(path) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found in %s", name, path)
}

// runProc runs argv in dir in its own process group. When ctx ends, or after
// the child exits, the whole group is killed so no descendant outlives the
// step, and orphans the program adopted as the container's first process are
// collected. The child's standard input is /dev/null, its output goes to
// pipes this program reads (never to its own standard output), and no other
// descriptor is passed on.
func runProc(ctx context.Context, cfg *Config, m worker.Manager, argv []string, dir string) procResult {
	exe, err := lookPath(cfg.Path, argv[0])
	if err != nil {
		return procResult{exitCode: -1, err: err}
	}
	stdout := newTailBuffer(worker.MaxStreamTail)
	stderr := newMarkedTailBuffer(worker.MaxStreamTail, releaseAgeMarker)
	cmd := &exec.Cmd{
		Path:        exe,
		Args:        argv,
		Dir:         dir,
		Env:         cfg.childEnv(m),
		Stdout:      stdout,
		Stderr:      stderr,
		SysProcAttr: &syscall.SysProcAttr{Setpgid: true},
		WaitDelay:   3 * time.Second,
	}
	res := procResult{}
	if err := cmd.Start(); err != nil {
		res.exitCode = -1
		res.err = err
		return res
	}
	pgid := cmd.Process.Pid
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-done:
	case <-ctx.Done():
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		res.timedOut = true
		waitErr = <-done
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	reapOrphans()

	res.exitCode = cmd.ProcessState.ExitCode()
	var exitErr *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &exitErr) && !errors.Is(waitErr, exec.ErrWaitDelay) {
		res.err = waitErr
	}
	res.stdout, res.stderr = stdout.String(), stderr.String()
	res.truncated = stdout.truncated || stderr.truncated
	res.releaseAge = stderr.found
	return res
}

// reapOrphans collects exited descendants that were re-parented to this
// process. It only acts as the container's first process; anywhere else it
// could take the exit status of a child that belongs to someone else.
func reapOrphans() {
	if os.Getpid() != 1 {
		return
	}
	for {
		pid, err := syscall.Wait4(-1, nil, syscall.WNOHANG, nil)
		if pid <= 0 || err != nil {
			return
		}
	}
}
