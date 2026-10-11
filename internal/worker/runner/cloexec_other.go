//go:build unix && !linux

package runner

// closeInheritedOnExec has nothing to do where the job runner is not run.
func closeInheritedOnExec() error { return nil }
