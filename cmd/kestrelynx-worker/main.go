//go:build unix

// Command kestrelynx-worker is the entry point of the work image. It accepts
// exactly one form, `run <job.json>`, and runs the fixed operations the job
// names. It has no other mode and takes no command from the job.
package main

import (
	"fmt"
	"os"

	"github.com/kitsunetrail/kestrelynx/internal/worker/runner"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) != 2 || args[0] != "run" {
		fmt.Fprintln(os.Stderr, "usage: kestrelynx-worker run <job.json>")
		return 2
	}
	// Anything on standard output other than the result block would corrupt
	// it, so diagnostics go to standard error only.
	if err := runner.Harden(); err != nil {
		fmt.Fprintln(os.Stderr, "kestrelynx-worker: harden:", err)
		return 3
	}
	if err := runner.Run(runner.DefaultConfig(), args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "kestrelynx-worker:", err)
		return 3
	}
	return 0
}
