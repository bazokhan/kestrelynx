//go:build unix

// Command kestrelynx-worker is the entry point of the work image. It accepts
// two forms, `run <job.json>` for a Docker work container and
// `run-kubernetes <job.json>` for a work Pod, and runs the fixed operations
// the job names. It takes no command from the job. In a Pod the result is
// sealed to the attempt's key and nothing but fixed status lines is printed
// besides it: the standard output and error of the container are its log.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
	"github.com/kitsunetrail/kestrelynx/internal/worker/runner"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 2 && args[0] == "run-kubernetes" {
		return runKubernetes(args[1])
	}
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

// runKubernetes runs the job of a work Pod. Whatever goes wrong, the only text
// it prints is a status line made of two words from a fixed set.
func runKubernetes(jobPath string) int {
	fail := func(stage, code string, exit int) int {
		if line, err := worker.StatusLine(stage, code); err == nil {
			fmt.Fprint(os.Stdout, line)
		}
		return exit
	}
	if err := runner.Harden(); err != nil {
		return fail("harden", "failed", 3)
	}
	data, err := readSealFile()
	if err != nil {
		return fail("seal", "unreadable", 3)
	}
	pub, binding, err := worker.ParseSealFile(data)
	if err != nil {
		return fail("seal", "invalid", 3)
	}
	cfg := runner.DefaultConfig()
	cfg.Environment = runner.KubernetesEnvironment()
	cfg.Seal = &runner.SealConfig{Public: pub, Binding: binding}
	if err := runner.Run(cfg, jobPath); err != nil {
		return fail("run", "failed", 3)
	}
	return 0
}

// readSealFile reads seal.json, which is small; a file that is not is refused.
func readSealFile() ([]byte, error) {
	f, err := os.Open(worker.SealFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 8192))
	if err != nil {
		return nil, err
	}
	return data, nil
}
