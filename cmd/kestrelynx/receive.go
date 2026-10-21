package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
	"github.com/kitsunetrail/kestrelynx/internal/worker/receive"
)

// runReceiveCommand is the receiving init container of a work Pod: it unpacks
// the job's input from its standard input into /work. It prints one status
// line of two fixed words and nothing else, whatever happens.
func runReceiveCommand() int {
	code, exit := receive.CodeOK, 0
	if err := receive.Run(os.Stdin, receive.DefaultConfig()); err != nil {
		var re *receive.Error
		code, exit = "failed", 1
		if errors.As(err, &re) {
			code = re.Code
		}
	}
	if line, err := worker.StatusLine("receive", code); err == nil {
		fmt.Fprint(os.Stdout, line)
	}
	return exit
}
