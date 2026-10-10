//go:build unix

package main

import "testing"

func TestRunAcceptsOnlyTheRunForm(t *testing.T) {
	for _, args := range [][]string{nil, {"run"}, {"sh", "-c", "id"}, {"run", "/work/job.json", "extra"}, {"exec", "/work/job.json"}} {
		if got := run(args); got != 2 {
			t.Errorf("run(%q) = %d, want 2", args, got)
		}
	}
}
