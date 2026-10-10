//go:build linux

package runner

import "syscall"

const prSetDumpable = 4

// Harden makes this process non-dumpable. The children run as the same user,
// and a dumpable process of that user could be inspected through /proc (its
// descriptors opened, including the standard output the result is printed to)
// or traced. A non-dumpable process's /proc entries belong to root, so the
// children cannot. It must run before any child starts.
func Harden() error {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0); errno != 0 {
		return errno
	}
	return nil
}
