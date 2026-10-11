//go:build linux

package runner

import (
	"os"
	"strconv"
	"syscall"
)

// closeInheritedOnExec marks every descriptor from 3 up close-on-exec, so a
// child started afterwards receives only its standard input, output and
// error. Descriptors this program opens itself are already close-on-exec,
// but ones it inherited from whatever started it need not be, and os/exec
// passes those on to every child unchanged. The job runner is built from the
// standard library alone, so this walks /proc/self/fd instead of calling
// close_range.
func closeInheritedOnExec() error {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return err
	}
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd < 3 {
			continue
		}
		// The descriptor ReadDir used for the listing is closed by now;
		// marking a descriptor that went away has no effect.
		syscall.CloseOnExec(fd)
	}
	return nil
}
