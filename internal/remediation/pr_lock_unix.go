//go:build unix

package remediation

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// lockFile takes an exclusive flock on path without waiting. The lock is
// tied to the open file, so it is released when unlock closes it or the
// process exits, even after a crash.
func lockFile(path string) (func() error, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open pull request record lock: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrPRStoreLocked
		}
		return nil, fmt.Errorf("lock pull request records: %w", err)
	}
	return f.Close, nil
}
