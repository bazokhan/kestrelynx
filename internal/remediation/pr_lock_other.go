//go:build !unix

package remediation

import "errors"

// lockFile is not available without flock; pull requests are not written
// on such systems.
func lockFile(string) (func() error, error) {
	return nil, errors.New("lock pull request records: file locking is not supported on this system")
}
