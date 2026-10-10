//go:build unix && !linux

package runner

// Harden has nothing to do on systems without the Linux dumpable flag.
func Harden() error { return nil }
