package worker

import "fmt"

// The sha256 of the program for each platform, as lowercase hex. They are set
// at link time by the build that produces the main program, from the very
// files it ships next to it, and are empty in a build that does not carry the
// program.
var (
	ProgramSHA256Amd64 = ""
	ProgramSHA256Arm64 = ""
)

// ProgramDir is where the main image keeps the program, one static file per
// platform.
const ProgramDir = "/usr/local/libexec/kestrelynx"

// ProgramFileName is the name of the program file for a GOARCH.
func ProgramFileName(goarch string) string { return "kestrelynx-worker-" + goarch }

// ProgramSHA256 returns the hash the build embedded for a GOARCH, or "".
func ProgramSHA256(goarch string) (string, error) {
	switch goarch {
	case "amd64":
		return ProgramSHA256Amd64, nil
	case "arm64":
		return ProgramSHA256Arm64, nil
	}
	return "", fmt.Errorf("no work program is built for %q", goarch)
}
