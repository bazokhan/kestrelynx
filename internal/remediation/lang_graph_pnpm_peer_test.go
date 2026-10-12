package remediation

import (
	"fmt"
	"testing"
)

// peerProject describes a pnpm project of three direct dependencies for the
// checks of the requirements of the project itself: next (the package being
// updated, with react as a peer), lib (which does not use next) and react.
type peerProject struct {
	next string // version of next
	lib  string // version of lib
	// libPeer is a peer context lib's snapshot key carries, "" for none;
	// libResolution replaces the resolution of lib when set.
	libPeer       string
	libResolution string
}

func (p peerProject) lock() []byte {
	libKey := p.lib
	if p.libPeer != "" {
		libKey += "(" + p.libPeer + ")"
	}
	libRes := p.libResolution
	if libRes == "" {
		libRes = "{integrity: " + partialIntegrity("lib", p.lib) + "}"
	}
	s := fmt.Sprintf(`lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      lib:
        specifier: ^1.0.0
        version: %[1]s
      next:
        specifier: ^16.0.0
        version: %[2]s(react@19.0.0)
      react:
        specifier: 19.0.0
        version: 19.0.0

packages:

  lib@%[3]s:
    resolution: %[4]s

  next@%[2]s:
    resolution: {integrity: %[5]s}
    peerDependencies:
      react: '*'

  react@19.0.0:
    resolution: {integrity: %[6]s}

snapshots:

  lib@%[1]s: {}

  next@%[2]s(react@19.0.0):
    dependencies:
      react: 19.0.0

  react@19.0.0: {}
`, libKey, p.next, p.lib, libRes, partialIntegrity("next", p.next), partialIntegrity("react", "19.0.0"))
	return []byte(s)
}

func TestDiffGraphsPnpmRequirementsOfTheProject(t *testing.T) {
	base := peerProject{next: "16.2.11", lib: "1.0.0"}
	cases := []struct {
		name  string
		after peerProject
		// want is the reason the change is refused with, "" when it is
		// explained, and refused says any reason will do.
		want    Reason
		detail  string
		refused bool
	}{
		{"only the updated package moves", peerProject{next: "16.3.8", lib: "1.0.0"}, "", "", false},
		{"an unrelated peer context appears on a direct dependency", peerProject{next: "16.3.8", lib: "1.0.0", libPeer: "supports-color@7.2.0"},
			ReasonUnexplainedDiff, "the requirements of the project itself point to different entries", false},
		{"the same unrelated peer context appears with no package updated beside it", peerProject{next: "16.2.11", lib: "1.0.0", libPeer: "supports-color@7.2.0"},
			ReasonUnexplainedDiff, "the requirements of the project itself point to different entries", false},
		{"a direct dependency that is not updated changes its version", peerProject{next: "16.3.8", lib: "1.0.1"},
			ReasonUnexplainedDiff, "the requirements of the project itself point to different entries", false},
		{"a direct dependency that is not updated changes where it is fetched from", peerProject{next: "16.3.8", lib: "1.0.0", libResolution: "{tarball: 'https://example.com/lib-1.0.0.tgz'}"},
			"", "", true},
	}
	gb, err := buildGraph(bg, ManagerPnpm, base.lock())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ga, err := buildGraph(bg, ManagerPnpm, c.after.lock())
			if err != nil {
				t.Fatal(err)
			}
			_, reason, detail := diffGraphs(bg, gb, ga, map[string]bool{"next": true})
			if c.refused {
				if reason == "" {
					t.Fatalf("the change was explained")
				}
				return
			}
			if reason != c.want || (c.detail != "" && detail != c.detail) {
				t.Errorf("reason = %q (%s), want %q (%s)", reason, detail, c.want, c.detail)
			}
		})
	}
}
