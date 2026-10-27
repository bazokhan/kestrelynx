package kubernetes

import (
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

func TestParseImageID(t *testing.T) {
	validHex := strings.Repeat("a", 64)
	cases := []struct {
		name     string
		raw      string
		wantOK   bool
		wantRepo string
		wantHex  string
	}{
		{
			name:     "repo at sha256 accepted",
			raw:      "docker.io/library/nginx@sha256:" + validHex,
			wantOK:   true,
			wantRepo: "docker.io/library/nginx",
			wantHex:  validHex,
		},
		{
			name:     "docker-pullable scheme accepted",
			raw:      "docker-pullable://docker.io/library/nginx@sha256:" + validHex,
			wantOK:   true,
			wantRepo: "docker.io/library/nginx",
			wantHex:  validHex,
		},
		{
			name:   "bare sha256 with no repository rejected",
			raw:    "sha256:" + validHex,
			wantOK: false,
		},
		{
			name:   "uppercase hex rejected",
			raw:    "docker.io/library/nginx@sha256:" + strings.Repeat("A", 64),
			wantOK: false,
		},
		{
			name:   "invalid repository rejected",
			raw:    "Docker.IO/Library/Nginx@sha256:" + validHex,
			wantOK: false,
		},
		{
			name:   "repository with invalid characters rejected",
			raw:    "docker.io/library/nginx!@sha256:" + validHex,
			wantOK: false,
		},
		{
			name:   "other scheme rejected",
			raw:    "containerd://docker.io/library/nginx@sha256:" + validHex,
			wantOK: false,
		},
		{
			name:   "empty string rejected",
			raw:    "",
			wantOK: false,
		},
		{
			name:     "host:port repository accepted",
			raw:      "registry.example.com:5000/team/app@sha256:" + validHex,
			wantOK:   true,
			wantRepo: "registry.example.com:5000/team/app",
			wantHex:  validHex,
		},
		{
			name:   "wrong digest algorithm rejected",
			raw:    "docker.io/library/nginx@sha512:" + validHex,
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseImageID(tc.raw)
			if ok != tc.wantOK {
				t.Fatalf("parseImageID(%q) ok = %v, want %v (got %+v)", tc.raw, ok, tc.wantOK, got)
			}
			if !tc.wantOK {
				if got != (inventory.RegistryRef{}) {
					t.Errorf("parseImageID(%q) = %+v on rejection, want zero value", tc.raw, got)
				}
				return
			}
			if got.Repository != tc.wantRepo {
				t.Errorf("Repository = %q, want %q", got.Repository, tc.wantRepo)
			}
			if got.Digest.Kind != inventory.DigestRegistry {
				t.Errorf("Digest.Kind = %q, want %q", got.Digest.Kind, inventory.DigestRegistry)
			}
			if got.Digest.Hex != tc.wantHex {
				t.Errorf("Digest.Hex = %q, want %q", got.Digest.Hex, tc.wantHex)
			}
			if !got.Digest.Valid() {
				t.Errorf("Digest.Valid() = false for %+v", got.Digest)
			}
		})
	}
}

func TestRunningImageOf(t *testing.T) {
	configHex := strings.Repeat("c", 64)
	indexHex := strings.Repeat("d", 64)
	platform := inventory.Platform{OS: "linux", Architecture: "amd64"}
	cases := []struct {
		name         string
		cs           containerStatus
		wantRef      string
		wantRepo     string
		wantBadImgID bool
	}{
		{
			name:     "tagged image keeps the status image",
			cs:       containerStatus{Image: "docker.io/library/nginx:1.25.4", ImageID: "docker.io/library/nginx@sha256:" + indexHex},
			wantRef:  "docker.io/library/nginx:1.25.4",
			wantRepo: "docker.io/library/nginx",
		},
		{
			// containerd reports the config ID as the image of a container
			// whose image was pulled by digest alone.
			name:     "image ID only takes the repository and digest of imageID",
			cs:       containerStatus{Image: "sha256:" + configHex, ImageID: "ghcr.io/team/app@sha256:" + indexHex},
			wantRef:  "ghcr.io/team/app@sha256:" + indexHex,
			wantRepo: "ghcr.io/team/app",
		},
		{
			// An image loaded onto the node without a pull: imageID names no
			// repository, and fails the checks of parseImageID as before.
			name:         "image ID only with a bare imageID stays as reported",
			cs:           containerStatus{Image: "sha256:" + configHex, ImageID: "sha256:" + configHex},
			wantRef:      "sha256:" + configHex,
			wantBadImgID: true,
		},
		{
			name:    "image ID only without imageID stays as reported",
			cs:      containerStatus{Image: "sha256:" + configHex},
			wantRef: "sha256:" + configHex,
		},
		{
			name:     "a digest reference is not an image ID",
			cs:       containerStatus{Image: "ghcr.io/team/app@sha256:" + indexHex, ImageID: "ghcr.io/team/app@sha256:" + indexHex},
			wantRef:  "ghcr.io/team/app@sha256:" + indexHex,
			wantRepo: "ghcr.io/team/app",
		},
		{
			name:         "invalid imageID is reported and the status image kept",
			cs:           containerStatus{Image: "sha256:" + configHex, ImageID: "containerd://ghcr.io/team/app@sha256:" + indexHex},
			wantRef:      "sha256:" + configHex,
			wantBadImgID: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			img, bad := runningImageOf(tc.cs, platform)
			if img.Ref != tc.wantRef {
				t.Errorf("Ref = %q, want %q", img.Ref, tc.wantRef)
			}
			if img.Registry.Repository != tc.wantRepo {
				t.Errorf("Registry.Repository = %q, want %q", img.Registry.Repository, tc.wantRepo)
			}
			if bad != tc.wantBadImgID {
				t.Errorf("badImageID = %v, want %v", bad, tc.wantBadImgID)
			}
			if img.Platform != platform {
				t.Errorf("Platform = %+v, want %+v", img.Platform, platform)
			}
		})
	}
}
