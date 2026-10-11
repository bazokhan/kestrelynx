package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/regauth"
)

// AuthChallenger tells how a registry wants requests for a repository
// authenticated: one answer for each place a client looks (implemented by
// *registry.Client).
type AuthChallenger interface {
	Challenges(ctx context.Context, repo string) ([]regauth.Challenge, error)
}

// registryCredential returns the credential to pass on for target: the one for
// the registry host of the repository it is fetched from, when the scan is a
// registry fetch, the scanner has a login for that host, and the host's
// authentication challenge leads only where the login may go. withheld says
// why a login that exists is not passed on.
//
// Trivy's own TRIVY_USERNAME and TRIVY_PASSWORD apply to every registry a
// scan touches, so they are not used; the credential goes out through a
// Docker config that names this host alone (see writeDockerConfig). Trivy's
// registry library answers a Bearer challenge by sending that login to the
// token service whatever host it is on, and takes the scheme and the token
// service from its first request to /v2/, so both that endpoint's challenge
// and the repository's are checked here first with this program's own
// client, and the login is passed on only if every one of them leads where
// the token_hosts rule allows. The configured host is one the user trusts;
// this guards against a misconfiguration or a challenge that names an
// unexpected host. Within the configured host the login may still travel
// further than the check sees: when the registry redirects a request to
// another path of the same host, Trivy's registry library attaches its token
// again, and it does not do so for a redirect to another host. That is taken
// as the trust the user placed in the host, not as a leak. The check and the
// scan are separate requests, so a
// registry that changes its answer in between is not caught: closing that
// would mean replacing Trivy's own registry access.
func (t Trivy) registryCredential(ctx context.Context, target ScanTarget) (cred regauth.Credential, ok bool, withheld string) {
	if t.Auth == nil || !pinnedByRegistry(target) {
		return regauth.Credential{}, false, ""
	}
	key, found := inventory.RepositoryKey(target.Registry.Repository)
	if !found {
		return regauth.Credential{}, false, ""
	}
	host, _, _ := strings.Cut(key, "/")
	cred, found = t.Auth.For(host)
	if !found {
		return regauth.Credential{}, false, ""
	}
	if t.Challenger == nil {
		return cred, false, "there is no way to check where it would be sent"
	}
	chs, err := t.Challenger.Challenges(ctx, target.Registry.Repository)
	if err != nil {
		return cred, false, "the registry's authentication challenge could not be read: " + cred.Scrub(err.Error())
	}
	if len(chs) == 0 {
		return cred, false, "the registry gave no authentication challenge to check"
	}
	for _, ch := range chs {
		if permitted, why := cred.Permits(ch); !permitted {
			return cred, false, why
		}
	}
	return cred, true, ""
}

// dockerConfigKey is the key Docker config files use for a registry host:
// Docker Hub has a historical URL, every other registry is its host.
func dockerConfigKey(host string) string {
	if host == "docker.io" {
		return "https://index.docker.io/v1/"
	}
	return host
}

// writeDockerConfig writes a Docker config directory, readable by this user
// only, and returns its path: with a credential it holds the login of that
// registry host and nothing else, without one it holds no logins. The caller
// removes the directory when the scan is over; set as DOCKER_CONFIG it is the
// only source of registry logins Trivy sees.
func writeDockerConfig(cred *regauth.Credential) (string, error) {
	dir, err := os.MkdirTemp("", "kestrelynx-dockercfg-")
	if err != nil {
		return "", err
	}
	auths := map[string]any{}
	if cred != nil {
		auths[dockerConfigKey(cred.Host)] = map[string]string{
			"auth": base64.StdEncoding.EncodeToString([]byte(cred.Username + ":" + cred.Password())),
		}
	}
	data, err := json.Marshal(map[string]any{"auths": auths})
	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), data, 0o600); err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("write the registry login directory: %w", err)
	}
	return dir, nil
}
