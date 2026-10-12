package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// boundedClient returns hc with a request timeout; a client without one, or
// none at all, gets the default. The caller's client is not changed.
func boundedClient(hc *http.Client) *http.Client {
	const def = 30 * time.Second
	if hc == nil {
		return &http.Client{Timeout: def}
	}
	if hc.Timeout > 0 {
		return hc
	}
	c := *hc
	c.Timeout = def
	return &c
}

// NpmDist is what the public registry publishes for one package version: the
// tarball URL and its integrity value, and the dependencies the version
// declares.
type NpmDist struct {
	Tarball              string
	Integrity            string
	Dependencies         map[string]string
	OptionalDependencies map[string]string
	PeerDependencies     map[string]string
	// Install is the registry's record of the fields that decide whether and
	// how the version is installed (see installRecord).
	Install map[string]string
	// Deprecated is the registry's deprecation note for the version, "" for
	// none.
	Deprecated string
	// HasShrinkwrap is the registry's _hasShrinkwrap for the version: the
	// package carries its own npm-shrinkwrap.json, which npm reads again after
	// unpacking it.
	HasShrinkwrap bool
}

// peersFor returns the peer dependencies of the version as manager m records
// them. pnpm records a peer dependency that a package only marks optional in
// peerDependenciesMeta, without listing it in peerDependencies, with the range
// "*"; npm records what the registry lists.
func (d NpmDist) peersFor(m DependencyManager) map[string]string {
	if m != ManagerPnpm {
		return d.PeerDependencies
	}
	out := make(map[string]string, len(d.PeerDependencies))
	for k, v := range d.PeerDependencies {
		out[k] = v
	}
	for _, name := range strings.Split(d.Install["peerDependenciesMeta"], ",") {
		if _, listed := out[name]; name != "" && !listed {
			out[name] = "*"
		}
	}
	return out
}

// NpmRegistry tells what the registry publishes for a package version.
type NpmRegistry interface {
	// VersionDist returns the distribution of name at version, or an error
	// wrapping ErrReleaseNotFound when the registry has no such version.
	VersionDist(ctx context.Context, name, version string) (NpmDist, error)
}

// NpmClient reads version documents from the public npm registry.
type NpmClient struct {
	HTTP *http.Client
	// BaseURL is the registry; empty means https://registry.npmjs.org.
	BaseURL string
}

var _ NpmRegistry = (*NpmClient)(nil)

// maxNpmBody bounds a version document, and maxDeclaredDeps the dependencies
// one version declares.
const (
	maxNpmBody      = 2 << 20
	maxDeclaredDeps = 5000
)

// VersionDist implements NpmRegistry with GET <base>/<name>/<version>. The
// name and version are checked before they are put in a URL, and the document
// must be for that package and version.
func (c *NpmClient) VersionDist(ctx context.Context, name, version string) (NpmDist, error) {
	if !worker.ValidNpmName(name) || !worker.ValidSemver(version) {
		return NpmDist{}, fmt.Errorf("%q %q is not a package name and version this client looks up", name, version)
	}
	base := c.BaseURL
	if base == "" {
		base = "https://registry.npmjs.org"
	}
	u := strings.TrimRight(base, "/") + "/" + strings.Replace(url.PathEscape(name), "/", "%2F", 1) + "/" + url.PathEscape(version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return NpmDist{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "kestrelynx")
	resp, err := boundedClient(c.HTTP).Do(req)
	if err != nil {
		return NpmDist{}, fmt.Errorf("registry request: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return NpmDist{}, ErrReleaseNotFound
	case resp.StatusCode != http.StatusOK:
		return NpmDist{}, fmt.Errorf("registry answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxNpmBody+1))
	if err != nil {
		return NpmDist{}, fmt.Errorf("read registry response: %w", err)
	}
	if len(body) > maxNpmBody {
		return NpmDist{}, fmt.Errorf("registry response is over %d bytes", maxNpmBody)
	}
	return parseNpmVersion(body, name, version)
}

func parseNpmVersion(body []byte, name, version string) (NpmDist, error) {
	var doc struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Dist    struct {
			Tarball   string `json:"tarball"`
			Integrity string `json:"integrity"`
		} `json:"dist"`
		Dependencies         map[string]string `json:"dependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		Deprecated           json.RawMessage   `json:"deprecated"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return NpmDist{}, fmt.Errorf("registry response cannot be read: %w", err)
	}
	if doc.Name != name || doc.Version != version {
		return NpmDist{}, fmt.Errorf("registry response is for %s %s, not %s %s", doc.Name, doc.Version, name, version)
	}
	if doc.Dist.Tarball == "" || doc.Dist.Integrity == "" {
		return NpmDist{}, errors.New("registry response has no tarball or integrity")
	}
	if len(doc.Dependencies)+len(doc.OptionalDependencies)+len(doc.PeerDependencies) > maxDeclaredDeps {
		return NpmDist{}, fmt.Errorf("registry response declares more than %d dependencies", maxDeclaredDeps)
	}
	members, err := nameMap(body)
	if err != nil {
		return NpmDist{}, fmt.Errorf("registry response cannot be read: %w", err)
	}
	// A lockfile of npm leaves out what npm does not store (see storedByNpm),
	// so the registry's members are reduced the same way before comparing.
	for _, k := range append([]string{"bundledDependencies"}, installKeys...) {
		if raw, ok := members[k]; ok && !storedByNpm(raw) {
			delete(members, k)
		}
	}
	rec, err := installRecord(members, name, doc.Dependencies, "bundleDependencies", "bundledDependencies")
	if err != nil {
		return NpmDist{}, fmt.Errorf("registry response: %w", err)
	}
	shrink := false
	if raw, ok := members["_hasShrinkwrap"]; ok {
		shrink = storedByNpm(raw)
	}
	// The note is text. Absent, null and false are no note (the registry has
	// written a deprecation away as an empty string or false); anything else is
	// not something to compare a lockfile with.
	deprecated := ""
	switch t := strings.TrimSpace(string(doc.Deprecated)); {
	case t == "" || t == "null" || t == "false":
	case strings.HasPrefix(t, `"`):
		if err := json.Unmarshal(doc.Deprecated, &deprecated); err != nil {
			return NpmDist{}, fmt.Errorf("registry response has a deprecated note that cannot be read: %w", err)
		}
	default:
		return NpmDist{}, errors.New("registry response has a deprecated member that is not text")
	}
	return NpmDist{
		Deprecated:    deprecated,
		HasShrinkwrap: shrink,
		Tarball:       doc.Dist.Tarball, Integrity: doc.Dist.Integrity,
		Dependencies: doc.Dependencies, OptionalDependencies: doc.OptionalDependencies, PeerDependencies: doc.PeerDependencies, Install: rec,
	}, nil
}
