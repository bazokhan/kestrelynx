package inventory

import (
	"regexp"
	"strings"
)

var (
	// refPathComponentRE is one repository path component.
	refPathComponentRE = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)
	// refHostRE is a registry host with an optional port: a name, or an IPv6
	// address in brackets.
	refHostRE = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?|\[[0-9a-fA-F:.]+\])(?::[0-9]+)?$`)
	// refTagRE is a tag.
	refTagRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
)

// splitReference splits an image reference into its repository as written
// (registry host and port kept), its tag and its digest part. ok is false for
// anything that is not a well-formed named reference: empty, a bare digest
// ("sha256:..."), or text with an invalid repository, tag or digest.
func splitReference(ref string) (repo, tag, digest string, ok bool) {
	if ref == "" || ref != strings.TrimSpace(ref) {
		return "", "", "", false
	}
	name := ref
	if i := strings.IndexByte(name, '@'); i >= 0 {
		digest = name[i+1:]
		name = name[:i]
		if !digestPattern.MatchString(digest) {
			return "", "", "", false
		}
	}
	// A colon after the last slash is a tag separator; one before it belongs
	// to a registry port.
	if i := strings.LastIndexByte(name, ':'); i >= 0 && !strings.Contains(name[i:], "/") {
		tag = name[i+1:]
		name = name[:i]
		if !refTagRE.MatchString(tag) {
			return "", "", "", false
		}
	}
	if name == "" || name == "sha256" {
		return "", "", "", false // a bare "sha256:<hex>" is a digest, not a name
	}
	parts := strings.Split(name, "/")
	rest := parts
	if len(parts) > 1 && isRegistryHost(parts[0]) {
		if !refHostRE.MatchString(parts[0]) {
			return "", "", "", false
		}
		rest = parts[1:]
	}
	for _, p := range rest {
		if !refPathComponentRE.MatchString(p) {
			return "", "", "", false
		}
	}
	return name, tag, digest, true
}

// isRegistryHost reports whether the first path component of a reference is a
// registry host rather than a repository namespace: it holds a dot or a
// port, is a bracketed IPv6 address, or is "localhost".
func isRegistryHost(s string) bool {
	return strings.ContainsAny(s, ".:[") || s == "localhost"
}

// RepositoryOf returns the repository of an image reference as written: the
// reference without its tag and digest, registry host and port kept. ok is
// false when no repository can be extracted (empty, a bare "sha256:..."
// digest, or a malformed reference); a repository is never guessed at.
func RepositoryOf(ref string) (string, bool) {
	repo, _, _, ok := splitReference(ref)
	return repo, ok
}

// TagOf returns the tag of an image reference, "" when it has none or is not
// a well-formed reference.
func TagOf(ref string) string {
	_, tag, _, ok := splitReference(ref)
	if !ok {
		return ""
	}
	return tag
}

// DigestOf returns the digest part ("sha256:...") of an image reference, ""
// when it has none or is not a well-formed reference.
func DigestOf(ref string) string {
	_, _, digest, ok := splitReference(ref)
	if !ok {
		return ""
	}
	return digest
}

// HasRegistryHost reports whether the repository part of an image reference
// names a registry host (a first path component with a dot or a port, or
// "localhost"). "app" and "team/app" do not; "ghcr.io/team/app" does. A
// reference that cannot be read has none.
func HasRegistryHost(ref string) bool {
	repo, ok := RepositoryOf(ref)
	if !ok {
		return false
	}
	parts := strings.Split(repo, "/")
	return len(parts) > 1 && isRegistryHost(parts[0])
}

// RepositoryKey returns a normalized form of the repository of ref for
// matching only: a reference without a registry host is taken to live on
// Docker Hub, and a single-component Docker Hub repository is taken to be in
// "library/". It is never stored or shown; "app" and "docker.io/library/app"
// share one key. ok is false exactly when RepositoryOf's is.
func RepositoryKey(ref string) (string, bool) {
	repo, ok := RepositoryOf(ref)
	if !ok {
		return "", false
	}
	parts := strings.Split(repo, "/")
	host := "docker.io"
	if len(parts) > 1 && isRegistryHost(parts[0]) {
		host, parts = parts[0], parts[1:]
	}
	switch host {
	case "index.docker.io", "registry-1.docker.io":
		host = "docker.io"
	}
	if host == "docker.io" && len(parts) == 1 {
		parts = []string{"library", parts[0]}
	}
	return host + "/" + strings.Join(parts, "/"), true
}
