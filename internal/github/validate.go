package github

import (
	"fmt"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxOwnerLen  = 39
	maxRepoLen   = 100
	maxBranchLen = 255
	maxPathLen   = 1024
)

// Repo is a GitHub repository.
type Repo struct {
	Owner string
	Name  string
}

// String returns the repository as owner/name.
func (r Repo) String() string { return r.Owner + "/" + r.Name }

// ParseRepo reads a repository written as owner/name. The owner follows
// GitHub's account name rules (alphanumerics and single hyphens, no hyphen at
// either end, at most 39 bytes); the name is up to 100 bytes of alphanumerics,
// '.', '_' and '-', and is neither "." nor ".." nor ends in ".git".
func ParseRepo(s string) (Repo, error) {
	owner, name, ok := strings.Cut(s, "/")
	if !ok || strings.Contains(name, "/") {
		return Repo{}, fmt.Errorf("%w: repository %q is not owner/name", ErrInvalidInput, s)
	}
	if !validOwner(owner) {
		return Repo{}, fmt.Errorf("%w: repository %q has an invalid owner", ErrInvalidInput, s)
	}
	if !validRepoName(name) {
		return Repo{}, fmt.Errorf("%w: repository %q has an invalid name", ErrInvalidInput, s)
	}
	return Repo{Owner: owner, Name: name}, nil
}

func validOwner(s string) bool {
	if s == "" || len(s) > maxOwnerLen || s[0] == '-' || s[len(s)-1] == '-' || strings.Contains(s, "--") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

func validRepoName(s string) bool {
	if s == "" || len(s) > maxRepoLen || s == "." || s == ".." || strings.HasSuffix(strings.ToLower(s), ".git") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c == '-' || c == '_' || c == '.' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// ValidBranch reports whether name is acceptable as a branch name: a valid
// git reference name (no "..", "@{", spaces, control characters or any of
// ~ ^ : ? * [ \; no empty, leading-dot or ".lock"-ending component; no
// leading "-" or "/", trailing "/" or "."), at most 255 bytes.
func ValidBranch(name string) bool {
	if name == "" || len(name) > maxBranchLen || !utf8.ValidString(name) || name == "@" {
		return false
	}
	if name[0] == '-' || name[0] == '/' || strings.HasSuffix(name, "/") || strings.HasSuffix(name, ".") ||
		strings.Contains(name, "..") || strings.Contains(name, "@{") || strings.Contains(name, "//") {
		return false
	}
	for _, r := range name {
		if r == ' ' || unicode.IsControl(r) || strings.ContainsRune("~^:?*[\\", r) {
			return false
		}
	}
	for _, comp := range strings.Split(name, "/") {
		if strings.HasPrefix(comp, ".") || strings.HasSuffix(comp, ".lock") {
			return false
		}
	}
	return true
}

// ValidPath reports whether p is a normalized path inside a repository: not
// empty, relative, with no ".", ".." or empty components, no backslashes or
// control characters, at most 1024 bytes. With allowRoot, "." (the repository
// root) is accepted as well.
func ValidPath(p string, allowRoot bool) bool {
	if p == "." {
		return allowRoot
	}
	if p == "" || len(p) > maxPathLen || !utf8.ValidString(p) || strings.HasPrefix(p, "/") ||
		strings.Contains(p, "\\") || path.Clean(p) != p {
		return false
	}
	for _, r := range p {
		if unicode.IsControl(r) {
			return false
		}
	}
	for _, comp := range strings.Split(p, "/") {
		if comp == "." || comp == ".." || comp == "" {
			return false
		}
	}
	return true
}

func validSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
