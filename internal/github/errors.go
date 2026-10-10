package github

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

var (
	// ErrNotFound means the repository, branch, directory or file does not
	// exist, or is not visible to the configured credentials (GitHub answers
	// 404 for a private repository it will not show).
	ErrNotFound = errors.New("github: not found")
	// ErrAuthRequired means GitHub answered 401: no credentials were sent, or
	// the configured token is not accepted.
	ErrAuthRequired = errors.New("github: authentication required")
	// ErrForbidden means GitHub answered 403 for a reason other than rate
	// limiting: the token lacks access to the repository.
	ErrForbidden = errors.New("github: access forbidden")
	// ErrRateLimited means GitHub is rate limiting the client (HTTP 429, or
	// 403 with an exhausted limit or a Retry-After). Use errors.As with
	// *RateLimitedError to read the reset time.
	ErrRateLimited = errors.New("github: rate limited")
	// ErrTooLarge means a file or a response exceeded its own cap, or a
	// directory listing may be incomplete. It is a property of that file;
	// running out of the cycle's total file bytes is ErrByteBudgetExhausted.
	ErrTooLarge = errors.New("github: too large")
	// ErrByteBudgetExhausted means reading the file would take the cycle's
	// total file bytes past their cap. Nothing is wrong with the file itself,
	// so a later cycle may read it.
	ErrByteBudgetExhausted = errors.New("github: cycle file byte budget exhausted")
	// ErrBudgetExhausted means the caller's request budget is used up; no
	// request was sent.
	ErrBudgetExhausted = errors.New("github: request budget exhausted")
	// ErrLFSPointer means the file is a Git LFS pointer, not its content.
	ErrLFSPointer = errors.New("github: file is a Git LFS pointer")
	// ErrNotRegularFile means the path is a directory, symlink or submodule.
	// Use errors.As with *NotRegularFileError to read which.
	ErrNotRegularFile = errors.New("github: not a regular file")
	// ErrNotDirectory means the path exists but is not a directory.
	ErrNotDirectory = errors.New("github: not a directory")
	// ErrHashMismatch means returned content does not hash to the blob SHA
	// GitHub reported for it.
	ErrHashMismatch = errors.New("github: content does not match its blob SHA")
	// ErrBadResponse means a response was malformed or pointed somewhere it
	// must not (a non-HTTPS URL, another host).
	ErrBadResponse = errors.New("github: bad response")
	// ErrForbiddenAddress means a connection was refused because the host is,
	// or resolves to, a loopback, private, link-local, unspecified, multicast
	// or carrier-grade NAT address.
	ErrForbiddenAddress = errors.New("github: address not allowed")
	// ErrInvalidInput means a repository, branch, commit or path argument is
	// unusable.
	ErrInvalidInput = errors.New("github: invalid input")
	// ErrRefExists means creating a branch failed because it already exists.
	ErrRefExists = errors.New("github: reference already exists")
	// ErrOutcomeUnknown means a write may or may not have been applied: the
	// request was sent but no usable answer came back (a transport error, a
	// timeout, a 5xx, or a success response that could not be read). The
	// writer never resends; read the state again to find out. The cause is
	// wrapped and reachable with errors.Is and errors.As.
	ErrOutcomeUnknown = errors.New("github: outcome of the write is unknown")
)

// RateLimitedError is the error for a rate-limited request. The client never
// waits or retries on its own.
type RateLimitedError struct {
	// Reset is when the primary limit renews (X-RateLimit-Reset); zero when
	// GitHub gave none.
	Reset time.Time
	// RetryAfter is the delay in Retry-After; 0 when absent.
	RetryAfter time.Duration
}

func (e *RateLimitedError) Error() string {
	switch {
	case !e.Reset.IsZero():
		return fmt.Sprintf("github: rate limited (resets at %s)", e.Reset.UTC().Format(time.RFC3339))
	case e.RetryAfter > 0:
		return fmt.Sprintf("github: rate limited (retry after %s)", e.RetryAfter)
	}
	return "github: rate limited"
}

func (e *RateLimitedError) Unwrap() error { return ErrRateLimited }

// NotRegularFileError is the error for ErrNotRegularFile.
type NotRegularFileError struct {
	Path string
	// Type is "dir", "symlink" or "submodule".
	Type string
}

func (e *NotRegularFileError) Error() string {
	return fmt.Sprintf("github: %s is a %s, not a regular file", e.Path, e.Type)
}

func (e *NotRegularFileError) Unwrap() error { return ErrNotRegularFile }

// StatusError is an unexpected HTTP status that has no more specific type.
type StatusError struct {
	Status int
	// Message is GitHub's "message" field, sanitized and shortened; empty when
	// the response had none. Only the write side fills it.
	Message string
}

func (e *StatusError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("github: api.github.com answered HTTP %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("github: api.github.com answered HTTP %d", e.Status)
}

// Is lets errors.Is match the sentinel for statuses that have one.
func (e *StatusError) Is(target error) bool {
	switch e.Status {
	case http.StatusUnauthorized:
		return target == ErrAuthRequired
	case http.StatusForbidden:
		return target == ErrForbidden
	case http.StatusNotFound:
		return target == ErrNotFound
	}
	return false
}
