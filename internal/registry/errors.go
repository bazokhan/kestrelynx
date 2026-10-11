package registry

import (
	"errors"
	"fmt"
	"time"
)

var (
	// ErrAuthRequired means the registry refused the request: with an
	// anonymous pull token and no credentials configured for its host, or
	// with the configured credentials, or it asked for a login this client
	// has no credentials for.
	ErrAuthRequired = errors.New("registry: authentication required")
	// ErrTimeout means one request did not finish within the client's
	// per-request timeout while the caller's own context was still live. It
	// is not a context error: the caller's deadline, if it passes, is
	// reported as context.DeadlineExceeded.
	ErrTimeout = errors.New("registry: request timed out")
	// ErrBudgetExhausted means the caller's request budget is used up; no
	// request was sent.
	ErrBudgetExhausted = errors.New("registry: request budget exhausted")
	// ErrRateLimited means the registry answered 429. Use errors.As with
	// *RateLimitedError to read the Retry-After.
	ErrRateLimited = errors.New("registry: rate limited")
	// ErrNotFound means the repository, tag or manifest does not exist.
	ErrNotFound = errors.New("registry: not found")
	// ErrTooLarge means a response body exceeded its size cap.
	ErrTooLarge = errors.New("registry: response too large")
	// ErrDigestMismatch means a fetched manifest body does not hash to the
	// digest it was requested by (or that the registry reported for it).
	ErrDigestMismatch = errors.New("registry: manifest digest mismatch")
	// ErrPlatformNotFound means an index holds no entry for the requested
	// platform.
	ErrPlatformNotFound = errors.New("registry: no manifest for the requested platform")
	// ErrPlatformAmbiguous means an index holds several different entries for
	// the requested platform.
	ErrPlatformAmbiguous = errors.New("registry: several manifests match the requested platform")
	// ErrUnsupported means the registry returned a manifest format this client
	// does not read.
	ErrUnsupported = errors.New("registry: unsupported manifest")
	// ErrBadResponse means a response was malformed or pointed somewhere it
	// must not (a non-HTTPS URL, another host).
	ErrBadResponse = errors.New("registry: bad response")
	// ErrForbiddenAddress means a connection was refused because the host is, or
	// resolves to, a loopback, private, link-local, unspecified, multicast or
	// carrier-grade NAT address. Only registries on public addresses are in
	// scope.
	ErrForbiddenAddress = errors.New("registry: address not allowed")
	// ErrPlatformMismatch means the image config names a different OS or
	// architecture than the one requested (or than its index entry claimed).
	ErrPlatformMismatch = errors.New("registry: image config platform differs from the requested platform")
	// ErrVariantUnsupported means a platform variant is involved (requested, or
	// observed on the selected index entry or image config), which cannot be
	// matched with confidence. Use errors.As with *VariantError to read it.
	ErrVariantUnsupported = errors.New("registry: platform variants are not supported")
	// ErrInvalidInput means a repository, reference or platform argument is
	// unusable.
	ErrInvalidInput = errors.New("registry: invalid input")
)

// RateLimitedError is the error for an HTTP 429. The client never waits or
// retries on its own; the caller decides what to do with RetryAfter.
type RateLimitedError struct {
	Host string
	// RetryAfter is the delay the registry asked for, 0 when it gave none or
	// an unusable value.
	RetryAfter time.Duration
}

func (e *RateLimitedError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("registry: rate limited by %s (retry after %s)", e.Host, e.RetryAfter)
	}
	return fmt.Sprintf("registry: rate limited by %s", e.Host)
}

func (e *RateLimitedError) Unwrap() error { return ErrRateLimited }

// StatusError is an unexpected HTTP status that has no more specific type.
type StatusError struct {
	Host   string
	Status int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("registry: %s answered HTTP %d", e.Host, e.Status)
}

// VariantError is the error for ErrVariantUnsupported.
type VariantError struct {
	// Requested is the variant of the requested platform, "" if none.
	Requested string
	// Observed is the variant found on the index entry or image config, ""
	// when the refusal came from the requested variant alone.
	Observed string
}

func (e *VariantError) Error() string {
	return fmt.Sprintf("registry: platform variants are not supported (requested %q, observed %q)", e.Requested, e.Observed)
}

func (e *VariantError) Unwrap() error { return ErrVariantUnsupported }
