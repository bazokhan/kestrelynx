package toolfetch

import "fmt"

// Class says what a failed request means for the update that asked.
type Class string

const (
	// ClassManual: the request cannot be met however often it is repeated
	// (a version outside the supported range, a wrong hash, a version the
	// registry does not have), so a person decides.
	ClassManual Class = "manual"
	// ClassDeferred: the request may be met later (a version still inside its
	// waiting period, a registry that did not answer, a full cache, a spent
	// budget).
	ClassDeferred Class = "deferred"
)

// Code names the reason of a failed request. The values are stored in plans
// and records, so they are fixed strings.
type Code string

const (
	// Manual.

	// CodeVersionUnsupported: the version is outside the supported range, is a
	// pre-release, is not written as an exact version, or its engines.node
	// does not allow the Node.js the job runs on.
	CodeVersionUnsupported Code = "tool_version_unsupported"
	// CodeVersionNotFound: the registry has no such version (or no file of it
	// for the platform).
	CodeVersionNotFound Code = "tool_version_not_found"
	// CodeHashMismatch: the bytes do not match the registry's digest or the
	// hash the project declared.
	CodeHashMismatch Code = "tool_hash_mismatch"
	// CodeHashUnsupported: the declared hash is written in a form that is not
	// read, or the tool takes no declared hash.
	CodeHashUnsupported Code = "tool_hash_unsupported"
	// CodeArtifactInvalid: the file is over its size limits or is not shaped
	// as expected (the entry is missing, there are too many files).
	CodeArtifactInvalid Code = "tool_artifact_invalid"
	// CodeMetadataInvalid: the registry's document for the version is over its
	// size limit or does not say what is needed.
	CodeMetadataInvalid Code = "tool_metadata_invalid"

	// Deferred.

	// CodeTooNew: the version was published less than the minimum age ago, or
	// its publication time is not known.
	CodeTooNew Code = "tool_too_new"
	// CodeFetchFailed: the registry could not be reached or answered with an
	// error, or an address was refused.
	CodeFetchFailed Code = "tool_fetch_failed"
	// CodeFetchBudget: the fetches allowed in the current cycle are spent.
	CodeFetchBudget Code = "tool_fetch_budget"
	// CodeCacheFull: the cache has no room for the file and nothing can be
	// evicted.
	CodeCacheFull Code = "tool_cache_full"
)

// Error is the failure of a request. Class and Code are the machine-readable
// part; Detail says what was seen.
type Error struct {
	Class  Class
	Code   Code
	Detail string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Detail) }

// Deferred reports whether the request may succeed later.
func (e *Error) Deferred() bool { return e.Class == ClassDeferred }

func manual(code Code, format string, args ...any) *Error {
	return &Error{Class: ClassManual, Code: code, Detail: fmt.Sprintf(format, args...)}
}

func deferred(code Code, format string, args ...any) *Error {
	return &Error{Class: ClassDeferred, Code: code, Detail: fmt.Sprintf(format, args...)}
}
