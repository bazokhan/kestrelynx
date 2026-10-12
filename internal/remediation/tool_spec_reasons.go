package remediation

// Reasons for a unit whose declared tool or runtime versions, or whose
// settings that fetch tools, are not ones the update can run with. Each is
// decided before anything runs.
const (
	// A declaration that cannot be read.
	ReasonNodeSpecInvalid    Reason = "node_spec_invalid"
	ReasonPythonSpecInvalid  Reason = "python_spec_invalid"
	ReasonManagerSpecInvalid Reason = "manager_spec_invalid"

	// Declarations that cannot all hold at once, or that name another
	// package manager than the one the unit's lockfile belongs to.
	ReasonNodeSpecConflict    Reason = "node_spec_conflict"
	ReasonPythonSpecConflict  Reason = "python_spec_conflict"
	ReasonManagerSpecConflict Reason = "manager_spec_conflict"

	// Declarations that are read and consistent but name a version, or a
	// form of declaration, that updates do not run with yet.
	ReasonNodeSpecUnsupported    Reason = "node_spec_unsupported"
	ReasonPythonSpecUnsupported  Reason = "python_spec_unsupported"
	ReasonManagerSpecUnsupported Reason = "manager_spec_unsupported"

	// ReasonToolFetchConfigUnsupported: the project sets something that makes
	// a package manager fetch a tool, a runtime or settings from the network
	// by itself (or that changes what it resolves from outside the lockfile
	// and package.json), which the update does not allow.
	ReasonToolFetchConfigUnsupported Reason = "tool_fetch_config_unsupported"
)

// Reasons of a package manager release that could not be provided; they are
// the codes of the fetching package.
const (
	ReasonToolVersionUnsupported Reason = "tool_version_unsupported"
	ReasonToolVersionNotFound    Reason = "tool_version_not_found"
	ReasonToolHashMismatch       Reason = "tool_hash_mismatch"
	ReasonToolHashUnsupported    Reason = "tool_hash_unsupported"
	ReasonToolArtifactInvalid    Reason = "tool_artifact_invalid"
	ReasonToolMetadataInvalid    Reason = "tool_metadata_invalid"
	ReasonToolTooNew             Reason = "tool_too_new"
	ReasonToolFetchFailed        Reason = "tool_fetch_failed"
	ReasonToolFetchBudget        Reason = "tool_fetch_budget"
	ReasonToolCacheFull          Reason = "tool_cache_full"
)
