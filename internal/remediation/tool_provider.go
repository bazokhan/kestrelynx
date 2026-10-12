package remediation

import (
	"context"
	"time"
)

// ToolRequest asks for one package manager release for one platform.
type ToolRequest struct {
	Manager DependencyManager // ManagerNpm, ManagerPnpm, ManagerUv
	Version string            // exact version, e.g. "10.34.4"
	// Platform is "linux/amd64" or "linux/arm64".
	Platform string
	// NodeVersion is the exact Node.js version the job runs on ("" for uv).
	NodeVersion string
	// SpecHash is "<algo>.<hex>" from the project's packageManager, or "".
	SpecHash string
}

// ToolArtifact is a verified release file in the main process's cache.
type ToolArtifact struct {
	Manager DependencyManager
	Version string
	// Format is "npm-tgz" or "wheel".
	Format string
	// Path is the absolute path of the cached file, read-only to callers.
	Path   string
	Size   int64
	SHA256 string // hex
	SHA512 string // hex
	// Entry is the path of the executable inside the archive after the
	// extraction rules (for example "bin/pnpm.cjs", or
	// "uv-0.13.0.data/scripts/uv"). RunWithNode says it is a JavaScript file
	// started with node.
	Entry       string
	RunWithNode bool
	// PublishedAt is when the registry published the release and
	// RegistryDigest the registry's digest of the file ("<algo>-<hex>").
	// SpecHashChecked is the declared hash the bytes matched, "" when the
	// project declared none.
	PublishedAt     time.Time
	RegistryDigest  string
	SpecHashChecked string
}

// ToolError carries the plan outcome for a failed request.
type ToolError struct {
	Category Category
	Reason   Reason
	Detail   string
}

func (e *ToolError) Error() string { return string(e.Reason) + ": " + e.Detail }

// ToolProvider resolves, verifies and caches package manager releases.
type ToolProvider interface {
	Provide(ctx context.Context, req ToolRequest) (ToolArtifact, error)
}

// ToolReleaser is implemented by a provider whose cache holds a file for as
// long as a caller may use it; Release says the caller is done with it.
type ToolReleaser interface {
	Release(ToolArtifact)
}
