package remediation

import (
	"context"
	"errors"

	"github.com/kitsunetrail/kestrelynx/internal/toolfetch"
)

// fetchedTools provides the package manager releases a toolfetch.Provider
// fetches, checks and caches.
type fetchedTools struct{ p *toolfetch.Provider }

// NewToolProvider adapts a toolfetch.Provider to the ToolProvider the update
// stage asks for releases.
func NewToolProvider(p *toolfetch.Provider) ToolProvider { return fetchedTools{p: p} }

func (f fetchedTools) Provide(ctx context.Context, req ToolRequest) (ToolArtifact, error) {
	a, err := f.p.Provide(ctx, toolfetch.Request{
		Manager: toolfetch.Manager(req.Manager), Version: req.Version, Platform: req.Platform,
		NodeVersion: req.NodeVersion, SpecHash: req.SpecHash,
	})
	if err != nil {
		return ToolArtifact{}, toolError(err)
	}
	return toolArtifactOf(a), nil
}

// toolError gives a failure of the fetching package the plan outcome it
// stands for. An error of another kind is returned as it is.
func toolError(err error) error {
	var fe *toolfetch.Error
	if !errors.As(err, &fe) {
		return err
	}
	cat := CategoryManual
	if fe.Deferred() {
		cat = CategoryDeferred
	}
	return &ToolError{Category: cat, Reason: Reason(fe.Code), Detail: fe.Detail}
}

// Release lets the cache go of the file of an artifact.
func (f fetchedTools) Release(a ToolArtifact) {
	f.p.Release(toolfetch.Artifact{SHA256: a.SHA256})
}

func toolArtifactOf(a toolfetch.Artifact) ToolArtifact {
	return ToolArtifact{
		Manager: DependencyManager(a.Manager), Version: a.Version, Format: a.Format, Path: a.Path,
		Size: a.Size, SHA256: a.SHA256, SHA512: a.SHA512, Entry: a.Entry, RunWithNode: a.RunWithNode,
		PublishedAt: a.PublishedAt, RegistryDigest: a.RegistryDigest, SpecHashChecked: a.SpecHashChecked,
	}
}
