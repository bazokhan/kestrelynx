package remediation

import (
	"context"
	"errors"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/toolfetch"
)

func TestToolProviderMapsFailuresToOutcomes(t *testing.T) {
	p, err := toolfetch.New(toolfetch.Config{StorageDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	tools := NewToolProvider(p)

	// Outside the supported range: nothing is requested, a person decides.
	_, err = tools.Provide(context.Background(), ToolRequest{Manager: ManagerPnpm, Version: "8.15.9", Platform: "linux/amd64", NodeVersion: "24.21.0"})
	var te *ToolError
	if !errors.As(err, &te) || te.Category != CategoryManual || te.Reason != ReasonToolVersionUnsupported || te.Detail == "" {
		t.Fatalf("error = %v", err)
	}
	// A request cut short is left for a later pass.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = tools.Provide(ctx, ToolRequest{Manager: ManagerNpm, Version: "11.21.0", Platform: "linux/amd64", NodeVersion: "24.21.0"})
	if !errors.As(err, &te) || te.Category != CategoryDeferred || te.Reason != ReasonToolFetchFailed {
		t.Fatalf("error = %v", err)
	}
}

func TestToolArtifactConversion(t *testing.T) {
	got := toolArtifactOf(toolfetch.Artifact{
		Manager: toolfetch.ManagerPnpm, Version: "11.28.5", Format: toolfetch.FormatNpmTgz, Path: "/x/blob", Size: 7,
		SHA256: "a", SHA512: "b", Entry: "bin/pnpm.mjs", RunWithNode: true,
	})
	want := ToolArtifact{Manager: ManagerPnpm, Version: "11.28.5", Format: "npm-tgz", Path: "/x/blob", Size: 7, SHA256: "a", SHA512: "b", Entry: "bin/pnpm.mjs", RunWithNode: true}
	if got != want {
		t.Fatalf("got %+v", got)
	}
	// The reasons are the codes of the fetching package.
	for code, reason := range map[toolfetch.Code]Reason{
		toolfetch.CodeVersionUnsupported: ReasonToolVersionUnsupported, toolfetch.CodeVersionNotFound: ReasonToolVersionNotFound,
		toolfetch.CodeHashMismatch: ReasonToolHashMismatch, toolfetch.CodeHashUnsupported: ReasonToolHashUnsupported,
		toolfetch.CodeArtifactInvalid: ReasonToolArtifactInvalid, toolfetch.CodeMetadataInvalid: ReasonToolMetadataInvalid,
		toolfetch.CodeTooNew: ReasonToolTooNew, toolfetch.CodeFetchFailed: ReasonToolFetchFailed,
		toolfetch.CodeFetchBudget: ReasonToolFetchBudget, toolfetch.CodeCacheFull: ReasonToolCacheFull,
	} {
		if Reason(code) != reason {
			t.Errorf("%s != %s", code, reason)
		}
	}
}
