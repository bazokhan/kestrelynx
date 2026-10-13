package remediation

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// The runtimes an update job runs in when a project's declarations do not
// choose another: Node.js 24 for npm and pnpm, Python 3.13 for uv and pip.
const (
	defaultNodeRuntime   = "node24"
	defaultPythonRuntime = "python3.13"
)

// Reasons that belong to the runtime and the files a job is given.
const (
	// ReasonRuntimeEndOfLife: the runtime the update would run in is past the
	// end of its support. Nothing is run in it.
	ReasonRuntimeEndOfLife Reason = "runtime_eol"
	// ReasonRuntimeEnginesMismatch: an entry the update added or changed
	// declares an engines.node that does not allow the lowest Node.js version
	// the project's declarations allow, while the update ran on a newer one.
	ReasonRuntimeEnginesMismatch Reason = "runtime_engines_mismatch"
	// ReasonWorkEnvironmentRejected: the program in the container refused to
	// run because the container or the runtime was not what it requires.
	ReasonWorkEnvironmentRejected Reason = "work_environment_rejected"
	// ReasonToolFileMismatch: the package manager archive the cache holds is
	// not the file it was recorded as.
	ReasonToolFileMismatch Reason = "tool_file_mismatch"
	// ReasonWorkProgramMismatch: the program placed into the container is not
	// the one this build was released with.
	ReasonWorkProgramMismatch Reason = "work_program_mismatch"
)

// DefaultRuntimeIDs are the runtimes update jobs run in, which the process
// that starts the containers sets up a client for.
func DefaultRuntimeIDs() []string {
	return []string{"node22", defaultNodeRuntime, "python3.11", "python3.12", defaultPythonRuntime, "python3.14"}
}

// runtimeIDFor is the runtime a manager's jobs run in.
func runtimeIDFor(m worker.Manager) string {
	if worker.KindFor(m) == worker.KindNode {
		return defaultNodeRuntime
	}
	return defaultPythonRuntime
}

// lockPython is the exact Python of the runtime uv locks with; a project whose
// requires-python does not admit it cannot be locked there.
func (r *updateRun) lockPython() string {
	id := r.toolSpec.Runtime
	if id == "" {
		id = defaultPythonRuntime
	}
	spec, _ := worker.LookupRuntime(id)
	return spec.Version
}

// RuntimeRecord is the runtime an update ran in: the row of the runtime table
// it came from and the image that was pinned for it.
type RuntimeRecord struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	// Pip is the version of pip the Python image carries.
	Pip string `json:"pip,omitempty"`
	// Image is the pinned reference (repository and index digest) and
	// Platform the digest of the manifest for the platform the job ran on.
	Image    string `json:"image,omitempty"`
	Platform string `json:"platform,omitempty"`
	Digest   string `json:"digest,omitempty"`
	// Support is the maintenance state of the runtime and EOL the date its
	// support ends.
	Support string `json:"support,omitempty"`
	EOL     string `json:"eol,omitempty"`
	// Basis says why the runtime was chosen (the RuntimeBasis values of a
	// Node.js runtime), Declared are the declarations it rests on and Excluded
	// the lower series they allow that were not used. EnginesFloor is the
	// lowest Node.js version the declarations allow when it is not the one of
	// the runtime: the entries the update added or changed were checked to run
	// on it.
	Basis        string             `json:"basis,omitempty"`
	Declared     []ToolDeclaration  `json:"declared,omitempty"`
	Excluded     []RuntimeExclusion `json:"excluded,omitempty"`
	EnginesFloor string             `json:"engines_floor,omitempty"`
}

// ToolRecord is the package manager release an update ran: the version, how
// the version was chosen, and the hashes of the archive that was checked.
type ToolRecord struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Source says where the version came from: "declared" is the exact version
	// the project names, "default" the version the build selects for the
	// runtime when the project declares none, and "default_in_range" that
	// version when the project declares ranges it falls inside.
	Source string `json:"source"`
	Format string `json:"format,omitempty"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512,omitempty"`
	// PublishedAt is when the registry published the release, RegistryDigest
	// the registry's own digest of the file, and SpecHash the hash the project
	// declared with the version, which the bytes matched.
	PublishedAt    time.Time `json:"published_at,omitempty"`
	RegistryDigest string    `json:"registry_digest,omitempty"`
	SpecHash       string    `json:"spec_hash,omitempty"`
}

// The values of ToolRecord.Source: the project names the exact version
// (packageManager, devEngines.packageManager, engines or required-version);
// it names none, and the build's default version runs; or it names version
// ranges only, and the build's default version is inside all of them.
const (
	toolSourceDefault        = "default"
	toolSourceDefaultInRange = "default_in_range"
)

// jobEnvironment is what a job needs besides its inputs: the runtime, the
// tool (none for pip) with its archive, and the records of both.
type jobEnvironment struct {
	runtime worker.Runtime
	spec    worker.RuntimeSpec
	tool    *worker.Tool
	archive []byte
	rtRec   *RuntimeRecord
	toolRec *ToolRecord
}

// prepareJob chooses the runtime of a manager, refuses one that is past its
// end of support, and obtains the verified archive of the manager's release.
func (u *LangUpdater) prepareJob(ctx context.Context, m worker.Manager, ts ToolSpec) (*jobEnvironment, *updateFailure) {
	rid := ts.Runtime
	if rid == "" {
		rid = runtimeIDFor(m)
	}
	spec, ok := worker.LookupRuntime(rid)
	if !ok || !spec.HasImage() {
		return nil, failedFailure(ReasonUpdateInputInvalid, "the runtime %q is not in the table", rid)
	}
	if spec.EndOfLife(u.now()) {
		return nil, runtimeEOLFailure(spec)
	}
	env := &jobEnvironment{runtime: spec.JobRuntime(), spec: spec}
	env.rtRec = &RuntimeRecord{
		ID: spec.ID, Version: spec.Version, Pip: spec.Pip, Image: spec.ImageRef(),
		Platform: u.cfg.Platform, Digest: spec.Platforms[u.cfg.Platform], Support: spec.Support, EOL: spec.EOL,
		Basis: ts.RuntimeBasis, Declared: ts.RuntimeDeclared, Excluded: ts.RuntimeExcluded, EnginesFloor: ts.NodeFloor,
	}
	if m == worker.ManagerPip {
		return env, nil
	}
	if u.cfg.Tools == nil || u.cfg.DefaultToolVersion == nil {
		return nil, failedFailure(ReasonUpdateInputInvalid, "no package manager provider is configured")
	}
	version, source := ts.ToolVersion, ts.ToolSource
	if version == "" {
		version, source = u.cfg.DefaultToolVersion(DependencyManager(m), spec.ID), toolSourceDefault
	}
	if version == "" {
		return nil, failedFailure(ReasonUpdateInputInvalid, "no default version of %s is set for %s", m, spec.ID)
	}
	req := ToolRequest{Manager: DependencyManager(m), Version: version, Platform: u.cfg.Platform, SpecHash: ts.SpecHash}
	if spec.Kind == worker.KindNode {
		req.NodeVersion = spec.Version
	}
	art, err := u.cfg.Tools.Provide(ctx, req)
	if err != nil {
		return nil, toolFailure(ctx, err)
	}
	// The archive is read into memory here, so the cache may let go of the
	// file as soon as it has been read.
	tool, content, fail := checkArtifact(art, req)
	if rel, ok := u.cfg.Tools.(ToolReleaser); ok {
		rel.Release(art)
	}
	if fail != nil {
		return nil, fail
	}
	env.tool, env.archive = tool, content
	env.toolRec = &ToolRecord{
		Name: string(m), Version: tool.Version, Source: source, Format: tool.Format,
		Size: tool.Size, SHA256: tool.SHA256, SHA512: tool.SHA512,
		PublishedAt: art.PublishedAt, RegistryDigest: art.RegistryDigest, SpecHash: art.SpecHashChecked,
	}
	if ts.SpecHash != "" {
		env.toolRec.SpecHash = ts.SpecHash
	}
	return env, nil
}

// toolFailure maps what the provider returned to the outcome of the item.
func toolFailure(ctx context.Context, err error) *updateFailure {
	var te *ToolError
	switch {
	case errors.As(err, &te):
		return &updateFailure{category: te.Category, reason: te.Reason, detail: te.Detail}
	case ctx.Err() != nil:
		return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
	}
	return failedFailure(ReasonUpdateJobFailed, "obtain the package manager: %s", clip(err.Error(), 300))
}

// checkArtifact requires the artifact to be the release that was asked for,
// reads its file and checks the file against the size and hashes the artifact
// states, and returns the tool as the job carries it.
func checkArtifact(art ToolArtifact, req ToolRequest) (*worker.Tool, []byte, *updateFailure) {
	if art.Manager != req.Manager || art.Version != req.Version {
		return nil, nil, failedFailure(ReasonToolFileMismatch, "the provider returned %s %s for a request for %s %s", art.Manager, art.Version, req.Manager, req.Version)
	}
	tool := &worker.Tool{
		Name: worker.Manager(art.Manager), Version: art.Version, Format: art.Format,
		Size: art.Size, SHA256: art.SHA256, SHA512: art.SHA512, Entry: art.Entry, RunWithNode: art.RunWithNode,
	}
	tool.Path = worker.ToolPath(*tool)
	f, err := os.Open(art.Path)
	if err != nil {
		return nil, nil, failedFailure(ReasonToolFileMismatch, "open the package manager archive: %s", clip(err.Error(), 200))
	}
	defer f.Close()
	if art.Size <= 0 || art.Size > worker.MaxToolArchiveBytes {
		return nil, nil, failedFailure(ReasonToolFileMismatch, "the package manager archive is declared as %d bytes", art.Size)
	}
	content, err := io.ReadAll(io.LimitReader(f, art.Size+1))
	if err != nil {
		return nil, nil, failedFailure(ReasonToolFileMismatch, "read the package manager archive: %s", clip(err.Error(), 200))
	}
	h256, h512 := sha256.Sum256(content), sha512.Sum512(content)
	if int64(len(content)) != art.Size || hex.EncodeToString(h256[:]) != art.SHA256 || hex.EncodeToString(h512[:]) != art.SHA512 {
		return nil, nil, failedFailure(ReasonToolFileMismatch, "the package manager archive is not the file whose size and hashes were recorded")
	}
	// The job's own validation checks the rest of the shape (format, entry).
	return tool, content, nil
}

// RuntimeEOLInfo names a runtime that is past the end of its support, for the
// notifications to word in the reader's language.
type RuntimeEOLInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// EOL is the date support ended, "YYYY-MM-DD"; it is empty for a series
	// older than every one of the runtime table.
	EOL string `json:"eol,omitempty"`
}

func runtimeEOLInfo(spec worker.RuntimeSpec) *RuntimeEOLInfo {
	return &RuntimeEOLInfo{ID: spec.ID, Name: spec.Label(), EOL: spec.EOL}
}

// RuntimeEndOfLifeText is the detail given when a runtime is past the end of
// its support.
func RuntimeEndOfLifeText(spec worker.RuntimeSpec) string {
	if spec.EOL == "" {
		return fmt.Sprintf("%s is past the end of its support; upgrade the runtime before updating", spec.Label())
	}
	return fmt.Sprintf("%s reached the end of its support on %s; upgrade the runtime before updating", spec.Label(), spec.EOL)
}

func runtimeEOLFailure(spec worker.RuntimeSpec) *updateFailure {
	f := manualFailure(ReasonRuntimeEndOfLife, "%s", RuntimeEndOfLifeText(spec))
	f.runtimeEOL = runtimeEOLInfo(spec)
	return f
}

func (u *LangUpdater) now() time.Time {
	if u.cfg.Now != nil {
		return u.cfg.Now()
	}
	return time.Now()
}

// readProgram returns the work program for the platform, checked against the
// hash this build embeds, every time it is placed into a container.
func (u *LangUpdater) readProgram() ([]byte, *updateFailure) {
	if u.cfg.Program == nil {
		return nil, failedFailure(ReasonWorkProgramMismatch, "no work program is configured")
	}
	b, err := u.cfg.Program()
	if err != nil {
		return nil, &updateFailure{category: CategoryDeferred, reason: ReasonWorkProgramMismatch, detail: clip(err.Error(), 300)}
	}
	return b, nil
}

// declaredRuntimeEndOfLife fails an update whose declarations allow only
// runtimes that are past the end of their support (an .nvmrc that says 20, a
// requires-python of 3.9 or 3.10): the update is not run in a newer runtime
// than the project asks for. Declarations that allow a runtime still in
// support, or that name none of the table, are left to ResolveToolSpec.
func (u *LangUpdater) declaredRuntimeEndOfLife(in ToolSpecInput) *updateFailure {
	in.Now = u.now()
	spec, ok := declaredRuntimeEOL(in, in.Now)
	if !ok {
		return nil
	}
	return runtimeEOLFailure(spec)
}
