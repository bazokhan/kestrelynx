package remediation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// LangUpdateConfig holds what the dependency update stage needs.
type LangUpdateConfig struct {
	// Work runs the update jobs, Scanner scans the dependency files before
	// and after, PyPI tells the distribution files of a pip release and
	// GitHub rereads the files a unit was planned from.
	Work    WorkRunner
	Scanner FSScanner
	PyPI    PyPIFiles
	// Npm tells what the public npm registry publishes for a version; the
	// update stage checks every package version an update adds or changes
	// against it.
	Npm    NpmRegistry
	GitHub GitHubReader
	// Prepared are the cycle's scan conditions (Plan.Conditions). The stage's
	// scans are valid only under them.
	Prepared scanner.ScanConditions
	// Images are the environments of the cycle's scanned images by entity key
	// (see ImageEnvs); a pip update takes its target environment from them.
	Images map[string]ImageEnv
	Intel  IntelFunc
	// MaxJobs is how many items one pass may update; the rest are deferred.
	// An item is one job however many containers it takes (a pip update runs
	// its original and its rewritten requirements in two). Zero allows none.
	MaxJobs int
	// JobTimeout bounds one container, from creation to deletion; zero means
	// DefaultUpdateJobTimeout.
	JobTimeout time.Duration
	// Resources are the limits of a container; a zero value means
	// DefaultUpdateResources.
	Resources docker.Resources
	// JobIDPrefix starts the job ids (letters, digits, '.', '_' and '-');
	// empty means "lang".
	JobIDPrefix string
	// Tools supplies the package manager releases, and DefaultToolVersion the
	// version of a manager to run in a runtime when the project declares
	// none. Platform is the platform the jobs run on ("linux/amd64"); empty
	// means this process's.
	Tools              ToolProvider
	DefaultToolVersion func(m DependencyManager, runtimeID string) string
	Platform           string
	// Program returns the bytes of the work program for Platform, checked
	// against the hash this build was released with. It is called whenever a
	// job is made, so the bytes that are sent are the ones that were checked.
	Program func() ([]byte, error)
	// Now is the clock the end of a runtime's support is judged by; nil means
	// time.Now.
	Now func() time.Time
}

// DefaultUpdateJobTimeout is the time one update container gets.
const DefaultUpdateJobTimeout = 6 * time.Minute

// DefaultUpdateResources are the container limits an update job runs under.
func DefaultUpdateResources() docker.Resources {
	return docker.Resources{
		MemoryBytes: 2 << 30, NanoCPUs: 2_000_000_000, PidsLimit: 512, NofileLimit: 4096,
		ShmSizeBytes: 64 << 20, TmpSizeBytes: 512 << 20, HomeSizeBytes: 512 << 20, ToolsSizeBytes: 256 << 20,
	}
}

// jobDeadlineSeconds is the deadline the work program is given for a job that
// the container may run for timeout: the timeout less the time the container
// needs to start and report.
func jobDeadlineSeconds(timeout time.Duration) int {
	return int(timeout.Seconds()) - 30
}

// LangUpdater runs the dependency update stage.
type LangUpdater struct {
	cfg LangUpdateConfig
	// runID makes the job ids of one pass distinct from those of another.
	runID string
}

// NewLangUpdater validates cfg and returns an updater.
func NewLangUpdater(cfg LangUpdateConfig) (*LangUpdater, error) {
	if cfg.Work == nil || cfg.Scanner == nil || cfg.PyPI == nil || cfg.Npm == nil || cfg.GitHub == nil {
		return nil, errors.New("remediation: the update stage needs a work runner, a scanner, a PyPI client, an npm registry client and a GitHub reader")
	}
	if cfg.MaxJobs < 0 {
		return nil, errors.New("remediation: the update job limit must not be negative")
	}
	if cfg.JobTimeout < 0 {
		return nil, errors.New("remediation: the update job timeout must not be negative")
	}
	if cfg.JobTimeout == 0 {
		cfg.JobTimeout = DefaultUpdateJobTimeout
	}
	if cfg.JobTimeout < time.Minute {
		return nil, errors.New("remediation: the update job timeout is under a minute")
	}
	if d := jobDeadlineSeconds(cfg.JobTimeout); d > worker.MaxDeadlineSeconds {
		return nil, fmt.Errorf("remediation: the update job timeout %s gives the work program a deadline of %d seconds, over its limit of %d", cfg.JobTimeout, d, worker.MaxDeadlineSeconds)
	}
	if cfg.Resources == (docker.Resources{}) {
		cfg.Resources = DefaultUpdateResources()
	}
	if cfg.JobIDPrefix == "" {
		cfg.JobIDPrefix = "lang"
	}
	if cfg.Platform == "" {
		cfg.Platform = "linux/" + runtime.GOARCH
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, fmt.Errorf("remediation: job id: %w", err)
	}
	return &LangUpdater{cfg: cfg, runID: hex.EncodeToString(b[:])}, nil
}

// LangUpdateUsage records what a pass spent.
type LangUpdateUsage struct {
	Jobs int
}

// Run updates every dependency_update_candidate item of the plan in place, in
// plan order, and returns what it spent. An item becomes a pr_candidate when
// its update ran, its result passed every check and the dependency files
// scanned before and after show the targets gone and nothing new. Any other
// outcome is a category of its own with a reason, and the item is never split:
// when part of its set fails, none of it is proposed.
func (u *LangUpdater) Run(ctx context.Context, plan *Plan) LangUpdateUsage {
	var use LangUpdateUsage
	for i := range plan.LanguageItems {
		it := &plan.LanguageItems[i]
		if it.Category != CategoryDependencyUpdateCandidate {
			continue
		}
		switch {
		case ctx.Err() != nil:
			deferItem(it, ReasonCycleDeadline, ctx.Err().Error())
		case use.Jobs >= u.cfg.MaxJobs:
			deferItem(it, ReasonUpdateJobLimit, fmt.Sprintf("the pass updates at most %d dependency units", u.cfg.MaxJobs))
		default:
			use.Jobs++
			u.updateItem(ctx, it, i)
		}
	}
	return use
}

// updateFailure is why an item was not turned into a pull request candidate.
type updateFailure struct {
	category Category
	reason   Reason
	detail   string
	// pkgs holds the reasons that belong to one package (by matching name);
	// the other packages of the set get ReasonUpdateSetNotApplied.
	pkgs map[string]updateFailureDetail
	// retryWithout, when set, says the update can be made again without these
	// packages (by matching name): they did not reach their target while the
	// others of the set may have, and the result cannot be used as it is. The
	// update stage runs the item once more without them.
	retryWithout map[string]updateFailureDetail
	// runtimeEOL names the runtime of a runtime_eol failure.
	runtimeEOL *RuntimeEOLInfo
}

type updateFailureDetail struct {
	reason Reason
	detail string
}

func manualFailure(reason Reason, format string, args ...any) *updateFailure {
	return &updateFailure{category: CategoryManual, reason: reason, detail: fmt.Sprintf(format, args...)}
}

// pkgFailure is a manual failure that belongs to one package of the set.
func pkgFailure(name string, reason Reason, format string, args ...any) *updateFailure {
	f := manualFailure(reason, format, args...)
	f.pkgs = map[string]updateFailureDetail{name: {reason, f.detail}}
	return f
}

func failedFailure(reason Reason, format string, args ...any) *updateFailure {
	return &updateFailure{category: CategoryFailed, reason: reason, detail: fmt.Sprintf(format, args...)}
}

// deferItem leaves an item undone; its packages stay as planned.
func deferItem(it *LanguageItem, reason Reason, detail string) {
	it.Category, it.Reason, it.Detail = CategoryDeferred, reason, detail
}

// apply records the failure on the item. The packages being updated become
// manual with the failure's reason, or their own when the failure is one
// package's; the update's artifacts are never kept.
func (f *updateFailure) apply(it *LanguageItem, upd []int) {
	it.Category, it.Reason, it.Detail = f.category, f.reason, f.detail
	it.RuntimeEOL = f.runtimeEOL
	it.Artifacts = nil
	for _, i := range upd {
		p := &it.Packages[i]
		if f.category == CategoryDeferred {
			continue
		}
		p.AdoptedVersion = ""
		if d, ok := f.pkgs[p.matchName()]; ok {
			manualPackage(p, d.reason, d.detail)
		} else if len(f.pkgs) > 0 {
			manualPackage(p, ReasonUpdateSetNotApplied, "another package of the unit's update set could not be updated, and a unit is updated as a whole: "+f.detail)
		} else {
			manualPackage(p, f.reason, f.detail)
		}
	}
}

// matchName is the name packages of one manager are matched by.
func (p LanguagePackage) matchName() string {
	if p.Normalized != "" {
		return p.Normalized
	}
	return p.Name
}

// updateSet is what an item's update works on.
type updateSet struct {
	idx   []int    // indexes of the packages with Action update
	names []string // distinct matching names, sorted
	// target is the lowest version that fixes the package, by matching name.
	target map[string]string
	// The following are indexed once, so that nothing in the update looks a
	// package up by scanning the list: the packages of each matching name,
	// the name the image reports for it, whether the project requires it
	// itself in an occurrence being updated, and the set of the names.
	byName  map[string][]int
	display map[string]string
	direct  map[string]bool
	targets map[string]bool
}

// newUpdateSet collects the packages to update. Packages of one name must
// share their target (the planner makes sure of it).
func newUpdateSet(it *LanguageItem) (updateSet, *updateFailure) {
	s := updateSet{target: map[string]string{}, byName: map[string][]int{}, display: map[string]string{}, direct: map[string]bool{}, targets: map[string]bool{}}
	for i, p := range it.Packages {
		if p.Action != ActionUpdate {
			continue
		}
		n := p.matchName()
		if p.SelectionLowerBound == "" {
			return s, failedFailure(ReasonUpdateInputInvalid, "%s has no target version in the plan", p.Name)
		}
		if old, ok := s.target[n]; ok && old != p.SelectionLowerBound {
			return s, failedFailure(ReasonUpdateInputInvalid, "%s has two different target versions in the plan", p.Name)
		}
		if _, ok := s.target[n]; !ok {
			s.names = append(s.names, n)
		}
		s.target[n] = p.SelectionLowerBound
		s.idx = append(s.idx, i)
		s.byName[n] = append(s.byName[n], i)
		s.targets[n] = true
		if _, ok := s.display[n]; !ok {
			s.display[n] = p.Name
		}
		for _, o := range p.Occurrences {
			if o.Matched && o.Direct {
				s.direct[n] = true
				break
			}
		}
	}
	if len(s.idx) == 0 {
		return s, failedFailure(ReasonUpdateInputInvalid, "the item has no package to update")
	}
	sort.Strings(s.names)
	return s, nil
}

// pnpmWorkspaceName is the file of pnpm settings.
const pnpmWorkspaceName = "pnpm-workspace.yaml"

// sourceFiles are the files of the unit as the plan recorded them, read
// again.
type sourceFiles struct {
	manifestName string // empty for pip
	lockName     string
	manifest     []byte
	lock         []byte
	manifestPath string
	manifestMode string
	// settings is the pnpm-workspace.yaml of a pnpm project that has one: a
	// file of settings the plan accepted, given to the work container as an
	// input and never changed or written back.
	settings []byte
	lockPath string
	lockMode string
	// specFiles are the files the declarations of the runtime and the package
	// manager are read from (see ToolSpecFileNames), by name, and uvToml the
	// paths of the uv.toml files the plan found.
	specFiles map[string][]byte
	uvToml    []string
}

// readSources reads the unit's manifest and lockfile again from the commit
// the plan recorded and requires them to be the blobs it recorded.
func (u *LangUpdater) readSources(ctx context.Context, it *LanguageItem) (*sourceFiles, *updateFailure) {
	sf, fail := u.readUnitSources(ctx, it)
	if fail != nil {
		return nil, fail
	}
	if fail := u.readToolSpecFiles(ctx, it, sf); fail != nil {
		return nil, fail
	}
	return sf, nil
}

// readUnitSources reads the manifest, the lockfile and the settings file of
// the unit.
func (u *LangUpdater) readUnitSources(ctx context.Context, it *LanguageItem) (*sourceFiles, *updateFailure) {
	src := it.Source
	if src.CommitSHA == "" {
		return nil, failedFailure(ReasonUpdateInputInvalid, "the plan recorded no commit")
	}
	sf := &sourceFiles{lockName: it.Manager.LockfileName()}
	switch it.Manager {
	case ManagerNpm, ManagerPnpm:
		sf.manifestName = "package.json"
	case ManagerUv:
		sf.manifestName = "pyproject.toml"
	case ManagerPip:
	default:
		return nil, failedFailure(ReasonUpdateInputInvalid, "unknown manager %q", it.Manager)
	}
	find := func(name string) (SourceFile, *updateFailure) {
		var found []SourceFile
		for _, f := range src.Files {
			if path.Base(f.Path) == name && f.Repository == "" {
				found = append(found, f)
			}
		}
		if len(found) != 1 {
			return SourceFile{}, failedFailure(ReasonUpdateInputInvalid, "the plan records %d files named %s", len(found), name)
		}
		return found[0], nil
	}
	read := func(f SourceFile) (github.File, *updateFailure) {
		got, err := u.cfg.GitHub.ReadFile(ctx, src.Repository, src.CommitSHA, f.Path)
		if err != nil {
			return github.File{}, readFailure(err, f.Path)
		}
		if got.SHA != f.BlobSHA || got.Path != f.Path {
			return github.File{}, failedFailure(ReasonSourceChanged, "%s is not the blob the plan was made from (%s, now %s)", f.Path, f.BlobSHA, got.SHA)
		}
		return got, nil
	}
	lf, fail := find(sf.lockName)
	if fail != nil {
		return nil, fail
	}
	got, fail := read(lf)
	if fail != nil {
		return nil, fail
	}
	sf.lock, sf.lockPath, sf.lockMode = got.Content, got.Path, got.Mode
	if sf.manifestName == "" {
		return sf, nil
	}
	mf, fail := find(sf.manifestName)
	if fail != nil {
		return nil, fail
	}
	if path.Dir(mf.Path) != path.Dir(lf.Path) {
		return nil, failedFailure(ReasonUpdateInputInvalid, "%s and %s are in different directories", mf.Path, lf.Path)
	}
	got, fail = read(mf)
	if fail != nil {
		return nil, fail
	}
	sf.manifest, sf.manifestPath, sf.manifestMode = got.Content, got.Path, got.Mode
	if it.Manager != ManagerPnpm {
		return sf, nil
	}
	// A settings file the plan did not find must not be there now either.
	for _, p := range src.Absent {
		if path.Base(p) != pnpmWorkspaceName || !isSameOrAbove(path.Dir(p), path.Dir(lf.Path)) {
			continue
		}
		for _, f := range src.Files {
			if f.Path == p {
				return nil, failedFailure(ReasonUpdateInputInvalid, "the plan records %s as both read and not found", p)
			}
		}
		_, err := u.cfg.GitHub.ReadFile(ctx, src.Repository, src.CommitSHA, p)
		var nr *github.NotRegularFileError
		switch {
		case errors.Is(err, github.ErrNotFound):
		case err == nil, errors.As(err, &nr), errors.Is(err, github.ErrLFSPointer), errors.Is(err, github.ErrTooLarge):
			return nil, failedFailure(ReasonSourceChanged, "%s did not exist when the plan was made and does now", p)
		default:
			return nil, readFailure(err, p)
		}
	}
	var settings []SourceFile
	for _, f := range src.Files {
		if path.Base(f.Path) == pnpmWorkspaceName && f.Repository == "" {
			settings = append(settings, f)
		}
	}
	switch len(settings) {
	case 0:
		return sf, nil
	case 1:
	default:
		return nil, failedFailure(ReasonUpdateInputInvalid, "the plan records %d files named %s", len(settings), pnpmWorkspaceName)
	}
	if path.Dir(settings[0].Path) != path.Dir(lf.Path) {
		return nil, failedFailure(ReasonUpdateInputInvalid, "%s and %s are in different directories", settings[0].Path, lf.Path)
	}
	got, fail = read(settings[0])
	if fail != nil {
		return nil, fail
	}
	// The plan accepted these bytes; they are checked again, as the plan did.
	if reason, why := pnpmWorkspaceProblem(got.Content); reason != "" {
		return nil, manualFailure(reason, "%s", why)
	}
	sf.settings = got.Content
	return sf, nil
}

// readFailure maps a GitHub read error: running out of time or of a request
// allowance defers the item, anything else fails it.
func readFailure(err error, file string) *updateFailure {
	var limited *github.RateLimitedError
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: err.Error()}
	case errors.Is(err, github.ErrBudgetExhausted):
		return &updateFailure{category: CategoryDeferred, reason: ReasonGitHubBudget, detail: "GitHub request budget exhausted"}
	case errors.Is(err, github.ErrByteBudgetExhausted):
		return &updateFailure{category: CategoryDeferred, reason: ReasonByteBudget, detail: err.Error()}
	case errors.As(err, &limited):
		return &updateFailure{category: CategoryDeferred, reason: ReasonRateLimited, detail: err.Error()}
	}
	return failedFailure(ReasonSourceReadFailed, "read %s: %v", file, err)
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// jobID makes a container job id for the n-th item of the plan.
func (u *LangUpdater) jobID(n int, role string) string {
	return fmt.Sprintf("%s-%s-%d-%s", strings.Trim(u.cfg.JobIDPrefix, "-"), u.runID, n, role)
}

// updateItem runs the update of one item and records the outcome on it.
//
// When part of the set does not reach its target, the item is proposed
// without those packages instead of failing as a whole: the result of the run
// is used as it is when it left them where they were, and the update is run
// once more without them when it moved them or the result cannot be used. A
// run that has left packages out is not left out again, so an item takes at
// most two runs, and both count as the one job the item is.
func (u *LangUpdater) updateItem(ctx context.Context, it *LanguageItem, n int) {
	set, fail := newUpdateSet(it)
	if fail != nil {
		fail.apply(it, set.idx)
		return
	}
	res := &updateRun{u: u, it: it, n: n, set: set, full: set, upd: &LanguageUpdate{}}
	fail = res.run(ctx)
	if fail != nil && len(fail.retryWithout) > 0 {
		first := res
		res, fail = u.runWithout(ctx, it, n, set, fail.retryWithout)
		if fail != nil && fail.category == CategoryDeferred {
			// The second run did not finish in time: the item stays as it was
			// planned, and what the first run found stays on record with the note
			// of the second.
			first.upd.Notes = uniqueSorted(append(first.upd.Notes, res.upd.Notes...))
			res = first
		}
	}
	if fail != nil {
		it.Update = res.upd
		it.SourceCheck = res.check
		fail.apply(it, set.idx)
		res.keepLeftOutReasons(fail)
		return
	}
	res.succeed()
}

// runWithout runs the update of the item again with the packages in without
// (by matching name) left out of the set.
func (u *LangUpdater) runWithout(ctx context.Context, it *LanguageItem, n int, set updateSet, without map[string]updateFailureDetail) (*updateRun, *updateFailure) {
	names := make([]string, 0, len(without))
	for name := range without {
		names = append(names, set.display[name])
	}
	sort.Strings(names)
	res := &updateRun{
		u: u, it: it, n: n, set: set.without(without), full: set, upd: &LanguageUpdate{},
		attempt: 1, noPartial: true, leftOut: without,
	}
	res.upd.Notes = append(res.upd.Notes, "the first run did not take "+strings.Join(names, ", ")+" to the target, so the update was run again without it")
	fail := res.run(ctx)
	if fail != nil {
		// A failure of the second run keeps why the packages were left out in
		// its detail, whatever its category.
		var why []string
		for _, n := range names {
			for m, d := range without {
				if set.display[m] == n {
					why = append(why, clip(d.detail, 200))
				}
			}
		}
		fail.detail = "after leaving out " + strings.Join(names, ", ") + ", which did not reach the target (" + strings.Join(why, "; ") + "), the update was run again and: " + fail.detail
		// A result of the work container that contradicts itself is a problem of
		// the result, as a refused diff is; it is not tried again as a failed
		// run is.
		if fail.category == CategoryFailed && resultProblemReasons[fail.reason] {
			fail.category = CategoryManual
		}
	}
	return res, fail
}

// resultProblemReasons are the reasons of a failed run that say the output of
// the work container itself cannot be used (its result block does not decode
// or contradicts its files), not that the run could not be made.
var resultProblemReasons = map[Reason]bool{ReasonUpdateResultInvalid: true}

// without returns the set with the packages of the given matching names taken
// out.
func (s updateSet) without(drop map[string]updateFailureDetail) updateSet {
	out := updateSet{target: map[string]string{}, byName: map[string][]int{}, display: map[string]string{}, direct: map[string]bool{}, targets: map[string]bool{}}
	for _, n := range s.names {
		if _, gone := drop[n]; gone {
			continue
		}
		out.names = append(out.names, n)
		out.target[n] = s.target[n]
		out.byName[n] = s.byName[n]
		out.display[n] = s.display[n]
		out.targets[n] = true
		if s.direct[n] {
			out.direct[n] = true
		}
		out.idx = append(out.idx, s.byName[n]...)
	}
	sort.Ints(out.idx)
	return out
}

// updateRun is the state of one item's update.
type updateRun struct {
	u   *LangUpdater
	it  *LanguageItem
	n   int
	set updateSet
	// full is the set the item was planned with. set is the same, or the
	// same without the packages in leftOut.
	full updateSet
	upd  *LanguageUpdate
	// attempt is 0 for the first run of the item and 1 for the run made
	// without the packages that did not reach their target; noPartial says the
	// run may not leave packages out (it is that second run, or the manager
	// has no lockfile to judge the packages by).
	attempt   int
	noPartial bool
	// leftOut are the packages of the item that were left out of the update,
	// by matching name, with why.
	leftOut map[string]updateFailureDetail
	// unreached are the packages of the set (by matching name) that the
	// updated file holds below their target, found while checking the
	// versions of the result.
	unreached map[string]updateFailureDetail

	src *sourceFiles
	// toolSpec is the runtime and package manager release the declarations of
	// the unit come to (the build's defaults where it declares none).
	toolSpec ToolSpec
	// pnpmTrigger is the direct dependency taken out of the importer of the
	// lockfile a pnpm update was made from so that pnpm resolves again, ""
	// when a target was taken out instead or the manifest was edited.
	pnpmTrigger string
	// manifest is the manifest the update runs on and must leave as it is:
	// the original, or the original with the edits in upd.ManifestEdits.
	manifest []byte
	// newLock is the updated lockfile (requirements for pip).
	newLock []byte
	// adopted is the lowest version of each updated package the new file
	// holds, by matching name.
	adopted map[string]string
	// afterVersions lists every version of each updated package the new file
	// holds, by matching name.
	afterVersions map[string][]string
	check         *SourceCheck
	// The registry documents looked up during this update, by name and
	// version, and how many lookups it has made.
	npmDocs map[string]NpmDist
	pyDocs  map[string]PyPIRelease
	lookups int
	// declMarkers is the budget (and token cache) for the markers judged
	// against the project's requires-python, and falseThrough the answers.
	declMarkers  *markerBudget
	falseThrough map[string]bool
}

// succeed records a passed update on the item.
func (r *updateRun) succeed() {
	it := r.it
	it.Category, it.Reason = CategoryPRCandidate, ReasonUpdateVerified
	it.Detail = fmt.Sprintf("%d packages were updated in %s, the result was inspected and the dependency files scanned before and after show the targets gone", len(r.set.idx), it.Manager.LockfileName())
	if len(r.leftOut) > 0 {
		it.Detail += fmt.Sprintf("; %d package(s) did not reach their target and are left out of the update", len(r.leftOut))
	}
	it.UpdateExecuted, it.PostUpdateCheckExecuted = true, true
	it.Update = r.upd
	it.SourceCheck = r.check
	for _, i := range r.set.idx {
		p := &it.Packages[i]
		p.AdoptedVersion = r.adopted[p.matchName()]
		p.Reason, p.Detail = ReasonUpdateVerified, ""
	}
	for _, i := range r.full.idx {
		p := &it.Packages[i]
		if d, ok := r.leftOut[p.matchName()]; ok {
			p.AdoptedVersion = ""
			manualPackage(p, d.reason, d.detail)
			p.LeftOut = true
		}
	}
	it.Artifacts = []ArtifactFile{{
		Path: r.src.lockPath, SHA256: sha256Hex(r.newLock), Size: int64(len(r.newLock)),
		Mode: r.src.lockMode, Content: r.newLock,
	}}
	if len(r.upd.ManifestEdits) > 0 {
		it.Artifacts = append(it.Artifacts, ArtifactFile{
			Path: r.src.manifestPath, SHA256: sha256Hex(r.manifest), Size: int64(len(r.manifest)),
			Mode: r.src.manifestMode, Content: r.manifest,
		})
	}
}

// keepLeftOutReasons gives the packages that were left out of a run that then
// failed their own reason, which is why they were left out, in place of the
// failure's. The packages stay as the plan had them when the run was deferred.
func (r *updateRun) keepLeftOutReasons(f *updateFailure) {
	if f.category == CategoryDeferred {
		return
	}
	for _, i := range r.full.idx {
		p := &r.it.Packages[i]
		if d, ok := r.leftOut[p.matchName()]; ok {
			manualPackage(p, d.reason, d.detail)
		}
	}
}

// ReasonUpdateVerified is the reason of an item whose update ran and passed
// every check.
const ReasonUpdateVerified Reason = "update_verified"

// isSameOrAbove reports whether directory dir is dir2 or one of the
// directories above it ("." is the root of the repository).
func isSameOrAbove(dir, dir2 string) bool {
	return dir == "." || dir == dir2 || strings.HasPrefix(dir2, dir+"/")
}
