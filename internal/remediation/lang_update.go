package remediation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
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
}

// DefaultUpdateJobTimeout is the time one update container gets.
const DefaultUpdateJobTimeout = 6 * time.Minute

// DefaultUpdateResources are the container limits an update job runs under.
func DefaultUpdateResources() docker.Resources {
	return docker.Resources{
		MemoryBytes: 2 << 30, NanoCPUs: 2_000_000_000, PidsLimit: 512, NofileLimit: 4096,
		ShmSizeBytes: 64 << 20, TmpSizeBytes: 512 << 20, HomeSizeBytes: 512 << 20,
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

// sourceFiles are the files of the unit as the plan recorded them, read
// again.
type sourceFiles struct {
	manifestName string // empty for pip
	lockName     string
	manifest     []byte
	lock         []byte
	manifestPath string
	manifestMode string
	lockPath     string
	lockMode     string
}

// readSources reads the unit's manifest and lockfile again from the commit
// the plan recorded and requires them to be the blobs it recorded.
func (u *LangUpdater) readSources(ctx context.Context, it *LanguageItem) (*sourceFiles, *updateFailure) {
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
func (u *LangUpdater) updateItem(ctx context.Context, it *LanguageItem, n int) {
	set, fail := newUpdateSet(it)
	if fail != nil {
		fail.apply(it, set.idx)
		return
	}
	res := &updateRun{u: u, it: it, n: n, set: set, upd: &LanguageUpdate{}}
	if fail = res.run(ctx); fail != nil {
		it.Update = res.upd
		it.SourceCheck = res.check
		fail.apply(it, set.idx)
		return
	}
	res.succeed()
}

// updateRun is the state of one item's update.
type updateRun struct {
	u   *LangUpdater
	it  *LanguageItem
	n   int
	set updateSet
	upd *LanguageUpdate

	src *sourceFiles
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
	it.UpdateExecuted, it.PostUpdateCheckExecuted = true, true
	it.Update = r.upd
	it.SourceCheck = r.check
	for _, i := range r.set.idx {
		p := &it.Packages[i]
		p.AdoptedVersion = r.adopted[p.matchName()]
		p.Reason, p.Detail = ReasonUpdateVerified, ""
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

// ReasonUpdateVerified is the reason of an item whose update ran and passed
// every check.
const ReasonUpdateVerified Reason = "update_verified"
