package remediation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// dockerfileStageLocation names the FROM an edit changes by its position
// among the Dockerfile's stages and, when it has one, its lower-cased AS
// name. A line number would change with every edit above it.
func dockerfileStageLocation(index int, name string) string {
	loc := fmt.Sprintf("stages[%d]", index)
	if name != "" {
		loc += ":" + strings.ToLower(name)
	}
	return loc
}

// dfOutcome is a plan outcome decided before any image work.
type dfOutcome struct {
	cat    Category
	reason Reason
	detail string
}

// dfWorkload is a running Compose workload with the images it runs.
type dfWorkload struct {
	key      string
	members  []int // indexes of the planner inputs that run it, in input order
	explicit *DockerfileMapping
	compose  *ComposeMapping
	priority Priority
	rank     int
	// active is set when one of the workload's images has a fixed finding,
	// which is what makes its edit location worth exploring. Every workload
	// sharing the location is part of the unit whether active or not.
	active bool
}

// dfLocated is where a workload's Dockerfile is, or why that is not known.
type dfLocated struct {
	w           *dfWorkload
	repo        string
	branch      string
	sha         string
	loc         DockerfileLocation
	origin      DockerfileOrigin
	composePath string
	files       []SourceFile
	// out, when set, ends the workload's processing; outKey groups workloads
	// that share the outcome into one item.
	out    *dfOutcome
	outKey string
	// poison, set beside a known location, stops the unit of that location:
	// something about how the workload is built casts doubt on the mapped
	// Dockerfile, so no workload sharing it is adopted.
	poison *dfOutcome
}

// dfGroup is one item to be produced: an edit location shared by workloads,
// or a set of workloads that share an outcome.
type dfGroup struct {
	key       string
	repo      string
	branch    string
	sha       string
	path      string
	targets   map[string]bool
	origin    DockerfileOrigin
	compose   string
	files     []SourceFile
	workloads []*dfWorkload
	out       *dfOutcome
	// base and file are set for an edit location.
	file *Dockerfile
	rank int
	prio Priority
	// active is set when a workload of the group is active.
	active bool
	// bases are the base resolutions of the build targets that lead to the
	// group's FROM, by target; poison is the first outcome that stops the
	// unit.
	bases  map[string]DockerfileBase
	poison *dfOutcome
}

type dfShaEntry struct {
	sha string
	out *dfOutcome
}

type dfFileEntry struct {
	file   github.File
	out    *dfOutcome
	parsed *Dockerfile
	prob   *DockerfileProblem
	done   bool // parsed or prob is set
}

// composeDeriveSilent are the reasons a service's Compose entry gives no
// Dockerfile without that meaning anything: the service just is not built
// from a Dockerfile, or the file is not one this reader interprets, which
// the Compose part reports on its own.
var composeDeriveSilent = map[Reason]bool{
	ReasonComposeNoBuild:        true,
	ReasonComposeServiceMissing: true,
	ReasonComposeInvalid:        true,
	ReasonComposeIncludeExtends: true,
	ReasonComposeMergeKey:       true,
	ReasonComposeAnchorAlias:    true,
}

// composeExplicitSilent are the reasons a Compose build section gives no
// Dockerfile although an explicit mapping names one, without that casting
// doubt on the mapping: the service is not built, or the file is not one this
// reader interprets. A build section that is there but cannot be followed
// does: the Dockerfile that is built may not be the mapped one.
var composeExplicitSilent = map[Reason]bool{
	ReasonComposeNoBuild:        true,
	ReasonComposeServiceMissing: true,
}

func sameRepoName(a, b string) bool { return strings.EqualFold(a, b) }

// githubOutcome maps a GitHub error to a plan outcome. Rate limiting, an
// exhausted budget and a dead context end all further reads of the pass;
// file says a file was being read.
func (r *run) githubOutcome(err error, file bool) *dfOutcome {
	var limited *github.RateLimitedError
	deferred := func(h *halt) *dfOutcome {
		r.srcHalt = h
		return &dfOutcome{CategoryDeferred, h.reason, h.detail}
	}
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return deferred(&halt{ReasonCycleDeadline, err.Error()})
	case errors.Is(err, github.ErrBudgetExhausted):
		return deferred(&halt{ReasonGitHubBudget, "GitHub request budget exhausted"})
	case errors.As(err, &limited):
		return deferred(&halt{ReasonRateLimited, err.Error()})
	case errors.Is(err, github.ErrByteBudgetExhausted):
		return deferred(&halt{ReasonByteBudget, err.Error()})
	case errors.Is(err, github.ErrLFSPointer), errors.Is(err, github.ErrNotRegularFile):
		return &dfOutcome{CategoryManual, ReasonDockerfileFileUnusable, err.Error()}
	case errors.Is(err, github.ErrNotFound):
		if file {
			return &dfOutcome{CategoryFailed, ReasonDockerfileFileNotFound, err.Error()}
		}
		return &dfOutcome{CategoryFailed, ReasonSourceNotFound, err.Error()}
	case errors.Is(err, github.ErrAuthRequired), errors.Is(err, github.ErrForbidden):
		return &dfOutcome{CategoryFailed, ReasonSourceAccessDenied, err.Error()}
	case errors.Is(err, github.ErrTooLarge):
		reason := ReasonSourceTooLarge
		if file {
			reason = ReasonFileTooLarge
		}
		return &dfOutcome{CategoryFailed, reason, err.Error()}
	}
	return &dfOutcome{CategoryFailed, ReasonSourceError, err.Error()}
}

// dfStopped is the deferral for a pass whose GitHub work has ended.
func (r *run) dfStopped() *dfOutcome {
	if h := r.stopReason(); h != nil {
		return &dfOutcome{CategoryDeferred, h.reason, h.detail}
	}
	return nil
}

// dfBranch resolves a branch to its commit once per cycle.
func (r *run) dfBranch(repo, branch string) (string, *dfOutcome) {
	key := strings.ToLower(repo) + "\x00" + branch
	if e, ok := r.dfSHA[key]; ok {
		return e.sha, e.out
	}
	if out := r.dfStopped(); out != nil {
		return "", out
	}
	sha, err := r.p.cfg.GitHub.ResolveBranch(r.ctx, repo, branch)
	e := dfShaEntry{sha: sha}
	if err != nil {
		e.out = r.githubOutcome(err, false)
	}
	r.dfSHA[key] = e
	return e.sha, e.out
}

// dfRead reads a file of a commit once per cycle.
func (r *run) dfRead(repo, sha, path string) *dfFileEntry {
	key := strings.ToLower(repo) + "\x00" + sha + "\x00" + path
	if e, ok := r.dfFiles[key]; ok {
		return e
	}
	e := &dfFileEntry{}
	if out := r.dfStopped(); out != nil {
		// A deferral is not cached: it holds for this pass only.
		e.out = out
		return e
	}
	f, err := r.p.cfg.GitHub.ReadFile(r.ctx, repo, sha, path)
	if err != nil {
		e.out = r.githubOutcome(err, true)
	} else {
		e.file = f
	}
	r.dfFiles[key] = e
	return e
}

// dfDerive reads the Dockerfile location of a service from the build section
// of its Compose file. read is the outcome of reading the file when that
// failed; prob says why a file that was read gave no location.
func (r *run) dfDerive(cm *ComposeMapping, sha string) (loc DockerfileLocation, file SourceFile, prob *DockerfileProblem, read *dfOutcome) {
	e := r.dfRead(cm.Repository, sha, cm.Path)
	if e.out != nil {
		return DockerfileLocation{}, SourceFile{}, nil, e.out
	}
	loc, prob = DeriveComposeDockerfile(e.file.Content, cm.Path, cm.ComposeService)
	return loc, SourceFile{Path: e.file.Path, BlobSHA: e.file.SHA}, prob, nil
}

// dfLocate finds the Dockerfile of a workload. ok is false for a workload
// that is not on this route at all.
func (r *run) dfLocate(w *dfWorkload) (dfLocated, bool) {
	em, cm := w.explicit, w.compose
	problem := func(l dfLocated, p *DockerfileProblem) dfLocated {
		l.out = &dfOutcome{CategoryManual, p.Reason, p.Detail}
		l.outKey = "dockerfile:" + w.key + "#config"
		return l
	}
	switch {
	case em != nil:
		l := dfLocated{w: w, repo: em.Repository, branch: em.BaseBranch, loc: DockerfileLocation{Path: em.Path, Target: em.Target}, origin: DockerfileFromMapping}
		fail := func(out *dfOutcome) dfLocated {
			l.out = out
			l.outKey = "dockerfile:" + strings.ToLower(em.Repository) + "@" + em.BaseBranch + ":" + em.Path
			if em.Target != "" {
				l.outKey += "?target=" + strings.ToLower(em.Target)
			}
			return l
		}
		sha, out := r.dfBranch(em.Repository, em.BaseBranch)
		if out != nil {
			return fail(out), true
		}
		l.sha = sha
		if cm != nil {
			// The service's build section, when it has one, says what is
			// built; it is read from the Compose mapping's own repository.
			// That the section is absent must have been read and confirmed:
			// a file or branch that cannot be read stops the unit, and a file
			// that confirms the absence is a plan input like any other.
			same := sameRepoName(cm.Repository, em.Repository) && cm.BaseBranch == em.BaseBranch
			csha, cout := sha, (*dfOutcome)(nil)
			if !same {
				csha, cout = r.dfBranch(cm.Repository, cm.BaseBranch)
			}
			if cout != nil {
				l.poison = cout
				return l, true
			}
			derived, file, prob, read := r.dfDerive(cm, csha)
			if read != nil {
				l.poison = read
				return l, true
			}
			if !same {
				file.Repository, file.BaseBranch = cm.Repository, cm.BaseBranch
			}
			switch {
			case prob != nil && !composeExplicitSilent[prob.Reason]:
				l.poison = &dfOutcome{CategoryManual, prob.Reason, prob.Detail}
			case prob != nil:
				l.files = append(l.files, file)
			case same:
				if p := AgreeDockerfileLocation(derived, l.loc); p != nil {
					l.poison = &dfOutcome{CategoryManual, p.Reason, p.Detail}
				}
				l.origin, l.composePath, l.files = DockerfileFromBoth, cm.Path, append(l.files, file)
			default:
				l.files = append(l.files, file)
			}
		}
		return l, true
	case cm != nil:
		l := dfLocated{w: w, repo: cm.Repository, branch: cm.BaseBranch, origin: DockerfileFromCompose, composePath: cm.Path}
		sha, out := r.dfBranch(cm.Repository, cm.BaseBranch)
		if out != nil {
			return dfLocated{}, false
		}
		l.sha = sha
		derived, file, prob, read := r.dfDerive(cm, sha)
		switch {
		case read != nil:
			// Whether the service is built at all is not known; the Compose
			// part, not this one, reports a file that cannot be read.
			return dfLocated{}, false
		case prob != nil && composeDeriveSilent[prob.Reason]:
			return dfLocated{}, false
		case prob != nil:
			return problem(l, prob), true
		}
		l.loc, l.files = derived, []SourceFile{file}
		return l, true
	}
	return dfLocated{}, false
}

// dockerfilePart builds the Dockerfile items: for each workload that has an
// explicit Dockerfile mapping, or a Compose mapping whose service builds from
// a static Dockerfile, it reads the Compose file and the Dockerfile from one
// commit, finds the FROM the build stage starts from, and judges the update
// of that base. It runs after the language part and shares its deadline and
// GitHub budget; nothing is executed and nothing is written.
func (r *run) dockerfilePart(inputs []ImageInput) {
	cfg := r.p.cfg
	if cfg.GitHub == nil || (len(cfg.Dockerfiles) == 0 && len(cfg.Composes) == 0) {
		return
	}
	r.initDF()

	explicit := map[string]*DockerfileMapping{}
	for i := range cfg.Dockerfiles {
		m := &cfg.Dockerfiles[i]
		if explicit[m.Workload] == nil {
			explicit[m.Workload] = m
		}
	}
	composes := map[string]*ComposeMapping{}
	for i := range cfg.Composes {
		m := &cfg.Composes[i]
		if composes[m.Workload] == nil {
			composes[m.Workload] = m
		}
	}

	var workloads []*dfWorkload
	byKey := map[string]*dfWorkload{}
	for idx, in := range inputs {
		ts := SelectTargets(in.Scan.Findings, cfg.Intel)
		prio := maxTargetPriority(ts)
		for _, s := range in.Services {
			k := workloadKey(s)
			if k == "" || (explicit[k] == nil && composes[k] == nil) {
				continue
			}
			w := byKey[k]
			if w == nil {
				w = &dfWorkload{key: k, explicit: explicit[k], compose: composes[k], rank: idx}
				byKey[k] = w
				workloads = append(workloads, w)
			}
			if !containsInt(w.members, idx) {
				w.members = append(w.members, idx)
			}
			if len(ts) > 0 {
				w.rank = minInt(w.rank, idx)
				w.active = true
			}
			if prio.Rank() > w.priority.Rank() {
				w.priority = prio
			}
		}
	}

	// Every mapped workload that runs is located, not only those with a fixed
	// finding: the workloads sharing a Dockerfile and edit location are one
	// unit, and one that failed its scan or has nothing to fix must hold the
	// unit back. A location is explored only when one of them is active.
	active := workloads
	sort.SliceStable(active, func(i, j int) bool {
		a, b := active[i], active[j]
		if a.priority.Rank() != b.priority.Rank() {
			return a.priority.Rank() > b.priority.Rank()
		}
		return a.rank < b.rank
	})

	groups := map[string]*dfGroup{}
	var order []*dfGroup
	join := func(key string, l dfLocated, path string) *dfGroup {
		g := groups[key]
		if g == nil {
			g = &dfGroup{key: key, repo: l.repo, branch: l.branch, sha: l.sha, path: path, targets: map[string]bool{},
				origin: l.origin, compose: l.composePath, rank: l.w.rank}
			groups[key] = g
			order = append(order, g)
		}
		if g.origin != l.origin {
			g.origin = DockerfileFromBoth
		}
		for _, f := range l.files {
			if !hasSourceFile(g.files, f) {
				g.files = append(g.files, f)
			}
		}
		g.workloads = append(g.workloads, l.w)
		if l.poison != nil && (g.poison == nil || string(l.poison.reason)+l.poison.detail < string(g.poison.reason)+g.poison.detail) {
			g.poison = l.poison
		}
		if l.composePath != "" && (g.compose == "" || l.composePath < g.compose) {
			g.compose = l.composePath
		}
		g.active = g.active || l.w.active
		if l.w.priority.Rank() > g.prio.Rank() {
			g.prio = l.w.priority
		}
		if l.w.rank < g.rank {
			g.rank = l.w.rank
		}
		return g
	}

	for _, w := range active {
		l, ok := r.dfLocate(w)
		if !ok {
			continue
		}
		if l.out != nil {
			g := join(l.outKey, l, l.loc.Path)
			g.out = l.out
			g.targets[l.loc.Target] = true
			continue
		}
		fileKey := "dockerfile:" + strings.ToLower(l.repo) + "@" + l.branch + ":" + l.loc.Path
		fe := r.dfRead(l.repo, l.sha, l.loc.Path)
		if fe.out != nil {
			g := join(fileKey+targetSuffix(l.loc.Target), l, l.loc.Path)
			g.out = fe.out
			g.targets[l.loc.Target] = true
			continue
		}
		if !fe.done {
			fe.parsed, fe.prob = ParseDockerfile(fe.file.Content)
			fe.done = true
		}
		l.files = append(l.files, SourceFile{Path: fe.file.Path, BlobSHA: fe.file.SHA})
		if fe.prob != nil {
			g := join(fileKey+targetSuffix(l.loc.Target), l, l.loc.Path)
			g.out = &dfOutcome{CategoryManual, fe.prob.Reason, fe.prob.Detail}
			g.targets[l.loc.Target] = true
			continue
		}
		base, prob := fe.parsed.ResolveBase(l.loc.Target)
		if prob != nil {
			g := join(fileKey+targetSuffix(l.loc.Target), l, l.loc.Path)
			g.out = &dfOutcome{CategoryManual, prob.Reason, prob.Detail}
			g.targets[l.loc.Target] = true
			continue
		}
		name := fe.parsed.Stages[base.Stage].Name
		g := join(fileKey+"#"+dockerfileStageLocation(base.Stage, name), l, l.loc.Path)
		if g.bases == nil {
			g.bases = map[string]DockerfileBase{}
		}
		g.bases[l.loc.Target], g.file = base, fe.parsed
		g.targets[l.loc.Target] = true
	}

	sort.SliceStable(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if a.prio.Rank() != b.prio.Rank() {
			return a.prio.Rank() > b.prio.Rank()
		}
		return a.rank < b.rank
	})
	for _, g := range order {
		if !g.active {
			continue
		}
		r.plan.DockerfileItems = append(r.plan.DockerfileItems, r.dockerfileItem(g, inputs))
	}
}

// canonicalBase is the base resolution that stands for the group. Every build
// target that leads to the group's FROM has its own resolution (what it
// inherits, the platforms between it and the FROM), and one that is not
// editable decides, taking the targets in sorted order so the result does not
// depend on the order the workloads came in.
func (g *dfGroup) canonicalBase() DockerfileBase {
	var targets []string
	for t := range g.bases {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	for _, t := range targets {
		b := g.bases[t]
		if b.OnBuildInherited || b.Disposition == DockerfileManual || b.Disposition == DockerfileExcluded {
			return b
		}
	}
	return g.bases[targets[0]]
}

func targetSuffix(target string) string {
	if target == "" {
		return ""
	}
	return "?target=" + strings.ToLower(target)
}

func hasSourceFile(fs []SourceFile, f SourceFile) bool {
	for _, x := range fs {
		if x == f {
			return true
		}
	}
	return false
}

func containsInt(s []int, v int) bool {
	for _, e := range s {
		if e == v {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// dockerfileItem builds the plan item of one group.
func (r *run) dockerfileItem(g *dfGroup, inputs []ImageInput) DockerfileItem {
	it := DockerfileItem{Key: g.key, Priority: g.prio, Counts: DockerfileCounts{}}
	for _, w := range g.workloads {
		it.Workloads = append(it.Workloads, w.key)
	}
	sort.Strings(it.Workloads)
	it.Workloads = dedupeSorted(it.Workloads)
	var targets []string
	for t := range g.targets {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	it.Source = DockerfileSource{
		Repository: g.repo, BaseBranch: g.branch, CommitSHA: g.sha, Path: g.path, Targets: targets,
		Origin: g.origin, ComposePath: g.compose, Files: g.files,
	}
	if g.out != nil {
		set0(&it, g.out.cat, g.out.reason, g.out.detail)
		return it
	}
	base := g.canonicalBase()
	st := g.file.Stages[base.Stage]
	stage := base.Stage
	it.Source.Stage, it.Source.StageName, it.Source.Line, it.Source.Platform = &stage, st.Name, st.Line, base.Platform
	it.BaseRef, it.BaseKind = base.Image, base.Ref.Kind

	if g.poison != nil {
		set0(&it, g.poison.cat, g.poison.reason, g.poison.detail)
		return it
	}
	switch {
	case base.OnBuildInherited:
		set0(&it, CategoryManual, ReasonDockerfileOnBuild, "a stage the build target inherits from has an ONBUILD instruction")
		return it
	case base.Disposition == DockerfileManual:
		set0(&it, CategoryManual, base.Reason, base.Detail)
		return it
	case base.Disposition == DockerfileExcluded:
		set0(&it, CategoryExcluded, base.Reason, base.Detail)
		return it
	case base.Disposition == DockerfilePinned && !base.AutoEditable():
		set0(&it, CategoryManual, ReasonDockerfileAmbiguous, "the tag of "+base.Image+" cannot be edited exactly")
		return it
	}

	// The running images of the unit: every image any of its workloads runs.
	var members []int
	for _, w := range g.workloads {
		for _, idx := range w.members {
			if !containsInt(members, idx) {
				members = append(members, idx)
			}
		}
	}
	sort.Ints(members)
	var sel dfSelection
	for _, idx := range members {
		it.Entities = append(it.Entities, r.dockerfileEntity(inputs[idx], base, &sel))
	}
	r.settleDockerfileItem(&it)
	return it
}

func set0(it *DockerfileItem, c Category, reason Reason, detail string) {
	it.Category, it.Reason, it.Detail = c, reason, detail
}

// dfSelection is the candidate tag of a pinned base, chosen once per item.
type dfSelection struct {
	done bool
	tag  string
	out  *Item // the outcome when no candidate could be chosen
}

// dockerfileEntity judges the update of one running image's base.
func (r *run) dockerfileEntity(in ImageInput, base DockerfileBase, sel *dfSelection) DockerfileEntity {
	ent := DockerfileEntity{
		Services: in.Services,
		Running:  runningState(in),
		Layers:   LayerConfirmation{Status: LayerNotChecked, ImageLayers: len(in.Scan.DiffIDs)},
	}
	outcome := func(c Category, reason Reason, detail string) DockerfileEntity {
		ent.Category, ent.Reason, ent.Detail = c, reason, detail
		return ent
	}
	fromItem := func(tmp Item) DockerfileEntity {
		return outcome(tmp.Category, tmp.Reason, tmp.Detail)
	}

	if reason, detail, ok := declaredCheck(in.Declared, in.Scan.Subject.Ref); !ok {
		return outcome(CategoryNotComparable, reason, detail)
	}
	if reason, detail, ok := baselineReady(in.Scan); !ok {
		cat := CategoryNotComparable
		if reason == ReasonScanFailed {
			cat = CategoryFailed
		}
		return outcome(cat, reason, detail)
	}
	platform := inventory.Platform{OS: in.Scan.Platform.OS, Architecture: in.Scan.Platform.Architecture}
	if reason, detail := platformFlagProblem(base.Platform, platform); reason != "" {
		return outcome(CategoryNotComparable, reason, detail)
	}
	ref := base.Ref
	pinned := base.Disposition == DockerfilePinned

	var tmp Item
	curRes, ok := r.resolve(ref.Repository, ref.Tag, platform, &tmp)
	if !ok {
		return fromItem(tmp)
	}
	cur := baseState(ref.Repository, ref.Tag, curRes, platform)
	ent.CurrentBase = &cur
	if curRes.OnBuild {
		return outcome(CategoryManual, ReasonBaseOnBuild, "the current base image "+cur.Ref+" has ONBUILD triggers")
	}

	bl := MatchBaseLayers(in.Scan.DiffIDs, curRes.RootFSType, curRes.DiffIDs)
	ent.Layers = LayerConfirmation{Status: string(bl.Status), BaseLayers: bl.Count, ImageLayers: len(in.Scan.DiffIDs), Detail: bl.Detail}
	switch bl.Status {
	case BaseLayersUnusable:
		return outcome(CategoryNotComparable, ReasonBaseLayersUnusable, "the layers cannot be compared: "+bl.Detail)
	case BaseLayersMismatch:
		if !pinned {
			return outcome(CategoryNotComparable, ReasonFloatingBaseUnconfirmed,
				"the tag no longer points at the layers the running image starts with ("+bl.Detail+"); which base the build used, why it changed and what a rebuild improves are unknown")
		}
		return outcome(CategoryNotComparable, ReasonBaseLayersMismatch,
			"the layers of "+cur.Ref+" are not the start of the running image's ("+bl.Detail+"): the tag changed after the build or the image was built another way, so no comparison is claimed")
	}
	if !pinned {
		return outcome(CategoryNoCandidate, ReasonBaseUnchanged,
			"the base the tag points at now is the one the running image already uses; no base update is visible")
	}

	cl := ClassifyFindingsByLayer(in.Scan.DiffIDs, bl.Count, in.Scan.Findings)
	ent.Findings = LayerCounts{Base: len(cl.Base), Upper: len(cl.Upper), Unknown: len(cl.Unknown)}
	targets := SelectTargets(cl.Base, r.p.cfg.Intel)
	attachLayers(targets, cl.Base)
	if len(targets) == 0 {
		return outcome(CategoryNoCandidate, ReasonNoBaseFindings,
			fmt.Sprintf("no fixed finding is in a layer of the base image (%d in later layers, %d without a layer)", len(cl.Upper), len(cl.Unknown)))
	}
	ent.Targets = targets

	if !sel.done {
		sel.done = true
		var t Item
		var tag string
		if !r.pinnedCandidate(ref, &t, &tag) {
			sel.out = &t
		} else {
			sel.tag = tag
		}
	}
	if sel.out != nil {
		return fromItem(*sel.out)
	}
	tmp = Item{}
	candRes, ok := r.resolve(ref.Repository, sel.tag, platform, &tmp)
	if !ok {
		return fromItem(tmp)
	}
	cand := baseState(ref.Repository, sel.tag, candRes, platform)
	ent.CandidateBase = &cand
	if candRes.OnBuild {
		return outcome(CategoryManual, ReasonBaseOnBuild, "the candidate base image "+cand.Ref+" has ONBUILD triggers")
	}
	if candRes.ManifestDigest == curRes.ManifestDigest || candRes.ConfigDigest == curRes.ConfigDigest {
		return outcome(CategoryNoCandidate, ReasonSameContent, "the candidate base resolves to the content of the current base")
	}

	prep := r.p.cfg.Prepared
	if !prep.Known() {
		return outcome(CategoryNotComparable, ReasonConditionsUnknown, "the cycle has no prepared scan conditions")
	}
	curDigest, ok1 := inventory.ParseDigest(inventory.DigestRegistry, curRes.ManifestDigest)
	candDigest, ok2 := inventory.ParseDigest(inventory.DigestRegistry, candRes.ManifestDigest)
	if !ok1 || !ok2 {
		return outcome(CategoryFailed, ReasonRegistryError, "the registry resolution has no usable manifest digest")
	}
	repoKey, _ := inventory.RepositoryKey(ref.Repository)
	baseScanKey := string(RoleBaseline) + "|" + repoKey + "|" + entityString(inventory.EntityKey{Digest: curDigest, Platform: platform})
	candScanKey := string(RoleCandidate) + "|" + repoKey + "|" + entityString(inventory.EntityKey{Digest: candDigest, Platform: platform})
	baseScan, baseCached := r.dfScans[baseScanKey]
	candScan, candCached := r.dfScans[candScanKey]
	// Both limits are checked before either is spent.
	if !baseCached && r.plan.Usage.BaselineRescans >= r.p.cfg.Limits.MaxBaselineRescans {
		return outcome(CategoryDeferred, ReasonBaselineRescanLimit, fmt.Sprintf("baseline rescan limit of %d reached", r.p.cfg.Limits.MaxBaselineRescans))
	}
	if !candCached && r.plan.Usage.CandidateScans >= r.p.cfg.Limits.MaxCandidateScans {
		return outcome(CategoryDeferred, ReasonCandidateScanLimit, fmt.Sprintf("candidate scan limit of %d reached", r.p.cfg.Limits.MaxCandidateScans))
	}
	scan := func(role ScanRole, repo, tag string, d inventory.Digest) scanned {
		target := scanner.ScanTarget{
			Subject: inventory.ImageSubject{
				Ref:      repo + ":" + tag,
				Key:      inventory.EntityKey{Digest: d, Platform: platform},
				Resolved: true,
			},
			Registry: inventory.RegistryRef{Repository: repo, Digest: d},
			Source:   scanner.SourceRemote,
		}
		return r.scanUnder(role, target)
	}
	if !baseCached {
		r.plan.Usage.BaselineRescans++
		baseScan = scan(RoleBaseline, ref.Repository, ref.Tag, curDigest)
		r.dfScans[baseScanKey] = baseScan
	}
	if !candCached {
		r.plan.Usage.CandidateScans++
		candScan = scan(RoleCandidate, ref.Repository, sel.tag, candDigest)
		r.dfScans[candScanKey] = candScan
	}
	ent.BaselineScan, ent.CandidateScan = baseScan.id, candScan.id
	if err := r.ctx.Err(); err != nil {
		return outcome(CategoryDeferred, ReasonCycleDeadline, err.Error())
	}

	vr := Compare(baseScan.rec, candScan.rec).ApplyCoverage(targets, baseScan.rec, candScan.rec)
	dec := Decide(targets, vr, r.p.cfg.Intel)
	ent.Comparison, ent.Decision = &vr, &dec
	switch dec.Kind {
	case DecisionAdopt:
		return outcome(CategoryPRCandidate, ReasonAdopted, fmt.Sprintf("all %d base findings resolved by the candidate base, nothing introduced", dec.Targets))
	case DecisionAdoptPartial:
		return outcome(CategoryPRCandidate, ReasonAdopted,
			fmt.Sprintf("%d of %d base findings resolved, %d remain, %d not detected on the current base, nothing introduced", dec.Resolved, dec.Targets, dec.Remaining, dec.Undetected))
	case DecisionIntroduced:
		return outcome(CategoryManual, ReasonIntroducedFindings, fmt.Sprintf("%d findings are introduced by the candidate base", dec.Introduced))
	case DecisionNewKEV:
		return outcome(CategoryManual, ReasonIntroducedKEV, fmt.Sprintf("the candidate base introduces KEV-listed vulnerabilities: %v", dec.IntroducedKEV))
	case DecisionAnalysisIncomplete:
		return outcome(CategoryNotComparable, ReasonAnalysisIncomplete, fmt.Sprintf("%d of %d base findings could not be judged: the candidate scan did not cover their package type", dec.Unknown, dec.Targets))
	case DecisionTargetsNotDetected:
		return outcome(CategoryNotComparable, ReasonTargetsNotDetected, fmt.Sprintf("none of the %d base findings is shown by the scan of the current base", dec.Targets))
	case DecisionNotResolving:
		return outcome(CategoryNoCandidate, ReasonCandidateNotFixing, fmt.Sprintf("none of %d base findings is resolved by the candidate base", dec.Targets))
	}
	cat := CategoryNotComparable
	if vr.Reason == ReasonScanFailed {
		cat = CategoryFailed
	}
	return outcome(cat, vr.Reason, vr.Detail)
}

// attachLayers records on each target the layers its findings were reported
// in.
func attachLayers(targets []Target, findings []scanner.Finding) {
	layers := map[verdictKey][]string{}
	for _, f := range findings {
		if f.Status != scanner.StatusFixed || f.FixedVer == "" || f.LayerDiffID == "" {
			continue
		}
		k := verdictKey{f.VulnID, coordOf(f)}
		if !containsString(layers[k], f.LayerDiffID) {
			layers[k] = append(layers[k], f.LayerDiffID)
		}
	}
	for i := range targets {
		ls := layers[verdictKey{targets[i].VulnID, targets[i].Package}]
		sort.Strings(ls)
		targets[i].Layers = ls
	}
}

// runningState is the state of the running image of a planner input.
func runningState(in ImageInput) ImageState {
	s := in.Scan
	ref := s.Subject.Ref
	if ref == "" {
		ref = s.Image
	}
	st := ImageState{Ref: ref, Entity: entityString(s.Subject.Key)}
	if s.Subject.Key.Digest.Kind == inventory.DigestConfig {
		st.ConfigDigest = s.Subject.Key.Digest.String()
		st.DigestKindUnverified = s.Source == scanner.SourceLocal
	}
	if s.Platform.Known() {
		st.Platform = s.Platform.OS + "/" + s.Platform.Architecture
	}
	st.Tag = ParseImageRef(ref).Tag
	return st
}

func baseState(repo, tag string, res registry.Resolution, platform inventory.Platform) ImageState {
	return ImageState{
		Ref: repo + ":" + tag, Tag: tag,
		ConfigDigest: res.ConfigDigest, ManifestDigest: res.ManifestDigest, TopDigest: res.TopDigest,
		Platform: platform.OS + "/" + platform.Architecture,
	}
}

// platformFlagProblem compares the static --platform of the FROM, "" when it
// has none, with the running image's platform.
func platformFlagProblem(flag string, running inventory.Platform) (Reason, string) {
	if flag == "" {
		return "", ""
	}
	parts := strings.Split(strings.ToLower(flag), "/")
	switch {
	case len(parts) == 3:
		return ReasonVariantUnsupported, fmt.Sprintf("the FROM sets --platform %s, which names a variant", flag)
	case len(parts) != 2 || parts[0] != running.OS || parts[1] != running.Architecture:
		return ReasonPlatformMismatch, fmt.Sprintf("the FROM sets --platform %s, the running image is %s/%s", flag, running.OS, running.Architecture)
	}
	return "", ""
}

// settleDockerfileItem sets the item's outcome from its entities. An edit
// location is proposed only when every running image of it confirmed the base
// and adopted the same candidate; the item is never narrowed to the images
// that did.
func (r *run) settleDockerfileItem(it *DockerfileItem) {
	it.Counts = dockerfileCounts(it.Entities)
	for i := range it.Entities {
		if c := it.Entities[i].CandidateBase; c != nil && it.Candidate == nil {
			cc := *c
			it.Candidate = &cc
		}
	}
	if len(it.Entities) == 0 {
		set0(it, CategoryNoCandidate, ReasonNoBaseFindings, "no running image")
		return
	}

	adopted := 0
	for _, e := range it.Entities {
		if e.Category == CategoryPRCandidate {
			adopted++
		}
	}
	if adopted == len(it.Entities) {
		first := it.Entities[0].CandidateBase
		for _, e := range it.Entities[1:] {
			if e.CandidateBase.Tag != first.Tag || e.CandidateBase.TopDigest != first.TopDigest {
				set0(it, CategoryManual, ReasonDockerfileSetNotAdopted,
					fmt.Sprintf("the running images have different candidates (%s and %s)", first.Ref, e.CandidateBase.Ref))
				return
			}
		}
		set0(it, CategoryPRCandidate, ReasonAdopted, it.Entities[0].Detail)
		if len(it.Entities) > 1 {
			it.Detail = fmt.Sprintf("all %d running images confirm the base and adopt %s", len(it.Entities), first.Ref)
		}
		return
	}

	// Not every image adopted. Images that agree on one outcome give it, so a
	// unit all of whose images were left undone stays deferred and one all of
	// whose images failed stays failed. Any other mix, including adopted
	// images beside one that failed or was deferred, is for a person; each
	// image keeps its own reason.
	first := it.Entities[0]
	same := true
	for _, e := range it.Entities[1:] {
		same = same && e.Category == first.Category && e.Reason == first.Reason
	}
	if same {
		set0(it, first.Category, first.Reason, first.Detail)
		return
	}
	for _, kind := range []Category{CategoryDeferred, CategoryFailed} {
		all := true
		for _, e := range it.Entities {
			all = all && e.Category == kind
		}
		if all {
			set0(it, kind, first.Reason, first.Detail)
			return
		}
	}
	var parts []string
	for _, e := range it.Entities {
		parts = append(parts, fmt.Sprintf("%s: %s/%s", e.Running.Ref, e.Category, e.Reason))
	}
	set0(it, CategoryManual, ReasonDockerfileSetNotAdopted,
		"the running images of this Dockerfile do not all confirm the base and adopt the candidate ("+strings.Join(parts, "; ")+"); a pull request never covers part of them")
}

// dockerfileCounts summarizes the comparisons of an item's running images. A
// target is resolved when every image that has it as a target resolves it, and
// remaining when any of them still has it; an image that lacks the target
// says nothing about it.
func dockerfileCounts(ents []DockerfileEntity) DockerfileCounts {
	union := map[verdictKey]bool{}
	for _, e := range ents {
		for _, t := range e.Targets {
			union[verdictKey{t.VulnID, t.Package}] = true
		}
	}
	out := DockerfileCounts{Targets: len(union)}
	for k := range union {
		resolved, remaining, owners := 0, false, 0
		for _, e := range ents {
			has := false
			for _, t := range e.Targets {
				has = has || verdictKey{t.VulnID, t.Package} == k
			}
			if !has {
				continue
			}
			owners++
			if e.Comparison == nil {
				continue
			}
			for _, v := range e.Comparison.Verdicts {
				if v.VulnID != k.vuln || v.Package != k.coord {
					continue
				}
				switch v.Outcome {
				case OutcomeResolved:
					resolved++
				case OutcomeRemaining:
					remaining = true
				}
			}
		}
		switch {
		case remaining:
			out.Remaining++
		case owners > 0 && resolved == owners:
			out.Resolved++
		}
	}
	introduced := map[verdictKey]bool{}
	for _, e := range ents {
		if e.Comparison == nil {
			continue
		}
		for _, v := range e.Comparison.Introduced {
			introduced[verdictKey{v.VulnID, v.Package}] = true
		}
	}
	out.Introduced = len(introduced)
	return out
}
