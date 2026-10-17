package worker

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// inputNames are the files a job must carry for each manager, which is also
// the set of files a step may leave changed.
var inputNames = map[Manager][]string{
	ManagerNpm:  {"package.json", "package-lock.json"},
	ManagerPnpm: {"package.json", "pnpm-lock.yaml"},
	ManagerUv:   {"pyproject.toml", "uv.lock"},
	ManagerPip:  {"requirements.txt"},
}

// optionalInputNames are the files a job may carry besides the required ones.
// They are settings the manager reads: a step may not change them (the result
// of a step that did is refused, see ReasonInputModified), and they are never
// returned.
var optionalInputNames = map[Manager][]string{
	ManagerPnpm: {"pnpm-workspace.yaml"},
}

// opManager is the manager each operation belongs to.
var opManager = map[Op]Manager{
	OpNpmRelock:      ManagerNpm,
	OpPnpmFrozen:     ManagerPnpm,
	OpPnpmRelock:     ManagerPnpm,
	OpUvCheck:        ManagerUv,
	OpUvUpgrade:      ManagerUv,
	OpUvUpgradeChain: ManagerUv,
	OpPipDryRun:      ManagerPip,
}

// RequiredInputNames returns the file names a job for m must carry.
func RequiredInputNames(m Manager) []string {
	return append([]string(nil), inputNames[m]...)
}

// OptionalInputNames returns the file names a job for m may carry besides the
// required ones.
func OptionalInputNames(m Manager) []string {
	return append([]string(nil), optionalInputNames[m]...)
}

// InputNames returns every file name a job for m may carry.
func InputNames(m Manager) []string {
	return append(RequiredInputNames(m), optionalInputNames[m]...)
}

// OutputNames returns the file names a job for m may ask to have collected:
// the required inputs, which a step may change, and the report of pip.
func OutputNames(m Manager) []string {
	out := RequiredInputNames(m)
	if m == ManagerPip {
		out = append(out, PipReportName)
	}
	return out
}

// Known reports whether m is a manager the protocol has.
func (m Manager) Known() bool { _, ok := inputNames[m]; return ok }

var (
	stepIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

	// npm names: lowercase, an optional @scope/ prefix, no leading dot,
	// underscore or dash.
	npmNameRe = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$`)
	// semver 2.0.0, without a leading v or range operator.
	semverRe = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
	// PEP 508 project names.
	pyNameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	// PEP 440 versions in their normalized (lowercase) form.
	pyVersionRe = regexp.MustCompile(`^([0-9]+!)?[0-9]+(\.[0-9]+)*((a|b|rc)[0-9]+)?(\.post[0-9]+)?(\.dev[0-9]+)?(\+[a-z0-9]+([-_.][a-z0-9]+)*)?$`)

	pyMinorRe   = regexp.MustCompile(`^3\.[0-9]{1,2}$`)
	platformRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.]{0,63}$`)
	abiRe       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.]{0,31}$`)
	implementRe = regexp.MustCompile(`^(py|cp|pp|ip|jy)$`)
)

// ValidNpmName reports whether s is an npm package name.
func ValidNpmName(s string) bool { return len(s) <= 214 && npmNameRe.MatchString(s) }

// ValidSemver reports whether s is a plain semantic version.
func ValidSemver(s string) bool { return len(s) <= 128 && semverRe.MatchString(s) }

// ValidPythonName reports whether s is a PEP 508 project name.
func ValidPythonName(s string) bool { return len(s) <= 100 && pyNameRe.MatchString(s) }

// ValidPythonVersion reports whether s is a normalized PEP 440 version.
func ValidPythonVersion(s string) bool { return len(s) <= 128 && pyVersionRe.MatchString(s) }

// ValidStepID reports whether s may name a step and its output directory.
func ValidStepID(s string) bool { return stepIDRe.MatchString(s) }

// ValidSHA256 reports whether s is a lowercase hex SHA-256.
func ValidSHA256(s string) bool {
	if !sha256Re.MatchString(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Validate checks everything about a job that does not need the files: the
// protocol, the manager and operation pairing, the declared inputs, every
// name and version, the output names and the time limits.
func (j *Job) Validate() error {
	if j.Protocol != ProtocolVersion {
		return fmt.Errorf("protocol %d is not %d", j.Protocol, ProtocolVersion)
	}
	if !j.Manager.Known() {
		return fmt.Errorf("unknown manager %q", j.Manager)
	}
	if err := j.validateRuntime(); err != nil {
		return err
	}
	if err := j.validateTool(); err != nil {
		return err
	}
	if err := j.validateInputs(); err != nil {
		return err
	}
	if err := j.validateReplacements(); err != nil {
		return err
	}
	if len(j.Steps) == 0 {
		return fmt.Errorf("no steps")
	}
	if len(j.Steps) > MaxSteps {
		return fmt.Errorf("%d steps exceed %d", len(j.Steps), MaxSteps)
	}
	seen := map[string]bool{}
	for i := range j.Steps {
		s := &j.Steps[i]
		if seen[s.ID] {
			return fmt.Errorf("duplicate step id %q", s.ID)
		}
		seen[s.ID] = true
		if err := s.Validate(j.Manager); err != nil {
			return fmt.Errorf("step %q: %w", s.ID, err)
		}
	}
	if len(j.Outputs) == 0 {
		return fmt.Errorf("no outputs")
	}
	allowed := OutputNames(j.Manager)
	outSeen := map[string]bool{}
	for _, o := range j.Outputs {
		if !contains(allowed, o) {
			return fmt.Errorf("output %q is not collectable for %s", o, j.Manager)
		}
		if outSeen[o] {
			return fmt.Errorf("duplicate output %q", o)
		}
		outSeen[o] = true
	}
	if j.DeadlineSeconds < 1 || j.DeadlineSeconds > MaxDeadlineSeconds {
		return fmt.Errorf("deadline_seconds %d is outside 1..%d", j.DeadlineSeconds, MaxDeadlineSeconds)
	}
	if j.StepTimeoutSeconds < 0 || j.StepTimeoutSeconds > j.DeadlineSeconds {
		return fmt.Errorf("step_timeout_seconds %d is outside 0..%d", j.StepTimeoutSeconds, j.DeadlineSeconds)
	}
	return nil
}

// digestRe is an image digest.
var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

var sha512Re = regexp.MustCompile(`^[0-9a-f]{128}$`)

// ToolPath is the path, relative to /work, at which the archive of a tool is
// placed. It follows from the tool alone.
func ToolPath(t Tool) string {
	ext := ".tgz"
	if t.Format == FormatWheel {
		ext = ".whl"
	}
	return ToolsDirName + "/" + string(t.Name) + "-" + t.Version + ext
}

// validateRuntime checks the runtime of the job against the table: it is a
// runtime with an image, of the kind the manager needs, and the versions have
// the form of versions.
func (j *Job) validateRuntime() error {
	spec, ok := LookupRuntime(j.Runtime.ID)
	if !ok || !spec.HasImage() {
		return fmt.Errorf("unknown runtime %q", j.Runtime.ID)
	}
	if spec.Kind != KindFor(j.Manager) {
		return fmt.Errorf("runtime %q is not one %s runs in", j.Runtime.ID, j.Manager)
	}
	if !ValidSemver(j.Runtime.Version) || !strings.HasPrefix(j.Runtime.Version, spec.Series+".") {
		return fmt.Errorf("runtime version %q is not a version of %s", j.Runtime.Version, j.Runtime.ID)
	}
	if spec.Kind == KindPython {
		if j.Manager == ManagerPip && !ValidPythonVersion(j.Runtime.Pip) {
			return fmt.Errorf("a pip job needs the version of pip")
		}
		if j.Runtime.Pip != "" && !ValidPythonVersion(j.Runtime.Pip) {
			return fmt.Errorf("invalid pip version %q", j.Runtime.Pip)
		}
	} else if j.Runtime.Pip != "" {
		return fmt.Errorf("a %s runtime has no pip", spec.Kind)
	}
	return nil
}

// validateTool requires the tool a manager needs, and none for pip, with every
// field in its form.
func (j *Job) validateTool() error {
	t := j.Tool
	if j.Manager == ManagerPip {
		if t != nil {
			return fmt.Errorf("pip runs from the Python image and takes no tool")
		}
		return nil
	}
	if t == nil {
		return fmt.Errorf("%s needs a tool", j.Manager)
	}
	if t.Name != j.Manager {
		return fmt.Errorf("tool %q is not the tool of %s", t.Name, j.Manager)
	}
	if !ValidSemver(t.Version) {
		return fmt.Errorf("invalid tool version %q", t.Version)
	}
	switch {
	case t.Format == FormatNpmTgz && t.Name != ManagerUv && t.RunWithNode && !pnpmIsExecutable(t):
	case t.Format == FormatNpmTgz && t.Name == ManagerPnpm && !t.RunWithNode && pnpmIsExecutable(t):
	case t.Format == FormatWheel && t.Name == ManagerUv && !t.RunWithNode:
	default:
		return fmt.Errorf("tool format %q (run with node: %v) does not fit %s", t.Format, t.RunWithNode, t.Name)
	}
	if t.Path != ToolPath(*t) {
		return fmt.Errorf("tool path %q is not %q", t.Path, ToolPath(*t))
	}
	if t.Size <= 0 || t.Size > MaxToolArchiveBytes {
		return fmt.Errorf("tool size %d is outside 1..%d", t.Size, MaxToolArchiveBytes)
	}
	if !ValidSHA256(t.SHA256) || !sha512Re.MatchString(t.SHA512) {
		return fmt.Errorf("tool has no valid sha256 and sha512")
	}
	if err := ValidEntry(t.Entry); err != nil {
		return fmt.Errorf("tool entry: %w", err)
	}
	return nil
}

// pnpmIsExecutable reports whether the tool is a pnpm release that is shipped
// as an executable and not as a script for node: from version 12 on.
func pnpmIsExecutable(t *Tool) bool {
	if t.Name != ManagerPnpm {
		return false
	}
	major, _, _ := strings.Cut(t.Version, ".")
	return major == "12"
}

// ValidEntry checks a path inside an archive: relative, clean, free of "..",
// backslashes and control characters, and not too long.
func ValidEntry(p string) error {
	if p == "" || len(p) > 256 || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\") {
		return fmt.Errorf("%q is empty, too long, absolute or has a backslash", p)
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%q has a control character", p)
		}
	}
	for _, e := range strings.Split(p, "/") {
		if e == "" || e == "." || e == ".." {
			return fmt.Errorf("%q has an invalid element", p)
		}
	}
	return nil
}

func (j *Job) validateInputs() error {
	if len(j.Inputs) > MaxInputs {
		return fmt.Errorf("%d inputs exceed %d", len(j.Inputs), MaxInputs)
	}
	allowed := InputNames(j.Manager)
	seen := map[string]bool{}
	var total int64
	for _, in := range j.Inputs {
		if !contains(allowed, in.Path) {
			return fmt.Errorf("input %q is not an input of %s", in.Path, j.Manager)
		}
		if seen[in.Path] {
			return fmt.Errorf("duplicate input %q", in.Path)
		}
		seen[in.Path] = true
		if in.Size < 0 || in.Size > MaxInputFileBytes {
			return fmt.Errorf("input %q size %d is outside 0..%d", in.Path, in.Size, MaxInputFileBytes)
		}
		total += in.Size
		if !ValidSHA256(in.SHA256) {
			return fmt.Errorf("input %q has no valid sha256", in.Path)
		}
	}
	if total > MaxInputTotalBytes {
		return fmt.Errorf("inputs total %d bytes, over %d", total, MaxInputTotalBytes)
	}
	for _, name := range inputNames[j.Manager] {
		if !seen[name] {
			return fmt.Errorf("input %q is missing", name)
		}
	}
	return nil
}

// LockfileName returns the name of the lockfile a job for m can replace, ""
// for a manager that has none to replace.
func LockfileName(m Manager) string {
	switch m {
	case ManagerNpm, ManagerPnpm:
		return inputNames[m][1]
	}
	return ""
}

// validateReplacements checks the replacement files: only the lockfile of npm
// or pnpm, at most once, each within the limit of an input file and, with the
// inputs, within the totals; and a job that has them has a step that is not a
// scratch step, which is where they are put in place.
func (j *Job) validateReplacements() error {
	if len(j.Replacements) == 0 {
		return nil
	}
	lock := LockfileName(j.Manager)
	if lock == "" {
		return fmt.Errorf("%s has no lockfile to replace", j.Manager)
	}
	if len(j.Inputs)+len(j.Replacements) > MaxInputs {
		return fmt.Errorf("%d inputs and replacements exceed %d", len(j.Inputs)+len(j.Replacements), MaxInputs)
	}
	var total int64
	for _, in := range j.Inputs {
		total += in.Size
	}
	seen := map[string]bool{}
	for _, r := range j.Replacements {
		if r.Path != lock {
			return fmt.Errorf("replacement %q is not %s, the only file of %s that is replaced", r.Path, lock, j.Manager)
		}
		if seen[r.Path] {
			return fmt.Errorf("duplicate replacement %q", r.Path)
		}
		seen[r.Path] = true
		if r.Size < 0 || r.Size > MaxInputFileBytes {
			return fmt.Errorf("replacement %q size %d is outside 0..%d", r.Path, r.Size, MaxInputFileBytes)
		}
		total += r.Size
		if !ValidSHA256(r.SHA256) {
			return fmt.Errorf("replacement %q has no valid sha256", r.Path)
		}
	}
	if total > MaxInputTotalBytes {
		return fmt.Errorf("inputs and replacements total %d bytes, over %d", total, MaxInputTotalBytes)
	}
	for _, s := range j.Steps {
		if !s.Scratch {
			return nil
		}
	}
	return fmt.Errorf("replacements need a step that is not a scratch step")
}

// FirstReplacingStep returns the index of the step the replacements are put in
// place before: the first that is not a scratch step. It is -1 when there is
// none.
func (j *Job) FirstReplacingStep() int {
	for i, s := range j.Steps {
		if !s.Scratch {
			return i
		}
	}
	return -1
}

// Validate checks one step against the manager of its job.
func (s *Step) Validate(m Manager) error {
	if !ValidStepID(s.ID) {
		return fmt.Errorf("invalid step id")
	}
	want, ok := opManager[s.Op]
	if !ok {
		return fmt.Errorf("unknown op %q", s.Op)
	}
	if want != m {
		return fmt.Errorf("op %q does not belong to %s", s.Op, m)
	}
	if len(s.Packages) > MaxPackages {
		return fmt.Errorf("%d packages exceed %d", len(s.Packages), MaxPackages)
	}
	needPkgs := s.Op == OpUvUpgrade || s.Op == OpUvUpgradeChain
	if needPkgs != (len(s.Packages) > 0) {
		if needPkgs {
			return fmt.Errorf("%s needs packages", s.Op)
		}
		return fmt.Errorf("%s takes no packages", s.Op)
	}
	if (s.RequireHashes || s.Target != nil) && s.Op != OpPipDryRun {
		return fmt.Errorf("require_hashes and target are only for %s", OpPipDryRun)
	}
	pkgSeen := map[string]bool{}
	for _, p := range s.Packages {
		if err := validatePackage(s.Op, p); err != nil {
			return err
		}
		if pkgSeen[p.Name] {
			return fmt.Errorf("duplicate package %q", p.Name)
		}
		pkgSeen[p.Name] = true
	}
	if s.Target != nil {
		return s.Target.validate()
	}
	return nil
}

// validatePackage checks a package of a uv.upgrade or uv.upgrade_chain step: a
// Python project name and normalized versions. uv.upgrade needs a version and
// takes no lowest version; uv.upgrade_chain takes a version, a lowest version
// or neither, and not both.
func validatePackage(op Op, p Package) error {
	if strings.HasPrefix(p.Name, "-") || strings.HasPrefix(p.Version, "-") || strings.HasPrefix(p.AtLeast, "-") {
		return fmt.Errorf("value starting with '-' is refused")
	}
	if !ValidPythonName(p.Name) {
		return fmt.Errorf("invalid package name %q", p.Name)
	}
	if p.Version != "" && !ValidPythonVersion(p.Version) {
		return fmt.Errorf("invalid version %q for %q", p.Version, p.Name)
	}
	if p.AtLeast != "" && !ValidPythonVersion(p.AtLeast) {
		return fmt.Errorf("invalid lowest version %q for %q", p.AtLeast, p.Name)
	}
	switch op {
	case OpUvUpgrade:
		if p.AtLeast != "" {
			return fmt.Errorf("%s takes no lowest version", op)
		}
		if p.Version == "" {
			return fmt.Errorf("package %q needs a version", p.Name)
		}
	case OpUvUpgradeChain:
		if p.Version != "" && p.AtLeast != "" {
			return fmt.Errorf("package %q has both a version and a lowest version", p.Name)
		}
	}
	return nil
}

func (t *Target) validate() error {
	if t.PythonVersion == "" && len(t.Platforms) == 0 && t.Implementation == "" && len(t.ABIs) == 0 {
		return fmt.Errorf("empty target")
	}
	if t.PythonVersion != "" && !pyMinorRe.MatchString(t.PythonVersion) {
		return fmt.Errorf("invalid python_version %q", t.PythonVersion)
	}
	if t.Implementation != "" && !implementRe.MatchString(t.Implementation) {
		return fmt.Errorf("invalid implementation %q", t.Implementation)
	}
	if len(t.Platforms) > MaxTargetList || len(t.ABIs) > MaxTargetList {
		return fmt.Errorf("target list exceeds %d", MaxTargetList)
	}
	for _, p := range t.Platforms {
		if !platformRe.MatchString(p) {
			return fmt.Errorf("invalid platform %q", p)
		}
	}
	for _, a := range t.ABIs {
		if !abiRe.MatchString(a) {
			return fmt.Errorf("invalid abi %q", a)
		}
	}
	return nil
}
