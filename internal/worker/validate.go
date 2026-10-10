package worker

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// inputNames are the only files a job may carry for each manager, which is
// also the set of files a step may leave changed. Every one is required.
var inputNames = map[Manager][]string{
	ManagerNpm:  {"package.json", "package-lock.json"},
	ManagerPnpm: {"package.json", "pnpm-lock.yaml"},
	ManagerUv:   {"pyproject.toml", "uv.lock"},
	ManagerPip:  {"requirements.txt"},
}

// opManager is the manager each operation belongs to.
var opManager = map[Op]Manager{
	OpNpmRelock:  ManagerNpm,
	OpNpmUpdate:  ManagerNpm,
	OpPnpmFrozen: ManagerPnpm,
	OpPnpmUpdate: ManagerPnpm,
	OpPnpmRelock: ManagerPnpm,
	OpUvCheck:    ManagerUv,
	OpUvUpgrade:  ManagerUv,
	OpPipDryRun:  ManagerPip,
}

// InputNames returns the file names a job for m carries.
func InputNames(m Manager) []string {
	return append([]string(nil), inputNames[m]...)
}

// OutputNames returns the file names a job for m may ask to have collected.
func OutputNames(m Manager) []string {
	out := InputNames(m)
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
	if err := j.validateInputs(); err != nil {
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

func (j *Job) validateInputs() error {
	if len(j.Inputs) > MaxInputs {
		return fmt.Errorf("%d inputs exceed %d", len(j.Inputs), MaxInputs)
	}
	allowed := inputNames[j.Manager]
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
	for _, name := range allowed {
		if !seen[name] {
			return fmt.Errorf("input %q is missing", name)
		}
	}
	return nil
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
	needPkgs, mode := false, versionNone
	switch s.Op {
	case OpNpmUpdate:
		needPkgs = true
	case OpPnpmUpdate:
		needPkgs, mode = true, versionOptional
	case OpUvUpgrade:
		needPkgs, mode = true, versionRequired
	}
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
		if err := validatePackage(m, p, mode); err != nil {
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

// versionMode says whether a package of an operation carries a version.
type versionMode int

const (
	versionNone versionMode = iota
	versionRequired
	// versionOptional is for pnpm.update: with a version it pins that
	// version, without one it updates within the range the lockfile's
	// dependents declare (the only form pnpm accepts for a transitive
	// dependency).
	versionOptional
)

func validatePackage(m Manager, p Package, mode versionMode) error {
	if strings.HasPrefix(p.Name, "-") || strings.HasPrefix(p.Version, "-") {
		return fmt.Errorf("value starting with '-' is refused")
	}
	python := m == ManagerUv || m == ManagerPip
	nameOK, verOK := ValidNpmName, ValidSemver
	if python {
		nameOK, verOK = ValidPythonName, ValidPythonVersion
	}
	if !nameOK(p.Name) {
		return fmt.Errorf("invalid package name %q", p.Name)
	}
	switch {
	case mode == versionNone && p.Version != "":
		return fmt.Errorf("package %q takes no version", p.Name)
	case mode == versionRequired && p.Version == "", p.Version != "" && !verOK(p.Version):
		return fmt.Errorf("invalid version %q for %q", p.Version, p.Name)
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
