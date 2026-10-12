package worker

import (
	"fmt"
	"strconv"
	"strings"
)

// PnpmFixedConfig returns the settings passed to pnpm on the command line for
// a release, which stop it from fetching or switching to another version of
// itself (the project may declare one) and from writing an environment
// document into its lockfile. pnpm 9 does neither and needs none; the setting
// that stops pnpm 10 is not read from the environment.
func PnpmFixedConfig(version string) ([]string, error) {
	major, _, _ := strings.Cut(version, ".")
	n, err := strconv.Atoi(major)
	if err != nil {
		return nil, fmt.Errorf("pnpm version %q has no major version", version)
	}
	switch {
	case n == 9:
		return nil, nil
	case n == 10:
		return []string{"--config.manage-package-manager-versions=false"}, nil
	case n == 11 || n == 12:
		return []string{"--config.pmOnFail=ignore"}, nil
	}
	return nil, fmt.Errorf("pnpm %s is not a version this program supports", version)
}

// Argv returns the command line for a step of a job. It depends on the job
// alone, so the program that runs a step and the process that checks the
// recorded command line of the result build the same one. The first element is
// the name of the program, found only in the directory of the tools; the
// interpreter that uv and pip use is named by its absolute path. Names and
// versions are separate arguments, never joined into a shell string, and a
// value that starts with '-' is refused by Step.Validate before it gets here.
func Argv(j Job, s Step) ([]string, error) {
	m := j.Manager
	if err := s.Validate(m); err != nil {
		return nil, err
	}
	spec, ok := LookupRuntime(j.Runtime.ID)
	if !ok || !spec.HasImage() || spec.Kind != KindFor(m) {
		return nil, fmt.Errorf("runtime %q does not fit %s", j.Runtime.ID, m)
	}
	var pnpmCfg []string
	if m == ManagerPnpm {
		if j.Tool == nil {
			return nil, fmt.Errorf("pnpm needs a tool")
		}
		var err error
		if pnpmCfg, err = PnpmFixedConfig(j.Tool.Version); err != nil {
			return nil, err
		}
	}
	python := spec.Interpreter()
	var a []string
	switch s.Op {
	case OpNpmRelock:
		a = []string{"npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"}
	case OpPnpmFrozen:
		a = []string{"pnpm", "install", "--lockfile-only", "--frozen-lockfile", "--ignore-scripts", "--ignore-pnpmfile"}
		a = append(a, pnpmCfg...)
	case OpPnpmRelock:
		a = []string{"pnpm", "install", "--lockfile-only", "--no-frozen-lockfile", "--ignore-scripts", "--ignore-pnpmfile"}
		a = append(a, pnpmCfg...)
	case OpUvCheck:
		a = []string{"uv", "lock", "--check", "--no-build", "--no-config", "--no-python-downloads", "--python", python}
	case OpUvUpgrade:
		a = []string{"uv", "lock"}
		for _, p := range s.Packages {
			a = append(a, "--upgrade-package", p.Name+"=="+p.Version)
		}
		a = append(a, "--no-build", "--no-config", "--no-python-downloads", "--python", python)
	case OpPipDryRun:
		a = []string{spec.InterpreterName(), "-m", "pip", "--isolated", "install", "--dry-run", "--ignore-installed",
			"--only-binary=:all:", "--disable-pip-version-check", "--no-input",
			"--index-url", "https://pypi.org/simple", "--report", PipReportName}
		if s.RequireHashes {
			a = append(a, "--require-hashes")
		}
		if t := s.Target; t != nil {
			if t.PythonVersion != "" {
				a = append(a, "--python-version", t.PythonVersion)
			}
			for _, p := range t.Platforms {
				a = append(a, "--platform", p)
			}
			if t.Implementation != "" {
				a = append(a, "--implementation", t.Implementation)
			}
			for _, abi := range t.ABIs {
				a = append(a, "--abi", abi)
			}
		}
		a = append(a, "-r", "requirements.txt")
	default:
		return nil, fmt.Errorf("unknown op %q", s.Op)
	}
	return a, nil
}
