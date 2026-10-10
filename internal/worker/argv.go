package worker

import "fmt"

// Argv returns the command line for a step of a job for manager m. The first
// element is the program name. Names and versions are separate arguments,
// never joined into a shell string, and a value that starts with '-' is
// refused by Step.Validate before it gets here.
func Argv(m Manager, s Step) ([]string, error) {
	if err := s.Validate(m); err != nil {
		return nil, err
	}
	var a []string
	switch s.Op {
	case OpNpmRelock:
		a = []string{"npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"}
	case OpNpmUpdate:
		a = []string{"npm", "update"}
		for _, p := range s.Packages {
			a = append(a, p.Name)
		}
		a = append(a, "--package-lock-only", "--ignore-scripts", "--no-save", "--no-audit", "--no-fund")
	case OpPnpmFrozen:
		a = []string{"pnpm", "install", "--lockfile-only", "--frozen-lockfile", "--ignore-scripts", "--ignore-pnpmfile"}
	case OpPnpmUpdate:
		a = []string{"pnpm", "update"}
		for _, p := range s.Packages {
			if p.Version == "" {
				a = append(a, p.Name)
			} else {
				a = append(a, p.Name+"@"+p.Version)
			}
		}
		a = append(a, "--lockfile-only", "--no-save", "--ignore-scripts", "--ignore-pnpmfile")
	case OpPnpmRelock:
		a = []string{"pnpm", "install", "--lockfile-only", "--no-frozen-lockfile", "--ignore-scripts", "--ignore-pnpmfile"}
	case OpUvCheck:
		a = []string{"uv", "lock", "--check", "--no-build", "--no-config", "--no-python-downloads"}
	case OpUvUpgrade:
		a = []string{"uv", "lock"}
		for _, p := range s.Packages {
			a = append(a, "--upgrade-package", p.Name+"=="+p.Version)
		}
		a = append(a, "--no-build", "--no-config", "--no-python-downloads")
	case OpPipDryRun:
		a = []string{"python", "-m", "pip", "--isolated", "install", "--dry-run", "--ignore-installed",
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
