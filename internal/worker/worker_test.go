package worker

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestNameAndVersionValidation(t *testing.T) {
	cases := []struct {
		fn   func(string) bool
		in   string
		want bool
	}{
		{ValidNpmName, "minimist", true},
		{ValidNpmName, "@scope/pkg.name-1", true},
		{ValidNpmName, "-minimist", false},
		{ValidNpmName, "--registry=x", false},
		{ValidNpmName, "@scope", false},
		{ValidNpmName, "@scope/", false},
		{ValidNpmName, "Upper", false},
		{ValidNpmName, ".hidden", false},
		{ValidNpmName, "a b", false},
		{ValidNpmName, "a/b", false},
		{ValidNpmName, "a;b", false},
		{ValidNpmName, "", false},
		{ValidNpmName, strings.Repeat("a", 215), false},
		{ValidSemver, "1.2.6", true},
		{ValidSemver, "1.2.6-rc.1+build.5", true},
		{ValidSemver, "^1.2.6", false},
		{ValidSemver, "v1.2.6", false},
		{ValidSemver, "-1.2.6", false},
		{ValidSemver, "1.2", false},
		{ValidSemver, "01.2.3", false},
		{ValidSemver, "1.2.3 ", false},
		{ValidPythonName, "urllib3", true},
		{ValidPythonName, "Zope.Interface_x-y", true},
		{ValidPythonName, "-urllib3", false},
		{ValidPythonName, "urllib3-", false},
		{ValidPythonName, "a b", false},
		{ValidPythonName, "a[extra]", false},
		{ValidPythonName, "", false},
		{ValidPythonVersion, "1.26.19", true},
		{ValidPythonVersion, "2!1.0.post1.dev2", true},
		{ValidPythonVersion, "1.0rc1", true},
		{ValidPythonVersion, "1.0+local.1", true},
		{ValidPythonVersion, "-1.0", false},
		{ValidPythonVersion, "==1.0", false},
		{ValidPythonVersion, "1.0 ", false},
		{ValidPythonVersion, "1.0;x", false},
		{ValidStepID, "s1", true},
		{ValidStepID, "../x", false},
		{ValidStepID, "-s", false},
		{ValidStepID, "S1", false},
		{ValidStepID, "", false},
	}
	for _, c := range cases {
		if got := c.fn(c.in); got != c.want {
			t.Errorf("%q = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestArgv(t *testing.T) {
	cases := []struct {
		name string
		m    Manager
		step Step
		want []string
	}{
		{"npm relock", ManagerNpm, Step{ID: "a", Op: OpNpmRelock},
			[]string{"npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"}},
		{"npm update", ManagerNpm, Step{ID: "a", Op: OpNpmUpdate, Packages: []Package{{Name: "minimist"}, {Name: "@s/x"}}},
			[]string{"npm", "update", "minimist", "@s/x", "--package-lock-only", "--ignore-scripts", "--no-save", "--no-audit", "--no-fund"}},
		{"pnpm frozen", ManagerPnpm, Step{ID: "a", Op: OpPnpmFrozen},
			[]string{"pnpm", "install", "--lockfile-only", "--frozen-lockfile", "--ignore-scripts", "--ignore-pnpmfile"}},
		{"pnpm update with version", ManagerPnpm, Step{ID: "a", Op: OpPnpmUpdate, Packages: []Package{{Name: "minimist", Version: "1.2.8"}}},
			[]string{"pnpm", "update", "minimist@1.2.8", "--lockfile-only", "--no-save", "--ignore-scripts", "--ignore-pnpmfile"}},
		{"pnpm update without version", ManagerPnpm, Step{ID: "a", Op: OpPnpmUpdate, Packages: []Package{{Name: "minimist"}, {Name: "@s/x", Version: "2.0.0"}}},
			[]string{"pnpm", "update", "minimist", "@s/x@2.0.0", "--lockfile-only", "--no-save", "--ignore-scripts", "--ignore-pnpmfile"}},
		{"pnpm relock", ManagerPnpm, Step{ID: "a", Op: OpPnpmRelock},
			[]string{"pnpm", "install", "--lockfile-only", "--no-frozen-lockfile", "--ignore-scripts", "--ignore-pnpmfile"}},
		{"uv check", ManagerUv, Step{ID: "a", Op: OpUvCheck},
			[]string{"uv", "lock", "--check", "--no-build", "--no-config", "--no-python-downloads"}},
		{"uv upgrade", ManagerUv, Step{ID: "a", Op: OpUvUpgrade, Packages: []Package{{Name: "urllib3", Version: "2.2.2"}, {Name: "idna", Version: "3.7"}}},
			[]string{"uv", "lock", "--upgrade-package", "urllib3==2.2.2", "--upgrade-package", "idna==3.7", "--no-build", "--no-config", "--no-python-downloads"}},
		{"pip dry run", ManagerPip, Step{ID: "a", Op: OpPipDryRun},
			[]string{"python", "-m", "pip", "--isolated", "install", "--dry-run", "--ignore-installed", "--only-binary=:all:",
				"--disable-pip-version-check", "--no-input", "--index-url", "https://pypi.org/simple", "--report", "pip-report.json", "-r", "requirements.txt"}},
		{"pip hashes and target", ManagerPip, Step{ID: "a", Op: OpPipDryRun, RequireHashes: true,
			Target: &Target{PythonVersion: "3.13", Platforms: []string{"manylinux2014_x86_64", "linux_x86_64"}, Implementation: "cp", ABIs: []string{"cp313"}}},
			[]string{"python", "-m", "pip", "--isolated", "install", "--dry-run", "--ignore-installed", "--only-binary=:all:",
				"--disable-pip-version-check", "--no-input", "--index-url", "https://pypi.org/simple", "--report", "pip-report.json",
				"--require-hashes", "--python-version", "3.13", "--platform", "manylinux2014_x86_64", "--platform", "linux_x86_64",
				"--implementation", "cp", "--abi", "cp313", "-r", "requirements.txt"}},
	}
	for _, c := range cases {
		got, err := Argv(c.m, c.step)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

func TestStepRejections(t *testing.T) {
	cases := []struct {
		name string
		m    Manager
		step Step
	}{
		{"unknown op", ManagerNpm, Step{ID: "a", Op: "npm.exec"}},
		{"wrong manager", ManagerNpm, Step{ID: "a", Op: OpPnpmRelock}},
		{"dash name npm", ManagerNpm, Step{ID: "a", Op: OpNpmUpdate, Packages: []Package{{Name: "--registry=http://x"}}}},
		{"dash name pnpm", ManagerPnpm, Step{ID: "a", Op: OpPnpmUpdate, Packages: []Package{{Name: "-r", Version: "1.0.0"}}}},
		{"dash version", ManagerPnpm, Step{ID: "a", Op: OpPnpmUpdate, Packages: []Package{{Name: "x", Version: "-1.0.0"}}}},
		{"dash uv name", ManagerUv, Step{ID: "a", Op: OpUvUpgrade, Packages: []Package{{Name: "-x", Version: "1.0"}}}},
		{"range version", ManagerPnpm, Step{ID: "a", Op: OpPnpmUpdate, Packages: []Package{{Name: "x", Version: "^1.0.0"}}}},
		{"npm update with version", ManagerNpm, Step{ID: "a", Op: OpNpmUpdate, Packages: []Package{{Name: "x", Version: "1.0.0"}}}},
		{"npm update without packages", ManagerNpm, Step{ID: "a", Op: OpNpmUpdate}},
		{"relock with packages", ManagerNpm, Step{ID: "a", Op: OpNpmRelock, Packages: []Package{{Name: "x"}}}},
		{"duplicate package", ManagerNpm, Step{ID: "a", Op: OpNpmUpdate, Packages: []Package{{Name: "x"}, {Name: "x"}}}},
		{"uv without version", ManagerUv, Step{ID: "a", Op: OpUvUpgrade, Packages: []Package{{Name: "urllib3"}}}},
		{"pnpm dash name no version", ManagerPnpm, Step{ID: "a", Op: OpPnpmUpdate, Packages: []Package{{Name: "-r"}}}},
		{"hashes on uv", ManagerUv, Step{ID: "a", Op: OpUvCheck, RequireHashes: true}},
		{"bad target version", ManagerPip, Step{ID: "a", Op: OpPipDryRun, Target: &Target{PythonVersion: "3.13; rm"}}},
		{"dash platform", ManagerPip, Step{ID: "a", Op: OpPipDryRun, Target: &Target{Platforms: []string{"--index-url=x"}}}},
		{"bad implementation", ManagerPip, Step{ID: "a", Op: OpPipDryRun, Target: &Target{Implementation: "cpython"}}},
		{"empty target", ManagerPip, Step{ID: "a", Op: OpPipDryRun, Target: &Target{}}},
		{"bad step id", ManagerNpm, Step{ID: "../a", Op: OpNpmRelock}},
	}
	for _, c := range cases {
		if _, err := Argv(c.m, c.step); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

func goodJob() *Job {
	h := strings.Repeat("a", 64)
	return &Job{
		Protocol: ProtocolVersion, Manager: ManagerNpm,
		Inputs:  []Input{{Path: "package.json", Size: 1, SHA256: h}, {Path: "package-lock.json", Size: 2, SHA256: h}},
		Steps:   []Step{{ID: "relock", Op: OpNpmRelock}},
		Outputs: []string{"package.json", "package-lock.json"}, DeadlineSeconds: 60, StepTimeoutSeconds: 30,
	}
}

func TestJobValidate(t *testing.T) {
	if err := goodJob().Validate(); err != nil {
		t.Fatalf("good job: %v", err)
	}
	mutations := map[string]func(*Job){
		"protocol":         func(j *Job) { j.Protocol = 2 },
		"manager":          func(j *Job) { j.Manager = "yarn" },
		"undeclared input": func(j *Job) { j.Inputs = append(j.Inputs, Input{Path: ".npmrc", SHA256: strings.Repeat("a", 64)}) },
		"missing input":    func(j *Job) { j.Inputs = j.Inputs[:1] },
		"nested input":     func(j *Job) { j.Inputs[0].Path = "sub/package.json" },
		"duplicate input":  func(j *Job) { j.Inputs[1] = j.Inputs[0] },
		"bad hash":         func(j *Job) { j.Inputs[0].SHA256 = "XYZ" },
		"upper hash":       func(j *Job) { j.Inputs[0].SHA256 = strings.Repeat("A", 64) },
		"negative size":    func(j *Job) { j.Inputs[0].Size = -1 },
		"huge size":        func(j *Job) { j.Inputs[0].Size = MaxInputFileBytes + 1 },
		"no steps":         func(j *Job) { j.Steps = nil },
		"duplicate step":   func(j *Job) { j.Steps = append(j.Steps, j.Steps[0]) },
		"unknown op":       func(j *Job) { j.Steps[0].Op = "npm.run" },
		"no outputs":       func(j *Job) { j.Outputs = nil },
		"bad output":       func(j *Job) { j.Outputs = []string{"../etc/passwd"} },
		"foreign output":   func(j *Job) { j.Outputs = []string{"uv.lock"} },
		"report on npm":    func(j *Job) { j.Outputs = []string{PipReportName} },
		"duplicate output": func(j *Job) { j.Outputs = []string{"package.json", "package.json"} },
		"no deadline":      func(j *Job) { j.DeadlineSeconds = 0 },
		"long deadline":    func(j *Job) { j.DeadlineSeconds = MaxDeadlineSeconds + 1 },
		"step over total":  func(j *Job) { j.StepTimeoutSeconds = 61 },
	}
	for name, mut := range mutations {
		j := goodJob()
		mut(j)
		if err := j.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// the pip report is collectable for pip only
	pj := &Job{Protocol: ProtocolVersion, Manager: ManagerPip,
		Inputs:  []Input{{Path: "requirements.txt", SHA256: strings.Repeat("a", 64)}},
		Steps:   []Step{{ID: "d", Op: OpPipDryRun, Scratch: true}},
		Outputs: []string{"requirements.txt", PipReportName}, DeadlineSeconds: 10}
	if err := pj.Validate(); err != nil {
		t.Errorf("pip job: %v", err)
	}
}

// The protocol label in the work image's Dockerfile must be the version this
// package speaks, or the main process would refuse (or wrongly accept) the image.
func TestDockerfileLabelMatchesProtocol(t *testing.T) {
	b, err := os.ReadFile("../../Dockerfile.worker")
	if err != nil {
		t.Skipf("Dockerfile.worker not readable: %v", err)
	}
	want := fmt.Sprintf("LABEL %s=%q", ProtocolLabel, fmt.Sprint(ProtocolVersion))
	if !strings.Contains(string(b), want) {
		t.Errorf("Dockerfile.worker lacks %s", want)
	}
}
