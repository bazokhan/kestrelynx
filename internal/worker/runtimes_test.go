package worker

import (
	"strings"
	"testing"
	"time"
)

func TestRuntimeTableIsConsistent(t *testing.T) {
	specs := Runtimes()
	for _, id := range []string{"node20", "node22", "node24", "node26", "python3.9", "python3.10", "python3.11", "python3.12", "python3.13", "python3.14", "python3.15"} {
		if _, ok := LookupRuntime(id); !ok {
			t.Errorf("%s is not in the table", id)
		}
	}
	for _, id := range []string{"node20", "python3.9", "python3.10"} {
		if r, _ := LookupRuntime(id); r.HasImage() {
			t.Errorf("%s has an image, but it is out of support", id)
		}
	}
	// The versions and digests are whatever the update workflow last pinned;
	// only their shape and agreement with each other are checked.
	for _, r := range specs {
		if !r.HasImage() {
			continue
		}
		if r.ImageRef() != r.Image+"@"+r.IndexDigest || r.Platforms["linux/amd64"] == r.Platforms["linux/arm64"] {
			t.Errorf("%s: image ref %s, platforms %v", r.ID, r.ImageRef(), r.Platforms)
		}
		if r.Tag != r.Series+strings.TrimPrefix(r.Tag, r.Series) || !strings.HasPrefix(r.ExactTag, r.Version) {
			t.Errorf("%s: tags %s / %s do not fit version %s", r.ID, r.Tag, r.ExactTag, r.Version)
		}
		switch r.Kind {
		case KindNode:
			if r.VersionEnv() != "NODE_VERSION" || r.Interpreter() != "/usr/local/bin/node" || r.InterpreterName() != "node" || r.Pip != "" {
				t.Errorf("%s: %+v", r.ID, r)
			}
		case KindPython:
			if r.VersionEnv() != "PYTHON_VERSION" || r.Interpreter() != "/usr/local/bin/"+r.ID || r.InterpreterName() != r.ID || r.Pip == "" {
				t.Errorf("%s: %+v", r.ID, r)
			}
		}
		for p, d := range r.Tested {
			if r.Platforms[p] != d {
				t.Errorf("%s: tested %s digest %s is not the pinned manifest", r.ID, p, d)
			}
		}
	}
	// Support ends later for a later series of the same language.
	byKind := map[RuntimeKind][]RuntimeSpec{}
	for _, r := range specs {
		byKind[r.Kind] = append(byKind[r.Kind], r)
	}
	for kind, list := range byKind {
		for _, a := range list {
			for _, b := range list {
				if len(a.Series) == len(b.Series) && a.Series < b.Series && a.EOL > b.EOL {
					t.Errorf("%s: %s ends after %s", kind, a.ID, b.ID)
				}
			}
		}
	}
	if len(specs) < 11 {
		t.Errorf("%d rows", len(specs))
	}
}

func TestParseRuntimesRejects(t *testing.T) {
	good := `{"schema":1,"runtimes":[{"id":"node20","kind":"node","series":"20","support":"end_of_life","eol":"2026-04-30","checked":"2026-10-12"}]}`
	if _, err := parseRuntimes([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"schema":     strings.Replace(good, `"schema":1`, `"schema":2`, 1),
		"id":         strings.Replace(good, `"id":"node20"`, `"id":"node21"`, 1),
		"kind":       strings.Replace(good, `"kind":"node"`, `"kind":"ruby"`, 1),
		"eol":        strings.Replace(good, `2026-04-30`, `soon`, 1),
		"no digests": strings.Replace(good, `"series":"20"`, `"series":"20","image":"node","version":"20.1.0"`, 1),
		"lts_from":   strings.Replace(good, `"eol":"2026-04-30"`, `"eol":"2026-04-30","lts_from":"later"`, 1),
		"duplicate":  strings.Replace(good, `}]}`, `},{"id":"node20","kind":"node","series":"20","eol":"2026-04-30"}]}`, 1),
	} {
		if _, err := parseRuntimes([]byte(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestEndOfLife(t *testing.T) {
	day := func(s string) time.Time { v, _ := time.Parse("2006-01-02", s); return v }
	n20, _ := LookupRuntime("node20")
	n24, _ := LookupRuntime("node24")
	p310, _ := LookupRuntime("python3.10")
	for _, c := range []struct {
		r    RuntimeSpec
		now  string
		want bool
	}{
		{n20, "2026-10-12", true},
		{n20, "2026-04-30", false}, // the last day of support
		{n20, "2026-05-01", true},
		{n24, "2026-10-12", false},
		{n24, "2028-04-30", false},
		{n24, "2028-05-01", true},
		{p310, "2026-10-12", true},
	} {
		if got := c.r.EndOfLife(day(c.now)); got != c.want {
			t.Errorf("%s on %s = %v, want %v", c.r.ID, c.now, got, c.want)
		}
	}
	// The time of day does not matter.
	if n20.EndOfLife(time.Date(2026, 4, 30, 23, 59, 0, 0, time.UTC)) {
		t.Error("the last day ends too early")
	}
}

func TestPnpmFixedConfig(t *testing.T) {
	for v, want := range map[string]string{"9.15.9": "", "10.34.4": "--config.manage-package-manager-versions=false", "11.28.5": "--config.pmOnFail=ignore", "12.11.2": "--config.pmOnFail=ignore"} {
		got, err := PnpmFixedConfig(v)
		if err != nil || strings.Join(got, " ") != want {
			t.Errorf("%s = %v, %v; want %q", v, got, err, want)
		}
	}
	for _, v := range []string{"8.0.0", "13.0.0", "x"} {
		if _, err := PnpmFixedConfig(v); err == nil {
			t.Errorf("%s accepted", v)
		}
	}
}

func TestArgvPnpmConfigFollowsToolVersion(t *testing.T) {
	for v, want := range map[string]string{"10.34.4": "--config.manage-package-manager-versions=false", "11.28.5": "--config.pmOnFail=ignore"} {
		j := testJob(ManagerPnpm)
		j.Tool = testTool(ManagerPnpm, v)
		a, err := Argv(j, Step{ID: "a", Op: OpPnpmRelock})
		if err != nil || a[len(a)-1] != want {
			t.Errorf("%s: %v, %v", v, a, err)
		}
	}
	j := testJob(ManagerPnpm)
	j.Tool = nil
	if _, err := Argv(j, Step{ID: "a", Op: OpPnpmRelock}); err == nil {
		t.Error("pnpm without a tool accepted")
	}
	j = testJob(ManagerNpm)
	j.Runtime = testRuntime(ManagerUv)
	if _, err := Argv(j, Step{ID: "a", Op: OpNpmRelock}); err == nil {
		t.Error("npm in a Python runtime accepted")
	}
}

func TestJobRuntimeAndToolValidation(t *testing.T) {
	ok := func() *Job { return goodJob() }
	mut := map[string]func(*Job){
		"unknown runtime":     func(j *Job) { j.Runtime.ID = "node99" },
		"end of life runtime": func(j *Job) { j.Runtime = Runtime{ID: "node20", Version: "20.20.2"} },
		"python for npm":      func(j *Job) { j.Runtime = testRuntime(ManagerUv) },
		"version off series":  func(j *Job) { j.Runtime.Version = "22.1.0" },
		"pip on node":         func(j *Job) { j.Runtime.Pip = "26.2.1" },
		"no tool":             func(j *Job) { j.Tool = nil },
		"wrong tool":          func(j *Job) { j.Tool = testTool(ManagerPnpm, "11.28.5") },
		"bad path":            func(j *Job) { j.Tool.Path = "tools/other.tgz" },
		"bad format":          func(j *Job) { j.Tool.Format = FormatWheel },
		"not run with node":   func(j *Job) { j.Tool.RunWithNode = false },
		"no size":             func(j *Job) { j.Tool.Size = 0 },
		"huge":                func(j *Job) { j.Tool.Size = MaxToolArchiveBytes + 1 },
		"short sha512":        func(j *Job) { j.Tool.SHA512 = strings.Repeat("b", 64) },
		"entry escapes":       func(j *Job) { j.Tool.Entry = "../x" },
		"entry absolute":      func(j *Job) { j.Tool.Entry = "/bin/sh" },
		"range version":       func(j *Job) { j.Tool.Version = "^11.0.0" },
	}
	for name, f := range mut {
		j := ok()
		f(j)
		if err := j.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// uv and pip.
	uj := testJob(ManagerUv)
	uj.Inputs = []Input{{Path: "pyproject.toml", SHA256: strings.Repeat("a", 64)}, {Path: "uv.lock", SHA256: strings.Repeat("a", 64)}}
	uj.Steps = []Step{{ID: "c", Op: OpUvCheck}}
	uj.Outputs, uj.DeadlineSeconds = []string{"pyproject.toml", "uv.lock"}, 10
	if err := uj.Validate(); err != nil {
		t.Errorf("uv job: %v", err)
	}
	pj := testJob(ManagerPip)
	pj.Tool = testTool(ManagerUv, "0.13.0")
	pj.Inputs = []Input{{Path: "requirements.txt", SHA256: strings.Repeat("a", 64)}}
	pj.Steps = []Step{{ID: "d", Op: OpPipDryRun}}
	pj.Outputs, pj.DeadlineSeconds = []string{"requirements.txt"}, 10
	if err := pj.Validate(); err == nil {
		t.Error("pip with a tool accepted")
	}
	pj.Tool = nil
	pj.Runtime.Pip = ""
	if err := pj.Validate(); err == nil {
		t.Error("pip without the version of pip accepted")
	}
}

func TestProgramSHA256(t *testing.T) {
	if _, err := ProgramSHA256("riscv64"); err == nil {
		t.Error("riscv64 accepted")
	}
	if got := ProgramFileName("arm64"); got != "kestrelynx-worker-arm64" {
		t.Error(got)
	}
}

func TestLongTermSupportAndTheDefaultNodeRuntime(t *testing.T) {
	day := func(s string) time.Time { v, _ := time.Parse("2006-01-02", s); return v }
	n26, _ := LookupRuntime("node26")
	for _, c := range []struct {
		now  string
		want bool
	}{{"2026-10-27", false}, {"2026-10-28", true}, {"2029-04-30", true}, {"2029-05-01", false}} {
		if got := n26.InLTS(day(c.now)); got != c.want {
			t.Errorf("node26 on %s: in LTS = %v, want %v", c.now, got, c.want)
		}
	}
	p313, _ := LookupRuntime("python3.13")
	if p313.InLTS(day("2026-10-13")) {
		t.Error("a Python series is never in long-term support")
	}
	for _, c := range []struct{ now, want string }{
		{"2024-10-29", "node22"}, // the newer series are not in long-term support yet
		{"2026-10-13", "node24"},
		{"2026-10-28", "node26"},
		{"2029-05-01", "node26"},
	} {
		got, ok := DefaultNodeRuntime(day(c.now))
		if !ok || got != c.want {
			t.Errorf("default Node.js runtime on %s = %q (%v), want %s", c.now, got, ok, c.want)
		}
	}
}
