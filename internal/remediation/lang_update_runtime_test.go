package remediation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// specWork records the specs the stage hands to the work runner.
type specWork struct {
	WorkRunner
	specs []docker.JobSpec
}

func (s *specWork) RunJob(ctx context.Context, spec docker.JobSpec) (docker.JobResult, error) {
	s.specs = append(s.specs, spec)
	return s.WorkRunner.RunJob(ctx, spec)
}

func TestLangUpdateJobCarriesRuntimeToolAndProgram(t *testing.T) {
	for _, name := range []string{"npm", "pnpm", "uv", "pip"} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, name)
			sw := &specWork{WorkRunner: h.work}
			h.cfg.Work = sw
			it, _ := h.run()
			wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)

			wantRuntime := "node24"
			if name == "uv" || name == "pip" {
				wantRuntime = "python3.13"
			}
			for _, spec := range sw.specs {
				if spec.Runtime != wantRuntime {
					t.Errorf("spec runtime = %q, want %q", spec.Runtime, wantRuntime)
				}
				var program, tool bool
				for _, in := range spec.Inputs {
					switch in.Kind {
					case docker.KindProgram:
						program = in.Path == worker.ProgramInputPath && in.Executable && string(in.Content) == "work program"
					case docker.KindTool:
						tool = strings.HasPrefix(in.Path, "tools/"+name+"-")
					}
				}
				if !program || tool != (name != "pip") {
					t.Errorf("program=%v tool=%v inputs=%v", program, tool, spec.Inputs)
				}
			}
			for _, job := range h.work.jobs {
				if err := job.Validate(); err != nil {
					t.Errorf("job: %v", err)
				}
				if job.Runtime.ID != wantRuntime || job.Runtime.Version == "" {
					t.Errorf("job runtime = %+v", job.Runtime)
				}
				if (job.Tool == nil) != (name == "pip") {
					t.Errorf("job tool = %+v", job.Tool)
				}
			}
			rt := it.Update.Runtime
			if rt == nil || rt.ID != wantRuntime || rt.Digest == "" || rt.Image == "" || rt.EOL == "" {
				t.Errorf("runtime record = %+v", rt)
			}
			if name == "pip" {
				if it.Update.Tool != nil || rt.Pip != pyPip() {
					t.Errorf("pip record: tool=%+v runtime=%+v", it.Update.Tool, rt)
				}
				return
			}
			tl := it.Update.Tool
			if tl == nil || tl.Name != name || tl.Version == "" || tl.Source != toolSourceDefault || tl.SHA256 == "" || tl.SHA512 == "" {
				t.Errorf("tool record = %+v", tl)
			}
			ft := h.cfg.Tools.(*fakeTools)
			if len(ft.reqs) == 0 || ft.reqs[0].Platform != "linux/amd64" || (wantRuntime == "node24") != (ft.reqs[0].NodeVersion != "") {
				t.Errorf("tool requests = %+v", ft.reqs)
			}
			if len(ft.released) != len(ft.reqs) {
				t.Errorf("released %d of %d artifacts", len(ft.released), len(ft.reqs))
			}
		})
	}
}

func TestLangUpdateRuntimeEndOfLifeIsManual(t *testing.T) {
	for _, c := range []struct {
		name, manager string
		now           time.Time
		text          string
	}{
		{"node", "npm", time.Date(2028, 5, 1, 0, 0, 0, 0, time.UTC), "Node.js 24 reached the end of its support on 2028-04-30; upgrade the runtime before updating"},
		{"python", "uv", time.Date(2029, 11, 1, 0, 0, 0, 0, time.UTC), "Python 3.13 reached the end of its support on 2029-10-01; upgrade the runtime before updating"},
		{"python pip", "pip", time.Date(2029, 11, 1, 0, 0, 0, 0, time.UTC), "Python 3.13 reached the end of its support on 2029-10-01; upgrade the runtime before updating"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, c.manager)
			h.cfg.Now = func() time.Time { return c.now }
			it, _ := h.run()
			wantCategory(t, it, CategoryManual, ReasonRuntimeEndOfLife)
			if it.Detail != c.text {
				t.Errorf("detail = %q", it.Detail)
			}
			if e := it.RuntimeEOL; e == nil || e.ID == "" || e.Name == "" || e.EOL == "" || !strings.HasPrefix(c.text, e.Name) {
				t.Errorf("runtime_eol = %+v", e)
			}
			if h.work.calls != 0 || len(h.cfg.Tools.(*fakeTools).reqs) != 0 {
				t.Error("something ran or was fetched")
			}
		})
	}
	// Just before the end of support the update still runs.
	h := newHarness(t, "npm")
	h.cfg.Now = func() time.Time { return time.Date(2028, 4, 30, 12, 0, 0, 0, time.UTC) }
	it, _ := h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
}

func TestLangUpdateDeclaredEndOfLifeRuntimeIsManual(t *testing.T) {
	h := newHarness(t, "npm")
	h.files[".nvmrc"] = "20\n"
	h.gh = ghFor(h.files)
	h.cfg.GitHub = h.gh
	// The plan read the file, so it is among the unit's sources.
	h.item.Source.Files = append(h.item.Source.Files, SourceFile{Path: ".nvmrc", BlobSHA: gitBlobSHA([]byte("20\n"))})
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonRuntimeEndOfLife)
	if !strings.Contains(it.Detail, "Node.js 20") || h.work.calls != 0 {
		t.Errorf("detail %q, calls %d", it.Detail, h.work.calls)
	}
}

func TestLangUpdateSpecFileThatAppearedIsSourceChanged(t *testing.T) {
	h := newHarness(t, "npm")
	h.item.Source.Absent = append(h.item.Source.Absent, ".nvmrc")
	h.files[".nvmrc"] = "24\n"
	h.gh = ghFor(h.files)
	h.cfg.GitHub = h.gh
	it, _ := h.run()
	wantCategory(t, it, CategoryFailed, ReasonSourceChanged)
}

func TestLangUpdateToolFailures(t *testing.T) {
	for name, c := range map[string]struct {
		err    error
		cat    Category
		reason Reason
	}{
		"too new": {&ToolError{Category: CategoryDeferred, Reason: "tool_too_new", Detail: "published 2h ago"}, CategoryDeferred, "tool_too_new"},
		"manual":  {&ToolError{Category: CategoryManual, Reason: "tool_unsupported", Detail: "x"}, CategoryManual, "tool_unsupported"},
		"other":   {errors.New("disk full"), CategoryFailed, ReasonUpdateJobFailed},
		"wrapped": {errors.Join(errors.New("ctx"), &ToolError{Category: CategoryDeferred, Reason: "tool_fetch_failed", Detail: "d"}), CategoryDeferred, "tool_fetch_failed"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "npm")
			h.cfg.Tools.(*fakeTools).err = c.err
			it, _ := h.run()
			wantCategory(t, it, c.cat, c.reason)
			if h.work.calls != 0 {
				t.Error("a job ran")
			}
		})
	}
}

func TestLangUpdateRefusesAnArtifactThatIsNotWhatWasAsked(t *testing.T) {
	h := newHarness(t, "npm")
	good := h.cfg.Tools
	for name, wrap := range map[string]func(ToolArtifact) ToolArtifact{
		"other version": func(a ToolArtifact) ToolArtifact { a.Version = "1.0.0"; return a },
		"other manager": func(a ToolArtifact) ToolArtifact { a.Manager = ManagerPnpm; return a },
		"other hash":    func(a ToolArtifact) ToolArtifact { a.SHA256 = strings.Repeat("0", 64); return a },
		"other size":    func(a ToolArtifact) ToolArtifact { a.Size++; return a },
		"missing file":  func(a ToolArtifact) ToolArtifact { a.Path += ".gone"; return a },
	} {
		h.cfg.Tools = alteredTools{good, wrap}
		it, _ := h.run()
		wantCategory(t, it, CategoryFailed, ReasonToolFileMismatch)
		if h.work.calls != 0 {
			t.Errorf("%s: a job ran", name)
		}
	}
}

type alteredTools struct {
	ToolProvider
	f func(ToolArtifact) ToolArtifact
}

func (a alteredTools) Provide(ctx context.Context, req ToolRequest) (ToolArtifact, error) {
	art, err := a.ToolProvider.Provide(ctx, req)
	return a.f(art), err
}

func TestLangUpdateWorkOutcomes(t *testing.T) {
	t.Run("image unavailable defers", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.work.script = func(int, worker.Job, map[string][]byte) fakeOutcome {
			return fakeOutcome{err: errors.Join(docker.ErrImageUnavailable, errors.New("429"))}
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryDeferred, ReasonWorkImageUnavailable)
	})
	t.Run("environment rejected fails", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.work.script = func(int, worker.Job, map[string][]byte) fakeOutcome {
			return fakeOutcome{status: worker.StatusEnvironmentRejected}
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryFailed, ReasonWorkEnvironmentRejected)
	})
	t.Run("program problems defer", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.cfg.Program = func() ([]byte, error) {
			return nil, errors.New("the work program is not the one this build was released with")
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryDeferred, ReasonWorkProgramMismatch)
		if h.work.calls != 0 {
			t.Error("a job ran")
		}
	})
}

func TestNewJobsDoNotUseOldRecordsAsVersions(t *testing.T) {
	// A record from before the versions were kept has neither, and says so in
	// the body.
	rec := &LangRecord{Manager: "npm"}
	var b strings.Builder
	writeEnvironment(textFor(BodyEN), &b, rec)
	if !strings.Contains(b.String(), "no record") {
		t.Errorf("body = %q", b.String())
	}
	b.Reset()
	writeEnvironment(textFor(BodyJA), &b, rec)
	if !strings.Contains(b.String(), "記録なし") {
		t.Errorf("body = %q", b.String())
	}
	rec.Runtime = &RuntimeRecord{ID: "node24", Version: "24.21.0", Image: "node@sha256:x"}
	rec.Tool = &ToolRecord{Name: "npm", Version: "11.21.0", Source: "declared", SHA256: "abc"}
	b.Reset()
	writeEnvironment(textFor(BodyEN), &b, rec)
	if out := b.String(); !strings.Contains(out, "24.21.0") || !strings.Contains(out, "11.21.0") || !strings.Contains(out, "declares") {
		t.Errorf("body = %q", out)
	}
}

// pyPip is the pip the table pins for Python 3.13.
func pyPip() string {
	spec, _ := worker.LookupRuntime("python3.13")
	return spec.Pip
}
