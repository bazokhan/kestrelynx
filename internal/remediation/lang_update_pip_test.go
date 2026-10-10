package remediation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

func h64(c byte) string { return strings.Repeat(string(c), 64) }

func TestRewriteRequirements(t *testing.T) {
	ed := func(line int, old, nw string, hashes ...string) reqEdit {
		return reqEdit{Line: line, OldVersion: old, NewVersion: nw, Hashes: hashes}
	}
	cases := []struct {
		name  string
		in    string
		edits []reqEdit
		want  string
	}{
		{"plain", "urllib3==1.26.4\n", []reqEdit{ed(1, "1.26.4", "1.26.17")}, "urllib3==1.26.17\n"},
		{"no final newline", "urllib3==1.26.4", []reqEdit{ed(1, "1.26.4", "1.26.17")}, "urllib3==1.26.17"},
		{"crlf", "# c\r\nurllib3==1.26.4\r\nsix==1.0\r\n", []reqEdit{ed(2, "1.26.4", "1.26.17")}, "# c\r\nurllib3==1.26.17\r\nsix==1.0\r\n"},
		{"mixed line endings", "a==1\nurllib3==1.26.4\r\nb==2\n", []reqEdit{ed(2, "1.26.4", "1.26.17")}, "a==1\nurllib3==1.26.17\r\nb==2\n"},
		{"spaces and trailing comment", "urllib3 == 1.26.4  # keep me\n\n\n", []reqEdit{ed(1, "1.26.4", "1.26.17")}, "urllib3 == 1.26.17  # keep me\n\n\n"},
		{"extras", "urllib3[socks]==1.26.4\n", []reqEdit{ed(1, "1.26.4", "1.26.17")}, "urllib3[socks]==1.26.17\n"},
		{"bom", "\xef\xbb\xbfurllib3==1.26.4\n", []reqEdit{ed(1, "1.26.4", "1.26.17")}, "\xef\xbb\xbfurllib3==1.26.17\n"},
		{"two requirements", "urllib3==1.26.4\nsix==1.16.0\nrequests==2.0.0\n", []reqEdit{ed(1, "1.26.4", "1.26.17"), ed(3, "2.0.0", "2.31.0")}, "urllib3==1.26.17\nsix==1.16.0\nrequests==2.31.0\n"},
		{"hashes on continuation lines", "# top\nurllib3==1.26.4 \\\n    --hash=sha256:" + h64('a') + " \\\n    --hash=sha256:" + h64('b') + "\nsix==1.0\n",
			[]reqEdit{ed(2, "1.26.4", "1.26.17", h64('c'))},
			"# top\nurllib3==1.26.17 \\\n    --hash=sha256:" + h64('c') + "\nsix==1.0\n"},
		{"more new hashes than old, crlf", "urllib3==1.26.4 \\\r\n  --hash=sha256:" + h64('a') + "\r\nsix==1.0\r\n",
			[]reqEdit{ed(1, "1.26.4", "1.26.17", h64('c'), h64('d'))},
			"urllib3==1.26.17 \\\r\n    --hash=sha256:" + h64('c') + " \\\r\n    --hash=sha256:" + h64('d') + "\r\nsix==1.0\r\n"},
		{"hashes at the end of the file", "urllib3==1.26.4 \\\n  --hash=sha256:" + h64('a'),
			[]reqEdit{ed(1, "1.26.4", "1.26.17", h64('c'))},
			"urllib3==1.26.17 \\\n    --hash=sha256:" + h64('c')},
		{"hashes on the requirement's line", "urllib3==1.26.4 --hash=sha256:" + h64('a') + " --hash=sha256:" + h64('b') + "\nsix==1.0\n",
			[]reqEdit{ed(1, "1.26.4", "1.26.17", h64('c'))},
			"urllib3==1.26.17 --hash=sha256:" + h64('c') + "\nsix==1.0\n"},
		{"edit after a hashed one keeps its line", "a==1 \\\n  --hash=sha256:" + h64('a') + " \\\n  --hash=sha256:" + h64('b') + " \\\n  --hash=sha256:" + h64('c') + "\nb==2 \\\n  --hash=sha256:" + h64('d') + "\n",
			[]reqEdit{ed(1, "1", "3", h64('e')), ed(5, "2", "4", h64('f'))},
			"a==3 \\\n    --hash=sha256:" + h64('e') + "\nb==4 \\\n    --hash=sha256:" + h64('f') + "\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := rewriteRequirements(bg, []byte(c.in), c.edits)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Errorf("got  %q\nwant %q", got, c.want)
			}
			if err := verifyRewrite([]byte(c.in), got, c.edits); err != nil {
				t.Errorf("verify: %v", err)
			}
		})
	}

	bad := []struct {
		name  string
		in    string
		edits []reqEdit
	}{
		{"wrong old version", "urllib3==1.26.4\n", []reqEdit{{Line: 1, OldVersion: "1.26.5", NewVersion: "1.26.17"}}},
		{"line outside", "urllib3==1.26.4\n", []reqEdit{{Line: 3, OldVersion: "1.26.4", NewVersion: "1.26.17"}}},
		{"hashes for a plain line", "urllib3==1.26.4\n", []reqEdit{{Line: 1, OldVersion: "1.26.4", NewVersion: "1.26.17", Hashes: []string{h64('a')}}}},
		{"no hashes for a hashed line", "urllib3==1.26.4 \\\n  --hash=sha256:" + h64('a') + "\n", []reqEdit{{Line: 1, OldVersion: "1.26.4", NewVersion: "1.26.17"}}},
		{"comment between hashes", "urllib3==1.26.4 \\\n  --hash=sha256:" + h64('a') + " \\\n  --hash=sha256:" + h64('b') + " # note\n", []reqEdit{{Line: 1, OldVersion: "1.26.4", NewVersion: "1.26.17", Hashes: []string{h64('c')}}}},
		{"other hash algorithm", "urllib3==1.26.4 \\\n  --hash=sha512:" + strings.Repeat("a", 128) + "\n", []reqEdit{{Line: 1, OldVersion: "1.26.4", NewVersion: "1.26.17", Hashes: []string{h64('c')}}}},
		{"hashes on both the line and the next", "urllib3==1.26.4 --hash=sha256:" + h64('a') + " \\\n  --hash=sha256:" + h64('b') + "\n", []reqEdit{{Line: 1, OldVersion: "1.26.4", NewVersion: "1.26.17", Hashes: []string{h64('c')}}}},
		{"twice", "urllib3==1.26.4\n", []reqEdit{{Line: 1, OldVersion: "1.26.4", NewVersion: "1.26.17"}, {Line: 1, OldVersion: "1.26.4", NewVersion: "1.26.18"}}},
	}
	for _, c := range bad {
		t.Run("refuses "+c.name, func(t *testing.T) {
			if got, err := rewriteRequirements(bg, []byte(c.in), c.edits); err == nil {
				t.Errorf("rewritten to %q", got)
			}
		})
	}
	t.Run("verify catches a rewrite that lost a requirement", func(t *testing.T) {
		in := "a==1\nb==2\n"
		if err := verifyRewrite([]byte(in), []byte("a==3\n"), []reqEdit{{Line: 1, OldVersion: "1", NewVersion: "3"}}); err == nil {
			t.Error("accepted")
		}
		if err := verifyRewrite([]byte(in), []byte("a==3\nb==9\n"), []reqEdit{{Line: 1, OldVersion: "1", NewVersion: "3"}}); err == nil {
			t.Error("accepted a changed untouched line")
		}
		if err := verifyRewrite([]byte(in), []byte("a==3\n-r other.txt\nb==2\n"), []reqEdit{{Line: 1, OldVersion: "1", NewVersion: "3"}}); err == nil {
			t.Error("accepted a file the plan does not read")
		}
	})
}

func TestPipPlatforms(t *testing.T) {
	amd := inventory.Platform{OS: "linux", Architecture: "amd64"}
	arm := inventory.Platform{OS: "linux", Architecture: "arm64"}
	cases := []struct {
		family, name string
		p            inventory.Platform
		first, last  string
		n            int
		ok           bool
	}{
		{"debian", "12.5", amd, "manylinux_2_36_x86_64", "manylinux_2_5_x86_64", 20 + 1 + 2, true},
		{"debian", "11", amd, "manylinux_2_31_x86_64", "manylinux_2_5_x86_64", 15 + 1 + 2, true},
		{"debian", "11.9", amd, "manylinux_2_31_x86_64", "manylinux_2_5_x86_64", 15 + 1 + 2, true},
		{"ubuntu", "22", amd, "", "", 0, false},
		{"alpine", "3", amd, "", "", 0, false},
		{"debian", "12.5", arm, "manylinux_2_36_aarch64", "manylinux2014_aarch64", 20 + 1, true},
		{"debian", "13.0", amd, "manylinux_2_41_x86_64", "manylinux_2_5_x86_64", 25 + 1 + 2, true},
		{"ubuntu", "22.04", amd, "manylinux_2_35_x86_64", "manylinux_2_5_x86_64", 19 + 1 + 2, true},
		{"ubuntu", "24.04", arm, "manylinux_2_39_aarch64", "manylinux2014_aarch64", 23 + 1, true},
		{"alpine", "3.19.1", amd, "musllinux_1_2_x86_64", "musllinux_1_0_x86_64", 3, true},
		{"alpine", "3.13.0", arm, "musllinux_1_2_aarch64", "musllinux_1_0_aarch64", 3, true},
		{"alpine", "3.12.9", amd, "", "", 0, false},
		{"alpine", "edge", amd, "", "", 0, false},
		{"debian", "99.0", amd, "", "", 0, false},
		{"debian", "", amd, "", "", 0, false},
		{"debian", "unstable", amd, "", "", 0, false},
		{"ubuntu", "26.04", amd, "", "", 0, false},
		{"redhat", "9.4", amd, "", "", 0, false},
		{"wolfi", "", amd, "", "", 0, false},
		{"debian", "12.5", inventory.Platform{OS: "linux", Architecture: "arm", Variant: "v7"}, "", "", 0, false},
		{"debian", "12.5", inventory.Platform{OS: "linux", Architecture: "s390x"}, "", "", 0, false},
		{"debian", "12.5", inventory.Platform{OS: "windows", Architecture: "amd64"}, "", "", 0, false},
		{"debian", "12.5", inventory.Platform{}, "", "", 0, false},
	}
	for _, c := range cases {
		t.Run(c.family+" "+c.name+" "+c.p.Architecture, func(t *testing.T) {
			got, ok := pipPlatforms(c.family, c.name, c.p)
			if ok != c.ok {
				t.Fatalf("ok = %v (%v)", ok, got)
			}
			if !ok {
				return
			}
			if got[0] != c.first || got[len(got)-1] != c.last || len(got) != c.n {
				t.Errorf("got %d tags %v", len(got), got)
			}
			if len(got) > worker.MaxTargetList {
				t.Errorf("%d tags exceed the job's limit", len(got))
			}
			if err := (&worker.Step{ID: "a", Op: worker.OpPipDryRun, Target: &worker.Target{Platforms: got}}).Validate(worker.ManagerPip); err != nil {
				t.Errorf("worker rejects the tags: %v", err)
			}
		})
	}
}

func TestPipTargetOf(t *testing.T) {
	envs := map[string]ImageEnv{
		"a": {Platform: inventory.Platform{OS: "linux", Architecture: "amd64"}, OSFamily: "debian", OSName: "12.5"},
		"b": {Platform: inventory.Platform{OS: "linux", Architecture: "amd64"}, OSFamily: "debian", OSName: "12.5"},
		"c": {Platform: inventory.Platform{OS: "linux", Architecture: "arm64"}, OSFamily: "debian", OSName: "12.5"},
		"d": {Platform: inventory.Platform{OS: "linux", Architecture: "amd64"}, OSFamily: "alpine", OSName: "3.19.1"},
	}
	pkg := func(origins ...FindingOrigin) LanguagePackage { return LanguagePackage{Name: "x", Origins: origins} }
	o := func(entity, py string) FindingOrigin {
		return FindingOrigin{Entity: entity, Name: "x", Workload: "w-" + entity, PkgPath: "usr/local/lib/python" + py + "/site-packages/x/METADATA"}
	}
	t.Run("one environment", func(t *testing.T) {
		tg, undecided, mismatch, why := pipTargetOf([]LanguagePackage{pkg(o("a", "3.12"))}, envs)
		if undecided || mismatch || tg == nil || tg.PythonVersion != "3.12" || tg.ABIs[0] != "cp312" || tg.Implementation != "cp" {
			t.Fatalf("%+v %v %v %s", tg, undecided, mismatch, why)
		}
	})
	t.Run("workloads agree", func(t *testing.T) {
		tg, undecided, mismatch, _ := pipTargetOf([]LanguagePackage{pkg(o("a", "3.12"), o("b", "3.12"))}, envs)
		if undecided || mismatch || tg == nil {
			t.Fatal("not decided")
		}
	})
	t.Run("python differs", func(t *testing.T) {
		if _, _, mismatch, _ := pipTargetOf([]LanguagePackage{pkg(o("a", "3.12"), o("b", "3.11"))}, envs); !mismatch {
			t.Error("no mismatch")
		}
	})
	t.Run("architecture differs", func(t *testing.T) {
		if _, _, mismatch, _ := pipTargetOf([]LanguagePackage{pkg(o("a", "3.12"), o("c", "3.12"))}, envs); !mismatch {
			t.Error("no mismatch")
		}
	})
	t.Run("libc differs", func(t *testing.T) {
		if _, _, mismatch, _ := pipTargetOf([]LanguagePackage{pkg(o("a", "3.12"), o("d", "3.12"))}, envs); !mismatch {
			t.Error("no mismatch")
		}
	})
	t.Run("packages differ", func(t *testing.T) {
		if _, _, mismatch, _ := pipTargetOf([]LanguagePackage{pkg(o("a", "3.12")), pkg(o("b", "3.10"))}, envs); !mismatch {
			t.Error("no mismatch")
		}
	})
	t.Run("undecided", func(t *testing.T) {
		for name, p := range map[string]LanguagePackage{
			"unknown image":     pkg(o("zz", "3.12")),
			"no python version": pkg(FindingOrigin{Entity: "a", PkgPath: "usr/lib/python3/dist-packages/x/METADATA", Target: "Python"}),
			"no origin":         pkg(),
		} {
			if _, undecided, _, _ := pipTargetOf([]LanguagePackage{p}, envs); !undecided {
				t.Errorf("%s: decided", name)
			}
		}
	})
	t.Run("python version from the target label", func(t *testing.T) {
		tg, undecided, _, _ := pipTargetOf([]LanguagePackage{pkg(FindingOrigin{Entity: "a", Target: "opt/venv/lib/python3.11/site-packages/x"})}, envs)
		if undecided || tg.PythonVersion != "3.11" {
			t.Errorf("%+v", tg)
		}
	})
}

func TestLangUpdatePip(t *testing.T) {
	t.Run("without hashes nothing is looked up and hashes are not required", func(t *testing.T) {
		h := newHarness(t, "pip")
		h.files["requirements.txt"] = "urllib3==1.26.4  # pinned\nsix==1.16.0\n"
		h.fx.beforePkgs = [][2]string{{"urllib3", "1.26.4"}, {"six", "1.16.0"}}
		h.fx.afterPkgs = [][2]string{{"urllib3", "1.26.17"}, {"six", "1.16.0"}}
		h.item = itemFor(t, ManagerPip, h.files, urllibGroup())
		h.gh = ghFor(h.files)
		h.cfg.GitHub = h.gh
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		// No hashes are fetched; only the packages of the two pip reports are
		// checked against the index.
		if strings.Join(h.pypi.lookups, " ") != "urllib3==1.26.4 six==1.16.0 urllib3==1.26.17" {
			t.Errorf("lookups = %v", h.pypi.lookups)
		}
		for i, j := range h.work.jobs {
			if j.Steps[0].RequireHashes {
				t.Errorf("job %d requires hashes", i)
			}
		}
		if got := string(it.Artifacts[0].Content); got != "urllib3==1.26.17  # pinned\nsix==1.16.0\n" {
			t.Errorf("artifact = %q", got)
		}
	})
	t.Run("sdist hash is dropped, wheels are all kept", func(t *testing.T) {
		h := newHarness(t, "pip")
		h.pypi.releases["urllib3==1.26.17"] = []PyPIFile{
			fakeWheel("urllib3", "1.26.17"),
			{Filename: "a-cp312-manylinux_2_17_x86_64.whl", Wheel: true, SHA256: h64('2')},
			{Filename: "a-cp312-musllinux_1_1_x86_64.whl", Wheel: true, SHA256: h64('1')},
			{Filename: "a.tar.gz", SHA256: h64('9')},
			{Filename: "a-dup.whl", Wheel: true, SHA256: h64('1')},
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		got := string(h.work.srcs[1]["requirements.txt"])
		want := "# pinned for the fixture\nurllib3==1.26.17 \\\n    --hash=sha256:" + h64('1') + " \\\n    --hash=sha256:" + h64('2') + " \\\n    --hash=sha256:" + urllibWheelSHA + "\n"
		if got != want {
			t.Errorf("rewritten = %q", got)
		}
	})
	type bad struct {
		name   string
		setup  func(h *harness)
		cat    Category
		reason Reason
	}
	for _, c := range []bad{
		{"release not on PyPI", func(h *harness) { h.pypi.missing = map[string]bool{"urllib3==1.26.17": true} }, CategoryManual, ReasonNoWheelForVersion},
		{"release without a wheel", func(h *harness) {
			h.pypi.releases["urllib3==1.26.17"] = []PyPIFile{{Filename: "a.tar.gz", SHA256: h64('9')}}
		}, CategoryManual, ReasonNoWheelForVersion},
		{"yanked release", func(h *harness) {
			h.pypi.releases["urllib3==1.26.17"][0].Yanked = true
		}, CategoryManual, ReasonReleaseYanked},
		{"PyPI unreachable", func(h *harness) { h.pypi.err = errors.New("dial tcp: no route") }, CategoryFailed, ReasonDistributionLookup},
		{"no scanned image for the environment", func(h *harness) { h.cfg.Images = nil }, CategoryManual, ReasonPipTargetUndecidable},
		{"unknown distribution", func(h *harness) {
			h.cfg.Images = map[string]ImageEnv{"img": {Platform: debianAmd64.Platform, OSFamily: "fedora", OSName: "40"}}
		}, CategoryManual, ReasonPipTargetUndecidable},
		{"two environments", func(h *harness) {
			g := urllibGroup()
			o2 := pyOrigin()
			o2.Entity, o2.Workload = "img2", "compose/p/worker"
			g.origins = append(g.origins, o2)
			h.item = itemFor(t, ManagerPip, h.files, g)
			h.cfg.Images = map[string]ImageEnv{"img": debianAmd64, "img2": {Platform: debianAmd64.Platform, OSFamily: "alpine", OSName: "3.19.1"}}
		}, CategoryManual, ReasonPipTargetMismatch},
		{"a comment inside the hashed requirement", func(h *harness) {
			h.files["requirements.txt"] = "urllib3==1.26.4 \\\n  --hash=sha256:" + h64('a') + " \\\n  --hash=sha256:" + h64('b') + " # why\n"
			h.item = itemFor(t, ManagerPip, h.files, urllibGroup())
			h.gh = ghFor(h.files)
			h.cfg.GitHub = h.gh
		}, CategoryManual, ReasonRequirementsRewrite},
		{"pip pulls in a new top-level package", func(h *harness) {
			useUnhashed(t, h)
			h.fx.afterPkgs = [][2]string{{"urllib3", "1.26.17"}, {"certifi", "2024.1.1"}}
		}, CategoryManual, ReasonUnexplainedDiff},
		{"pip drops a package the file requires", func(h *harness) {
			h.files["requirements.txt"] = "urllib3==1.26.4\ncertifi==2024.1.1\n"
			h.item = itemFor(t, ManagerPip, h.files, urllibGroup())
			h.gh = ghFor(h.files)
			h.cfg.GitHub = h.gh
			h.fx.beforePkgs = [][2]string{{"urllib3", "1.26.4"}, {"certifi", "2024.1.1"}}
		}, CategoryManual, ReasonDistributionMismatch},
		{"pip downloads from elsewhere", func(h *harness) {
			h.checkReport(func(r string) string { return strings.Replace(r, "files.pythonhosted.org", "evil.example", 1) })
		}, CategoryManual, ReasonDistributionMismatch},
		{"missing pip report", func(h *harness) {
			h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome { return fakeOutcome{} }
		}, CategoryFailed, ReasonUpdateResultInvalid},
		{"report that is not pip's", func(h *harness) {
			h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
				return fakeOutcome{edit: map[string]map[string][]byte{stepBaseline: {worker.PipReportName: []byte(`{"version":"2"}`)}, stepCheck: {worker.PipReportName: []byte(`{"version":"2"}`)}}}
			}
		}, CategoryManual, ReasonOutputFilesInvalid},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, "pip")
			c.setup(h)
			it, _ := h.run()
			wantCategory(t, it, c.cat, c.reason)
			if len(it.Artifacts) != 0 {
				t.Error("artifacts kept")
			}
		})
	}
	t.Run("a new dependency of the updated package is explained", func(t *testing.T) {
		h := newHarness(t, "pip")
		useUnhashed(t, h)
		h.pypi.requires = map[string][]string{"urllib3==1.26.17": {"extra-dep>=1; python_version >= '3'"}}
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			if n == 0 {
				return fakeOutcome{edit: map[string]map[string][]byte{stepBaseline: {worker.PipReportName: pipReportJSON([2]string{"urllib3", "1.26.4"})}}}
			}
			rep := pipReportItems(
				pipItem{name: "urllib3", ver: "1.26.17", requires: []string{"extra-dep>=1; python_version >= '3'"}},
				pipItem{name: "extra-dep", ver: "1.0", notReq: true})
			return fakeOutcome{edit: map[string]map[string][]byte{stepCheck: {worker.PipReportName: rep}}}
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if len(it.Update.Diff.Added) != 1 || it.Update.Diff.Added[0] != "extra-dep" {
			t.Errorf("diff = %+v", it.Update.Diff)
		}
	})
	t.Run("a package pip no longer needs is explained", func(t *testing.T) {
		h := newHarness(t, "pip")
		useUnhashed(t, h)
		h.pypi.requires = map[string][]string{"urllib3==1.26.4": {"old-dep"}}
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			if n == 0 {
				rep := pipReportItems(pipItem{name: "urllib3", ver: "1.26.4", requires: []string{"old-dep"}}, pipItem{name: "old-dep", ver: "1.0", notReq: true})
				return fakeOutcome{edit: map[string]map[string][]byte{stepBaseline: {worker.PipReportName: rep}}}
			}
			return fakeOutcome{edit: map[string]map[string][]byte{stepCheck: {worker.PipReportName: pipReportJSON([2]string{"urllib3", "1.26.17"})}}}
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if len(it.Update.Diff.Removed) != 1 || it.Update.Diff.Removed[0] != "old-dep" {
			t.Errorf("diff = %+v", it.Update.Diff)
		}
	})
	t.Run("deadline during the lookup defers", func(t *testing.T) {
		h := newHarness(t, "pip")
		ctx, cancel := context.WithCancel(context.Background())
		h.cfg.PyPI = pypiFunc(func(ctx context.Context, name, version string) (PyPIRelease, error) {
			cancel()
			return PyPIRelease{}, ctx.Err()
		})
		it, _ := h.runCtx(ctx)
		wantCategory(t, it, CategoryDeferred, ReasonCycleDeadline)
	})
}

type pypiFunc func(ctx context.Context, name, version string) (PyPIRelease, error)

func (f pypiFunc) Release(ctx context.Context, name, version string) (PyPIRelease, error) {
	return f(ctx, name, version)
}

func TestPyPIClient(t *testing.T) {
	doc := func(name, version string, urls string) string {
		return fmt.Sprintf(`{"info":{"name":%q,"version":%q},"urls":[%s]}`, name, version, urls)
	}
	wheel := `{"filename":"urllib3-1.26.17-py2.py3-none-any.whl","url":"https://files.pythonhosted.org/w.whl","packagetype":"bdist_wheel","yanked":false,"digests":{"sha256":"` + h64('a') + `"}}`
	sdist := `{"filename":"urllib3-1.26.17.tar.gz","url":"https://files.pythonhosted.org/s.tar.gz","packagetype":"sdist","yanked":false,"digests":{"sha256":"` + h64('b') + `"}}`
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		switch r.URL.Path {
		case "/pypi/urllib3/1.26.17/json":
			fmt.Fprint(w, doc("urllib3", "1.26.17", wheel+","+sdist))
		case "/pypi/other/1.0/json":
			fmt.Fprint(w, doc("urllib3", "1.26.17", wheel))
		case "/pypi/bad-digest/1.0/json":
			fmt.Fprint(w, doc("bad-digest", "1.0", `{"filename":"x.whl","url":"https://x/x.whl","packagetype":"bdist_wheel","digests":{"sha256":"zz"}}`))
		case "/pypi/bad-wheel/1.0/json":
			fmt.Fprint(w, doc("bad-wheel", "1.0", `{"filename":"x.tar.gz","url":"https://x/x","packagetype":"bdist_wheel","digests":{"sha256":"`+h64('a')+`"}}`))
		case "/pypi/broken/1.0/json":
			fmt.Fprint(w, "{")
		case "/pypi/huge/1.0/json":
			w.Write([]byte(strings.Repeat(" ", maxPyPIBody+10)))
		case "/pypi/boom/1.0/json":
			w.WriteHeader(500)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := &PyPIClient{BaseURL: srv.URL}
	ctx := context.Background()

	rel, err := c.Release(ctx, "urllib3", "1.26.17")
	files := rel.Files
	if err != nil || len(files) != 2 || !files[0].Wheel || files[1].Wheel || files[0].SHA256 != h64('a') || files[0].URL != "https://files.pythonhosted.org/w.whl" {
		t.Fatalf("files = %+v, err = %v", files, err)
	}
	hs, yanked := wheelHashes(files)
	if len(hs) != 1 || hs[0] != h64('a') || yanked {
		t.Errorf("hashes = %v yanked = %v", hs, yanked)
	}
	if _, err := c.Release(ctx, "Urllib3", "1.26.17"); err != nil || gotPath != "/pypi/urllib3/1.26.17/json" {
		t.Errorf("name is not normalized in the request: %q %v", gotPath, err)
	}
	if _, err := c.Release(ctx, "urllib3", "9.9.9"); !errors.Is(err, ErrReleaseNotFound) {
		t.Errorf("not found = %v", err)
	}
	for _, n := range []string{"other", "bad-digest", "bad-wheel", "broken", "huge", "boom"} {
		if _, err := c.Release(ctx, n, "1.0"); err == nil || errors.Is(err, ErrReleaseNotFound) {
			t.Errorf("%s: err = %v", n, err)
		}
	}
	for _, bad := range [][2]string{{"-x", "1.0"}, {"x", "1.0; rm"}, {"x", ""}, {"", "1.0"}, {"a/b", "1.0"}} {
		if _, err := c.Release(ctx, bad[0], bad[1]); err == nil {
			t.Errorf("%v: no error", bad)
		}
	}
}

// useUnhashed makes the pip fixture a requirements file without hashes.
func useUnhashed(t *testing.T, h *harness) {
	t.Helper()
	h.files["requirements.txt"] = "urllib3==1.26.4\n"
	h.item = itemFor(t, ManagerPip, h.files, urllibGroup())
	h.gh = ghFor(h.files)
	h.cfg.GitHub = h.gh
}

// checkReport has the check step return the correct report changed by edit.
func (h *harness) checkReport(edit func(string) string) {
	h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		o := h.okScript(n, job, src)
		if n == 1 {
			o.edit = map[string]map[string][]byte{stepCheck: {worker.PipReportName: []byte(edit(string(pipReportJSON(h.fx.afterPkgs...))))}}
		}
		return o
	}
}

func TestNpmClient(t *testing.T) {
	var gotPath, gotRaw string
	slow := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotRaw = r.URL.Path, r.URL.EscapedPath()
		doc := func(name, ver, dist string) { fmt.Fprintf(w, `{"name":%q,"version":%q,"dist":%s}`, name, ver, dist) }
		good := `{"tarball":"https://registry.npmjs.org/x/-/x-1.0.0.tgz","integrity":"sha512-abc"}`
		switch r.URL.EscapedPath() {
		case "/minimist/1.2.8":
			doc("minimist", "1.2.8", good)
		case "/@s%2Fpkg/1.0.0":
			doc("@s/pkg", "1.0.0", good)
		case "/other/1.0.0":
			doc("minimist", "1.2.8", good)
		case "/noint/1.0.0":
			doc("noint", "1.0.0", `{"tarball":"https://registry.npmjs.org/x.tgz"}`)
		case "/broken/1.0.0":
			fmt.Fprint(w, "{")
		case "/huge/1.0.0":
			w.Write([]byte(strings.Repeat(" ", maxNpmBody+10)))
		case "/boom/1.0.0":
			w.WriteHeader(500)
		case "/slow/1.0.0":
			<-slow
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	defer close(slow)
	c := &NpmClient{BaseURL: srv.URL, HTTP: &http.Client{}}
	ctx := context.Background()

	d, err := c.VersionDist(ctx, "minimist", "1.2.8")
	if err != nil || d.Integrity != "sha512-abc" || d.Tarball != "https://registry.npmjs.org/x/-/x-1.0.0.tgz" {
		t.Fatalf("%+v %v", d, err)
	}
	if _, err := c.VersionDist(ctx, "@s/pkg", "1.0.0"); err != nil || gotRaw != "/@s%2Fpkg/1.0.0" {
		t.Errorf("scoped name: %v, path %q (%q)", err, gotRaw, gotPath)
	}
	if _, err := c.VersionDist(ctx, "minimist", "9.9.9"); !errors.Is(err, ErrReleaseNotFound) {
		t.Errorf("not found = %v", err)
	}
	for _, n := range []string{"other", "noint", "broken", "huge", "boom"} {
		if _, err := c.VersionDist(ctx, n, "1.0.0"); err == nil || errors.Is(err, ErrReleaseNotFound) {
			t.Errorf("%s: err = %v", n, err)
		}
	}
	for _, bad := range [][2]string{{"-x", "1.0.0"}, {"X", "1.0.0"}, {"a/b", "1.0.0"}, {"x", "1.0"}, {"x", "^1.0.0"}, {"", "1.0.0"}, {"x", ""}} {
		if _, err := c.VersionDist(ctx, bad[0], bad[1]); err == nil {
			t.Errorf("%v: no error", bad)
		}
	}
	// A client without a timeout is given one; a slow server does not hold the
	// request past the caller's deadline.
	cctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if _, err := c.VersionDist(cctx, "slow", "1.0.0"); err == nil {
		t.Error("a slow server was waited for")
	}
	short := &NpmClient{BaseURL: srv.URL, HTTP: &http.Client{Timeout: 50 * time.Millisecond}}
	if _, err := short.VersionDist(ctx, "slow", "1.0.0"); err == nil {
		t.Error("the client's own timeout was ignored")
	}
}
