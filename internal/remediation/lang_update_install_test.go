package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// editNpmEntry changes the entry of a package in a package-lock.json.
func editNpmEntry(t *testing.T, lock, path string, edit func(entry map[string]any)) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(lock), &doc); err != nil {
		t.Fatal(err)
	}
	pk := doc["packages"].(map[string]any)
	e, ok := pk[path].(map[string]any)
	if !ok {
		t.Fatalf("no entry %s", path)
	}
	edit(e)
	b, _ := json.MarshalIndent(doc, "", "  ")
	return string(b)
}

// --- the two representations of a lockfileVersion 2 file ---

func TestEveryLegacyEntryMustAgreeWithPackages(t *testing.T) {
	setup := func(t *testing.T, edit func(map[string]map[string]any)) *harness {
		h := newHarness(t, "npm")
		h.files["package-lock.json"] = npmV2(t, h.files["package-lock.json"], nil)
		h.gh = ghFor(h.files)
		h.cfg.GitHub = h.gh
		h.item = itemFor(t, ManagerNpm, h.files, minimistGroup())
		h.editLock(npmV2(t, string(h.after), edit))
		return h
	}
	other := "https://registry.npmjs.org/mkdirp/-/mkdirp-0.5.6.tgz"
	cases := map[string]func(map[string]map[string]any){
		"another canonical tarball for a package the update did not touch": func(l map[string]map[string]any) { l["mkdirp"]["resolved"] = other },
		"another integrity for such a package": func(l map[string]map[string]any) {
			l["mkdirp"]["integrity"] = "sha512-" + strings.Repeat("A", 86) + "=="
		},
		"another version for such a package":   func(l map[string]map[string]any) { l["mkdirp"]["version"] = "0.5.6" },
		"such a package missing from the tree": func(l map[string]map[string]any) { delete(l, "mkdirp") },
		"a node that packages does not have": func(l map[string]map[string]any) {
			l["extra"] = map[string]any{"version": "1.0.0", "resolved": other, "integrity": "sha512-x"}
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			it, _ := setup(t, edit).run()
			wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
			if !strings.Contains(it.Detail, "legacy") {
				t.Errorf("detail = %q", it.Detail)
			}
		})
	}
	t.Run("the nodes' names and paths are bounded", func(t *testing.T) {
		it, _ := setup(t, func(l map[string]map[string]any) {
			l[strings.Repeat("n", maxNpmNameBytes+1)] = map[string]any{"version": "1.0.0"}
		}).run()
		wantCategory(t, it, CategoryManual, ReasonOutputFilesInvalid)
	})
	t.Run("the total length of the paths is bounded", func(t *testing.T) {
		old := maxLegacyPathSum
		maxLegacyPathSum = 30
		defer func() { maxLegacyPathSum = old }()
		it, _ := setup(t, nil).run()
		wantCategory(t, it, CategoryManual, ReasonOutputFilesInvalid)
	})
}

// --- uv: the environment of the image ---

func TestUvPythonOfTheImageIsChecked(t *testing.T) {
	t.Run("a wheel whose requires-python excludes the image's Python", func(t *testing.T) {
		h := newHarness(t, "uv")
		rel := h.pypi.releases["urllib3==1.26.17"]
		for i := range rel {
			rel[i].RequiresPython = ">=3.8,!=3.12.*" // fine for the project's lowest Python 3.9
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonRequiresPythonUnsupported)
	})
	t.Run("a requires-python that depends on the patch level", func(t *testing.T) {
		h := newHarness(t, "uv")
		rel := h.pypi.releases["urllib3==1.26.17"]
		for i := range rel {
			rel[i].RequiresPython = ">=3.9,!=3.12.1"
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonRequiresPythonUnsupported)
	})
	t.Run("an image whose Python is not known", func(t *testing.T) {
		h := newHarness(t, "uv")
		h.item.Packages[0].Origins[0].PkgPath, h.item.Packages[0].Origins[0].Target = "usr/lib/python3/dist-packages/x", "Python"
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonPipTargetUndecidable)
	})
	t.Run("an image whose operating system is not known", func(t *testing.T) {
		h := newHarness(t, "uv")
		h.cfg.Images = map[string]ImageEnv{"img": {Platform: debianAmd64.Platform, OSFamily: "fedora", OSName: "40"}}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonPipTargetUndecidable)
	})
}

func TestUvNeedsAWheelThatFitsTheImage(t *testing.T) {
	wheelURL := "https://files.pythonhosted.org/packages/48/fe/a5c6cc46e9fe9171d7ecf0f33ee7aae14642f8d74baa7af4d7840f9358be/urllib3-1.26.17-py2.py3-none-any.whl"
	rename := func(h *harness, file string) {
		url := strings.Replace(wheelURL, "urllib3-1.26.17-py2.py3-none-any.whl", file, 1)
		h.editLock(strings.Replace(string(h.after), wheelURL, url, 1))
		h.pypi.releases["urllib3==1.26.17"] = append(h.pypi.releases["urllib3==1.26.17"], PyPIFile{Filename: file, URL: url, Wheel: true, SHA256: urllibWheelSHA})
	}
	t.Run("only a Windows wheel is left", func(t *testing.T) {
		h := newHarness(t, "uv")
		rename(h, "urllib3-1.26.17-cp312-cp312-win_amd64.whl")
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
		if !strings.Contains(it.Detail, "fits the image") {
			t.Errorf("detail = %q", it.Detail)
		}
	})
	t.Run("only a wheel for another interpreter", func(t *testing.T) {
		h := newHarness(t, "uv")
		rename(h, "urllib3-1.26.17-cp311-cp311-manylinux_2_17_x86_64.whl")
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("a glibc wheel on a musl image", func(t *testing.T) {
		h := newHarness(t, "uv")
		rename(h, "urllib3-1.26.17-cp312-cp312-manylinux_2_17_x86_64.whl")
		h.cfg.Images = map[string]ImageEnv{"img": {Platform: debianAmd64.Platform, OSFamily: "alpine", OSName: "3.19.1"}}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("the same wheel on a glibc image", func(t *testing.T) {
		h := newHarness(t, "uv")
		rename(h, "urllib3-1.26.17-cp312-cp312-manylinux_2_17_x86_64.whl")
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("a source distribution alone", func(t *testing.T) {
		h := newHarness(t, "uv")
		h.editLock(cutUvWheels(string(h.after)))
		it, _ := h.run()
		if it.Category != CategoryManual {
			t.Fatalf("%s/%s", it.Category, it.Reason)
		}
	})
}

// cutUvWheels removes the wheels list of every package.
func cutUvWheels(s string) string {
	var out []string
	skip := false
	for _, l := range strings.Split(s, "\n") {
		switch {
		case strings.HasPrefix(l, "wheels = ["):
			skip = true
		case skip && l == "]":
			skip = false
		case skip:
		default:
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// --- uv: the types of the records ---

func TestUvRecordsOfTheWrongTypeAreRefused(t *testing.T) {
	uv := readTestdata(t, "uv", "pyproject.toml", "uv.lock")
	sdistLine := func(s string) string {
		for _, l := range strings.Split(s, "\n") {
			if strings.HasPrefix(l, "sdist = ") {
				return l
			}
		}
		return ""
	}
	cases := map[string]func(string) string{
		"sdist that is a string":         func(s string) string { return strings.Replace(s, sdistLine(s), `sdist = "invalid"`, 1) },
		"sdist with a negative size":     func(s string) string { return strings.Replace(s, "size = 293008", "size = -1", 1) },
		"sdist with a size that is text": func(s string) string { return strings.Replace(s, "size = 293008", `size = "big"`, 1) },
		"sdist with an unknown member":   func(s string) string { return strings.Replace(s, ", size = 293008", ", size = 293008, evil = 1", 1) },
		"sdist without a url":            func(s string) string { return strings.Replace(s, "sdist = { url = ", "sdist = { Url = ", 1) },
		"wheels that is a string":        func(s string) string { return strings.Replace(s, "wheels = [", `wheels = "x"`+"\nignored = [", 1) },
		"a wheel with a negative size":   func(s string) string { return strings.Replace(s, "size = 153320", "size = -5", 1) },
		"a wheel with an unknown member": func(s string) string {
			return strings.Replace(s, ", size = 153320", ", size = 153320, extra = true", 1)
		},
		"an upload time that is a number": func(s string) string {
			return strings.Replace(s, `upload-time = "2021-03-15T15:04:35.709Z"`, "upload-time = 5", 1)
		},
		"a dependency that is a string": func(s string) string {
			return strings.Replace(s, "dependencies = [\n    { name = \"urllib3\" },\n]", `dependencies = "urllib3"`, 1)
		},
		"a dependency with an unknown member": func(s string) string {
			return strings.Replace(s, `{ name = "urllib3" },`, `{ name = "urllib3", evil = 1 },`, 1)
		},
		"a dependency marker that is a number": func(s string) string {
			return strings.Replace(s, `{ name = "urllib3" },`, `{ name = "urllib3", marker = 1 },`, 1)
		},
	}
	for name, edit := range cases {
		forged := edit(uv["uv.lock"])
		if forged == uv["uv.lock"] {
			t.Errorf("%s: the edit changed nothing", name)
			continue
		}
		if _, err := uvGraph(bg, []byte(forged)); err == nil {
			t.Errorf("%s: accepted by the graph", name)
		}
		if _, err := parseUv([]byte(uv["pyproject.toml"]), []byte(forged)); err == nil {
			t.Errorf("%s: accepted by the plan's parser", name)
		}
	}
	// An honest file passes both.
	if _, err := uvGraph(bg, []byte(uv["uv.lock"])); err != nil {
		t.Errorf("graph: %v", err)
	}
	if _, err := parseUv([]byte(uv["pyproject.toml"]), []byte(uv["uv.lock"])); err != nil {
		t.Errorf("parser: %v", err)
	}
}

// --- the fields that decide whether and how an entry is installed ---

func TestNpmInstallFieldsMustSayWhatTheRegistrySays(t *testing.T) {
	registry := func(install map[string]string) *harness {
		h := newHarness(t, "npm")
		d := h.npm.dists["minimist@1.2.8"]
		d.Install = install
		h.npm.dists["minimist@1.2.8"] = d
		return h
	}
	forge := func(h *harness, edit func(map[string]any)) {
		h.editLock(editNpmEntry(t, string(h.after), "node_modules/minimist", edit))
	}
	cases := []struct {
		name string
		edit func(map[string]any)
	}{
		{"a platform restriction the registry lacks", func(e map[string]any) { e["os"] = []any{"win32"} }},
		{"a cpu restriction", func(e map[string]any) { e["cpu"] = []any{"arm"} }},
		{"a libc restriction", func(e map[string]any) { e["libc"] = []any{"musl"} }},
		{"engines", func(e map[string]any) { e["engines"] = map[string]any{"node": ">=99"} }},
		{"a command", func(e map[string]any) { e["bin"] = map[string]any{"minimist": "evil.js"} }},
		{"an optional peer", func(e map[string]any) {
			e["peerDependenciesMeta"] = map[string]any{"x": map[string]any{"optional": true}}
		}},
		{"extraneous", func(e map[string]any) { e["extraneous"] = true }},
		{"development only", func(e map[string]any) { e["dev"] = true }},
		{"optional only", func(e map[string]any) { e["optional"] = true }},
		{"development or optional", func(e map[string]any) { e["devOptional"] = true }},
		{"a member nobody knows", func(e map[string]any) { e["evil"] = 1 }},
		{"a member that is a patch record", func(e map[string]any) { e["patched"] = true }},
		{"a member that is an extension record", func(e map[string]any) { e["npmExtensionApplied"] = true }},
		{"os that is not a list", func(e map[string]any) { e["os"] = "linux" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := registry(nil)
			forge(h, c.edit)
			it, _ := h.run()
			wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
		})
	}
	t.Run("what the registry says is accepted", func(t *testing.T) {
		h := registry(map[string]string{"os": `["darwin","linux"]`, "cpu": `["arm64","x64"]`, "libc": `["glibc"]`, "engines": `{"node":">=10"}`, "bin": `{"minimist":"bin/min.js"}`})
		forge(h, func(e map[string]any) {
			e["os"], e["cpu"], e["libc"] = []any{"linux", "darwin", "linux"}, []any{"x64", "arm64"}, []any{"glibc"}
			e["engines"] = map[string]any{"node": ">=10"}
			e["bin"] = map[string]any{"minimist": "./bin/min.js"}
		})
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("a command given as a bare string is the package's own", func(t *testing.T) {
		h := registry(map[string]string{"bin": `{"minimist":"cli.js"}`})
		forge(h, func(e map[string]any) { e["bin"] = "cli.js" })
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("the flags of a development dependency", func(t *testing.T) {
		root := map[string]string{"a": "^1.0.0"}
		before := map[string]npmEntry{"node_modules/a": {ver: "1.0.0", deps: map[string]string{"t": "^1.0.0"}}, "node_modules/t": {ver: "1.0.0"}}
		after := map[string]npmEntry{"node_modules/a": before["node_modules/a"], "node_modules/t": {ver: "1.0.5"}}
		h := newNpmCase(t, root, before, after)
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		// t is needed in production; recording it as development-only keeps it out of a production install.
		h = newNpmCase(t, root, before, after)
		h.editLock(editNpmEntry(t, string(h.after), "node_modules/t", func(e map[string]any) { e["dev"] = true }))
		it, _ = h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
		if !strings.Contains(it.Detail, "dev") {
			t.Errorf("detail = %q", it.Detail)
		}
	})
}

func TestPnpmInstallFieldsMustSayWhatTheRegistrySays(t *testing.T) {
	pkgLine := "  minimist@1.2.8:\n    resolution: {integrity: " + minimist128.Integrity + "}"
	forge := func(extra string) *harness {
		h := newHarness(t, "pnpm")
		forged := strings.Replace(string(h.after), pkgLine, pkgLine+"\n"+extra, 1)
		if forged == string(h.after) {
			t.Fatal("the forgery changed nothing")
		}
		h.editLock(forged)
		return h
	}
	for name, extra := range map[string]string{
		"a platform restriction": "    os: [win32]",
		"a cpu restriction":      "    cpu: [arm]",
		"a libc restriction":     "    libc: [musl]",
		"engines":                "    engines: {node: '>=99'}",
		"a command":              "    hasBin: true",
		"a bundled dependency":   "    bundledDependencies: [x]",
		"an optional peer":       "    peerDependenciesMeta:\n      x:\n        optional: true",
		"a build record":         "    prepare: true",
		"an id":                  "    id: https://example.com/x.tgz",
		"another name":           "    name: other",
		"a patch":                "    patched: true",
		"a member nobody knows":  "    evil: 1",
	} {
		t.Run(name, func(t *testing.T) {
			it, _ := forge(extra).run()
			if it.Category != CategoryManual || (it.Reason != ReasonDistributionMismatch && it.Reason != ReasonResolvedSourceChanged) {
				t.Fatalf("%s/%s (%s)", it.Category, it.Reason, it.Detail)
			}
		})
	}
	t.Run("a resolution member besides the integrity", func(t *testing.T) {
		h := newHarness(t, "pnpm")
		h.editLock(strings.Replace(string(h.after), "resolution: {integrity: "+minimist128.Integrity+"}", "resolution: {integrity: "+minimist128.Integrity+", revision: 3}", 1))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("a snapshot member nobody knows", func(t *testing.T) {
		h := newHarness(t, "pnpm")
		h.editLock(strings.Replace(string(h.after), "  minimist@1.2.8: {}", "  minimist@1.2.8:\n    evil: 1", 1))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("the optional flag follows the graph", func(t *testing.T) {
		h := newHarness(t, "pnpm")
		h.editLock(strings.Replace(string(h.after), "  minimist@1.2.8: {}", "  minimist@1.2.8:\n    optional: true", 1))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("what the registry says is accepted", func(t *testing.T) {
		h := forge("    os: [linux, darwin]\n    engines: {node: '>=10'}\n    hasBin: true")
		d := h.npm.dists["minimist@1.2.8"]
		d.Install = map[string]string{"os": `["darwin","linux"]`, "engines": `{"node":">=10"}`, "bin": `{"minimist":"bin/m.js"}`}
		h.npm.dists["minimist@1.2.8"] = d
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
}

func TestUvPackageMembersNobodyKnowsAreRefused(t *testing.T) {
	for name, edit := range map[string]func(string) string{
		"a member of the package": func(s string) string {
			return strings.Replace(s, "[[package]]\nname = \"urllib3\"\nversion = \"1.26.17\"\n", "[[package]]\nname = \"urllib3\"\nversion = \"1.26.17\"\nevil = 1\n", 1)
		},
		"a source that is not the registry": func(s string) string {
			return strings.Replace(s, `source = { registry = "https://pypi.org/simple" }`+"\nsdist", `source = { registry = "https://pypi.org/simple", git = "https://example.com/x" }`+"\nsdist", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "uv")
			forged := edit(string(h.after))
			if forged == string(h.after) {
				t.Fatal("no change")
			}
			h.editLock(forged)
			it, _ := h.run()
			if it.Category != CategoryManual {
				t.Fatalf("%s/%s", it.Category, it.Reason)
			}
		})
	}
}

// --- how the result is read and how big it may be ---

func TestResultJSONIsReadStrictly(t *testing.T) {
	edit := func(f func(res map[string]any)) func(map[string][]byte) {
		return func(files map[string][]byte) {
			var res map[string]any
			_ = json.Unmarshal(files["result.json"], &res)
			f(res)
			files["result.json"], _ = json.Marshal(res)
		}
	}
	steps := func(res map[string]any) []any { return res["steps"].([]any) }
	step := func(res map[string]any, i int) map[string]any { return steps(res)[i].(map[string]any) }
	cases := map[string]func(map[string][]byte){
		"exit_code missing":            edit(func(r map[string]any) { delete(step(r, 1), "exit_code") }),
		"exit_code null":               edit(func(r map[string]any) { step(r, 1)["exit_code"] = nil }),
		"exit_code a string":           edit(func(r map[string]any) { step(r, 1)["exit_code"] = "0" }),
		"argv missing":                 edit(func(r map[string]any) { delete(step(r, 1), "argv") }),
		"argv null":                    edit(func(r map[string]any) { step(r, 1)["argv"] = nil }),
		"id missing":                   edit(func(r map[string]any) { delete(step(r, 1), "id") }),
		"op missing":                   edit(func(r map[string]any) { delete(step(r, 1), "op") }),
		"duration missing":             edit(func(r map[string]any) { delete(step(r, 1), "duration_ms") }),
		"status missing":               edit(func(r map[string]any) { delete(r, "status") }),
		"protocol missing":             edit(func(r map[string]any) { delete(r, "protocol") }),
		"steps missing":                edit(func(r map[string]any) { delete(r, "steps") }),
		"steps null":                   edit(func(r map[string]any) { r["steps"] = nil }),
		"an output without a hash":     edit(func(r map[string]any) { delete(step(r, 1)["outputs"].([]any)[0].(map[string]any), "sha256") }),
		"a step that is not an object": edit(func(r map[string]any) { steps(r)[1] = "x" }),
		"a key in two spellings": func(files map[string][]byte) {
			files["result.json"] = []byte(strings.Replace(string(files["result.json"]), `"status": "completed"`, `"status": "step_failed", "Status": "completed"`, 1))
		},
		"a repeated key": func(files map[string][]byte) {
			files["result.json"] = []byte(strings.Replace(string(files["result.json"]), `"exit_code": 0`, `"exit_code": 1, "exit_code": 0`, 1))
		},
		"an upper-case exit code over the real one": func(files map[string][]byte) {
			files["result.json"] = []byte(strings.Replace(string(files["result.json"]), `"exit_code": 0`, `"exit_code": 7, "EXIT_CODE": 0`, 1))
		},
	}
	for name, mangle := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "npm")
			h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
				o := h.okScript(n, job, src)
				o.mangle = mangle
				return o
			}
			it, _ := h.run()
			wantCategory(t, it, CategoryFailed, ReasonUpdateResultInvalid)
		})
	}
	t.Run("argv is compared element by element", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			o := h.okScript(n, job, src)
			o.mangleResult = func(r *worker.Result) {
				a := r.Steps[1].Argv
				// Two elements run together with a NUL between them.
				r.Steps[1].Argv = append([]string{a[0] + "\x00" + a[1]}, a[2:]...)
			}
			return o
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryFailed, ReasonUpdateResultInvalid)
	})
	t.Run("a result that is over the size the format allows", func(t *testing.T) {
		if _, err := parseResultJSON(make([]byte, worker.MaxResultBytes+1)); err == nil {
			t.Error("accepted")
		}
	})
}

func TestReturnedFilesAreBoundedBySizeOfWhatWasSent(t *testing.T) {
	pad := func(n int) func(e map[string]any) {
		return func(e map[string]any) { e["license"] = strings.Repeat("x", n) }
	}
	t.Run("a lockfile a little larger is fine", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.editLock(editNpmEntry(t, string(h.after), "node_modules/minimist", pad(200<<10)))
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("a lockfile much larger is refused before it is read", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.editLock(editNpmEntry(t, string(h.after), "node_modules/minimist", pad(2<<20)))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonOutputFilesInvalid)
		if !strings.Contains(it.Detail, "bytes") {
			t.Errorf("detail = %q", it.Detail)
		}
	})
	t.Run("the same for the copies the steps return", func(t *testing.T) {
		h := newHarness(t, "npm")
		big := []byte(strings.Repeat("x", 2<<20))
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			return fakeOutcome{edit: map[string]map[string][]byte{stepBaseline: {"package-lock.json": big}, stepUpdate: {"package-lock.json": h.after}}}
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonOutputFilesInvalid)
	})
	t.Run("a pip report grows with the lines of the requirements", func(t *testing.T) {
		h := newHarness(t, "pip")
		useUnhashed(t, h)
		huge := []byte(strings.Repeat(" ", reportBase+reportPerLine*2+1))
		h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			return fakeOutcome{edit: map[string]map[string][]byte{stepBaseline: {worker.PipReportName: huge}}}
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonOutputFilesInvalid)
	})
}

func TestPnpmLockWithASecondYAMLDocumentIsRefused(t *testing.T) {
	pnpm := readTestdata(t, "pnpm", "package.json", "pnpm-lock.yaml")
	lock := pnpm["pnpm-lock.yaml"]
	for name, text := range map[string]string{
		"a second document":              lock + "\n---\nlockfileVersion: '9.0'\nimporters: {}\n",
		"a syntax error after the first": lock + "\n---\n: : [\n",
		"an empty second document":       lock + "\n---\n",
		"a document end marker and more": lock + "\n...\n---\nx: 1\n",
	} {
		if _, err := readPnpmLock([]byte(text)); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := parsePnpm([]byte(pnpm["package.json"]), []byte(text)); err == nil {
			t.Errorf("%s: the plan's parser accepted it", name)
		}
		if _, err := pnpmGraph(bg, []byte(text)); err == nil {
			t.Errorf("%s: the graph accepted it", name)
		}
	}
	if _, err := readPnpmLock([]byte("---\n" + lock)); err != nil {
		t.Errorf("a document start marker: %v", err)
	}
	h := newHarness(t, "pnpm")
	h.editLock(string(h.after) + "\n---\nlockfileVersion: '9.0'\n")
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonOutputFilesInvalid)
}

func TestPnpmYAMLIsBoundedAndReadInLinearTime(t *testing.T) {
	build := func(n int) string {
		var b strings.Builder
		b.WriteString("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies: {}\npackages:\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "  p%d@1.0.0:\n    resolution: {integrity: sha512-x}\n", i)
		}
		b.WriteString("snapshots:\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "  p%d@1.0.0: {}\n", i)
		}
		return b.String()
	}
	text := build(60000)
	if len(text) > maxYAMLBytes {
		t.Fatalf("the test file is %d bytes", len(text))
	}
	start := time.Now()
	doc, err := readPnpmLock([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(gmap(doc.top["packages"])); got != 60000 {
		t.Errorf("%d packages", got)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("reading %d keys took %s", 60000, d)
	}
	for name, text := range map[string]string{
		"anchors":        "lockfileVersion: '9.0'\nimporters: &a {}\n",
		"aliases":        "lockfileVersion: '9.0'\nx: &a 1\ny: *a\n",
		"merge keys":     "lockfileVersion: '9.0'\nx: &a {a: 1}\ny:\n  <<: *a\n",
		"nesting":        "a: " + strings.Repeat("[", maxYAMLDepth+2) + strings.Repeat("]", maxYAMLDepth+2) + "\n",
		"a repeated key": "lockfileVersion: '9.0'\nimporters: {}\nimporters: {}\n",
		"a complex key":  "? [a]\n: 1\n",
	} {
		if _, err := readPnpmLock([]byte(text)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := readPnpmLock(make([]byte, maxYAMLBytes+1)); err == nil {
		t.Error("a file over the size bound was accepted")
	}
}

func TestSnapshotsShareTheMetadataOfTheirPackage(t *testing.T) {
	var b strings.Builder
	b.WriteString("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: 1.0.0\n        version: 1.0.0\npackages:\n  a@1.0.0:\n    resolution: {integrity: sha512-x}\n    engines: {node: '")
	b.WriteString(strings.Repeat("9", 1<<20))
	b.WriteString("'}\nsnapshots:\n")
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&b, "  a@1.0.0(peer@%d.0.0): {}\n", i)
	}
	b.WriteString("  a@1.0.0: {}\n")
	start := time.Now()
	g, err := pnpmGraph(bg, []byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %s", d)
	}
	for k, n := range g.nodes {
		if len(n.attrs) > 400 {
			t.Fatalf("%s carries %d bytes of attributes", k, len(n.attrs))
		}
	}
	old := maxAttrBytes
	maxAttrBytes = 1000
	defer func() { maxAttrBytes = old }()
	if _, err := pnpmGraph(bg, []byte(b.String())); err == nil || !strings.Contains(err.Error(), "attributes") {
		t.Errorf("err = %v", err)
	}
}

func TestPnpmPeerContextSnapshotsAreMatchedToTheirPackage(t *testing.T) {
	lock := `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a:
        specifier: 1.0.0
        version: 1.0.0(peer@2.0.0)
packages:
  a@1.0.0:
    resolution: {integrity: sha512-x}
  peer@2.0.0:
    resolution: {integrity: sha512-y}
snapshots:
  a@1.0.0(peer@2.0.0):
    dependencies:
      peer: 2.0.0
  peer@2.0.0: {}
`
	g, err := pnpmGraph(bg, []byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	if len(g.nodes) != 2 || g.roots[0].key != "a@1.0.0(peer@2.0.0)" {
		t.Errorf("nodes %v roots %+v", len(g.nodes), g.roots)
	}
	if _, err := pnpmGraph(bg, []byte(strings.Replace(lock, "snapshots:\n  a@1.0.0(peer@2.0.0):\n    dependencies:\n      peer: 2.0.0\n", "snapshots:\n", 1))); err == nil {
		t.Error("a package without any snapshot was accepted")
	}
}

// --- the TOML reader ---

func TestTOMLLongNamesAreNotCopiedForEveryKey(t *testing.T) {
	name := strings.Repeat("n", 1000)
	var b strings.Builder
	fmt.Fprintf(&b, "[%s]\n", name)
	for i := 0; i < 150000; i++ {
		fmt.Fprintf(&b, "k.x%d = 1\n", i)
	}
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	start := time.Now()
	doc, err := parseTOML([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&m1)
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %s", d)
	}
	if grew := m1.TotalAlloc - m0.TotalAlloc; grew > 400<<20 {
		t.Errorf("parsing allocated %d MiB", grew>>20)
	}
	if len(doc[name].(map[string]any)["k"].(map[string]any)) != 150000 {
		t.Error("the keys were not all kept")
	}
	if _, err := parseTOML([]byte("[" + strings.Repeat("n", maxTOMLKeyBytes+1) + "]\nx = 1\n")); err == nil {
		t.Error("a table name over the bound was accepted")
	}
	if _, err := parseTOML([]byte(strings.Repeat("n", maxTOMLKeyBytes+1) + " = 1\n")); err == nil {
		t.Error("a key over the bound was accepted")
	}
	// The rules about defining a table twice still hold.
	for name, text := range map[string]string{
		"header twice":           "[a]\nx = 1\n[a]\ny = 2\n",
		"header after dotted":    "a.b = 1\n[a]\nc = 2\n",
		"dotted into a header":   "[a]\nx = 1\n[b]\n[a.c]\nd = 1\n[a]\n",
		"key set twice":          "a = 1\na = 2\n",
		"extend an inline table": "a = {b = 1}\n[a]\nc = 2\n",
	} {
		if _, err := parseTOML([]byte(text)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := parseTOML([]byte("[a.b]\nx = 1\n[a]\ny = 2\n[[c]]\nz = 1\n[[c]]\nz = 2\n[c.d]\nq = 1\n")); err != nil {
		t.Errorf("a valid document: %v", err)
	}
}

// --- adopted versions ---

func TestManyOccurrencesOfAnUpdatedPackageAreCheckedInLinearTime(t *testing.T) {
	pkgs := map[string]any{"": map[string]any{}}
	for i := 0; i < 20000; i++ {
		pkgs[fmt.Sprintf("node_modules/p%d/node_modules/t", i)] = map[string]any{"version": "1.0.5", "resolved": npmURL("t", "1.0.5"), "integrity": "sha512-t1.0.5"}
	}
	lock, _ := json.Marshal(map[string]any{"lockfileVersion": 3, "packages": pkgs})
	lf, err := parseNpm([]byte(`{"name":"a"}`), lock)
	if err != nil {
		t.Fatal(err)
	}
	r := &updateRun{
		it:  &LanguageItem{Manager: ManagerNpm, Packages: []LanguagePackage{{Name: "t", Action: ActionUpdate, SelectionLowerBound: "1.0.5"}}},
		set: updateSet{idx: []int{0}, names: []string{"t"}, target: map[string]string{"t": "1.0.5"}},
	}
	start := time.Now()
	if fail := r.checkVersions(lf); fail != nil {
		t.Fatalf("%s %s", fail.reason, fail.detail)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %s", d)
	}
	if got := r.afterVersions["t"]; len(got) != 1 || got[0] != "1.0.5" {
		t.Errorf("versions = %v", got)
	}
	// Too many different versions of one package are refused.
	for i := 0; i < maxVersionsPerPackage+1; i++ {
		pkgs[fmt.Sprintf("node_modules/q%d/node_modules/t", i)] = map[string]any{"version": fmt.Sprintf("1.%d.0", i+1), "resolved": npmURL("t", "1.0.5"), "integrity": "x"}
	}
	lock, _ = json.Marshal(map[string]any{"lockfileVersion": 3, "packages": pkgs})
	lf, err = parseNpm([]byte(`{"name":"a"}`), lock)
	if err != nil {
		t.Fatal(err)
	}
	fail := (&updateRun{it: r.it, set: r.set}).checkVersions(lf)
	if fail == nil || fail.reason != ReasonOutputFilesInvalid {
		t.Errorf("fail = %+v", fail)
	}
}

// --- the budget for marker evaluations also counts requirements ---

func TestInstalledRequirementsAreFoundThroughBigRequirementLists(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 20000; i++ {
		fmt.Fprintf(&b, "p%d==1.0\n", i)
	}
	lf, err := parseRequirements([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	installed := map[string]string{}
	for i := 0; i < 20000; i++ {
		installed[fmt.Sprintf("p%d", i)] = "1.0"
	}
	r := &updateRun{it: &LanguageItem{Manager: ManagerPip}, set: updateSet{names: nil}}
	tgt := &worker.Target{PythonVersion: "3.12", Platforms: []string{"manylinux_2_36_x86_64"}}
	start := time.Now()
	roots, fail := r.checkFileRequirements(context.Background(), lf, installed, tgt, &markerBudget{ctx: context.Background(), max: 1000})
	if fail != nil {
		t.Fatalf("%s %s", fail.reason, fail.detail)
	}
	if len(roots) != 20000 {
		t.Errorf("%d roots", len(roots))
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %s", d)
	}
}

func TestPipReportMembersOfAnotherKindOfSourceAreRefused(t *testing.T) {
	for name, edit := range map[string]func(string) string{
		"a VCS source": func(r string) string {
			return strings.Replace(r, `"archive_info":`, `"vcs_info":{"vcs":"git","commit_id":"abc"},"archive_info":`, 1)
		},
		"a directory source": func(r string) string {
			return strings.Replace(r, `"archive_info":`, `"dir_info":{"editable":true},"archive_info":`, 1)
		},
		"an archive member": func(r string) string { return strings.Replace(r, `"hashes":`, `"extra":"x","hashes":`, 1) },
		"an install member": func(r string) string {
			return strings.Replace(r, `"requested":`, `"build_isolation":false,"requested":`, 1)
		},
		"a top-level member": func(r string) string {
			return strings.Replace(r, `"install":`, `"index_url":"https://evil.example/simple","install":`, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "pip")
			h.checkReport(edit)
			it, _ := h.run()
			wantCategory(t, it, CategoryManual, ReasonOutputFilesInvalid)
		})
	}
}

func TestPipReportEntryInstalledFromAURLIsRefused(t *testing.T) {
	h := newHarness(t, "pip")
	h.checkReport(func(r string) string {
		return strings.Replace(r, `"is_yanked":false`, `"is_yanked":false,"is_direct":true`, 1)
	})
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
}
