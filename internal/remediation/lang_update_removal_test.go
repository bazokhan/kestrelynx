package remediation

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// --- the dependency taken out of the importer has to come back as it was ---

func TestLangUpdatePnpmDependencyTakenOutToResolveAgainComesBackAsItWas(t *testing.T) {
	// minimist is under mkdirp, and two direct dependencies have a closure of
	// two (holder with pinned, mkdirp with minimist): holder, the first by
	// name, is the one taken out of the importer.
	good := func(job worker.Job, src map[string][]byte) string { return partialLock("1.2.8", "2.0.0", "") }
	t.Run("it comes back", func(t *testing.T) {
		h := newPartialHarness(t, "", []string{"minimist"}, good)
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		repl := string(h.work.repls[0]["pnpm-lock.yaml"])
		importer := strings.SplitN(strings.SplitN(repl, "importers:", 2)[1], "packages:", 2)[0]
		if strings.Contains(importer, "holder") || !strings.Contains(importer, "mkdirp") {
			t.Errorf("the importer of the replacement lockfile is %s", importer)
		}
	})
	// A change that makes the lockfile disagree with package.json is found
	// before the dependency is looked at.
	for name, change := range map[string]func(lock string) string{
		"another specifier": func(l string) string {
			return strings.Replace(l, "      holder:\n        specifier: 1.0.0", "      holder:\n        specifier: ^1.0.0", 1)
		},
		"not in the importer": func(l string) string {
			return strings.Replace(l, "      holder:\n        specifier: 1.0.0\n        version: 1.0.0\n", "", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newPartialHarness(t, "", []string{"minimist"}, func(job worker.Job, src map[string][]byte) string {
				return change(good(job, src))
			})
			it, _ := h.run()
			wantCategory(t, it, CategoryManual, ReasonOutputFilesInvalid)
		})
	}
	for name, change := range map[string]func(lock string) string{
		"another resolution": func(l string) string {
			return strings.Replace(l, partialIntegrity("holder", "1.0.0"), partialIntegrity("holder", "1.0.1"), 1)
		},
		"another requirement": func(l string) string {
			return strings.Replace(l, "  holder@1.0.0:\n    dependencies:\n      pinned: 2.0.0\n", "  holder@1.0.0:\n    dependencies:\n      pinned: 2.0.0\n      extra: 1.0.0\n", 1)
		},
		"another version": func(l string) string {
			l = strings.Replace(l, "      holder:\n        specifier: 1.0.0\n        version: 1.0.0\n", "      holder:\n        specifier: 1.0.0\n        version: 1.0.1\n", 1)
			return l
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newPartialHarness(t, "", []string{"minimist"}, func(job worker.Job, src map[string][]byte) string {
				return change(good(job, src))
			})
			it, _ := h.run()
			wantCategory(t, it, CategoryManual, ReasonDropSideEffect)
			if h.work.calls != 1 {
				t.Errorf("work calls = %d: the update is not made again with another dependency taken out", h.work.calls)
			}
			if !strings.Contains(it.Detail, "holder") {
				t.Errorf("detail = %q", it.Detail)
			}
		})
	}
}

func TestLangUpdatePnpmTargetsThatAreDirectNeedNoOtherDependencyTakenOut(t *testing.T) {
	// pinned is direct here, so it is itself what is taken out.
	h := newPartialHarness(t, "^2.0.0", []string{"pinned"}, func(job worker.Job, src map[string][]byte) string {
		return partialLock("1.2.5", "2.0.2", "^2.0.0")
	})
	h.run()
	// Whether pinned reaches its target does not matter here; which dependency
	// was taken out does.
	if h.work.calls == 0 {
		t.Fatal("no job ran")
	}
	repl := string(h.work.repls[0]["pnpm-lock.yaml"])
	importer := strings.SplitN(strings.SplitN(repl, "importers:", 2)[1], "packages:", 2)[0]
	for _, name := range []string{"holder", "mkdirp"} {
		if !strings.Contains(importer, name) {
			t.Errorf("%s is no longer in the importer: %s", name, importer)
		}
	}
	if strings.Contains(importer, "pinned") {
		t.Errorf("pinned is still in the importer: %s", importer)
	}
}

// --- deprecation notes follow the registry ---

func deprecateMkdirp(p partialProject, note string) func(lock string) string {
	return func(lock string) string {
		switch p.mgr {
		case ManagerNpm:
			return strings.Replace(lock, `"node_modules/mkdirp": {`, `"node_modules/mkdirp": {
      "deprecated": "`+note+`",`, 1)
		}
		return strings.Replace(lock, "    hasBin: true", "    hasBin: true\n    deprecated: "+note, 1)
	}
}

func TestLangUpdateDeprecatedNotesFollowTheRegistry(t *testing.T) {
	for _, p := range []partialProject{npmPartialProject(), pnpmPartialProject()} {
		t.Run(p.name, func(t *testing.T) {
			moved := func(job worker.Job, src map[string][]byte) string { return p.lock(p.fastTo, p.slowFrom, "") }
			registry := func(h *harness, note string) {
				d := h.npm.dists["mkdirp@0.5.5"]
				d.Deprecated = note
				h.npm.dists["mkdirp@0.5.5"] = d
			}
			t.Run("a note the registry has is accepted and counted", func(t *testing.T) {
				h := p.newHarness(t, "", func(job worker.Job, src map[string][]byte) string {
					return deprecateMkdirp(p, "use something else")(moved(job, src))
				})
				registry(h, "use something else")
				it, _ := h.run()
				wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
				if it.Update.DeprecatedChanged != 1 {
					t.Errorf("deprecated notes changed = %d", it.Update.DeprecatedChanged)
				}
				want := []DeprecationChange{{Name: "mkdirp", Version: "0.5.5", Kind: DeprecationGained}}
				if !reflect.DeepEqual(it.Update.DeprecatedNotes, want) {
					t.Errorf("deprecated notes = %+v, want %+v", it.Update.DeprecatedNotes, want)
				}
				u := buildLanguageUnit(&it, 0)
				if u.manual || u.lang.record.DeprecatedChanged != 1 || !reflect.DeepEqual(u.lang.record.DeprecatedNotes, want) {
					t.Errorf("unit = %+v", u)
				}
			})
			t.Run("a note the registry does not have is refused", func(t *testing.T) {
				h := p.newHarness(t, "", func(job worker.Job, src map[string][]byte) string {
					return deprecateMkdirp(p, "made up")(moved(job, src))
				})
				registry(h, "")
				it, _ := h.run()
				wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
				if !strings.Contains(it.Detail, "mkdirp 0.5.5") {
					t.Errorf("detail = %q", it.Detail)
				}
			})
			t.Run("a note that differs from the registry's is refused", func(t *testing.T) {
				h := p.newHarness(t, "", func(job worker.Job, src map[string][]byte) string {
					return deprecateMkdirp(p, "one wording")(moved(job, src))
				})
				registry(h, "another wording")
				it, _ := h.run()
				wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
			})
			t.Run("a note taken away is accepted when the registry has none", func(t *testing.T) {
				h := p.newHarness(t, "", moved)
				h.files[p.lockName] = deprecateMkdirp(p, "old note")(h.files[p.lockName])
				h.gh = ghFor(h.files)
				h.cfg.GitHub = h.gh
				h.item = itemFor(t, p.mgr, h.files, p.groups([]string{p.fast, p.slow})...)
				registry(h, "")
				it, _ := h.run()
				wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
				if it.Update.DeprecatedChanged != 1 {
					t.Errorf("deprecated notes changed = %d", it.Update.DeprecatedChanged)
				}
				if want := []DeprecationChange{{Name: "mkdirp", Version: "0.5.5", Kind: DeprecationLost}}; !reflect.DeepEqual(it.Update.DeprecatedNotes, want) {
					t.Errorf("deprecated notes = %+v, want %+v", it.Update.DeprecatedNotes, want)
				}
			})
			t.Run("a note taken away that the registry still has is refused", func(t *testing.T) {
				h := p.newHarness(t, "", moved)
				h.files[p.lockName] = deprecateMkdirp(p, "old note")(h.files[p.lockName])
				h.gh = ghFor(h.files)
				h.cfg.GitHub = h.gh
				h.item = itemFor(t, p.mgr, h.files, p.groups([]string{p.fast, p.slow})...)
				registry(h, "old note")
				it, _ := h.run()
				wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
			})
			t.Run("a note left as it was is not looked up", func(t *testing.T) {
				h := p.newHarness(t, "", func(job worker.Job, src map[string][]byte) string {
					return deprecateMkdirp(p, "old note")(moved(job, src))
				})
				h.files[p.lockName] = deprecateMkdirp(p, "old note")(h.files[p.lockName])
				h.gh = ghFor(h.files)
				h.cfg.GitHub = h.gh
				h.item = itemFor(t, p.mgr, h.files, p.groups([]string{p.fast, p.slow})...)
				registry(h, "the registry says something else today")
				it, _ := h.run()
				wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
				if it.Update.DeprecatedChanged != 0 {
					t.Errorf("deprecated notes changed = %d", it.Update.DeprecatedChanged)
				}
			})
		})
	}
}

func TestNpmVersionDocumentDeprecation(t *testing.T) {
	doc := func(member string) []byte {
		return []byte(`{"name":"a","version":"1.0.0","dist":{"tarball":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"sha512-x"}` + member + `}`)
	}
	for _, c := range []struct {
		member, want string
		ok           bool
	}{
		{``, "", true},
		{`,"deprecated":"Use b instead."`, "Use b instead.", true},
		{`,"deprecated":""`, "", true},
		{`,"deprecated":false`, "", true},
		{`,"deprecated":null`, "", true},
		{`,"deprecated":true`, "", false},
		{`,"deprecated":{"a":1}`, "", false},
	} {
		d, err := parseNpmVersion(doc(c.member), "a", "1.0.0")
		if (err == nil) != c.ok || d.Deprecated != c.want {
			t.Errorf("%s: %q, %v", c.member, d.Deprecated, err)
		}
	}
}

// --- other checks of the way the update is made ---

func TestLangUpdatePnpmRefusesALockfileOfTwoDocuments(t *testing.T) {
	// pnpm 12 writes a second document into the lockfile unless it is told not
	// to; the file is not read as a lockfile of the project then.
	h := newHarness(t, "pnpm")
	h.editLock(string(h.after) + "\n---\nlockfileVersion: '9.0'\npackageManagerDependencies: {}\n")
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonOutputFilesInvalid)
}

func TestLangUpdateUvChecksTheNameInTheLockfileBeforeRunning(t *testing.T) {
	h := newHarness(t, "uv")
	h.item.Packages = append(h.item.Packages, LanguagePackage{
		Name: "missing", Normalized: "missing", Ecosystem: typePythonPkg, Installed: "1.0.0", SelectionLowerBound: "1.0.1", Action: ActionUpdate, Reason: ReasonUpdateCandidateInSource,
		Occurrences: []SourceOccurrence{{Path: "missing", Version: "1.0.0", Matched: true}},
	})
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonTargetNotInLockfile)
	if h.work.calls != 0 {
		t.Errorf("work calls = %d: uv would have changed nothing and succeeded", h.work.calls)
	}
}

// --- the package manager release follows the project's declaration ---

func TestLangUpdateRunsTheManagerReleaseTheProjectDeclares(t *testing.T) {
	hash := strings.Repeat("ab", 64)
	cases := []struct {
		name, manager, field, wantVersion, wantSource, wantHash string
	}{
		{"packageManager pnpm 10", "pnpm", `"packageManager":"pnpm@10.34.4+sha512.` + hash + `"`, "10.34.4", "declared", "sha512." + hash},
		{"packageManager npm 10", "npm", `"packageManager":"npm@10.9.9"`, "10.9.9", "declared", ""},
		{"engines.npm names the release", "npm", `"engines":{"npm":"9.9.4"}`, "9.9.4", "declared", ""},
		{"ranges the default is inside", "npm", `"engines":{"npm":">=10"},"devEngines":{"packageManager":{"name":"npm","version":"^11"}}`, defaultTool(ManagerNpm), "default_in_range", ""},
		{"nothing declared", "pnpm", ``, defaultTool(ManagerPnpm), "default", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, c.manager)
			if c.field != "" {
				h.files["package.json"] = withManifestField(h.files["package.json"], c.field)
				h.gh = ghFor(h.files)
				h.cfg.GitHub = h.gh
				h.item = itemFor(t, h.fx.mgr, h.files, h.fx.group())
			}
			it, _ := h.run()
			wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
			tools := h.cfg.Tools.(*fakeTools)
			if len(tools.reqs) == 0 {
				t.Fatal("no release was asked for")
			}
			for _, req := range tools.reqs {
				if req.Version != c.wantVersion || req.SpecHash != c.wantHash || req.NodeVersion == "" {
					t.Errorf("request = %+v", req)
				}
			}
			tl := it.Update.Tool
			if tl == nil || tl.Version != c.wantVersion || tl.Source != c.wantSource || tl.SpecHash != c.wantHash {
				t.Errorf("tool record = %+v", tl)
			}
			// The job runs the release it was given.
			for _, j := range h.work.jobs {
				if j.Tool == nil || j.Tool.Version != c.wantVersion {
					t.Errorf("job tool = %+v", j.Tool)
				}
				if err := j.Validate(); err != nil {
					t.Error(err)
				}
			}
		})
	}
}

func TestLangUpdateRefusesAManagerReleaseBeforeRunning(t *testing.T) {
	for _, c := range []struct {
		name, manager, field string
	}{
		{"pnpm older than 9", "pnpm", `"packageManager":"pnpm@8.15.9"`},
		{"npm newer than 12", "npm", `"packageManager":"npm@13.0.0"`},
		{"pre-release", "pnpm", `"packageManager":"pnpm@12.0.0-rc.1"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, c.manager)
			h.files["package.json"] = withManifestField(h.files["package.json"], c.field)
			h.gh = ghFor(h.files)
			h.cfg.GitHub = h.gh
			h.item = itemFor(t, h.fx.mgr, h.files, h.fx.group())
			it, _ := h.run()
			wantCategory(t, it, CategoryManual, ReasonManagerSpecUnsupported)
			if h.work.calls != 0 || len(h.cfg.Tools.(*fakeTools).reqs) != 0 {
				t.Errorf("a job ran or a release was asked for")
			}
		})
	}
}

// withManifestField adds a member to the top level of a package.json.
func withManifestField(manifest, field string) string {
	return strings.Replace(manifest, "{", "{"+field+",", 1)
}

func TestLangUpdatePnpm12BeforeTheFixingReleaseIsLeftToAPerson(t *testing.T) {
	for _, v := range []string{"12.0.0", "12.9.1"} {
		t.Run(v, func(t *testing.T) {
			h := newHarness(t, "pnpm")
			h.files["package.json"] = withManifestField(h.files["package.json"], `"packageManager":"pnpm@`+v+`"`)
			h.gh = ghFor(h.files)
			h.cfg.GitHub = h.gh
			h.item = itemFor(t, h.fx.mgr, h.files, h.fx.group())
			it, _ := h.run()
			wantCategory(t, it, CategoryManual, ReasonPnpm12RemovalUnsupported)
			if h.work.calls != 0 || len(h.cfg.Tools.(*fakeTools).reqs) != 0 {
				t.Error("a job ran or a release was asked for")
			}
			if !strings.Contains(it.Detail, v) || !strings.Contains(it.Detail, minPnpm12Removal) {
				t.Errorf("detail = %q", it.Detail)
			}
		})
	}
}

func TestLangUpdatePnpm12FromTheFixingReleaseRuns(t *testing.T) {
	for _, v := range []string{minPnpm12Removal, "12.11.2"} {
		t.Run(v, func(t *testing.T) {
			h := newHarness(t, "pnpm")
			h.files["package.json"] = withManifestField(h.files["package.json"], `"packageManager":"pnpm@`+v+`"`)
			h.gh = ghFor(h.files)
			h.cfg.GitHub = h.gh
			h.item = itemFor(t, h.fx.mgr, h.files, h.fx.group())
			it, _ := h.run()
			if it.Reason == ReasonPnpm12RemovalUnsupported {
				t.Fatalf("pnpm %s was left to a person: %s", v, it.Detail)
			}
			if h.work.calls == 0 {
				t.Errorf("no job ran for pnpm %s (category/reason = %s/%s)", v, it.Category, it.Reason)
			}
		})
	}
}

func TestLangUpdateRefusesADeprecatedNoteThatIsNotText(t *testing.T) {
	for _, p := range []partialProject{npmPartialProject(), pnpmPartialProject()} {
		t.Run(p.name, func(t *testing.T) {
			// An entry the update has nothing to do with gets a deprecated member
			// that is a mapping, with no note before or after to compare.
			h := p.newHarness(t, "", func(job worker.Job, src map[string][]byte) string {
				lock := p.lock(p.fastTo, p.slowFrom, "")
				if p.mgr == ManagerNpm {
					return strings.Replace(lock, `"node_modules/holder": {`, `"node_modules/holder": {
      "deprecated": {},`, 1)
				}
				return strings.Replace(lock, "  holder@1.0.0:\n    resolution:", "  holder@1.0.0:\n    deprecated: {}\n    resolution:", 1)
			})
			it, _ := h.run()
			wantCategory(t, it, CategoryManual, ReasonOutputFilesInvalid)
			if !strings.Contains(it.Detail, "deprecated") {
				t.Errorf("detail = %q", it.Detail)
			}
		})
	}
}

func TestLangUpdateReadsADeprecatedNoteByItsType(t *testing.T) {
	p := pnpmPartialProject()
	moved := func(job worker.Job, src map[string][]byte) string { return p.lock(p.fastTo, p.slowFrom, "") }
	with := func(member string) func(job worker.Job, src map[string][]byte) string {
		return func(job worker.Job, src map[string][]byte) string {
			return strings.Replace(moved(job, src), "    hasBin: true", "    hasBin: true\n    deprecated: "+member, 1)
		}
	}
	for _, member := range []string{"false", "true", "1", "{}", "[]"} {
		t.Run("plain "+member, func(t *testing.T) {
			h := p.newHarness(t, "", with(member))
			it, _ := h.run()
			wantCategory(t, it, CategoryManual, ReasonOutputFilesInvalid)
		})
	}
	// The text "false" is a note; it is judged against the registry's, which has none.
	t.Run("quoted false", func(t *testing.T) {
		h := p.newHarness(t, "", with(`"false"`))
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonDistributionMismatch)
	})
}

// The note of an entry is called a change only when the name and version are
// the same as before; for another version it is only stated, and only when
// the new version has one.
func TestDeprecationKind(t *testing.T) {
	node := func(version, note string) *depNode {
		return &depNode{name: "eslint", version: version, deprecated: note}
	}
	for _, c := range []struct {
		name     string
		old, now *depNode
		want     string
	}{
		{"same version gained a note", node("9.0.0", ""), node("9.0.0", "x"), DeprecationGained},
		{"same version lost its note", node("9.0.0", "x"), node("9.0.0", ""), DeprecationLost},
		{"same version changed its note", node("9.0.0", "x"), node("9.0.0", "y"), DeprecationChanged},
		{"deprecated version replaced by a clean one", node("8.0.0", "x"), node("9.0.0", ""), ""},
		{"clean version replaced by a deprecated one", node("8.0.0", ""), node("9.0.0", "y"), DeprecationPresent},
		{"deprecated replaced by deprecated", node("8.0.0", "x"), node("9.0.0", "y"), DeprecationPresent},
		{"new entry, deprecated", nil, node("9.0.0", "y"), DeprecationPresent},
		{"new entry, clean", nil, node("9.0.0", ""), ""},
	} {
		if got := deprecationKind(c.old, c.now); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// A new version of an entry with the same note text as the version before is
// stated as deprecated, checked against the registry, and not counted among
// the notes that changed.
func TestCheckDeprecatedStatesACarriedNote(t *testing.T) {
	graph := func(version, note string) *depGraph {
		return &depGraph{nodes: map[string]*depNode{"node_modules/pkg": {name: "pkg", version: version, deprecated: note}}}
	}
	run := func(registryNote string) (*updateRun, *updateFailure) {
		r := &updateRun{upd: &LanguageUpdate{}, npmDocs: map[string]NpmDist{"pkg@2.0.0": {Deprecated: registryNote}}}
		return r, r.checkDeprecated(context.Background(), graph("1.0.0", "use other"), graph("2.0.0", "use other"))
	}
	r, fail := run("use other")
	if fail != nil {
		t.Fatalf("failure: %+v", fail)
	}
	want := []DeprecationChange{{Name: "pkg", Version: "2.0.0", Kind: DeprecationPresent}}
	if !reflect.DeepEqual(r.upd.DeprecatedNotes, want) || r.upd.DeprecatedChanged != 0 {
		t.Errorf("notes = %+v, changed = %d", r.upd.DeprecatedNotes, r.upd.DeprecatedChanged)
	}
	// The note is stated only as far as the registry has it.
	if _, fail := run("another text"); fail == nil {
		t.Error("a carried note the registry does not have was accepted")
	}
	// The same version with the same note is not looked at.
	same := &updateRun{upd: &LanguageUpdate{}}
	if fail := same.checkDeprecated(context.Background(), graph("1.0.0", "use other"), graph("1.0.0", "use other")); fail != nil || len(same.upd.DeprecatedNotes) != 0 {
		t.Errorf("unchanged: %+v %+v", fail, same.upd.DeprecatedNotes)
	}
}
