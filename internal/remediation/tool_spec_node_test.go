package remediation

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/toolfetch"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

func nodeSpec(t *testing.T, m DependencyManager, manifest string, files map[string]string) (ToolSpec, *UnsupportedError) {
	t.Helper()
	return ResolveToolSpec(ToolSpecInput{
		Manager: m, Manifest: []byte(manifest), Files: fileBytes(files),
		Now: time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC),
	})
}

func TestNodeSelection(t *testing.T) {
	pnpm := func(field string) string { return withField(pnpmManifest, field) }
	npm := func(field string) string { return withField(npmManifest, field) }
	// imageVersion is the exact version of a row's pinned image, read from the
	// table so the cases keep holding when the weekly update moves the pins.
	imageVersion := func(id string) string {
		r, ok := worker.LookupRuntime(id)
		if !ok || r.Version == "" {
			t.Fatalf("runtime %s has no pinned version", id)
		}
		return r.Version
	}
	cases := []struct {
		name     string
		manager  DependencyManager
		manifest string
		files    map[string]string
		runtime  string
		basis    string
		floor    string
		tool     string // the manager release, "" for the default
		excluded []RuntimeExclusion
		reason   Reason // for a unit that cannot be run
	}{
		{name: "nothing declared uses the newest series in long-term support", manager: ManagerPnpm, manifest: pnpmManifest, runtime: "node24", basis: RuntimeBasisDefault},
		{name: ".nvmrc 26", manager: ManagerNpm, manifest: npmManifest, files: map[string]string{".nvmrc": "26"}, runtime: "node26", basis: RuntimeBasisFile, floor: "26.0.0"},
		{name: ".node-version v<node26 image> has the image's own version", manager: ManagerPnpm, manifest: pnpmManifest, files: map[string]string{".node-version": "v" + imageVersion("node26")}, runtime: "node26", basis: RuntimeBasisFile},
		{name: "engines.node >=26", manager: ManagerNpm, manifest: npm(`"engines":{"node":">=26"}`), runtime: "node26", basis: RuntimeBasisLowestInRange, floor: "26.0.0"},
		{name: "engines.node >=24 takes the lowest series", manager: ManagerPnpm, manifest: pnpm(`"engines":{"node":">=24"}`), runtime: "node24", basis: RuntimeBasisLowestInRange, floor: "24.0.0"},
		{name: "npm 12 declared on Node.js 26", manager: ManagerNpm, manifest: npm(`"packageManager":"npm@12.2.0"`), files: map[string]string{".nvmrc": "26"}, runtime: "node26", basis: RuntimeBasisFile, floor: "26.0.0", tool: "12.2.0"},
		{name: ".nvmrc 22", manager: ManagerPnpm, manifest: pnpmManifest, files: map[string]string{".nvmrc": "22\n"}, runtime: "node22", basis: RuntimeBasisFile, floor: "22.0.0"},
		{name: ".nvmrc 24", manager: ManagerNpm, manifest: npmManifest, files: map[string]string{".nvmrc": "v24\n"}, runtime: "node24", basis: RuntimeBasisFile, floor: "24.0.0"},
		{name: ".node-version with the image's own version has no floor", manager: ManagerNpm, manifest: npmManifest, files: map[string]string{".node-version": imageVersion("node22")}, runtime: "node22", basis: RuntimeBasisFile},
		{name: ".node-version 22.5.0 is the floor", manager: ManagerNpm, manifest: npm(`"engines":{"node":">=22.5.0"}`), files: map[string]string{".node-version": "22.5.0"}, runtime: "node22", basis: RuntimeBasisFile, floor: "22.5.0"},
		{name: ".nvmrc 22 with engines.node >=22.12 floors at 22.12.0", manager: ManagerPnpm, manifest: pnpm(`"engines":{"node":">=22.12"}`), files: map[string]string{".nvmrc": "22"}, runtime: "node22", basis: RuntimeBasisFile, floor: "22.12.0"},
		{name: "engines.node >=20 and engines.pnpm >=11 run on the lowest series that is in support", manager: ManagerPnpm,
			manifest: pnpm(`"engines":{"node":">=20","pnpm":">=11"}`), runtime: "node22", basis: RuntimeBasisLowestInRange, floor: "20.0.0",
			excluded: []RuntimeExclusion{{ID: "node20", Why: ExcludedEndOfLife, EOL: "2026-04-30"}}},
		{name: "a range alone takes the lowest series", manager: ManagerNpm, manifest: npm(`"engines":{"node":"^22 || ^24"}`), runtime: "node22", basis: RuntimeBasisLowestInRange, floor: "22.0.0"},
		{name: "a range that needs 24", manager: ManagerNpm, manifest: npm(`"engines":{"node":">=24"}`), runtime: "node24", basis: RuntimeBasisLowestInRange, floor: "24.0.0",
			excluded: nil},
		{name: "an open lower bound floors at the next patch", manager: ManagerNpm, manifest: npm(`"engines":{"node":">24.1.0"}`), runtime: "node24", basis: RuntimeBasisLowestInRange, floor: "24.1.1"},
		{name: "devEngines.runtime picks the series like engines.node", manager: ManagerNpm, manifest: npm(`"devEngines":{"runtime":{"name":"node","version":"^22"}}`), runtime: "node22", basis: RuntimeBasisLowestInRange, floor: "22.0.0"},
		{name: "a file wins over the lowest series of a range", manager: ManagerNpm, manifest: npm(`"engines":{"node":">=20"}`), files: map[string]string{".nvmrc": "24"}, runtime: "node24", basis: RuntimeBasisFile, floor: "24.0.0"},
		{name: "npm 12 runs on a Node.js it supports", manager: ManagerNpm, manifest: npm(`"packageManager":"npm@12.2.0"`), files: map[string]string{".nvmrc": "22"}, runtime: "node22", basis: RuntimeBasisFile, floor: "22.0.0", tool: "12.2.0"},
		{name: "pnpm 10 declared with Node.js 22", manager: ManagerPnpm, manifest: pnpm(`"packageManager":"pnpm@10.34.4"`), files: map[string]string{".nvmrc": "22"}, runtime: "node22", basis: RuntimeBasisFile, floor: "22.0.0", tool: "10.34.4"},

		{name: ".nvmrc 18", manager: ManagerNpm, manifest: npmManifest, files: map[string]string{".nvmrc": "18"}, reason: ReasonNodeSpecUnsupported},
		{name: ".nvmrc of a series not in the table yet", manager: ManagerNpm, manifest: npmManifest, files: map[string]string{".nvmrc": nextNodeSeries()}, reason: ReasonNodeSpecUnsupported},
		{name: ".nvmrc 25 is not in the table", manager: ManagerNpm, manifest: npmManifest, files: map[string]string{".nvmrc": "25"}, reason: ReasonNodeSpecUnsupported},
		{name: ".nvmrc 20 is not a runtime updates run on", manager: ManagerNpm, manifest: npmManifest, files: map[string]string{".nvmrc": "20"}, reason: ReasonNodeSpecUnsupported},
		{name: "engines.node of 18 and below", manager: ManagerNpm, manifest: npm(`"engines":{"node":"<=18"}`), reason: ReasonNodeSpecUnsupported},
		{name: "engines.node of odd series only", manager: ManagerNpm, manifest: npm(`"engines":{"node":"^21 || ^23 || ^25"}`), reason: ReasonNodeSpecUnsupported},
		{name: "engines.node above the table", manager: ManagerNpm, manifest: npm(`"engines":{"node":">=` + nextNodeSeries() + `"}`), reason: ReasonNodeSpecUnsupported},
		{name: "a full version in a range is not the image's", manager: ManagerNpm, manifest: npm(`"engines":{"node":"22.5.0"}`), reason: ReasonNodeSpecUnsupported},
		{name: "two full versions of one series disagree", manager: ManagerNpm, manifest: npmManifest, files: map[string]string{".node-version": "22.5.0", ".nvmrc": "22.5.1"}, reason: ReasonNodeSpecConflict},
		{name: "a file and a range share nothing", manager: ManagerNpm, manifest: npm(`"engines":{"node":">=24"}`), files: map[string]string{".nvmrc": "22"}, reason: ReasonNodeSpecConflict},
		{name: "a file and a range of the same series share nothing", manager: ManagerPnpm, manifest: pnpm(`"engines":{"node":">=22.12"}`), files: map[string]string{".node-version": "22.5.0"}, reason: ReasonNodeSpecConflict},
		{name: "a manager release outside its range", manager: ManagerPnpm, manifest: pnpm(`"engines":{"node":">=20","pnpm":"<11"}`), reason: ReasonManagerSpecUnsupported},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec, uerr := nodeSpec(t, c.manager, c.manifest, c.files)
			if c.reason != "" {
				if uerr == nil || uerr.Reason != c.reason {
					t.Fatalf("spec = %+v, error = %v, want %s", spec, uerr, c.reason)
				}
				return
			}
			if uerr != nil {
				t.Fatal(uerr)
			}
			if spec.Runtime != c.runtime || spec.RuntimeBasis != c.basis || spec.NodeFloor != c.floor {
				t.Errorf("runtime %s basis %s floor %q, want %s %s %q", spec.Runtime, spec.RuntimeBasis, spec.NodeFloor, c.runtime, c.basis, c.floor)
			}
			want := c.tool
			if want == "" {
				want = defaultTool(c.manager)
			}
			if spec.ToolVersion != want {
				t.Errorf("tool = %s, want %s", spec.ToolVersion, want)
			}
			if !reflect.DeepEqual(spec.RuntimeExcluded, c.excluded) {
				t.Errorf("excluded = %+v, want %+v", spec.RuntimeExcluded, c.excluded)
			}
			if len(spec.RuntimeDeclared) == 0 && c.basis != RuntimeBasisDefault {
				t.Error("the declarations the runtime rests on are not recorded")
			}
		})
	}
}

// The runtime of a project that declares nothing about Node.js is the newest
// series in long-term support, which the table's dates decide.
func TestNodeDefaultFollowsLongTermSupport(t *testing.T) {
	useSnapshotTable(t)
	day := func(s string) time.Time { v, _ := time.Parse("2006-01-02", s); return v }
	for _, c := range []struct {
		now, want string
	}{
		{"2026-10-13", "node24"},
		{"2026-10-27", "node24"},
		{"2026-10-28", "node26"},
		{"2028-04-30", "node26"},
		{"2029-04-30", "node26"},
		// Every series has ended: the newest is named, so the failure says so.
		{"2029-05-01", "node26"},
	} {
		in := ToolSpecInput{Manager: ManagerNpm, Manifest: []byte(npmManifest), Now: day(c.now)}
		spec, uerr := ResolveToolSpec(in)
		if c.now == "2029-05-01" {
			if uerr == nil || uerr.Reason != ReasonNodeSpecUnsupported {
				t.Errorf("%s: %+v %v", c.now, spec, uerr)
			}
			if got := defaultNodeRuntime(day(c.now)); got != c.want {
				t.Errorf("%s: default = %s", c.now, got)
			}
			continue
		}
		if uerr != nil || spec.Runtime != c.want || spec.RuntimeBasis != RuntimeBasisDefault {
			t.Errorf("%s: runtime %s basis %s (%v), want %s", c.now, spec.Runtime, spec.RuntimeBasis, uerr, c.want)
		}
		if spec.ToolVersion != defaultTool(ManagerNpm) {
			t.Errorf("%s: tool %s", c.now, spec.ToolVersion)
		}
	}
	// "lts/*" in .nvmrc follows the same dates.
	for now, want := range map[string]string{"2026-10-13": "node24", "2026-10-28": "node26"} {
		spec, uerr := ResolveToolSpec(ToolSpecInput{Manager: ManagerNpm, Manifest: []byte(npmManifest), Files: fileBytes(map[string]string{".nvmrc": "lts/*"}), Now: day(now)})
		if uerr != nil || spec.Runtime != want {
			t.Errorf("lts/* on %s: %s (%v), want %s", now, spec.Runtime, uerr, want)
		}
	}
}

func TestNodeSelectionAtTheEndOfASupport(t *testing.T) {
	useSnapshotTable(t)
	after22 := time.Date(2027, 5, 1, 0, 0, 0, 0, time.UTC)
	in := func(manifest string, files map[string]string) ToolSpecInput {
		return ToolSpecInput{Manager: ManagerNpm, Manifest: []byte(manifest), Files: fileBytes(files), Now: after22}
	}
	// Past the end of Node.js 22 a declaration of 22 alone is a runtime past
	// its support, and a range that reaches 24 runs on 24.
	spec, ok := declaredRuntimeEOL(in(npmManifest, map[string]string{".nvmrc": "22"}), after22)
	if !ok || spec.ID != "node22" {
		t.Errorf("declaredRuntimeEOL = %+v %v", spec, ok)
	}
	if _, ok := declaredRuntimeEOL(in(withField(npmManifest, `"engines":{"node":">=22"}`), nil), after22); ok {
		t.Error("a range that allows 24 is not a runtime past its support")
	}
	got, uerr := ResolveToolSpec(in(withField(npmManifest, `"engines":{"node":">=20"}`), nil))
	if uerr != nil || got.Runtime != "node24" {
		t.Fatalf("spec = %+v %v", got, uerr)
	}
	want := []RuntimeExclusion{{ID: "node20", Why: ExcludedEndOfLife, EOL: "2026-04-30"}, {ID: "node22", Why: ExcludedEndOfLife, EOL: "2027-04-30"}}
	if !reflect.DeepEqual(got.RuntimeExcluded, want) {
		t.Errorf("excluded = %+v", got.RuntimeExcluded)
	}
	if _, uerr := ResolveToolSpec(in(npmManifest, map[string]string{".nvmrc": "22"})); uerr == nil || uerr.Reason != ReasonNodeSpecUnsupported {
		t.Errorf("resolve past the end of support: %v", uerr)
	}
}

func TestNodeCandidateAgainstTheManagersEngines(t *testing.T) {
	in := ToolSpecInput{Manager: ManagerPnpm, Manifest: []byte(withField(pnpmManifest, `"packageManager":"pnpm@11.0.0"`))}
	d2, uerr := readNodeDeclarations(in)
	if uerr != nil {
		t.Fatal(uerr)
	}
	old := worker.RuntimeSpec{ID: "node22", Kind: worker.KindNode, Series: "22", Version: "22.10.0"}
	if _, rej := nodeCandidate(in, d2, old); rej == nil || rej.ex.Why != ExcludedManagerEngines || rej.ex.Engines != ">=22.13.0" || rej.ex.ManagerVersion != "11.0.0" || rej.err.Reason != ReasonManagerSpecUnsupported {
		t.Errorf("pnpm 11 on Node.js 22.10.0: %+v", rej)
	}
	fresh := worker.RuntimeSpec{ID: "node22", Kind: worker.KindNode, Series: "22", Version: "22.13.0"}
	if _, rej := nodeCandidate(in, d2, fresh); rej != nil {
		t.Errorf("pnpm 11 on Node.js 22.13.0: %+v", rej)
	}
	in = ToolSpecInput{Manager: ManagerNpm, Manifest: []byte(withField(npmManifest, `"packageManager":"npm@12.2.0"`))}
	d2, _ = readNodeDeclarations(in)
	if _, rej := nodeCandidate(in, d2, worker.RuntimeSpec{ID: "node22", Kind: worker.KindNode, Series: "22", Version: "22.21.0"}); rej == nil || rej.ex.Why != ExcludedManagerEngines {
		t.Errorf("npm 12 on Node.js 22.21.0: %+v", rej)
	}
	// Lower series that were rejected are told apart from the ones past
	// their support.
	got := excludedBelow([]string{"node20", "node22", "node24"}, worker.RuntimeSpec{ID: "node24"}, []nodeRejection{{rt: old, ex: RuntimeExclusion{ID: "node22", Why: ExcludedManagerEngines, Manager: "pnpm", ManagerVersion: "11.0.0", Engines: ">=22.13.0"}}})
	if len(got) != 2 || got[0].Why != ExcludedEndOfLife || got[1].Why != ExcludedManagerEngines {
		t.Errorf("excludedBelow = %+v", got)
	}
}

func TestNodeEnginesProblem(t *testing.T) {
	dist := func(engines string) NpmDist {
		d := NpmDist{Install: map[string]string{}}
		if engines != "" {
			d.Install["engines"] = engines
		}
		return d
	}
	cases := []struct {
		name, engines, floor string
		bad                  bool
	}{
		{"no floor, nothing to check", `{"node":">=99"}`, "", false},
		{"no engines", "", "22.12.0", false},
		{"engines of another tool", `{"npm":">=10"}`, "22.12.0", false},
		{"range allows the floor", `{"node":">=18"}`, "22.12.0", false},
		{"range allows exactly the floor", `{"node":">=22.12"}`, "22.12.0", false},
		{"range needs more than the floor", `{"node":">=22.13"}`, "22.12.0", true},
		{"range of another series", `{"node":"^24"}`, "22.0.0", true},
		{"alternatives, one allows it", `{"node":"^22.12.0 || ^24"}`, "22.12.0", false},
		{"floor in an older series", `{"node":">=20.19"}`, "20.0.0", true},
		{"floor from an alternative with an empty interval", `{"node":"<=22.0.1 || >=24.10.0"}`, "24.0.0", true},
		{"alternative below every release", `{"node":"0.0.0 || >=22.12.0"}`, "22.0.0", true},
		{"engines.node is null", `{"node":null}`, "22.12.0", true},
		{"engines.node is a number", `{"node":22}`, "22.12.0", true},
		{"range that is not read", `{"node":"latest"}`, "22.12.0", true},
		{"engines that are not an object", `["node"]`, "22.12.0", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := nodeEnginesProblem(dist(c.engines), c.floor)
			if (got != "") != c.bad {
				t.Errorf("problem = %q, want bad=%v", got, c.bad)
			}
		})
	}
}

// The update of a project that declares a Node.js version lower than the one
// the image runs checks the entries it added or changed against the declared
// version.
func TestUpdateChecksEnginesAgainstTheDeclaredNode(t *testing.T) {
	setup := func(t *testing.T, files map[string]string, enginesText string) *harness {
		h := newHarness(t, "npm")
		for k, v := range files {
			h.files[k] = v
		}
		h.gh = ghFor(h.files)
		h.cfg.GitHub = h.gh
		h.item = itemFor(t, ManagerNpm, h.files, minimistGroup())
		if enginesText != "" {
			h.editLock(editNpmEntry(t, string(h.after), "node_modules/minimist", func(e map[string]any) {
				e["engines"] = map[string]any{"node": enginesText}
			}))
			d := h.npm.dists["minimist@1.2.8"]
			d.Install = map[string]string{"engines": `{"node":"` + enginesText + `"}`}
			h.npm.dists["minimist@1.2.8"] = d
		}
		return h
	}
	t.Run("an entry that allows the declared version passes", func(t *testing.T) {
		h := setup(t, map[string]string{".nvmrc": "22\n"}, ">=22")
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		rt := it.Update.Runtime
		if rt == nil || rt.ID != "node22" || rt.Basis != RuntimeBasisFile || rt.EnginesFloor != "22.0.0" || len(rt.Declared) != 1 || rt.Declared[0].Source != ".nvmrc" {
			t.Errorf("runtime record = %+v", rt)
		}
		if got := h.work.jobs[0].Runtime.ID; got != "node22" {
			t.Errorf("the job ran in %s", got)
		}
	})
	t.Run("an entry that needs a newer version of the series is refused", func(t *testing.T) {
		h := setup(t, map[string]string{".nvmrc": "22\n"}, ">=22.13")
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonRuntimeEnginesMismatch)
		if !strings.Contains(it.Detail, "minimist 1.2.8") || !strings.Contains(it.Detail, "22.0.0") {
			t.Errorf("detail = %q", it.Detail)
		}
	})
	t.Run("the engines declared in package.json set the floor", func(t *testing.T) {
		manifest := strings.Replace(h0Manifest(t), "{", `{"engines":{"node":">=22.12"},`, 1)
		h := setup(t, map[string]string{".nvmrc": "22\n", "package.json": manifest}, ">=22.13")
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonRuntimeEnginesMismatch)
		if !strings.Contains(it.Detail, "22.12.0") {
			t.Errorf("detail = %q", it.Detail)
		}
	})
	t.Run("nothing declared runs on the image and checks nothing", func(t *testing.T) {
		h := setup(t, nil, ">=24.5")
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if rt := it.Update.Runtime; rt == nil || rt.ID != "node24" || rt.Basis != RuntimeBasisDefault || rt.EnginesFloor != "" {
			t.Errorf("runtime record = %+v", rt)
		}
	})
}

func h0Manifest(t *testing.T) string {
	t.Helper()
	return readTestdata(t, "npm", "package.json")["package.json"]
}

func TestRuntimeBasisInThePullRequestBody(t *testing.T) {
	rec := &LangRecord{Runtime: &RuntimeRecord{
		ID: "node22", Version: "22.23.3", Image: "node@sha256:abc", Basis: RuntimeBasisLowestInRange,
		Declared:     []ToolDeclaration{{Source: "engines.node", Value: ">=20"}},
		Excluded:     []RuntimeExclusion{{ID: "node20", Why: ExcludedEndOfLife, EOL: "2026-04-30"}},
		EnginesFloor: "20.0.0",
	}}
	var en, ja strings.Builder
	writeEnvironment(textFor(BodyEN), &en, rec)
	writeEnvironment(textFor(BodyJA), &ja, rec)
	for _, want := range []string{"`node22` `22.23.3`", "`engines.node` `>=20`", "lowest series", "Node.js `20` is not used because its support ended on `2026-04-30`", "`20.0.0`"} {
		if !strings.Contains(en.String(), want) {
			t.Errorf("English body lacks %q:\n%s", want, en.String())
		}
	}
	for _, want := range []string{"`node22` `22.23.3`", "`engines.node` `>=20` を満たす対応イメージの中で最小の主要な版", "Node.js `20` は `2026-04-30` にサポート終了のため使わない", "`20.0.0`"} {
		if !strings.Contains(ja.String(), want) {
			t.Errorf("Japanese body lacks %q:\n%s", want, ja.String())
		}
	}
	// A record from before the basis was kept is worded as it was.
	rec.Runtime.Basis = ""
	var old strings.Builder
	writeEnvironment(textFor(BodyEN), &old, rec)
	if strings.Contains(old.String(), "lowest series") {
		t.Errorf("a record without a basis names one:\n%s", old.String())
	}
}

func TestManagerEnginesRangesAreRead(t *testing.T) {
	for _, m := range []toolfetch.Manager{toolfetch.ManagerNpm, toolfetch.ManagerPnpm} {
		for _, v := range []string{"9.0.0", "10.0.0", "11.0.0", "12.0.0"} {
			text, ok := toolfetch.NodeEngines(m, v)
			if !ok {
				t.Fatalf("no engines for %s %s", m, v)
			}
			set, ok := rangeSet(text)
			if !ok || set.isEmpty() {
				t.Errorf("%s %s: %q is not read", m, v, text)
			}
		}
	}
	text, _ := toolfetch.NodeEngines(toolfetch.ManagerNpm, "12.2.0")
	set, _ := rangeSet(text)
	if !set.contains(triple{"22", "22", "2"}) || set.contains(triple{"22", "22", "1"}) || !set.contains(triple{"24", "15", "0"}) || set.contains(triple{"24", "14", "9"}) || !set.contains(triple{"26", "0", "0"}) || set.contains(triple{"25", "0", "0"}) {
		t.Errorf("npm 12 range %q is read wrongly: %v", text, set)
	}
}
