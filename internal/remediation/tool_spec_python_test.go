package remediation

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func pySpec(t *testing.T, requires string, files map[string]string, toolSection string) (ToolSpec, *UnsupportedError) {
	t.Helper()
	pyproject := strings.Replace(uvPyproject, `requires-python = ">=3.12"`, `requires-python = "`+requires+`"`, 1)
	if requires == "" {
		pyproject = strings.Replace(uvPyproject, `requires-python = ">=3.12"`+"\n", "", 1)
	}
	if toolSection != "" {
		pyproject += "\n[tool.uv]\n" + toolSection + "\n"
	}
	return ResolveToolSpec(ToolSpecInput{
		Manager: ManagerUv, Manifest: []byte(pyproject), Files: fileBytes(files),
		Now: time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC),
	})
}

func TestPythonSelection(t *testing.T) {
	file := func(v string) map[string]string { return map[string]string{".python-version": v + "\n"} }
	cases := []struct {
		name     string
		requires string
		files    map[string]string
		runtime  string
		basis    string
		declared []ToolDeclaration
		excluded []RuntimeExclusion
		reason   Reason
	}{
		{name: ".python-version 3.12", requires: ">=3.11", files: file("3.12"), runtime: "python3.12", basis: RuntimeBasisFile,
			declared: []ToolDeclaration{{Source: ".python-version", Value: "3.12"}}},
		{name: ".python-version 3.13", requires: ">=3.11", files: file("3.13"), runtime: "python3.13", basis: RuntimeBasisFile,
			declared: []ToolDeclaration{{Source: ".python-version", Value: "3.13"}}},
		{name: ".python-version 3.14", requires: ">=3.11", files: file("3.14"), runtime: "python3.14", basis: RuntimeBasisFile,
			declared: []ToolDeclaration{{Source: ".python-version", Value: "3.14"}}},
		{name: ".python-version 3.11 names a series that is lower than the default", requires: ">=3.9", files: file("3.11"), runtime: "python3.11", basis: RuntimeBasisFile,
			declared: []ToolDeclaration{{Source: ".python-version", Value: "3.11"}}},
		{name: "a patch that differs from the image is allowed and recorded", requires: ">=3.12.1", files: file("cpython-3.12.3"), runtime: "python3.12", basis: RuntimeBasisFile,
			declared: []ToolDeclaration{{Source: ".python-version", Value: "cpython-3.12.3"}}},
		{name: ">=3.11 takes 3.11", requires: ">=3.11", runtime: "python3.11", basis: RuntimeBasisLowestInRange,
			declared: []ToolDeclaration{{Source: "requires-python", Value: ">=3.11"}}},
		{name: ".python-version 3.15", requires: ">=3.12", files: file("3.15"), runtime: "python3.15", basis: RuntimeBasisFile,
			declared: []ToolDeclaration{{Source: ".python-version", Value: "3.15"}}},
		{name: "requires-python >=3.15 takes 3.15", requires: ">=3.15", runtime: "python3.15", basis: RuntimeBasisLowestInRange,
			declared: []ToolDeclaration{{Source: "requires-python", Value: ">=3.15"}}},
		{name: ">=3.9 skips the series past the end of support", requires: ">=3.9", runtime: "python3.11", basis: RuntimeBasisLowestInRange,
			declared: []ToolDeclaration{{Source: "requires-python", Value: ">=3.9"}},
			excluded: []RuntimeExclusion{{ID: "python3.9", Why: ExcludedEndOfLife, EOL: "2025-10-31"}, {ID: "python3.10", Why: ExcludedEndOfLife, EOL: "2026-10-01"}}},
		{name: ">=3.13,<3.14 takes 3.13", requires: ">=3.13,<3.14", runtime: "python3.13", basis: RuntimeBasisLowestInRange,
			declared: []ToolDeclaration{{Source: "requires-python", Value: ">=3.13,<3.14"}}},
		{name: "!=3.11.* skips 3.11", requires: ">=3.11,!=3.11.*", runtime: "python3.12", basis: RuntimeBasisLowestInRange,
			declared: []ToolDeclaration{{Source: "requires-python", Value: ">=3.11,!=3.11.*"}}},
		{name: "a patch the image does not reach leaves the series out", requires: ">=3.11.99", runtime: "python3.12", basis: RuntimeBasisLowestInRange,
			declared: []ToolDeclaration{{Source: "requires-python", Value: ">=3.11.99"}},
			excluded: []RuntimeExclusion{{ID: "python3.11", Why: ExcludedDeclarations}}},
		{name: "a compatible release ~=3.12.0 takes 3.12", requires: "~=3.12.0", runtime: "python3.12", basis: RuntimeBasisLowestInRange,
			declared: []ToolDeclaration{{Source: "requires-python", Value: "~=3.12.0"}}},
		{name: "the file and a range that agree", requires: ">=3.12.5", files: file("3.12.5"), runtime: "python3.12", basis: RuntimeBasisFile,
			declared: []ToolDeclaration{{Source: ".python-version", Value: "3.12.5"}}},

		{name: "the file and the range contradict each other", requires: ">=3.12.5", files: file("3.12.3"), reason: ReasonPythonSpecConflict},
		{name: "the file names a series below the range", requires: ">=3.12", files: file("3.11"), reason: ReasonPythonSpecConflict},
		{name: "3.9 alone is past the end of support", requires: ">=3.9,<3.10", reason: ReasonPythonSpecUnsupported},
		{name: "3.8 and below is outside the table", requires: "<3.9", reason: ReasonPythonSpecUnsupported},
		{name: "above the table is outside the table", requires: ">=" + nextPythonSeries(), reason: ReasonPythonSpecUnsupported},
		{name: ".python-version above the table", requires: ">=3.12", files: file(nextPythonSeries()), reason: ReasonPythonSpecUnsupported},
		{name: ".python-version 3.8", requires: ">=3.8", files: file("3.8"), reason: ReasonPythonSpecUnsupported},
		{name: "a range the image's Python is just outside of", requires: ">=3.12.99,<3.13", reason: ReasonPythonSpecUnsupported},
		{name: ".python-versions lists several versions", requires: ">=3.12", files: map[string]string{".python-versions": "3.13\n3.12\n"}, reason: ReasonPythonSpecUnsupported},
		{name: "a specifier that is not read", requires: "python 3", reason: ReasonPythonSpecInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec, uerr := pySpec(t, c.requires, c.files, "")
			if c.reason != "" {
				if uerr == nil || uerr.Reason != c.reason {
					t.Fatalf("error = %v, want %s (spec %+v)", uerr, c.reason, spec)
				}
				return
			}
			if uerr != nil {
				t.Fatal(uerr)
			}
			if spec.Runtime != c.runtime || spec.RuntimeBasis != c.basis {
				t.Errorf("runtime %s basis %s, want %s %s", spec.Runtime, spec.RuntimeBasis, c.runtime, c.basis)
			}
			if !reflect.DeepEqual(spec.RuntimeDeclared, c.declared) {
				t.Errorf("declared = %+v, want %+v", spec.RuntimeDeclared, c.declared)
			}
			if !reflect.DeepEqual(spec.RuntimeExcluded, c.excluded) {
				t.Errorf("excluded = %+v, want %+v", spec.RuntimeExcluded, c.excluded)
			}
			if spec.ToolVersion != "0.13.0" || spec.ToolSource != toolSourceDefault {
				t.Errorf("tool = %s (%s)", spec.ToolVersion, spec.ToolSource)
			}
		})
	}
}

func TestPythonWithoutRequiresPythonKeepsTheDefaultRuntime(t *testing.T) {
	spec, uerr := pySpec(t, "", nil, "")
	if uerr != nil || spec.Runtime != defaultPythonRuntime || spec.RuntimeBasis != "" {
		t.Errorf("spec = %+v, %v", spec, uerr)
	}
	// A file alone still chooses the series.
	spec, uerr = pySpec(t, "", map[string]string{".python-version": "3.11\n"}, "")
	if uerr != nil || spec.Runtime != "python3.11" || spec.RuntimeBasis != RuntimeBasisFile {
		t.Errorf("spec = %+v, %v", spec, uerr)
	}
}

func TestUvRequiredVersion(t *testing.T) {
	cases := []struct {
		name     string
		section  string
		requires string
		tool     string
		source   string
		reason   Reason
	}{
		{name: "an exact release inside the supported range", section: `required-version = "==0.12.30"`, tool: "0.12.30", source: "declared"},
		{name: "the lowest supported release", section: `required-version = "==0.12.22"`, tool: "0.12.22", source: "declared"},
		{name: "an exact release below the supported range", section: `required-version = "==0.12.21"`, reason: ReasonManagerSpecUnsupported},
		{name: "an exact release below the range, with Python 3.11", section: `required-version = "==0.5.31"`, requires: ">=3.11", reason: ReasonManagerSpecUnsupported},
		{name: "a range that holds the default", section: `required-version = ">=0.12.22,<0.14"`, tool: "0.13.0", source: "default_in_range"},
		{name: "a range that holds the default, with Python 3.11", section: `required-version = ">=0.12"`, requires: ">=3.11", tool: "0.13.0", source: "default_in_range"},
		{name: "a range that does not hold the default", section: `required-version = "<0.13"`, reason: ReasonManagerSpecUnsupported},
		{name: "a version that is not a specifier", section: `required-version = "latest"`, reason: ReasonManagerSpecInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			requires := c.requires
			if requires == "" {
				requires = ">=3.12"
			}
			spec, uerr := pySpec(t, requires, nil, c.section)
			if c.reason != "" {
				if uerr == nil || uerr.Reason != c.reason {
					t.Fatalf("error = %v, want %s", uerr, c.reason)
				}
				return
			}
			if uerr != nil || spec.ToolVersion != c.tool || spec.ToolSource != c.source {
				t.Errorf("tool = %s (%s), %v; want %s (%s)", spec.ToolVersion, spec.ToolSource, uerr, c.tool, c.source)
			}
		})
	}
}

func TestPythonBasisInThePullRequestBody(t *testing.T) {
	rec := &LangRecord{Runtime: &RuntimeRecord{
		ID: "python3.11", Version: "3.11.17", Pip: "24.0", Image: "python@sha256:abc", Basis: RuntimeBasisLowestInRange,
		Declared: []ToolDeclaration{{Source: "requires-python", Value: ">=3.9"}},
		Excluded: []RuntimeExclusion{{ID: "python3.9", Why: ExcludedEndOfLife, EOL: "2025-10-31"}, {ID: "python3.10", Why: ExcludedEndOfLife, EOL: "2026-10-01"}},
	}}
	var en, ja strings.Builder
	writeEnvironment(textFor(BodyEN), &en, rec)
	writeEnvironment(textFor(BodyJA), &ja, rec)
	for _, want := range []string{"`python3.11` `3.11.17`", "`requires-python` `>=3.9`", "lowest series", "Python `3.9` is not used because its support ended on `2025-10-31`", "Python `3.10` is not used"} {
		if !strings.Contains(en.String(), want) {
			t.Errorf("English body lacks %q:\n%s", want, en.String())
		}
	}
	for _, want := range []string{"`requires-python` `>=3.9` を満たす対応イメージの中で最小の小版", "Python `3.9` は `2025-10-31` にサポート終了のため使わない"} {
		if !strings.Contains(ja.String(), want) {
			t.Errorf("Japanese body lacks %q:\n%s", want, ja.String())
		}
	}
	if strings.Contains(en.String(), "Node.js") || strings.Contains(ja.String(), "Node.js") {
		t.Errorf("a Python record names Node.js:\n%s\n%s", en.String(), ja.String())
	}
	rec.Runtime.Basis, rec.Runtime.Excluded = RuntimeBasisFile, nil
	rec.Runtime.Declared = []ToolDeclaration{{Source: ".python-version", Value: "3.12.3"}}
	en.Reset()
	ja.Reset()
	writeEnvironment(textFor(BodyEN), &en, rec)
	writeEnvironment(textFor(BodyJA), &ja, rec)
	if !strings.Contains(en.String(), "the minor version `.python-version` `3.12.3` name(s)") || !strings.Contains(ja.String(), "`.python-version` `3.12.3` が指す小版") {
		t.Errorf("file basis is worded wrongly:\n%s\n%s", en.String(), ja.String())
	}
}

func TestLangUpdatePipTargetPastEndOfSupportIsManual(t *testing.T) {
	for _, c := range []struct{ minor, text string }{
		{"3.10", "Python 3.10 reached the end of its support on 2026-10-01; upgrade the runtime before updating"},
		{"3.8", "Python 3.8 is past the end of its support; upgrade the runtime before updating"},
		{"3.9", "Python 3.9 reached the end of its support on 2025-10-31; upgrade the runtime before updating"},
	} {
		t.Run(c.minor, func(t *testing.T) {
			h := newHarness(t, "pip")
			for i := range h.item.Packages {
				for j := range h.item.Packages[i].Origins {
					o := &h.item.Packages[i].Origins[j]
					o.PkgPath = strings.Replace(o.PkgPath, "python3.12", "python"+c.minor, 1)
				}
			}
			it, _ := h.run()
			wantCategory(t, it, CategoryManual, ReasonRuntimeEndOfLife)
			if it.Detail != c.text {
				t.Errorf("detail = %q", it.Detail)
			}
			if e := it.RuntimeEOL; e == nil || e.ID != "python"+c.minor || (c.minor == "3.8") != (e.EOL == "") {
				t.Errorf("runtime_eol = %+v", e)
			}
			if h.work.calls != 0 {
				t.Error("a job ran")
			}
		})
	}
}

func TestDeclaredEndOfLifeNamesTheLowestSeriesTheDeclarationsAllow(t *testing.T) {
	useSnapshotTable(t)
	now := time.Date(2031, 11, 1, 0, 0, 0, 0, time.UTC)
	spec, ok := declaredRuntimeEOL(ToolSpecInput{Manager: ManagerUv, Manifest: []byte(strings.Replace(uvPyproject, ">=3.12", ">=3.11", 1))}, now)
	if !ok || spec.ID != "python3.11" {
		t.Errorf("uv: %+v %v", spec, ok)
	}
	spec, ok = declaredRuntimeEOL(ToolSpecInput{Manager: ManagerNpm, Manifest: []byte(withField(npmManifest, `"engines":{"node":">=20"}`))}, time.Date(2029, 5, 1, 0, 0, 0, 0, time.UTC))
	if !ok || spec.ID != "node20" {
		t.Errorf("npm: %+v %v", spec, ok)
	}
}

func TestPythonPastSupport(t *testing.T) {
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	for minor, want := range map[string]bool{"3.7": true, "3.8": true, "3.9": true, "3.10": true, "3.11": false, "3.14": false, "3.15": false, "2.7": false, "x": false} {
		if _, got := pythonPastSupport(minor, now); got != want {
			t.Errorf("%s: %v, want %v", minor, got, want)
		}
	}
}
