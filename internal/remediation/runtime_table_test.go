package remediation

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/toolfetch"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// Tests that judge dates or the order of series against the table as it was
// when they were written call useSnapshotTable: Node.js up to 26 and Python up
// to 3.15. A row the table update adds later (a newer series) is left out of
// them, so that adding it does not change what they expect. No other test, the
// integration tests in particular, is given anything but the real table.
const (
	snapshotNodeMax   = 26
	snapshotPythonMax = 15
)

func useSnapshotTable(t *testing.T) {
	t.Helper()
	var keep []worker.RuntimeSpec
	for _, r := range worker.Runtimes() {
		n, err := strconv.Atoi(strings.TrimPrefix(r.Series, "3."))
		if err == nil && ((r.Kind == worker.KindNode && n > snapshotNodeMax) || (r.Kind == worker.KindPython && n > snapshotPythonMax)) {
			continue
		}
		keep = append(keep, r)
	}
	t.Cleanup(worker.OverrideRuntimesForTest(keep))
}

// nextNodeSeries and nextPythonSeries name a series the table does not have:
// the one after its newest.
func nextNodeSeries() string {
	top := 0
	for _, r := range worker.Runtimes() {
		if n, err := strconv.Atoi(r.Series); err == nil && r.Kind == worker.KindNode && n > top {
			top = n
		}
	}
	return strconv.Itoa(top + 1)
}

func nextPythonSeries() string {
	top := 0
	for _, r := range worker.Runtimes() {
		if n, err := strconv.Atoi(strings.TrimPrefix(r.Series, "3.")); err == nil && r.Kind == worker.KindPython && n > top {
			top = n
		}
	}
	return "3." + strconv.Itoa(top+1)
}

// checkDefaultManagers reports a runtime of the table with an image that has no
// default release of the managers that run on it.
func checkDefaultManagers(t *testing.T) {
	t.Helper()
	for _, r := range worker.Runtimes() {
		if !r.HasImage() {
			continue
		}
		managers := []toolfetch.Manager{toolfetch.ManagerNpm, toolfetch.ManagerPnpm}
		if r.Kind == worker.KindPython {
			managers = []toolfetch.Manager{toolfetch.ManagerUv}
		}
		for _, m := range managers {
			if toolfetch.DefaultVersion(m, r.ID) == "" {
				t.Errorf("%s has no default %s", r.ID, m)
			}
		}
	}
}

// Every runtime of the table that updates run in has a default release of the
// managers that run on it, whatever rows the table gains.
func TestEveryRuntimeWithAnImageHasDefaultManagerVersions(t *testing.T) {
	checkDefaultManagers(t)
	// The defaults of the series the table has now run on their Node.js. A
	// series added later is judged by the pair check when it is chosen.
	for _, id := range []string{"node22", "node24", "node26"} {
		r, _ := worker.LookupRuntime(id)
		for _, m := range []toolfetch.Manager{toolfetch.ManagerNpm, toolfetch.ManagerPnpm} {
			v := toolfetch.DefaultVersion(m, id)
			text, known := toolfetch.NodeEngines(m, v)
			exact, ok := fullVersion(r.Version)
			set, readable := rangeSet(text)
			if !known || !ok || !readable || !set.contains(exact) {
				t.Errorf("%s %s needs Node.js %q, which %s (%s) is outside of", m, v, text, id, r.Version)
			}
		}
	}
}

// A table that has gained a newer series (what the table update adds) still
// selects it and runs with default managers.
func TestANewerSeriesInTheTableIsSelectable(t *testing.T) {
	useSnapshotTable(t)
	day := func(s string) time.Time { v, _ := time.Parse("2006-01-02", s); return v }
	rows := worker.Runtimes()
	n26, _ := worker.LookupRuntime("node26")
	p315, _ := worker.LookupRuntime("python3.15")
	n27, p316 := n26, p315
	n27.ID, n27.Series, n27.Version, n27.ExactTag, n27.Tag = "node27", "27", "27.0.0", "27.0.0-trixie-slim", "27-trixie-slim"
	n27.EOL, n27.LTSFrom, n27.Support = "2030-04-30", "2027-10-26", "current"
	p316.ID, p316.Series, p316.Version, p316.ExactTag, p316.Tag = "python3.16", "3.16", "3.16.0", "3.16.0-slim-trixie", "3.16-slim-trixie"
	p316.EOL, p316.Support = "2032-10-31", "bugfix"
	t.Cleanup(worker.OverrideRuntimesForTest(append(rows, n27, p316)))

	checkDefaultManagers(t)
	ids := DefaultRuntimeIDs()
	if !strings.Contains(strings.Join(ids, " "), "node27") || !strings.Contains(strings.Join(ids, " "), "python3.16") {
		t.Errorf("runtime ids = %v", ids)
	}
	// Chosen by a declaration.
	spec, uerr := ResolveToolSpec(ToolSpecInput{Manager: ManagerPnpm, Manifest: []byte(pnpmManifest), Files: fileBytes(map[string]string{".nvmrc": "27"}), Now: day("2026-11-01")})
	if uerr != nil || spec.Runtime != "node27" || spec.ToolVersion != toolfetch.DefaultVersion(toolfetch.ManagerPnpm, "node27") || spec.ToolVersion == "" {
		t.Errorf("node27: %+v %v", spec, uerr)
	}
	spec, uerr = pySpec(t, ">=3.12", map[string]string{".python-version": "3.16\n"}, "")
	if uerr != nil || spec.Runtime != "python3.16" || spec.ToolVersion != "0.13.0" {
		t.Errorf("python3.16: %+v %v", spec, uerr)
	}
	// The default follows long-term support: 26 until 27 enters it.
	for now, want := range map[string]string{"2027-10-25": "node26", "2027-10-26": "node27"} {
		got, uerr := ResolveToolSpec(ToolSpecInput{Manager: ManagerNpm, Manifest: []byte(npmManifest), Now: day(now)})
		if uerr != nil || got.Runtime != want {
			t.Errorf("default on %s = %s (%v), want %s", now, got.Runtime, uerr, want)
		}
	}
	// The series after them is still not in the table.
	if _, uerr := ResolveToolSpec(ToolSpecInput{Manager: ManagerNpm, Manifest: []byte(npmManifest), Files: fileBytes(map[string]string{".nvmrc": "28"}), Now: day("2026-11-01")}); uerr == nil || uerr.Reason != ReasonNodeSpecUnsupported {
		t.Errorf("node 28: %v", uerr)
	}
	if got, uerr := RequestedRuntimes(ToolSpecInput{Manager: ManagerNpm, Manifest: []byte(npmManifest)}); uerr != nil || got[len(got)-1] != "node27" {
		t.Errorf("requested = %v %v", got, uerr)
	}
}
