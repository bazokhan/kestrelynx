package worker

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// runtimesJSON is the table of runtimes (official Node.js and Python images)
// jobs may run in. It is part of the build: a runtime is selected only when
// the table pins an image for it.
//
//go:embed runtimes.json
var runtimesJSON []byte

// RuntimeKind says which language a runtime is.
type RuntimeKind string

const (
	KindNode   RuntimeKind = "node"
	KindPython RuntimeKind = "python"
)

// RuntimeSpec is one row of the runtime table.
type RuntimeSpec struct {
	// ID names the runtime in a job ("node24", "python3.13").
	ID   string      `json:"id"`
	Kind RuntimeKind `json:"kind"`
	// Series is the major version of Node.js or the X.Y of Python.
	Series string `json:"series"`
	// Version is the exact Node.js or Python version of the pinned image, and
	// Pip the version of the pip it carries (Python only). Both are empty for
	// a runtime that has no image.
	Version string `json:"version,omitempty"`
	Pip     string `json:"pip,omitempty"`
	// Image is the repository of the official image on Docker Hub, Tag the
	// series tag the table is updated from and ExactTag the tag of the exact
	// version. IndexDigest is the digest of the image index, and Platforms
	// the digest of the manifest of each platform. A runtime without an image
	// (one that is already out of support) has none of these.
	Image       string            `json:"image,omitempty"`
	Tag         string            `json:"tag,omitempty"`
	ExactTag    string            `json:"exact_tag,omitempty"`
	IndexDigest string            `json:"index_digest,omitempty"`
	Platforms   map[string]string `json:"platforms,omitempty"`
	// CoveredPaths are the paths of the image that are writable by everyone
	// and that the container covers with a tmpfs of its own.
	CoveredPaths []string `json:"covered_paths,omitempty"`
	// VolumesEmpty and Healthcheck record what the image's configuration
	// holds: no declared volumes, and whether it declares a health check.
	VolumesEmpty bool `json:"volumes_empty,omitempty"`
	Healthcheck  bool `json:"healthcheck,omitempty"`
	// Support is the maintenance state and EOL the date support ends (the
	// first of the month where only the month is published, EOLMonthOnly).
	Support      string `json:"support"`
	EOL          string `json:"eol"`
	EOLMonthOnly bool   `json:"eol_month_only,omitempty"`
	// LTSFrom is the date a Node.js series enters long-term support; it is
	// empty for a series that never does and for Python.
	LTSFrom string `json:"lts_from,omitempty"`
	// Checked is the date the row was last confirmed. Tested holds, per
	// platform, the manifest digest that passed the integration tests.
	Checked string            `json:"checked"`
	Tested  map[string]string `json:"tested,omitempty"`
}

type runtimeTable struct {
	Schema   int           `json:"schema"`
	Runtimes []RuntimeSpec `json:"runtimes"`
}

var runtimeSpecs = mustLoadRuntimes(runtimesJSON)

func mustLoadRuntimes(raw []byte) []RuntimeSpec {
	specs, err := parseRuntimes(raw)
	if err != nil {
		panic("worker: runtimes.json: " + err.Error())
	}
	return specs
}

// parseRuntimes decodes and checks a runtime table.
func parseRuntimes(raw []byte) ([]RuntimeSpec, error) {
	var t runtimeTable
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, err
	}
	if t.Schema != 1 {
		return nil, fmt.Errorf("schema %d is not 1", t.Schema)
	}
	seen := map[string]bool{}
	for _, r := range t.Runtimes {
		if r.ID == "" || seen[r.ID] {
			return nil, fmt.Errorf("runtime id %q is empty or repeated", r.ID)
		}
		seen[r.ID] = true
		switch r.Kind {
		case KindNode:
			if r.ID != "node"+r.Series {
				return nil, fmt.Errorf("runtime %q does not match its series %q", r.ID, r.Series)
			}
		case KindPython:
			if r.ID != "python"+r.Series {
				return nil, fmt.Errorf("runtime %q does not match its series %q", r.ID, r.Series)
			}
		default:
			return nil, fmt.Errorf("runtime %q has the unknown kind %q", r.ID, r.Kind)
		}
		if _, err := time.Parse("2006-01-02", r.EOL); err != nil {
			return nil, fmt.Errorf("runtime %q: eol %q is not a date", r.ID, r.EOL)
		}
		if r.LTSFrom != "" {
			if _, err := time.Parse("2006-01-02", r.LTSFrom); err != nil || r.Kind != KindNode {
				return nil, fmt.Errorf("runtime %q: lts_from %q is not a date of a Node.js series", r.ID, r.LTSFrom)
			}
		}
		if r.Image == "" {
			if r.IndexDigest != "" || len(r.Platforms) != 0 || r.Version != "" {
				return nil, fmt.Errorf("runtime %q has no image but carries image fields", r.ID)
			}
			continue
		}
		if !ValidSemver(r.Version) || !strings.HasPrefix(r.Version, r.Series+".") {
			return nil, fmt.Errorf("runtime %q: version %q is not in the series %q", r.ID, r.Version, r.Series)
		}
		if r.Kind == KindPython && !ValidPythonVersion(r.Pip) {
			return nil, fmt.Errorf("runtime %q: pip version %q is invalid", r.ID, r.Pip)
		}
		if !digestRe.MatchString(r.IndexDigest) {
			return nil, fmt.Errorf("runtime %q: index digest %q is invalid", r.ID, r.IndexDigest)
		}
		for _, p := range []string{"linux/amd64", "linux/arm64"} {
			if !digestRe.MatchString(r.Platforms[p]) {
				return nil, fmt.Errorf("runtime %q: no valid manifest digest for %s", r.ID, p)
			}
		}
		if len(r.CoveredPaths) == 0 || !r.VolumesEmpty {
			return nil, fmt.Errorf("runtime %q: its safety record is incomplete", r.ID)
		}
	}
	out := append([]RuntimeSpec(nil), t.Runtimes...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Runtimes returns every row of the table, ordered by id.
func Runtimes() []RuntimeSpec {
	return append([]RuntimeSpec(nil), runtimeSpecs...)
}

// LookupRuntime returns the row with the given id.
func LookupRuntime(id string) (RuntimeSpec, bool) {
	for _, r := range runtimeSpecs {
		if r.ID == id {
			return r, true
		}
	}
	return RuntimeSpec{}, false
}

// HasImage reports whether the table pins an image for the runtime, which is
// what makes it selectable.
func (r RuntimeSpec) HasImage() bool { return r.Image != "" }

// ImageRef is the pinned reference of the runtime's image in the familiar form
// "node@sha256:<index digest>".
func (r RuntimeSpec) ImageRef() string { return r.Image + "@" + r.IndexDigest }

// VersionEnv is the environment variable of the image that holds the exact
// version of the language.
func (r RuntimeSpec) VersionEnv() string {
	if r.Kind == KindNode {
		return "NODE_VERSION"
	}
	return "PYTHON_VERSION"
}

// Interpreter is the absolute path of the node or python executable the
// official image provides.
func (r RuntimeSpec) Interpreter() string {
	if r.Kind == KindNode {
		return "/usr/local/bin/node"
	}
	return "/usr/local/bin/" + r.ID
}

// InterpreterName is the name the interpreter is linked as in the directory of
// the tools.
func (r RuntimeSpec) InterpreterName() string {
	if r.Kind == KindNode {
		return "node"
	}
	return r.ID
}

// EOLDate is the date support for the runtime ends.
func (r RuntimeSpec) EOLDate() time.Time {
	t, _ := time.Parse("2006-01-02", r.EOL)
	return t
}

// EndOfLife reports whether the date of now is past the end of support.
func (r RuntimeSpec) EndOfLife(now time.Time) bool {
	y, m, d := now.UTC().Date()
	today := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	return today.After(r.EOLDate())
}

// InLTS reports whether the series is in long-term support at the time now:
// its long-term support has begun and its support has not ended.
func (r RuntimeSpec) InLTS(now time.Time) bool {
	if r.LTSFrom == "" || r.EndOfLife(now) {
		return false
	}
	from, err := time.Parse("2006-01-02", r.LTSFrom)
	if err != nil {
		return false
	}
	y, m, d := now.UTC().Date()
	return !time.Date(y, m, d, 0, 0, 0, 0, time.UTC).Before(from)
}

// DefaultNodeRuntime is the id of the Node.js runtime used when a project
// declares nothing about Node.js: the newest series of the table that has an
// image and is in long-term support at the time now. When none is, it is the
// newest series that has an image and is in support, and when the support of
// every series has ended, the newest series that has an image.
func DefaultNodeRuntime(now time.Time) (string, bool) {
	var lts, supported, newest RuntimeSpec
	for _, r := range runtimeSpecs {
		if r.Kind != KindNode || !r.HasImage() {
			continue
		}
		if seriesOrder(r.Series, newest.Series) {
			newest = r
		}
		if r.EndOfLife(now) {
			continue
		}
		if seriesOrder(r.Series, supported.Series) {
			supported = r
		}
		if r.InLTS(now) && seriesOrder(r.Series, lts.Series) {
			lts = r
		}
	}
	for _, r := range []RuntimeSpec{lts, supported, newest} {
		if r.ID != "" {
			return r.ID, true
		}
	}
	return "", false
}

// seriesOrder reports whether the Node.js series a is newer than b; an empty
// b is older than every series.
func seriesOrder(a, b string) bool {
	if b == "" {
		return true
	}
	x, ex := strconv.Atoi(a)
	y, ey := strconv.Atoi(b)
	return ex == nil && ey == nil && x > y
}

// Label is how the runtime is named to a person.
func (r RuntimeSpec) Label() string {
	if r.Kind == KindNode {
		return "Node.js " + r.Series
	}
	return "Python " + r.Series
}

// JobRuntime is the Runtime a job for this runtime carries.
func (r RuntimeSpec) JobRuntime() Runtime {
	return Runtime{ID: r.ID, Version: r.Version, Pip: r.Pip}
}

// KindFor is the kind of runtime a manager needs.
func KindFor(m Manager) RuntimeKind {
	if m == ManagerNpm || m == ManagerPnpm {
		return KindNode
	}
	return KindPython
}
