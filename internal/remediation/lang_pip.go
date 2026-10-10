package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// --- distribution files of a release (PyPI) ---

// PyPIFile is one distribution file of a release.
type PyPIFile struct {
	Filename string
	URL      string
	Wheel    bool
	// Sdist is set for a source distribution (packagetype sdist).
	Sdist bool
	// RequiresPython is the Python versions the file says it supports (a PEP
	// 440 specifier); empty when it says none.
	RequiresPython string
	SHA256         string // lower-case hex
	Yanked         bool
}

// PyPIRelease is what the index publishes for one release: its distribution
// files and the requirements its metadata declares (PEP 508 strings).
type PyPIRelease struct {
	Files        []PyPIFile
	RequiresDist []string
	// RequiresPython is the release's own requires-python, for a file that
	// has none of its own.
	RequiresPython string
}

// PyPIFiles tells what the index publishes for a release of a package.
type PyPIFiles interface {
	// Release returns the release of name at version, or an error wrapping
	// ErrReleaseNotFound when the index has no such release.
	Release(ctx context.Context, name, version string) (PyPIRelease, error)
}

// ErrReleaseNotFound: the index has no such package version.
var ErrReleaseNotFound = errors.New("the release is not on the index")

// PyPIClient reads release metadata from the public PyPI JSON API.
type PyPIClient struct {
	HTTP *http.Client
	// BaseURL is the index host; empty means https://pypi.org.
	BaseURL string
}

var _ PyPIFiles = (*PyPIClient)(nil)

// maxPyPIBody bounds a release document.
const maxPyPIBody = 8 << 20

// maxReleaseFiles bounds the files of one release the client accepts.
const maxReleaseFiles = 2000

var sha256HexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Release implements PyPIFiles with GET <base>/pypi/<name>/<version>/json.
// The name is the PEP 503 form and the version must be a normalized PEP 440
// version; the document must be for that package and version.
func (c *PyPIClient) Release(ctx context.Context, name, version string) (PyPIRelease, error) {
	if !worker.ValidPythonName(name) || !worker.ValidPythonVersion(version) {
		return PyPIRelease{}, fmt.Errorf("%q %q is not a package name and version this client looks up", name, version)
	}
	base := c.BaseURL
	if base == "" {
		base = "https://pypi.org"
	}
	hc := boundedClient(c.HTTP)
	norm := normalizePyName(name)
	u := strings.TrimRight(base, "/") + "/pypi/" + url.PathEscape(norm) + "/" + url.PathEscape(version) + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return PyPIRelease{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "kestrelynx")
	resp, err := hc.Do(req)
	if err != nil {
		return PyPIRelease{}, fmt.Errorf("index request: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return PyPIRelease{}, ErrReleaseNotFound
	case resp.StatusCode != http.StatusOK:
		return PyPIRelease{}, fmt.Errorf("index answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPyPIBody+1))
	if err != nil {
		return PyPIRelease{}, fmt.Errorf("read index response: %w", err)
	}
	if len(body) > maxPyPIBody {
		return PyPIRelease{}, fmt.Errorf("index response is over %d bytes", maxPyPIBody)
	}
	return parsePyPIRelease(body, norm, version)
}

// parsePyPIRelease reads the release document: the name and version in its
// info must be the ones asked for, and every file entry well formed.
func parsePyPIRelease(body []byte, normName, version string) (PyPIRelease, error) {
	var doc struct {
		Info struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			// RequiresDist is null for a release that declares none.
			RequiresDist   []string `json:"requires_dist"`
			RequiresPython *string  `json:"requires_python"`
		} `json:"info"`
		URLs []struct {
			Filename       string  `json:"filename"`
			URL            string  `json:"url"`
			PackageType    string  `json:"packagetype"`
			Yanked         bool    `json:"yanked"`
			RequiresPython *string `json:"requires_python"`
			Digests        struct {
				SHA256 string `json:"sha256"`
			} `json:"digests"`
		} `json:"urls"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return PyPIRelease{}, fmt.Errorf("index response cannot be read: %w", err)
	}
	if normalizePyName(doc.Info.Name) != normName || !versionsEqual(schemePEP440, doc.Info.Version, version) {
		return PyPIRelease{}, fmt.Errorf("index response is for %s %s, not %s %s", doc.Info.Name, doc.Info.Version, normName, version)
	}
	var out []PyPIFile
	for _, f := range doc.URLs {
		if f.Filename == "" || f.URL == "" || !sha256HexRE.MatchString(f.Digests.SHA256) {
			return PyPIRelease{}, fmt.Errorf("index response has a file entry without a name, a url or a sha256 digest")
		}
		wheel := f.PackageType == "bdist_wheel"
		if wheel && !strings.HasSuffix(f.Filename, ".whl") {
			return PyPIRelease{}, fmt.Errorf("index response lists the wheel %q without the .whl suffix", f.Filename)
		}
		rp := ""
		if f.RequiresPython != nil {
			rp = strings.TrimSpace(*f.RequiresPython)
		}
		out = append(out, PyPIFile{Filename: f.Filename, URL: f.URL, Wheel: wheel, Sdist: f.PackageType == "sdist", RequiresPython: rp, SHA256: f.Digests.SHA256, Yanked: f.Yanked})
	}
	if len(doc.Info.RequiresDist) > maxDeclaredDeps || len(out) > maxReleaseFiles {
		return PyPIRelease{}, fmt.Errorf("index response lists more than %d requirements or %d files", maxDeclaredDeps, maxReleaseFiles)
	}
	rp := ""
	if doc.Info.RequiresPython != nil {
		rp = strings.TrimSpace(*doc.Info.RequiresPython)
	}
	return PyPIRelease{Files: out, RequiresDist: doc.Info.RequiresDist, RequiresPython: rp}, nil
}

// wheelHashes returns the sorted, de-duplicated sha256 of every wheel of a
// release. yanked is true when the release has a yanked file.
func wheelHashes(files []PyPIFile) (hashes []string, yanked bool) {
	seen := map[string]bool{}
	for _, f := range files {
		if f.Yanked {
			yanked = true
		}
		if f.Wheel && !seen[f.SHA256] {
			seen[f.SHA256] = true
			hashes = append(hashes, f.SHA256)
		}
	}
	sort.Strings(hashes)
	return hashes, yanked
}

// --- requirements.txt rewrite ---

// reqEdit is the new version of one requirement line.
type reqEdit struct {
	// Name is the PEP 503 name of the package the line is expected to
	// require; a line that names another package is not rewritten.
	Name string
	// Line is the 1-based physical line the logical requirement starts at.
	Line       int
	OldVersion string
	NewVersion string
	// Hashes are the sha256 digests (hex) the line carries afterwards. They
	// are required when the line has --hash options and replace all of them;
	// they must be empty for a line without.
	Hashes []string
}

type reqLine struct {
	text string // without the line terminator
	eol  string // "\n", "\r\n" or ""
}

var (
	reqVersionRE  = regexp.MustCompile(`(==\s*)([^\s\\#;]+)`)
	reqHashTokRE  = regexp.MustCompile(`--hash=[A-Za-z0-9_]+:[0-9a-fA-F]+`)
	reqHashSHARE  = regexp.MustCompile(`^--hash=sha256:[0-9a-f]{64}$`)
	leadingSpaces = regexp.MustCompile(`^[ \t]*`)
)

func splitReqLines(data []byte) []reqLine {
	var out []reqLine
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			out = append(out, reqLine{text: string(data)})
			break
		}
		l := reqLine{text: string(data[:i]), eol: "\n"}
		if strings.HasSuffix(l.text, "\r") {
			l.text, l.eol = strings.TrimSuffix(l.text, "\r"), "\r\n"
		}
		out = append(out, l)
		data = data[i+1:]
	}
	return out
}

// maxLogicalLine bounds how many physical lines one requirement may span.
const maxLogicalLine = 10000

// reqSpan returns the index of the last physical line of the logical line
// that starts at index s, by the continuation rule parseRequirements uses, and
// stops after maxLogicalLine lines (a line that long is the limit's to
// handle: callers compare the span with it). It is worked out once per logical
// line.
func reqSpan(lines []reqLine, s int) int {
	e := s
	for e+1 < len(lines) && e-s+1 < maxLogicalLine {
		phys := strings.TrimRight(pipCommentRE.ReplaceAllString(lines[e].text, ""), " \t")
		if !strings.HasSuffix(phys, "\\") {
			break
		}
		e++
	}
	return e
}

// requirementHasHashes reports whether the logical line starting at the
// 1-based physical line carries --hash options.
func requirementHasHashes(lines []reqLine, line int) bool {
	if line < 1 || line > len(lines) {
		return false
	}
	s := line - 1
	e := reqSpan(lines, s)
	for i := s; i <= e; i++ {
		if reqHashTokRE.MatchString(pipCommentRE.ReplaceAllString(lines[i].text, "")) {
			return true
		}
	}
	return false
}

// Bounds on a rewrite. The hashes come from a release's wheels, which the
// index decides, so what is generated from them is bounded before it is built.
const (
	maxPipEdits        = 256
	maxWheelsPerEdit   = 64
	maxRewriteGrowth   = 1 << 20
	hashIndent         = "    "
	hashLineBytes      = len(hashIndent+"--hash=sha256:") + 64 + len(" \\\r\n")
	rewriteCtxInterval = 256
)

// errRewriteLimit: the rewrite would be larger than this program builds. The
// work is not wrong; it is more than one update takes.
var errRewriteLimit = errors.New("the rewrite is over a limit")

// rewriteRequirements changes the version, and the hashes where the line has
// them, of the requirement lines named by edits. Every other byte of the file
// is kept: other lines, comments, blank lines and the line terminators. A
// rewritten line keeps its layout: hashes that were on continuation lines
// stay on one continuation line each, indented by four spaces whatever the
// original indentation was (so the size of the result follows from the number
// of hashes alone), and hashes written after the requirement stay on its line.
//
// The size of the result is worked out from the edits before anything is
// built, the file is split once and written in one pass, and the deadline is
// watched.
func rewriteRequirements(ctx context.Context, data []byte, edits []reqEdit) ([]byte, error) {
	lines := splitReqLines(data)
	return rewriteLines(ctx, data, lines, edits)
}

func rewriteLines(ctx context.Context, data []byte, lines []reqLine, edits []reqEdit) ([]byte, error) {
	if len(edits) > maxPipEdits {
		return nil, fmt.Errorf("%w: %d lines to edit, more than %d", errRewriteLimit, len(edits), maxPipEdits)
	}
	growth := 0
	for _, ed := range edits {
		if len(ed.Hashes) > maxWheelsPerEdit {
			return nil, fmt.Errorf("%w: %d hashes for one requirement, more than %d", errRewriteLimit, len(ed.Hashes), maxWheelsPerEdit)
		}
		growth += len(ed.Hashes)*hashLineBytes + len(ed.NewVersion)
	}
	if growth > maxRewriteGrowth || int64(len(data))+int64(growth) > worker.MaxInputFileBytes {
		return nil, fmt.Errorf("%w: the new file would be about %d bytes", errRewriteLimit, int64(len(data))+int64(growth))
	}
	sorted := append([]reqEdit(nil), edits...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Line < sorted[j].Line })
	for i := 1; i < len(sorted); i++ {
		if sorted[i].Line == sorted[i-1].Line {
			return nil, fmt.Errorf("line %d is edited twice", sorted[i].Line)
		}
	}
	var out bytes.Buffer
	out.Grow(len(data) + growth)
	next := 0 // the first line not yet written
	write := func(ls []reqLine) {
		for _, l := range ls {
			out.WriteString(l.text)
			out.WriteString(l.eol)
		}
	}
	for n, ed := range sorted {
		if n%rewriteCtxInterval == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if ed.Line < 1 || ed.Line > len(lines) {
			return nil, fmt.Errorf("line %d is outside the file", ed.Line)
		}
		s := ed.Line - 1
		if s < next {
			return nil, fmt.Errorf("line %d is inside the requirement edited before it", ed.Line)
		}
		e := reqSpan(lines, s)
		if e-s+1 >= maxLogicalLine {
			return nil, fmt.Errorf("%w: a requirement spans %d lines or more", errRewriteLimit, maxLogicalLine)
		}
		repl, err := rewriteRequirement(lines[s:e+1], ed)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", ed.Line, err)
		}
		write(lines[next:s])
		write(repl)
		next = e + 1
	}
	write(lines[next:])
	return out.Bytes(), nil
}

func rewriteRequirement(span []reqLine, ed reqEdit) ([]reqLine, error) {
	first := span[0].text
	pre := pipCommentRE.ReplaceAllString(first, "")
	nm := pipNameRE.FindStringSubmatch(strings.TrimSpace(strings.TrimPrefix(pre, "\xef\xbb\xbf")))
	if nm == nil || (ed.Name != "" && normalizePyName(nm[1]) != ed.Name) {
		return nil, fmt.Errorf("the line does not require %s", ed.Name)
	}
	m := reqVersionRE.FindStringSubmatchIndex(pre)
	if m == nil || pre[m[4]:m[5]] != ed.OldVersion {
		return nil, fmt.Errorf("the line does not pin %s", ed.OldVersion)
	}
	newFirst := pre[:m[4]] + ed.NewVersion + pre[m[5]:] + first[len(pre):]

	var hashLines []int
	for i, l := range span {
		if reqHashTokRE.MatchString(pipCommentRE.ReplaceAllString(l.text, "")) {
			hashLines = append(hashLines, i)
		}
	}
	if len(hashLines) == 0 {
		if len(ed.Hashes) > 0 {
			return nil, errors.New("hashes were given for a line that has none")
		}
		out := append([]reqLine(nil), span...)
		out[0].text = newFirst
		return out, nil
	}
	if len(ed.Hashes) == 0 {
		return nil, errors.New("the line has hashes and no new hashes were given")
	}
	for _, l := range span {
		if pipCommentRE.MatchString(l.text) {
			return nil, errors.New("a comment sits inside a requirement with hashes")
		}
		for _, tok := range reqHashTokRE.FindAllString(l.text, -1) {
			if !reqHashSHARE.MatchString(tok) {
				return nil, errors.New("the line has a hash that is not a sha256 digest")
			}
		}
	}
	head := strings.TrimRight(reqHashTokRE.ReplaceAllString(newFirst, ""), " \t")
	head = strings.TrimRight(strings.TrimSuffix(head, "\\"), " \t")
	lastEOL := span[len(span)-1].eol

	switch {
	case len(hashLines) == 1 && hashLines[0] == 0 && len(span) == 1:
		// The hashes follow the requirement on its own line.
		var b strings.Builder
		b.WriteString(head)
		for _, h := range ed.Hashes {
			b.WriteString(" --hash=sha256:" + h)
		}
		return []reqLine{{text: b.String(), eol: lastEOL}}, nil
	case hashLines[0] != 0:
		indent := hashIndent
		out := []reqLine{{text: head + " \\", eol: span[0].eol}}
		for i, h := range ed.Hashes {
			l := reqLine{text: indent + "--hash=sha256:" + h, eol: span[0].eol}
			if i < len(ed.Hashes)-1 {
				l.text += " \\"
			} else {
				l.eol = lastEOL
			}
			out = append(out, l)
		}
		// Any other text on the continuation lines would be lost.
		for i, l := range span[1:] {
			rest := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(reqHashTokRE.ReplaceAllString(l.text, "")), "\\"))
			if rest != "" {
				return nil, fmt.Errorf("continuation line %d holds text besides hashes", i+2)
			}
		}
		return out, nil
	}
	return nil, errors.New("the hashes are laid out in a way the rewrite does not keep")
}

// verifyRewrite checks that new is a requirements file the plan reads and
// that it differs from old only as edits say: every requirement is still
// there, edited ones at their new version, the rest untouched.
func verifyRewrite(old, new []byte, edits []reqEdit) error {
	lo, err := parseRequirements(old)
	if err != nil {
		return fmt.Errorf("the original file: %w", err)
	}
	ln, err := parseRequirements(new)
	if err != nil {
		return fmt.Errorf("the rewritten file: %w", err)
	}
	count := func(l *lockfile) map[string][]string {
		m := map[string][]string{}
		for k, p := range l.pkgs {
			for _, o := range p.occs {
				m[k] = append(m[k], o.Version+"|"+o.Constraint+"|"+o.Marker)
			}
		}
		for k := range m {
			sort.Strings(m[k])
		}
		return m
	}
	want := count(lo)
	oldLines := splitReqLines(old)
	for _, ed := range edits {
		// The edited line's name is the one on its first physical line.
		pre := pipCommentRE.ReplaceAllString(oldLines[ed.Line-1].text, "")
		nm := pipNameRE.FindStringSubmatch(strings.TrimSpace(strings.TrimPrefix(pre, "\xef\xbb\xbf")))
		if nm == nil {
			return fmt.Errorf("line %d has no requirement", ed.Line)
		}
		k := ln.key(nm[1])
		vs := want[k]
		found := false
		for i, v := range vs {
			if strings.HasPrefix(v, ed.OldVersion+"|") {
				vs[i] = ed.NewVersion + v[len(ed.OldVersion):]
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("line %d: %s is not pinned at %s in the original", ed.Line, nm[1], ed.OldVersion)
		}
		sort.Strings(vs)
	}
	got := count(ln)
	if len(got) != len(want) {
		return errors.New("the rewritten file lists different packages")
	}
	for k, vs := range want {
		g := got[k]
		if len(g) != len(vs) {
			return fmt.Errorf("the rewritten file lists %s differently", k)
		}
		for i := range vs {
			if g[i] != vs[i] {
				return fmt.Errorf("the rewritten file lists %s differently", k)
			}
		}
	}
	return nil
}

// --- the environment pip resolves for ---

// ImageEnv is what a scanned running image says about the environment its
// Python packages run in.
type ImageEnv struct {
	Platform inventory.Platform
	OSFamily string
	OSName   string
}

// ImageEnvs lists the environments of the cycle's scanned images by their
// entity key, as plan items name them.
func ImageEnvs(inputs []ImageInput) map[string]ImageEnv {
	out := map[string]ImageEnv{}
	for _, in := range inputs {
		if in.Scan.Err != nil || !in.Scan.Pinned {
			continue
		}
		p := in.Scan.Platform
		if p.OS == "" || p.Architecture == "" {
			p = in.Scan.Subject.Key.Platform
		}
		out[entityString(in.Scan.Subject.Key)] = ImageEnv{Platform: p, OSFamily: in.Scan.OSFamily, OSName: in.Scan.OSName}
	}
	return out
}

// glibcMinor is the glibc 2.x of the distribution releases the platform
// tags are decided for. A release not listed here is not guessed.
var (
	debianGlibc = map[int]int{10: 28, 11: 31, 12: 36, 13: 41}
	ubuntuGlibc = map[string]int{"18.04": 27, "20.04": 31, "22.04": 35, "24.04": 39, "24.10": 40, "25.04": 41}
)

var (
	pyMinorPathRE = regexp.MustCompile(`(?:^|/)python(3\.[0-9]{1,2})(?:/|$)`)
	osVersionRE   = regexp.MustCompile(`^([0-9]+)(?:\.([0-9]+))?`)
)

// pipPythonVersion reads the Python X.Y a package was installed under from
// the path the scanner found it at ("usr/local/lib/python3.12/site-packages/...")
// or, failing that, the Result target.
func pipPythonVersion(o FindingOrigin) (string, bool) {
	for _, s := range []string{o.PkgPath, o.Target} {
		if m := pyMinorPathRE.FindStringSubmatch(s); m != nil {
			return m[1], true
		}
	}
	return "", false
}

// pipPlatforms lists the platform tags pip is given for a Linux image: the
// tags the C library the image runs allows, newest first. pip does not add the
// older compatible tags by itself, so they are listed:
//
//   - Debian and Ubuntu use glibc: manylinux_2_<n> for the release's glibc
//     minor n down to 2_17 (the oldest for aarch64), then manylinux2014 (pip
//     expands that alias to the older manylinux2010 and manylinux1 tags) and,
//     on x86_64, manylinux_2_12 and manylinux_2_5 for wheels named only that
//     way. Releases are looked up in a table (Debian 10..13, Ubuntu 18.04
//     to 25.04); another release is not decided.
//   - Alpine from 3.13 uses musl 1.2: musllinux_1_2, 1_1 and 1_0.
//
// ok is false when the architecture, the family or the release is not one of
// those.
func pipPlatforms(osFamily, osName string, p inventory.Platform) ([]string, bool) {
	var arch string
	switch p.Architecture {
	case "amd64":
		arch = "x86_64"
	case "arm64":
		arch = "aarch64"
	default:
		return nil, false
	}
	if p.OS != "linux" || (p.Variant != "" && p.Variant != "v8") {
		return nil, false
	}
	switch osFamily {
	case "alpine":
		m := osVersionRE.FindStringSubmatch(osName)
		if m == nil || m[2] == "" {
			return nil, false
		}
		maj, _ := strconv.Atoi(m[1])
		min, _ := strconv.Atoi(m[2])
		if maj < 3 || (maj == 3 && min < 13) {
			return nil, false
		}
		return []string{"musllinux_1_2_" + arch, "musllinux_1_1_" + arch, "musllinux_1_0_" + arch}, true
	case "debian", "ubuntu":
		minor, ok := 0, false
		if osFamily == "debian" {
			if m := osVersionRE.FindStringSubmatch(osName); m != nil {
				maj, _ := strconv.Atoi(m[1])
				minor, ok = debianGlibc[maj]
			}
		} else if m := osVersionRE.FindStringSubmatch(osName); m != nil && m[2] != "" {
			minor, ok = ubuntuGlibc[m[1]+"."+m[2]]
		}
		if !ok {
			return nil, false
		}
		var out []string
		for n := minor; n >= 17; n-- {
			out = append(out, fmt.Sprintf("manylinux_2_%d_%s", n, arch))
		}
		out = append(out, "manylinux2014_"+arch)
		if arch == "x86_64" {
			out = append(out, "manylinux_2_12_"+arch, "manylinux_2_5_"+arch)
		}
		return out, true
	}
	return nil, false
}

// pipTargetOf decides the environment pip resolves for from the origins of
// the item's packages. All origins must agree; undecided is true when one
// cannot be decided, mismatch when two decide differently.
func pipTargetOf(pkgs []LanguagePackage, images map[string]ImageEnv) (t *worker.Target, undecided, mismatch bool, detail string) {
	var chosen *worker.Target
	var chosenFrom string
	seen := 0
	for _, p := range pkgs {
		for _, o := range p.Origins {
			seen++
			env, ok := images[o.Entity]
			if !ok {
				return nil, true, false, fmt.Sprintf("the scan of %s is not known", o.Entity)
			}
			py, ok := pipPythonVersion(o)
			if !ok {
				return nil, true, false, fmt.Sprintf("the Python version of %s is not in %q or %q", o.Name, o.PkgPath, o.Target)
			}
			plats, ok := pipPlatforms(env.OSFamily, env.OSName, env.Platform)
			if !ok {
				return nil, true, false, fmt.Sprintf("no platform tags are decided for %s %s on %s/%s", env.OSFamily, env.OSName, env.Platform.OS, env.Platform.Architecture)
			}
			cand := &worker.Target{
				PythonVersion: py, Platforms: plats, Implementation: "cp",
				ABIs: []string{"cp" + strings.Replace(py, ".", "", 1)},
			}
			from := fmt.Sprintf("%s (Python %s, %s %s %s/%s)", o.Workload, py, env.OSFamily, env.OSName, env.Platform.OS, env.Platform.Architecture)
			if chosen == nil {
				chosen, chosenFrom = cand, from
				continue
			}
			if !sameTarget(*chosen, *cand) {
				return nil, false, true, fmt.Sprintf("%s and %s run in different environments", chosenFrom, from)
			}
		}
	}
	if seen == 0 {
		return nil, true, false, "the packages have no scanned origin"
	}
	return chosen, false, false, ""
}

func sameTarget(a, b worker.Target) bool {
	return a.PythonVersion == b.PythonVersion && a.Implementation == b.Implementation &&
		strings.Join(a.Platforms, ",") == strings.Join(b.Platforms, ",") && strings.Join(a.ABIs, ",") == strings.Join(b.ABIs, ",")
}

// normalizeSpecifier reads a PEP 440 specifier set (">=3.8, !=3.9.*") and
// returns its clauses joined by commas without spaces; ok is false for text
// that is not one.
// Bounds on a version specifier: its length and its number of clauses. A
// longer one is not judged.
const (
	maxSpecifierBytes   = 4096
	maxSpecifierClauses = 64
)

func normalizeSpecifier(s string) (string, bool) {
	if strings.TrimSpace(s) == "" {
		return "", true
	}
	if len(s) > maxSpecifierBytes || strings.Count(s, ",") >= maxSpecifierClauses {
		return "", false
	}
	var clauses []string
	for _, c := range strings.Split(s, ",") {
		cm := pipClauseRE.FindStringSubmatch(strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(c), " ", "")))
		if cm == nil {
			return "", false
		}
		clauses = append(clauses, cm[1]+cm[2])
	}
	return strings.Join(clauses, ","), true
}

// pythonMinorAllows reports whether every Python X.Y.z, whatever the patch
// level, satisfies the requires-python specifier. decided is false when some
// patch levels satisfy it and others do not, or the specifier cannot be
// judged.
func pythonMinorAllows(spec, minor string) (ok, decided bool) {
	norm, valid := normalizeSpecifier(spec)
	if !valid {
		return false, false
	}
	if norm == "" {
		return true, true
	}
	// The patch levels to try: the lowest, a high one, and every patch level
	// the specifier names (a clause such as != 3.12.1 is decided by that one).
	samples := []string{minor + ".0", minor + ".9999"}
	for _, c := range strings.Split(norm, ",") {
		cm := pipClauseRE.FindStringSubmatch(c)
		if cm == nil {
			continue
		}
		lit := strings.TrimSuffix(cm[2], ".*")
		if strings.HasPrefix(lit, minor+".") {
			samples = append(samples, lit)
		}
	}
	var results []bool
	for _, sample := range samples {
		v, parsed := parsePEP440(sample)
		if !parsed {
			return false, false
		}
		ok, evaluable := pySatisfies(v, norm)
		if !evaluable {
			return false, false
		}
		results = append(results, ok)
	}
	for _, r := range results[1:] {
		if r != results[0] {
			return false, false
		}
	}
	return results[0], true
}

// pythonLowerBound returns the lowest Python the project's requires-python
// admits, read from a ">=" (or "~=" or "==X.*") clause; ok is false when it
// has none that can be read.
func pythonLowerBound(spec string) (string, bool) {
	norm, valid := normalizeSpecifier(spec)
	if !valid || norm == "" {
		return "", false
	}
	best, found := "", false
	var bestV pyVersion
	for _, c := range strings.Split(norm, ",") {
		var v string
		switch {
		case strings.HasPrefix(c, ">="):
			v = strings.TrimPrefix(c, ">=")
		case strings.HasPrefix(c, "~="):
			v = strings.TrimPrefix(c, "~=")
		case strings.HasPrefix(c, "==") && strings.HasSuffix(c, ".*"):
			v = strings.TrimSuffix(strings.TrimPrefix(c, "=="), ".*") + ".0"
		default:
			continue
		}
		pv, ok := parsePEP440(v)
		if !ok {
			return "", false
		}
		if !found || pv.compare(bestV) > 0 {
			best, bestV, found = v, pv, true
		}
	}
	return best, found
}
