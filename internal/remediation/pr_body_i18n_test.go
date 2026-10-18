package remediation

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

var updateBodyGolden = os.Getenv("KESTRELYNX_UPDATE_GOLDEN") != ""

func bodyFixtureEvidence() *VerificationSummary {
	dbAt := time.Date(2026, 10, 9, 1, 2, 3, 0, time.UTC)
	vuln := func(id, pkg string, kev bool, sev string, pr Priority) VulnSummary {
		return VulnSummary{VulnID: id, Package: PackageCoord{Ecosystem: "debian", Class: inventory.ClassOS, Name: pkg}, Severity: sev, KEV: kev, Priority: pr}
	}
	return &VerificationSummary{
		TrivyVersion: "0.71.2", VulnDBUpdatedAt: &dbAt, Severities: []string{"CRITICAL", "HIGH"}, Scope: "os packages",
		PlanGeneratedAt: time.Date(2026, 10, 9, 4, 0, 0, 0, time.UTC),
		Items: []ItemEvidence{{
			Current:        ImageState{Ref: "nginx:1.25.3", ConfigDigest: "sha256:" + hex64('a'), Platform: "linux/amd64", DigestKindUnverified: true},
			CurrentBase:    &ImageState{Ref: "debian:12.5", TopDigest: topDigest('b'), ManifestDigest: topDigest('c'), ConfigDigest: topDigest('d'), Platform: "linux/amd64"},
			Layers:         &LayerConfirmation{Status: "confirmed", BaseLayers: 3, ImageLayers: 7},
			Candidate:      ImageState{Ref: "nginx:1.25.4", TopDigest: topDigest('1'), ManifestDigest: topDigest('2'), ConfigDigest: topDigest('3'), Platform: "linux/amd64"},
			BaselineScan:   "scan-base-1",
			CandidateScan:  "scan-cand-1",
			Locations:      []string{"services.web.image", "services.worker.image"},
			Resolved:       []VulnSummary{vuln("CVE-2026-0001", "libc6", true, "CRITICAL", PriorityActNow), vuln("CVE-2026-0002", "openssl", false, "HIGH", PriorityNone)},
			Remaining:      []VulnSummary{vuln("CVE-2026-0003", "zlib1g", false, "HIGH", PriorityNone)},
			OtherRemaining: []VulnSummary{vuln("CVE-2026-0004", "tar", false, "", PriorityNone)},
		}},
	}
}

// bodyFixtures renders one body of each kind, for the given wording.
func bodyFixtures(t *testing.T, lang BodyLanguage) map[string]string {
	t.Helper()
	marker := encodeMarker(sampleMarker())
	out := map[string]string{}
	var err error

	out["compose"], err = buildPRBody(prBodyInput{
		Repo: testRepo, BaseBranch: "main", BaseSHA: hex40('1'), Path: "compose.yml", Current: "nginx:1.25.3",
		Services:    []string{"web", "worker"},
		Locations:   []string{"services.web.image", "services.worker.image"},
		Workloads:   []string{"compose/app/web", "compose/app/worker"},
		AlsoRunning: []ServiceRef{{Project: "app", Service: "extra", Container: "app-extra-1"}, {Container: "loose"}},
		Changes: []ComposeChange{
			{Service: "web", Location: "services.web.image", Old: "nginx:1.25.3", New: "nginx:1.25.4"},
			{Service: "worker", Location: "services.worker.image", Old: "nginx:1.25.3", New: "nginx:1.25.4"},
		},
		CandidateTag: "1.25.4", Evidence: bodyFixtureEvidence(), UpdateKey: "uk1", AttemptKey: "ak1", Marker: marker,
		Language: lang,
	})
	if err != nil {
		t.Fatal(err)
	}

	out["dockerfile"], err = buildDockerfilePRBody(dockerfileBodyInput{
		Repo: testRepo, BaseBranch: "main", BaseSHA: hex40('1'), Path: "build/Dockerfile", Current: "app:2.0",
		Workloads: []string{"compose/app/web"}, Stage: 1, Change: DockerfileChange{Stage: 1, Line: 3, Old: "debian:12.5", New: "debian:12.6"},
		CandidateTag: "12.6", Evidence: bodyFixtureEvidence(), UpdateKey: "uk2", AttemptKey: "ak2", Marker: marker,
		Language: lang,
	})
	if err != nil {
		t.Fatal(err)
	}

	out["language"], err = buildLanguagePRBody(languageBodyFixture(lang, marker, true))
	if err != nil {
		t.Fatal(err)
	}
	noDB := languageBodyFixture(lang, marker, true)
	noDB.Item.SourceCheck.Conditions.VulnerabilityDB.UpdatedAt = time.Time{}
	out["language_nodb"], err = buildLanguagePRBody(noDB)
	if err != nil {
		t.Fatal(err)
	}
	out["language_minimal"], err = buildLanguagePRBody(languageBodyFixture(lang, marker, false))
	if err != nil {
		t.Fatal(err)
	}
	chain := languageBodyFixture(lang, marker, true)
	chain.Item.Manager = ManagerNpm
	chain.LockPath = "svc/package-lock.json"
	chain.Record.Chain = []LangChainMove{
		{Name: "mkdirp", From: "0.5.1", To: "0.5.6", Held: "minimist", HeldRange: "0.0.8"},
		{Name: "optimist", From: "0.6.0", To: "0.6.1", Held: "minimist", HeldRange: "~0.0.1", HeldBy: "wordwrap"},
	}
	chain.Item.SourceCheck.Basis = "package_version_vuln_edges"
	out["language_chain"], err = buildLanguagePRBody(chain)
	if err != nil {
		t.Fatal(err)
	}
	checked := languageBodyFixture(lang, marker, true)
	checked.Item.Manager = ManagerNpm
	checked.LockPath = "svc/package-lock.json"
	checked.Record.Chain = []LangChainMove{{Name: "mkdirp", From: "0.5.1", To: "0.5.6", Held: "minimist", HeldRange: "0.0.8"}}
	checked.Item.SourceCheck.Basis = "package_version_vuln_edges_positions"
	checked.Item.SourceCheck.ChainCarried = []ChainCarried{{Package: "rc", From: "1.2.8", To: "1.2.9", VulnID: "CVE-2026-0001", Positions: 1}, {Package: "x", From: "1", To: "2", VulnID: "CVE-2026-0002", Positions: 2}}
	out["language_chain_positions"], err = buildLanguagePRBody(checked)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func languageBodyFixture(lang BodyLanguage, marker string, full bool) languageBodyInput {
	item := &LanguageItem{
		Manager: ManagerPnpm,
		Packages: []LanguagePackage{
			{Name: "lodash", Installed: "4.17.20", AdoptedVersion: "4.17.21", Relation: RelationDirect, Action: ActionUpdate,
				CVEs: []CVERef{{VulnID: "CVE-2026-1111", Severity: scanner.SeverityCritical, KEV: true, Priority: PriorityActNow}}},
			{Name: "minimist", Installed: "0.2.1", AdoptedVersion: "1.2.8", Relation: RelationTransitive, Action: ActionUpdate,
				CVEs: []CVERef{{VulnID: "CVE-2026-2222", Severity: scanner.SeverityHigh}}},
			{Name: "left-pad", Installed: "1.0.0", Relation: RelationMixed, Action: ActionManual},
			{Name: "odd", Installed: "2.0.0", AdoptedVersion: "2.0.1", Action: ActionUpdate},
		},
	}
	rec := &LangRecord{Manager: "pnpm", Packages: []LangKeyEntry{{Ecosystem: "node-pkg", Name: "lodash", Adopted: "4.17.21"}, {Ecosystem: "node-pkg", Name: "minimist", Adopted: "1.2.8"}}}
	files := []FileChange{{Path: "svc/pnpm-lock.yaml"}, {Path: "svc/package.json"}}
	in := languageBodyInput{
		Repo: testRepo, BaseBranch: "main", BaseSHA: hex40('1'), LockPath: "svc/pnpm-lock.yaml", Root: "svc",
		Item: item, Record: rec, Files: files, Workloads: []string{"compose/app/web"},
		UpdateKey: "uk3", AttemptKey: "ak3", Marker: marker,
		Language: lang,
	}
	if !full {
		item.Manager = ManagerUv
		item.Packages = item.Packages[:1]
		rec.Packages = rec.Packages[:1]
		in.Files = files[:1]
		return in
	}
	rec.ManifestEdits = []LangEdit{
		{File: "svc/package.json", Section: "dependencies", Name: "minimist", From: "^0.2.0", To: "^1.2.8", Major: true},
		{File: "svc/package.json", Section: "devDependencies", Name: "lodash", From: "^4.17.0", To: "^4.17.21"},
	}
	rec.Runtime = &RuntimeRecord{ID: "node24", Version: "24.21.0", Image: "node@sha256:" + strings.Repeat("c", 64), Support: "lts", EOL: "2028-04-30"}
	rec.Tool = &ToolRecord{Name: "pnpm", Version: "11.28.2", Source: toolSourceDefaultInRange, SHA256: strings.Repeat("d", 64)}
	rec.DeprecatedChanged = 2
	rec.DeprecatedNotes = []DeprecationChange{{Name: "eslint", Version: "9.39.4", Kind: DeprecationGained}, {Name: "glob", Version: "7.2.3", Kind: DeprecationChanged}, {Name: "tar", Version: "6.2.1", Kind: DeprecationPresent}, {Name: "rimraf", Version: "3.0.2", Kind: DeprecationLost}}
	rec.Followed = []FollowedEntry{{Entry: "browserslist@4.28.2", Moves: []FollowMove{{Name: "caniuse-lite", From: "1.0.30001792", To: "1.0.30001806"}}}}
	item.Update = &LanguageUpdate{
		Steps: []UpdateStep{{Op: "pnpm update lodash", ExitCode: 0}, {Op: "pnpm install --lockfile-only", Scratch: true, ExitCode: 0}},
		Notes: []string{"the declared packageManager differs from the one installed"},
		Diff:  &DependencyDiff{Added: []string{"semver@7.5.4"}, Changed: []string{"lodash@4.17.20 -> 4.17.21"}, Removed: nil, Truncated: true},
	}
	item.SourceCheck = &SourceCheck{
		Before: []HashedFile{{Path: "svc/pnpm-lock.yaml", SHA256: strings.Repeat("a", 64)}},
		After:  []HashedFile{{Path: "svc/pnpm-lock.yaml", SHA256: strings.Repeat("b", 64)}},
		Conditions: scanner.ScanConditions{TrivyVersion: "0.71.2", VulnerabilityDB: scanner.DBInfo{Version: 2, UpdatedAt: time.Date(2026, 10, 9, 1, 2, 3, 0, time.UTC)},
			Severities: []string{"CRITICAL", "HIGH"}},
		Counts: [3]int{2, 1, 0}, Truncated: true,
		Resolved:  []SourceVuln{{Package: "lodash", Version: "4.17.20", VulnID: "CVE-2026-1111", Severity: scanner.SeverityCritical, FixedVer: "4.17.21", KEV: true}, {Package: "minimist", Version: "0.2.1", VulnID: "CVE-2026-2222"}},
		Remaining: []SourceVuln{{Package: "semver", Version: "7.5.4", VulnID: "CVE-2026-3333", Severity: scanner.SeverityHigh}},
	}
	return in
}

func goldenPath(kind string, lang BodyLanguage) string {
	return filepath.Join("testdata", "pr_body", kind+"."+string(lang)+".md")
}

func TestPRBodyGolden(t *testing.T) {
	for _, lang := range []BodyLanguage{BodyEN, BodyJA} {
		for kind, got := range bodyFixtures(t, lang) {
			path := goldenPath(kind, lang)
			if updateBodyGolden {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				continue
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%s: %v (set KESTRELYNX_UPDATE_GOLDEN=1 to write it)", path, err)
			}
			if got != string(want) {
				t.Errorf("%s differs from the golden file:\n%s", path, got)
			}
		}
	}
}

func TestPRBodyEmptyLanguageIsEnglish(t *testing.T) {
	en, empty := bodyFixtures(t, BodyEN), bodyFixtures(t, "")
	for kind := range en {
		if en[kind] != empty[kind] {
			t.Errorf("%s: the empty language is not English", kind)
		}
	}
}

var codeSpanRE = regexp.MustCompile("`[^`]*`")

// lineKind is the Markdown role of a line, whatever its wording.
func lineKind(l string) string {
	switch {
	case strings.TrimSpace(l) == "":
		return "blank"
	case strings.HasPrefix(l, "### "):
		return "h3"
	case strings.HasPrefix(l, "## "):
		return "h2"
	case strings.HasPrefix(l, "  - "):
		return "sub"
	case strings.HasPrefix(l, "- "):
		return "item"
	case strings.HasPrefix(l, "**"):
		return "bold"
	case strings.HasPrefix(l, "<!--"):
		return "marker"
	case l == "---":
		return "rule"
	}
	return "text"
}

// TestPRBodyJapaneseKeepsEnglishStructure checks that the Japanese body has
// the same lines in the same roles as the English one, with the same code
// spans (names, versions, digests, paths, commands) and the same marker.
func TestPRBodyJapaneseKeepsEnglishStructure(t *testing.T) {
	en, ja := bodyFixtures(t, BodyEN), bodyFixtures(t, BodyJA)
	for kind := range en {
		el, jl := strings.Split(en[kind], "\n"), strings.Split(ja[kind], "\n")
		if len(el) != len(jl) {
			t.Errorf("%s: %d lines in English, %d in Japanese", kind, len(el), len(jl))
			continue
		}
		for i := range el {
			if lineKind(el[i]) != lineKind(jl[i]) {
				t.Errorf("%s line %d: role %s in English, %s in Japanese:\n  %s\n  %s", kind, i+1, lineKind(el[i]), lineKind(jl[i]), el[i], jl[i])
				continue
			}
			ec, jc := codeSpanRE.FindAllString(el[i], -1), codeSpanRE.FindAllString(jl[i], -1)
			sort.Strings(ec)
			sort.Strings(jc)
			if !reflect.DeepEqual(ec, jc) {
				t.Errorf("%s line %d: code spans differ:\n  %s\n  %s", kind, i+1, el[i], jl[i])
			}
			if lineKind(el[i]) == "marker" && el[i] != jl[i] {
				t.Errorf("%s: the marker differs", kind)
			}
		}
		me, err1 := parsePRMarker(en[kind])
		mj, err2 := parsePRMarker(ja[kind])
		if err1 != nil || err2 != nil || !reflect.DeepEqual(me, mj) {
			t.Errorf("%s: markers differ or do not parse: %v %v", kind, err1, err2)
		}
		if strings.Contains(ja[kind], "製品") {
			t.Errorf("%s: the Japanese body uses a banned word", kind)
		}
	}
}

var verbRE = regexp.MustCompile(`%(\[\d+\])?[sdv]`)

// verbs lists the argument slots of a format, each as index and verb.
func verbs(s string) []string {
	var out []string
	next := 1
	for _, m := range verbRE.FindAllStringSubmatch(s, -1) {
		idx := next
		if m[1] != "" {
			idx = 0
			for _, c := range m[1][1 : len(m[1])-1] {
				idx = idx*10 + int(c-'0')
			}
		}
		next = idx + 1
		out = append(out, string(rune('0'+idx))+m[0][len(m[0])-1:])
	}
	sort.Strings(out)
	return out
}

func TestPRTextDictionariesMatch(t *testing.T) {
	en, ja := reflect.ValueOf(enPRText), reflect.ValueOf(jaPRText)
	ty := en.Type()
	for i := 0; i < ty.NumField(); i++ {
		name := ty.Field(i).Name
		e, j := en.Field(i).String(), ja.Field(i).String()
		if e == "" || j == "" {
			t.Errorf("%s is empty in one language", name)
			continue
		}
		if !reflect.DeepEqual(verbs(e), verbs(j)) {
			t.Errorf("%s: arguments differ: %q / %q", name, e, j)
		}
		// The shape around the text, the line breaks and the list marker, is
		// what the layout depends on.
		shape := func(s string) string {
			lead := s[:len(s)-len(strings.TrimLeft(s, "\n"))]
			trail := s[len(strings.TrimRight(s, "\n")):]
			bullet := ""
			if t := strings.TrimLeft(s, "\n"); strings.HasPrefix(t, "- ") || strings.HasPrefix(t, "  - ") || strings.HasPrefix(t, "**") {
				bullet = t[:2]
			}
			return lead + "|" + trail + "|" + bullet + "|" + string(rune('0'+strings.Count(s, "\n")))
		}
		if shape(e) != shape(j) {
			t.Errorf("%s: layout differs: %q / %q", name, e, j)
		}
	}
}

func TestPRStageRejectsUnknownLanguage(t *testing.T) {
	h := newPRHarness(t)
	_, err := NewPRStage(PRStageConfig{GitHub: h.gh, Source: h.gh, Resolver: h.gh, Store: h.store, Limits: h.limits, Language: "fr"})
	if err == nil {
		t.Fatal("an unknown language was accepted")
	}
}

// runIn runs one cycle with the given wording.
func (h *prHarness) runIn(lang BodyLanguage, plan Plan) PRStageResult {
	h.t.Helper()
	h.clock = h.clock.Add(24 * time.Hour)
	now := h.clock
	stage, err := NewPRStage(PRStageConfig{GitHub: h.gh, Source: h.gh, Resolver: h.gh, Store: h.store, Limits: h.limits, Language: lang, Now: func() time.Time { return now }})
	if err != nil {
		h.t.Fatal(err)
	}
	res := stage.Run(context.Background(), PRStageInput{Plan: plan, Containers: h.containers, Mappings: h.mappings})
	h.gh.checkInvariants(h.t)
	return res
}

func TestPRStageBodyIsInTheConfiguredLanguage(t *testing.T) {
	for _, tc := range []struct {
		lang BodyLanguage
		want string
	}{{BodyEN, "## What"}, {BodyJA, "## 概要"}} {
		h := newPRHarness(t)
		wantStatus(t, onlyUnit(t, h.runIn(tc.lang, testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)))), PRStatusCreated, "")
		pr := h.gh.pulls(testRepo)[0]
		if !strings.Contains(pr.Body, tc.want) {
			t.Errorf("%s: body lacks %q:\n%s", tc.lang, tc.want, pr.Body)
		}
		if pr.Title != "Update nginx to 1.25.4 in compose.yml" {
			t.Errorf("%s: title %q", tc.lang, pr.Title)
		}
	}
}

// TestPRStageLanguageChangeLeavesPullRequestsAlone checks that a pull request
// written in one language is recognised in the other: nothing is written,
// nothing is marked as edited by someone else and nothing is replaced.
func TestPRStageLanguageChangeLeavesPullRequestsAlone(t *testing.T) {
	for _, order := range [][2]BodyLanguage{{BodyEN, BodyJA}, {BodyJA, BodyEN}} {
		h := newPRHarness(t)
		plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
		res := h.runIn(order[0], plan)
		wantStatus(t, onlyUnit(t, res), PRStatusCreated, "")
		if err := MarkPROperationsDelivered(h.store, res.LastSeq); err != nil {
			t.Fatal(err)
		}
		before := h.load()
		writes := h.gh.writeCount()

		res2 := h.runIn(order[1], plan)
		wantStatus(t, onlyUnit(t, res2), PRStatusOpen, "")
		if h.gh.writeCount() != writes || len(res2.Operations) != 0 || len(res2.Problems) != 0 {
			t.Errorf("%v: wrote %d, operations %d, problems %+v", order, h.gh.writeCount()-writes, len(res2.Operations), res2.Problems)
		}
		after := h.load()
		if len(after.PRs) != 1 || after.PRs[0].UserModified || after.PRs[0].Number != before.PRs[0].Number || after.PRs[0].AttemptKey != before.PRs[0].AttemptKey {
			t.Errorf("%v: record changed: before %+v after %+v", order, before.PRs, after.PRs)
		}
		if n := len(h.gh.pulls(testRepo)); n != 1 {
			t.Errorf("%v: %d pull requests", order, n)
		}
	}
}

// TestPRStageRecoversPullRequestOfOtherLanguage checks that a pull request is
// adopted from its marker alone, whatever the language of its text.
func TestPRStageRecoversPullRequestOfOtherLanguage(t *testing.T) {
	h := newPRHarness(t)
	plan := testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
	wantStatus(t, onlyUnit(t, h.runIn(BodyJA, plan)), PRStatusCreated, "")
	if err := os.RemoveAll(h.dir); err != nil {
		t.Fatal(err)
	}
	writes := h.gh.writeCount()
	res := h.runIn(BodyEN, plan)
	wantStatus(t, onlyUnit(t, res), PRStatusOpen, "")
	if h.gh.writeCount() != writes || len(h.gh.pulls(testRepo)) != 1 {
		t.Errorf("wrote %d, pull requests %d", h.gh.writeCount()-writes, len(h.gh.pulls(testRepo)))
	}
	if f := h.load(); len(f.PRs) != 1 || !f.PRs[0].Recovered || f.PRs[0].UserModified {
		t.Errorf("records = %+v", f.PRs)
	}
}

// bodyKind builds one pull request of a kind in a harness, for the stage tests.
type bodyKind struct {
	name string
	set  func(t *testing.T) (*prHarness, Plan)
}

func bodyKinds() []bodyKind {
	return []bodyKind{
		{"compose", func(t *testing.T) (*prHarness, Plan) {
			return newPRHarness(t), testPlan(nginxItem("1.25.4", '1', []string{"CVE-1"}, nil))
		}},
		{"dockerfile", func(t *testing.T) (*prHarness, Plan) {
			return newDFPRHarness(t), dfPlan(dfPlanItem("3.12.5-slim", '5', []string{"CVE-1", "CVE-2"}, []string{"CVE-3"}))
		}},
		{"language", func(t *testing.T) (*prHarness, Plan) {
			fx := langFixtures()["npm"]
			h := langHarness(t, fx)
			return h, prLangPlan(h.langItem(fx))
		}},
	}
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > 0x7f {
			return false
		}
	}
	return true
}

func TestPRStageBodyIsInTheConfiguredLanguageForEveryKind(t *testing.T) {
	for _, k := range bodyKinds() {
		for _, tc := range []struct {
			lang BodyLanguage
			want string
		}{{BodyEN, "## What"}, {BodyJA, "## 概要"}} {
			h, plan := k.set(t)
			wantStatus(t, onlyUnit(t, h.runIn(tc.lang, plan)), PRStatusCreated, "")
			pr := h.gh.pulls(testRepo)[0]
			if !strings.Contains(pr.Body, tc.want) {
				t.Errorf("%s/%s: body lacks %q", k.name, tc.lang, tc.want)
			}
			if !isASCII(pr.Title) {
				t.Errorf("%s/%s: the title is not English: %q", k.name, tc.lang, pr.Title)
			}
		}
	}
}

func TestPRStageLanguageChangeLeavesEveryKindAlone(t *testing.T) {
	for _, k := range bodyKinds() {
		for _, order := range [][2]BodyLanguage{{BodyEN, BodyJA}, {BodyJA, BodyEN}} {
			h, plan := k.set(t)
			res := h.runIn(order[0], plan)
			wantStatus(t, onlyUnit(t, res), PRStatusCreated, "")
			if err := MarkPROperationsDelivered(h.store, res.LastSeq); err != nil {
				t.Fatal(err)
			}
			before := h.load()
			title := h.gh.pulls(testRepo)[0].Title
			writes := h.gh.writeCount()

			res2 := h.runIn(order[1], plan)
			wantStatus(t, onlyUnit(t, res2), PRStatusOpen, "")
			if h.gh.writeCount() != writes || len(res2.Operations) != 0 || len(res2.Problems) != 0 {
				t.Errorf("%s %v: wrote %d, operations %d, problems %+v", k.name, order, h.gh.writeCount()-writes, len(res2.Operations), res2.Problems)
			}
			after := h.load()
			if len(after.PRs) != 1 || len(before.PRs) != 1 {
				t.Fatalf("%s %v: records %d -> %d", k.name, order, len(before.PRs), len(after.PRs))
			}
			b, a := before.PRs[0], after.PRs[0]
			if a.UserModified || a.Number != b.Number || a.UpdateKey != b.UpdateKey || a.AttemptKey != b.AttemptKey || a.TargetKey != b.TargetKey || a.State != b.State {
				t.Errorf("%s %v: record changed: %+v -> %+v", k.name, order, b, a)
			}
			pulls := h.gh.pulls(testRepo)
			if len(pulls) != 1 || pulls[0].Title != title {
				t.Errorf("%s %v: pull requests %d, title %q", k.name, order, len(pulls), pulls[0].Title)
			}
		}
	}
}

func TestPRStageRecoversEveryKindOfOtherLanguage(t *testing.T) {
	for _, k := range bodyKinds() {
		h, plan := k.set(t)
		wantStatus(t, onlyUnit(t, h.runIn(BodyJA, plan)), PRStatusCreated, "")
		if err := os.RemoveAll(h.dir); err != nil {
			t.Fatal(err)
		}
		writes := h.gh.writeCount()
		wantStatus(t, onlyUnit(t, h.runIn(BodyEN, plan)), PRStatusOpen, "")
		if h.gh.writeCount() != writes || len(h.gh.pulls(testRepo)) != 1 {
			t.Errorf("%s: wrote %d, pull requests %d", k.name, h.gh.writeCount()-writes, len(h.gh.pulls(testRepo)))
		}
		if f := h.load(); len(f.PRs) != 1 || !f.PRs[0].Recovered || f.PRs[0].UserModified {
			t.Errorf("%s: records = %+v", k.name, f.PRs)
		}
	}
}

func TestPRBodyJapaneseScanSentencesWithAndWithoutDatabaseTime(t *testing.T) {
	got := bodyFixtures(t, BodyJA)
	with, without := got["language"], got["language_nodb"]
	for _, want := range []string{
		"両方のスキャンで Trivy `0.71.2` を使用しました。",
		"脆弱性データベースは、どちらも 2026-10-09T01:02:03Z に作成されたものを使用しました。",
		"重大度の範囲 (`CRITICAL`、`HIGH`) と設定は、両方のスキャンで同じです。",
	} {
		if !strings.Contains(with, want) {
			t.Errorf("with the database time, the body lacks %q", want)
		}
		if strings.Contains(without, "データベース") && strings.Contains(want, "データベース") {
			t.Error("the database sentence is present without a database time")
		}
	}
	if strings.Contains(without, "脆弱性データベースは、どちらも") || !strings.Contains(without, "両方のスキャンで Trivy `0.71.2` を使用しました。") {
		t.Error("without the database time, the sentences are not independent")
	}
	if !strings.Contains(without, "重大度の範囲 (`CRITICAL`、`HIGH`) と設定は、両方のスキャンで同じです。") {
		t.Error("the severity sentence is missing without the database time")
	}
}

func bigEvidence(items, vulns int) *VerificationSummary {
	ev := bodyFixtureEvidence()
	var vs []VulnSummary
	for i := 0; i < vulns; i++ {
		vs = append(vs, VulnSummary{VulnID: "CVE-2026-" + strings.Repeat("9", 280), Package: PackageCoord{Ecosystem: "debian", Class: inventory.ClassOS, Name: strings.Repeat("あ", 250)}})
	}
	base := ev.Items[0]
	ev.Items = nil
	for i := 0; i < items; i++ {
		it := base
		it.Resolved = vs
		ev.Items = append(ev.Items, it)
	}
	return ev
}

func TestPRBodyJapaneseListsAreCountedAndCut(t *testing.T) {
	marker := encodeMarker(sampleMarker())
	// A list over its cap says how many are not shown; nothing is cut here.
	body, err := buildPRBody(prBodyInput{Repo: testRepo, BaseBranch: "main", BaseSHA: hex40('1'), Path: "compose.yml", Current: "nginx:1.25.3",
		Services: []string{"web"}, Workloads: []string{"w"}, CandidateTag: "1.25.4", Evidence: bigEvidence(1, maxListedVulns+7),
		UpdateKey: "uk", AttemptKey: "ak", Marker: marker, Language: BodyJA})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "- ほか 7 件\n") || strings.Contains(body, "省略しました") {
		t.Errorf("list over its cap:\n%s", body[:min(len(body), 3000)])
	}

	// A body over the limit is cut at a line, with the note and the whole marker.
	checkCut := func(name, body string) {
		t.Helper()
		if n := utf8.RuneCountInString(body); n > maxPRBodyChars {
			t.Errorf("%s: %d characters", name, n)
		}
		if !utf8.ValidString(body) {
			t.Errorf("%s: invalid UTF-8", name)
		}
		if !strings.Contains(body, jaPRText.CutNote) {
			t.Errorf("%s: no note that the text was cut", name)
		}
		if !strings.HasSuffix(body, "\n"+marker) {
			t.Errorf("%s: the marker is not whole and last", name)
		}
		if _, err := parsePRMarker(body); err != nil {
			t.Errorf("%s: marker: %v", name, err)
		}
	}
	big, err := buildPRBody(prBodyInput{Repo: testRepo, BaseBranch: "main", BaseSHA: hex40('1'), Path: "compose.yml", Current: "nginx:1.25.3",
		Services: []string{"web"}, Workloads: []string{"w"}, CandidateTag: "1.25.4", Evidence: bigEvidence(60, maxListedVulns+7),
		UpdateKey: "uk", AttemptKey: "ak", Marker: marker, Language: BodyJA})
	if err != nil {
		t.Fatal(err)
	}
	checkCut("compose", big)

	// A language body counts the packages and the vulnerabilities it does not list.
	in := languageBodyFixture(BodyJA, marker, true)
	var pkgs []LanguagePackage
	for i := 0; i < maxListedNames+10; i++ {
		var cves []CVERef
		for j := 0; j < maxListedVulns+5; j++ {
			cves = append(cves, CVERef{VulnID: "CVE-2026-" + strings.Repeat("7", 200+j), Severity: scanner.SeverityHigh})
		}
		pkgs = append(pkgs, LanguagePackage{Name: "pkg-" + strings.Repeat("あ", 30) + string(rune('a'+i%26)) + string(rune('a'+i/26)), Installed: "1.0.0", AdoptedVersion: "1.0.1", Action: ActionUpdate, CVEs: cves})
	}
	in.Item.Packages = pkgs
	lang, err := buildLanguagePRBody(in)
	if err != nil {
		t.Fatal(err)
	}
	checkCut("language", lang)
	if !strings.Contains(lang, "について、ほか 5 件\n") {
		t.Error("language: no count of the vulnerabilities not listed for a package")
	}
	// Without the cut, the line for packages over the cap reads in Japanese.
	in.Item.Packages = pkgs[:maxListedNames+3]
	for i := range in.Item.Packages {
		in.Item.Packages[i].CVEs = in.Item.Packages[i].CVEs[:1]
	}
	small, err := buildLanguagePRBody(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(small, "- ほか 3 個のパッケージ\n") || strings.Contains(small, "省略しました") {
		t.Error("language: no count of the packages not listed")
	}
}
