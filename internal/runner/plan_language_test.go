package runner

import (
	"context"
	"crypto/sha1" //nolint:gosec // git blob IDs are SHA-1
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

const langCommit = "0123456789abcdef0123456789abcdef01234567"

const langManifest = `{"name":"web","dependencies":{"lodash":"^4.17.20"}}`

const langLock = `{"lockfileVersion":3,"packages":{
  "":{"name":"web","dependencies":{"lodash":"^4.17.20"}},
  "node_modules/lodash":{"version":"4.17.20","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz","integrity":"sha512-x"}}}`

func blobSHA(content string) string {
	h := sha1.New() //nolint:gosec
	fmt.Fprintf(h, "blob %d\x00%s", len(content), content)
	return hex.EncodeToString(h.Sum(nil))
}

// fakeSource serves one directory of one repository.
type fakeSource struct {
	repo      string
	files     map[string]string
	branchErr error
	calls     []string
}

func (f *fakeSource) ResolveBranch(_ context.Context, repo, branch string) (string, error) {
	f.calls = append(f.calls, "branch:"+repo)
	return langCommit, f.branchErr
}

func (f *fakeSource) ListDirectory(_ context.Context, repo, _, dir string) ([]github.Entry, error) {
	f.calls = append(f.calls, "list:"+repo+"/"+dir)
	var out []github.Entry
	for name, c := range f.files {
		out = append(out, github.Entry{Name: name, Path: name, Type: github.EntryFile, SHA: blobSHA(c)})
	}
	return out, nil
}

func (f *fakeSource) ReadFile(_ context.Context, repo, _, p string) (github.File, error) {
	f.calls = append(f.calls, "read:"+repo+"/"+p)
	c, ok := f.files[p]
	if !ok {
		return github.File{}, github.ErrNotFound
	}
	return github.File{Path: p, SHA: blobSHA(c), Content: []byte(c)}, nil
}

func nodeFinding(vuln, pkg, ver, fixed string) scanner.Finding {
	return scanner.Finding{
		Class: scanner.ClassLang, Type: "node-pkg", Target: "Node.js", Package: pkg, InstalledVer: ver, FixedVer: fixed,
		Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: vuln,
	}
}

// withSource gives the harness a dependency mapping for its service shop/web
// and a source factory that counts the clients it builds.
func (h *planHarness) withSource(src *fakeSource) *int {
	built := 0
	h.r.Plan.Dependencies = []remediation.DependencyMapping{
		{Workload: "compose/shop/web", Project: "shop", Service: "web", Repository: "ex/web", BaseBranch: "main", Directory: "."},
	}
	h.r.Plan.NewGitHub = func() remediation.GitHubReader {
		built++
		return src
	}
	return &built
}

func newLangSource() *fakeSource {
	return &fakeSource{repo: "ex/web", files: map[string]string{"package.json": langManifest, "package-lock.json": langLock}}
}

func TestPlan_LanguageItemsIncludedAndStored(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"), nodeFinding("CVE-2", "lodash", "4.17.20", "4.17.21"))
	src := newLangSource()
	built := h.withSource(src)
	h.run(t)

	p := h.notif.msg.Plan
	if p == nil || p.Plan == nil {
		t.Fatalf("Message.Plan = %+v", p)
	}
	if len(p.Plan.Items) != 1 || len(p.Plan.LanguageItems) != 1 {
		t.Fatalf("items = %d, language items = %d", len(p.Plan.Items), len(p.Plan.LanguageItems))
	}
	it := p.Plan.LanguageItems[0]
	if it.Category != remediation.CategoryDependencyUpdateCandidate || it.Manager != remediation.ManagerNpm ||
		it.Source.CommitSHA != langCommit || len(it.Packages) != 1 || it.Packages[0].SelectionLowerBound != "4.17.21" {
		t.Errorf("language item = %+v", it)
	}
	if it.Source.Files[1].BlobSHA != blobSHA(langLock) {
		t.Errorf("blob SHA = %q", it.Source.Files[1].BlobSHA)
	}
	if *built != 1 {
		t.Errorf("GitHub clients built = %d, want one for the cycle", *built)
	}
	if len(h.plans.saved) != 1 || len(h.plans.saved[0].LanguageItems) != 1 {
		t.Errorf("the saved plan lacks the language items: %+v", h.plans.saved)
	}
	if want := remediation.Fingerprint(*p.Plan); len(h.delivered.saves) != 1 || h.delivered.saves[0] != want {
		t.Errorf("delivered = %v, want %q", h.delivered.saves, want)
	}

	// The next cycle builds its own client.
	h.run(t)
	if *built != 2 {
		t.Errorf("GitHub clients built after two cycles = %d", *built)
	}
}

func TestPlan_LanguageChangeChangesFingerprint(t *testing.T) {
	without := newPlanHarness(osFinding("CVE-1"))
	without.run(t)

	with := newPlanHarness(osFinding("CVE-1"), nodeFinding("CVE-2", "lodash", "4.17.20", "4.17.21"))
	with.withSource(newLangSource())
	with.run(t)

	if len(without.delivered.saves) != 1 || len(with.delivered.saves) != 1 || without.delivered.saves[0] == with.delivered.saves[0] {
		t.Errorf("fingerprints: without=%v with=%v", without.delivered.saves, with.delivered.saves)
	}
}

func TestPlan_NoDependencyMappingsReadsNothing(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"), nodeFinding("CVE-2", "lodash", "4.17.20", "4.17.21"))
	called := false
	h.r.Plan.NewGitHub = func() remediation.GitHubReader { called = true; return newLangSource() }
	h.run(t)
	if called {
		t.Error("a GitHub client was built without dependency mappings")
	}
	if p := h.notif.msg.Plan; p == nil || p.Plan == nil || p.Plan.LanguageItems != nil {
		t.Errorf("plan = %+v", p)
	}
}

func TestPlan_GitHubFailureNeverStopsTheCycle(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"), nodeFinding("CVE-2", "lodash", "4.17.20", "4.17.21"))
	src := newLangSource()
	src.branchErr = &github.RateLimitedError{}
	h.withSource(src)
	h.run(t)

	if !h.notif.called || h.store.saved == nil {
		t.Fatal("the cycle did not complete")
	}
	p := h.notif.msg.Plan
	if p == nil || p.Plan == nil || len(p.Plan.LanguageItems) != 1 {
		t.Fatalf("plan = %+v", p)
	}
	if it := p.Plan.LanguageItems[0]; it.Category != remediation.CategoryDeferred || it.Reason != remediation.ReasonRateLimited {
		t.Errorf("language item = %s / %s", it.Category, it.Reason)
	}
	if len(p.Plan.Items) != 1 {
		t.Error("the image part was lost")
	}
}

func TestPlan_CycleTimeoutAlsoDefersLanguageUnits(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"), nodeFinding("CVE-2", "lodash", "4.17.20", "4.17.21"))
	src := newLangSource()
	h.withSource(src)
	h.reg.block = true
	h.r.Plan.CycleTimeout = 30 * 1000 * 1000 // 30ms
	h.run(t)

	p := h.notif.msg.Plan
	if p == nil || p.Plan == nil || len(p.Plan.LanguageItems) != 1 {
		t.Fatalf("plan = %+v", p)
	}
	if it := p.Plan.LanguageItems[0]; it.Category != remediation.CategoryDeferred || it.Reason != remediation.ReasonCycleDeadline {
		t.Errorf("language item = %s / %s; the language part shares the cycle deadline", it.Category, it.Reason)
	}
	if len(src.calls) != 0 {
		t.Errorf("GitHub was read after the deadline: %v", src.calls)
	}
}
