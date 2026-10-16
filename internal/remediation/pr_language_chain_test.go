package remediation

import (
	"strings"
	"testing"
)

// chainedItem is the npm fixture's item as a chain update leaves it: minimist
// taken to its fixed version through mkdirp.
func chainedItem(h *prHarness, fx langFixture) LanguageItem {
	it := h.langItem(fx)
	it.Packages[0].Through = []string{"mkdirp"}
	it.Update.Chain = &ChainUpdate{
		Outcome: ChainAdopted, Source: "chain_job",
		Blocked: []ChainBlock{{Package: "minimist", Version: "1.2.5", Parent: "mkdirp", ParentVersion: "0.5.1", Range: "0.0.8", Proof: "exact"}},
		Tops:    []ChainMove{{Name: "mkdirp", From: "0.5.1", To: "0.5.6", Kind: "top"}},
	}
	it.SourceCheck.Basis = "package_version_vuln_edges"
	return it
}

func TestLangUpdateKeyOfAnUpdateWithoutAChainIsWhatItWas(t *testing.T) {
	packages := []LangKeyEntry{{Ecosystem: "node-pkg", Name: "a", Positions: []string{"x"}, Adopted: "2"}}
	edits := []LangEdit{{File: "package.json", Section: "dependencies", Name: "a", From: "1", To: "2"}}
	// The key as it was computed before chains existed.
	type edit struct {
		File    string `json:"file"`
		Section string `json:"section"`
		Name    string `json:"name"`
		From    string `json:"from"`
		To      string `json:"to"`
	}
	type oldEntry struct {
		Ecosystem string   `json:"ecosystem"`
		Name      string   `json:"name"`
		Positions []string `json:"positions"`
		Adopted   string   `json:"adopted"`
	}
	want := hashCanonical(struct {
		TargetKey string     `json:"target_key"`
		Kind      string     `json:"kind"`
		Packages  []oldEntry `json:"packages"`
		Edits     []edit     `json:"manifest_edits"`
	}{"t", prKindLanguage, []oldEntry{{"node-pkg", "a", []string{"x"}, "2"}}, []edit{{"package.json", "dependencies", "a", "1", "2"}}})
	if got := LangUpdateKey("t", packages, edits); got != want {
		t.Errorf("key = %s, want %s", got, want)
	}
	if got := LangUpdateKey("t", packages, edits, []LangChainMove{}...); got != want {
		t.Errorf("an empty chain changes the key: %s", got)
	}
}

func TestLangUpdateKeyNamesTheDirectDependenciesTheChainMoved(t *testing.T) {
	packages := []LangKeyEntry{{Ecosystem: "node-pkg", Name: "a", Positions: []string{"x"}, Adopted: "2", Through: []string{"top"}}}
	one := []LangChainMove{{Name: "top", From: "1", To: "2", Held: "a", HeldRange: "1.0.0"}}
	base := LangUpdateKey("t", packages, nil, one...)
	if base == LangUpdateKey("t", packages, nil) {
		t.Error("the chain is not in the key")
	}
	// What is shown of the evidence is not part of it; the versions are.
	if LangUpdateKey("t", packages, nil, LangChainMove{Name: "top", From: "1", To: "2"}) != base {
		t.Error("the evidence is in the key")
	}
	for name, other := range map[string][]LangChainMove{
		"to":   {{Name: "top", From: "1", To: "3"}},
		"from": {{Name: "top", From: "0", To: "2"}},
		"name": {{Name: "other", From: "1", To: "2"}},
	} {
		if LangUpdateKey("t", packages, nil, other...) == base {
			t.Errorf("the key ignores %s", name)
		}
	}
	two := []LangChainMove{{Name: "b", From: "1", To: "2"}, {Name: "a", From: "1", To: "2"}}
	rev := []LangChainMove{two[1], two[0]}
	if LangUpdateKey("t", packages, nil, two...) != LangUpdateKey("t", packages, nil, rev...) {
		t.Error("the order of the moves is in the key")
	}
}

func TestMarkerOfAChainUpdateRoundTrips(t *testing.T) {
	m := sampleMarker()
	m.Kind = prKindLanguage
	m.Lang = &LangRecord{
		Manager:  "npm",
		Packages: []LangKeyEntry{{Ecosystem: "node-pkg", Name: "minimist", Positions: []string{"node_modules/minimist"}, Adopted: "1.2.8", Through: []string{"mkdirp"}}},
		Chain:    []LangChainMove{{Name: "mkdirp", From: "0.5.1", To: "0.5.6", Held: "minimist", HeldRange: "0.0.8"}},
	}
	m.TargetKey = TargetKeyOf(prKindLanguage, m.RepoID, m.BaseBranch, m.Path, m.Locations)
	m.UpdateKey = LangUpdateKey(m.TargetKey, m.Lang.Packages, m.Lang.ManifestEdits, m.Lang.Chain...)
	m.AttemptKey = AttemptKey(m.UpdateKey, m.BaseSHA, m.InputBlobSHA, m.Changes)
	got, err := parsePRMarker("x\n\n" + encodeMarker(m))
	if err != nil || got.verify(7) != nil {
		t.Fatalf("parse %+v err %v", got, err)
	}
	if len(got.Lang.Chain) != 1 || got.Lang.Chain[0].Name != "mkdirp" {
		t.Errorf("chain = %+v", got.Lang.Chain)
	}
	// A chain the key was not made from does not verify.
	tampered := m
	lang := *m.Lang
	lang.Chain = []LangChainMove{{Name: "mkdirp", From: "0.5.1", To: "0.5.9"}}
	tampered.Lang = &lang
	if g, _ := parsePRMarker(encodeMarker(tampered)); g.verify(7) == nil {
		t.Error("a marker whose chain does not give the update key verified")
	}
	bad := m
	badLang := *m.Lang
	badLang.Chain = []LangChainMove{{From: "1", To: "2"}}
	bad.Lang = &badLang
	if bad.Lang.wellFormed() == nil {
		t.Error("a chain move with no name is well formed")
	}
}

func TestPRStageOfAChainUpdate(t *testing.T) {
	fx := langFixtures()["npm"]
	h := langHarness(t, fx)
	u := onlyUnit(t, h.run(prLangPlan(chainedItem(h, fx))))
	wantStatus(t, u, PRStatusCreated, "")
	if u.Language == nil || len(u.Language.Chain) != 1 || u.Language.Chain[0].Name != "mkdirp" || len(u.Language.Packages[0].Through) != 1 {
		t.Fatalf("view = %+v", u.Language)
	}
	pr := h.gh.pulls(testRepo)[0]
	for _, want := range []string{"### Packages updated along with the fix", "- `mkdirp`: `0.5.1` to `0.5.6` (it required `minimist` `0.0.8`)", "in `package.json`.", "compared by package, version and vulnerability ID"} {
		if !strings.Contains(pr.Body, want) {
			t.Errorf("body lacks %q:\n%s", want, pr.Body)
		}
	}
	m, err := parsePRMarker(pr.Body)
	if err != nil || len(m.Lang.Chain) != 1 || m.Lang.Packages[0].Through[0] != "mkdirp" || m.verify(testRepoID) != nil {
		t.Fatalf("marker = %+v err %v", m.Lang, err)
	}
	// Without the chain the same update has another key and no section.
	h2 := langHarness(t, fx)
	plain := onlyUnit(t, h2.run(prLangPlan(h2.langItem(fx))))
	if plain.UpdateKey == u.UpdateKey {
		t.Error("the update key does not tell a chain update from a plain one")
	}
	if strings.Contains(h2.gh.pulls(testRepo)[0].Body, "Packages updated along with the fix") {
		t.Error("a plain update has the section")
	}
	// The same chain update planned again is the same pull request.
	writes := h.gh.writeCount()
	again := onlyUnit(t, h.run(prLangPlan(chainedItem(h, fx))))
	wantStatus(t, again, PRStatusOpen, "")
	if again.UpdateKey != u.UpdateKey || h.gh.writeCount() != writes {
		t.Errorf("key %s -> %s, writes %d -> %d", u.UpdateKey, again.UpdateKey, writes, h.gh.writeCount())
	}
	// A tied item shows the direct dependencies from the pull request's record.
	tied := candidateOf(chainedItem(h, fx))
	tied.Packages[0].Through = nil
	order, bound := BindProposedLanguageUpdates(&Plan{LanguageItems: []LanguageItem{tied}}, h.store)
	if bound != 1 || len(order) != 0 {
		t.Errorf("bound %d, order %v: the inputs are those of the pull request", bound, order)
	}
}
