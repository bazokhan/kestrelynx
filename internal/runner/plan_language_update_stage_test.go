package runner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

type recordingUpdater struct {
	ran  int
	mark func(*remediation.Plan)
}

func (u *recordingUpdater) Run(_ context.Context, plan *remediation.Plan) remediation.LangUpdateUsage {
	u.ran++
	if u.mark != nil {
		u.mark(plan)
	}
	return remediation.LangUpdateUsage{Jobs: 1}
}

func languagePlanWith(cats ...remediation.Category) *remediation.Plan {
	p := &remediation.Plan{}
	for _, c := range cats {
		p.LanguageItems = append(p.LanguageItems, remediation.LanguageItem{Key: string(c), Category: c, Reason: remediation.ReasonUpdateCandidateInSource})
	}
	return p
}

func TestRunLanguageUpdates(t *testing.T) {
	ctx := context.Background()
	in := LanguageUpdateInput{GitHub: nil}

	t.Run("a unit that is not a candidate needs no stage", func(t *testing.T) {
		built := 0
		cfg := &LanguageUpdateConfig{NewUpdater: func(context.Context, LanguageUpdateInput) (LanguageUpdater, error) {
			built++
			return &recordingUpdater{}, nil
		}}
		Runner{}.runLanguageUpdates(ctx, cfg, languagePlanWith(remediation.CategoryManual, remediation.CategoryRebuildExpected), nil, in)
		if built != 0 {
			t.Errorf("the stage was built %d times", built)
		}
	})

	t.Run("without a work image every candidate is deferred and nothing runs", func(t *testing.T) {
		built := 0
		cfg := &LanguageUpdateConfig{
			Unavailable: &LanguageUnavailable{Reason: remediation.ReasonWorkImageNotConfigured, Detail: "no work image"},
			NewUpdater: func(context.Context, LanguageUpdateInput) (LanguageUpdater, error) {
				built++
				return &recordingUpdater{}, nil
			},
		}
		p := languagePlanWith(remediation.CategoryDependencyUpdateCandidate, remediation.CategoryManual, remediation.CategoryDependencyUpdateCandidate)
		Runner{}.runLanguageUpdates(ctx, cfg, p, nil, in)
		if built != 0 {
			t.Error("the stage was built although it is unavailable")
		}
		for i, it := range p.LanguageItems {
			switch i {
			case 1:
				if it.Category != remediation.CategoryManual {
					t.Errorf("a manual item changed: %+v", it)
				}
			default:
				if it.Category != remediation.CategoryDeferred || it.Reason != remediation.ReasonWorkImageNotConfigured || it.Detail != "no work image" {
					t.Errorf("item %d = %s/%s/%s", i, it.Category, it.Reason, it.Detail)
				}
			}
		}
	})

	t.Run("a work image that cannot be made ready defers the candidates with its reason", func(t *testing.T) {
		cfg := &LanguageUpdateConfig{NewUpdater: func(context.Context, LanguageUpdateInput) (LanguageUpdater, error) {
			return nil, errors.New("pull failed: " + strings.Repeat("x", 500))
		}}
		p := languagePlanWith(remediation.CategoryDependencyUpdateCandidate)
		Runner{}.runLanguageUpdates(ctx, cfg, p, nil, LanguageUpdateInput{GitHub: fakeReader{}})
		it := p.LanguageItems[0]
		if it.Category != remediation.CategoryDeferred || it.Reason != remediation.ReasonWorkImageUnavailable || !strings.Contains(it.Detail, "pull failed") || len(it.Detail) > 400 {
			t.Errorf("item = %s/%s/%q", it.Category, it.Reason, it.Detail)
		}
	})

	t.Run("items tied to a pull request need no work image", func(t *testing.T) {
		built := 0
		cfg := &LanguageUpdateConfig{NewUpdater: func(context.Context, LanguageUpdateInput) (LanguageUpdater, error) {
			built++
			return nil, errors.New("pull failed")
		}}
		it := remediation.LanguageItem{
			Key: "deps:ex/app@main:.#npm", Manager: remediation.ManagerNpm, Category: remediation.CategoryDependencyUpdateCandidate,
			Source:   remediation.SourceRecord{Repository: "ex/app", BaseBranch: "main", Directory: ".", Files: []remediation.SourceFile{{Path: "package-lock.json", BlobSHA: strings.Repeat("a", 40)}}},
			Packages: []remediation.LanguagePackage{{Name: "minimist", Ecosystem: "node-pkg", Installed: "1.2.5", SelectionLowerBound: "1.2.6", Action: remediation.ActionUpdate}},
		}
		store := fakeRecords{PRStoreFile: remediation.PRStoreFile{PRs: []remediation.PRRecord{{
			Repo: "ex/app", RepoID: 7, Kind: "language", State: remediation.PRStateOpen, BaseBranch: "main", Path: "package-lock.json", Number: 3,
			TargetKey: remediation.TargetKeyOf("language", 7, "main", "package-lock.json", []string{"."}),
			Lang:      &remediation.LangRecord{Manager: "npm", InputFingerprint: remediation.LanguageInputFingerprint(it)},
		}}}}
		other := it
		other.Key, other.Source.Directory = "deps:ex/app@main:other#npm", "other"
		other.Source.Files = []remediation.SourceFile{{Path: "other/package-lock.json", BlobSHA: strings.Repeat("b", 40)}}

		p := &remediation.Plan{LanguageItems: []remediation.LanguageItem{it}}
		Runner{}.runLanguageUpdates(ctx, cfg, p, store, LanguageUpdateInput{GitHub: fakeReader{}})
		if built != 0 || p.LanguageItems[0].Category != remediation.CategoryPRCandidate || p.LanguageItems[0].Reason != remediation.ReasonUpdateAlreadyProposed {
			t.Errorf("built %d, item %s/%s", built, p.LanguageItems[0].Category, p.LanguageItems[0].Reason)
		}
		// With a unit left to run, the failing work image defers only that one.
		p = &remediation.Plan{LanguageItems: []remediation.LanguageItem{other, it}}
		Runner{}.runLanguageUpdates(ctx, cfg, p, store, LanguageUpdateInput{GitHub: fakeReader{}})
		if built != 1 || p.LanguageItems[0].Category != remediation.CategoryDeferred || p.LanguageItems[0].Reason != remediation.ReasonWorkImageUnavailable ||
			p.LanguageItems[1].Reason != remediation.ReasonUpdateAlreadyProposed {
			t.Errorf("built %d, items %s/%s and %s/%s", built, p.LanguageItems[0].Category, p.LanguageItems[0].Reason, p.LanguageItems[1].Category, p.LanguageItems[1].Reason)
		}
	})

	t.Run("the stage runs over the plan", func(t *testing.T) {
		u := &recordingUpdater{mark: func(p *remediation.Plan) { p.LanguageItems[0].Category = remediation.CategoryPRCandidate }}
		cfg := &LanguageUpdateConfig{NewUpdater: func(context.Context, LanguageUpdateInput) (LanguageUpdater, error) { return u, nil }}
		p := languagePlanWith(remediation.CategoryDependencyUpdateCandidate)
		Runner{}.runLanguageUpdates(ctx, cfg, p, nil, LanguageUpdateInput{GitHub: fakeReader{}})
		if u.ran != 1 || p.LanguageItems[0].Category != remediation.CategoryPRCandidate {
			t.Errorf("ran %d, category %s", u.ran, p.LanguageItems[0].Category)
		}
	})

	t.Run("without a GitHub reader nothing runs", func(t *testing.T) {
		u := &recordingUpdater{}
		cfg := &LanguageUpdateConfig{NewUpdater: func(context.Context, LanguageUpdateInput) (LanguageUpdater, error) { return u, nil }}
		p := languagePlanWith(remediation.CategoryDependencyUpdateCandidate)
		Runner{}.runLanguageUpdates(ctx, cfg, p, nil, LanguageUpdateInput{})
		if u.ran != 0 || p.LanguageItems[0].Category != remediation.CategoryDeferred {
			t.Errorf("ran %d, category %s", u.ran, p.LanguageItems[0].Category)
		}
	})
}

func waitsTestItem(dir string) remediation.LanguageItem {
	lock := "package-lock.json"
	if dir != "." {
		lock = dir + "/package-lock.json"
	}
	return remediation.LanguageItem{
		Key: "deps:ex/app@main:" + dir + "#npm", Manager: remediation.ManagerNpm, Category: remediation.CategoryDependencyUpdateCandidate,
		Reason: remediation.ReasonUpdateCandidateInSource,
		Source: remediation.SourceRecord{Repository: "ex/app", BaseBranch: "main", Directory: dir,
			Files: []remediation.SourceFile{{Path: lock, BlobSHA: strings.Repeat("a", 40)}}},
		Packages: []remediation.LanguagePackage{{Name: "minimist", Ecosystem: "node-pkg", Installed: "1.2.5", SelectionLowerBound: "1.2.6", Action: remediation.ActionUpdate}},
	}
}

func waitRecord(it remediation.LanguageItem, kind string, seen time.Time) remediation.LangWaitRecord {
	lock := "package-lock.json"
	if it.Source.Directory != "." {
		lock = it.Source.Directory + "/package-lock.json"
	}
	return remediation.LangWaitRecord{
		Repo: it.Source.Repository, BaseBranch: it.Source.BaseBranch, LockPath: lock,
		InputFingerprint: remediation.LanguageInputFingerprint(it), Kind: kind, Count: 1, LastSeenAt: seen,
	}
}

func openPullRequestFor(it remediation.LanguageItem, number int) remediation.PRRecord {
	lock := it.Source.Files[0].Path
	return remediation.PRRecord{
		Repo: "ex/app", RepoID: 7, Kind: "language", State: remediation.PRStateOpen, BaseBranch: "main", Path: lock, Number: number, UpdateKey: "k",
		TargetKey: remediation.TargetKeyOf("language", 7, "main", lock, []string{it.Source.Directory}),
		Lang:      &remediation.LangRecord{Manager: "npm", InputFingerprint: remediation.LanguageInputFingerprint(it)},
	}
}

// TestRunLanguageUpdatesKeepsWaits checks that the waits of the items are
// saved on every way out of the stage after the items were bound, the ones that
// run nothing included.
func TestRunLanguageUpdatesKeepsWaits(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	earlier := now.Add(-48 * time.Hour)
	r := Runner{Now: func() time.Time { return now }}
	ctx := context.Background()
	built := 0
	cfg := &LanguageUpdateConfig{NewUpdater: func(context.Context, LanguageUpdateInput) (LanguageUpdater, error) {
		built++
		return &recordingUpdater{}, nil
	}}
	in := LanguageUpdateInput{GitHub: fakeReader{}}
	newStore := func(t *testing.T, f remediation.PRStoreFile) remediation.PRStore {
		t.Helper()
		f.NextSeq = 1
		s := remediation.PRStore{Dir: t.TempDir()}
		if err := s.Save(f); err != nil {
			t.Fatal(err)
		}
		return s
	}
	waitsOf := func(t *testing.T, s remediation.PRStore) []remediation.LangWaitRecord {
		t.Helper()
		f, _, err := s.Load()
		if err != nil {
			t.Fatal(err)
		}
		return f.LangWaits
	}

	t.Run("every item tied to a pull request: the waits end and the stops are seen", func(t *testing.T) {
		it := waitsTestItem(".")
		stopped := waitsTestItem("sub")
		wait := waitRecord(it, "budget_lookups", earlier)
		stop := waitRecord(stopped, "chain_stopped", earlier)
		stop.Count, stop.StopReason = 0, remediation.ReasonChainItemBudget
		pr := openPullRequestFor(it, 3)
		pr2 := openPullRequestFor(stopped, 4)
		store := newStore(t, remediation.PRStoreFile{PRs: []remediation.PRRecord{pr, pr2}, LangWaits: []remediation.LangWaitRecord{wait, stop}})
		p := &remediation.Plan{LanguageItems: []remediation.LanguageItem{it, stopped}}
		r.runLanguageUpdates(ctx, cfg, p, store, in)
		if built != 0 || p.LanguageItems[0].Reason != remediation.ReasonUpdateAlreadyProposed {
			t.Fatalf("built %d, item %s/%s", built, p.LanguageItems[0].Category, p.LanguageItems[0].Reason)
		}
		w := waitsOf(t, store)
		if len(w) != 1 || w[0].Kind != "chain_stopped" || !w[0].LastSeenAt.Equal(now) {
			t.Errorf("waits = %+v: the wait should be gone and the stop seen", w)
		}
	})

	t.Run("every item waiting for a release: nothing runs, the waits are kept and seen", func(t *testing.T) {
		it := waitsTestItem(".")
		wait := waitRecord(it, "release_age", earlier)
		wait.RetryAfter = now.Add(time.Hour)
		store := newStore(t, remediation.PRStoreFile{LangWaits: []remediation.LangWaitRecord{wait}})
		p := &remediation.Plan{LanguageItems: []remediation.LanguageItem{it}}
		r.runLanguageUpdates(ctx, cfg, p, store, in)
		got := p.LanguageItems[0]
		if built != 0 || got.Category != remediation.CategoryDeferred || got.Reason != remediation.ReasonReleaseTooNew || got.RetryAfter == nil || !got.RetryAfter.Equal(wait.RetryAfter) {
			t.Fatalf("built %d, item %s/%s/%v", built, got.Category, got.Reason, got.RetryAfter)
		}
		w := waitsOf(t, store)
		if len(w) != 1 || w[0].Kind != "release_age" || w[0].Count != 1 || !w[0].LastSeenAt.Equal(now) || !w[0].RetryAfter.Equal(wait.RetryAfter) {
			t.Errorf("waits = %+v", w)
		}
	})

	t.Run("the work image is not available: the waits are saved anyway", func(t *testing.T) {
		waiting, running, tied := waitsTestItem("a"), waitsTestItem("b"), waitsTestItem("c")
		w1 := waitRecord(waiting, "release_age", earlier)
		w1.RetryAfter = now.Add(time.Hour)
		w2 := waitRecord(running, "budget_time", earlier)
		w3 := waitRecord(tied, "budget_bytes", earlier)
		store := newStore(t, remediation.PRStoreFile{PRs: []remediation.PRRecord{openPullRequestFor(tied, 5)}, LangWaits: []remediation.LangWaitRecord{w1, w2, w3}})
		p := &remediation.Plan{LanguageItems: []remediation.LanguageItem{waiting, running, tied}}
		unavailable := &LanguageUpdateConfig{Unavailable: &LanguageUnavailable{Reason: remediation.ReasonWorkImageNotConfigured, Detail: "no work image"}}
		r.runLanguageUpdates(ctx, unavailable, p, store, in)
		if p.LanguageItems[1].Reason != remediation.ReasonWorkImageNotConfigured {
			t.Fatalf("running item = %s/%s", p.LanguageItems[1].Category, p.LanguageItems[1].Reason)
		}
		got := map[string]remediation.LangWaitRecord{}
		for _, w := range waitsOf(t, store) {
			got[w.Kind] = w
		}
		if len(got) != 2 || !got["release_age"].LastSeenAt.Equal(now) || !got["budget_time"].LastSeenAt.Equal(now) || got["budget_time"].Count != 1 {
			t.Errorf("waits = %+v: the tied item's wait ends, the others are seen and not counted", got)
		}
	})

	t.Run("the stage cannot be set up: the waits are saved anyway", func(t *testing.T) {
		it := waitsTestItem(".")
		wait := waitRecord(it, "budget_time", earlier)
		store := newStore(t, remediation.PRStoreFile{LangWaits: []remediation.LangWaitRecord{wait}})
		p := &remediation.Plan{LanguageItems: []remediation.LanguageItem{it}}
		r.runLanguageUpdates(ctx, cfg, p, store, LanguageUpdateInput{})
		if w := waitsOf(t, store); len(w) != 1 || !w[0].LastSeenAt.Equal(now) {
			t.Errorf("waits = %+v", w)
		}
	})

	t.Run("without records there is nothing to save and nothing fails", func(t *testing.T) {
		p := &remediation.Plan{LanguageItems: []remediation.LanguageItem{waitsTestItem(".")}}
		r.runLanguageUpdates(ctx, cfg, p, nil, in)
		if p.LanguageItems[0].Category != remediation.CategoryDependencyUpdateCandidate && p.LanguageItems[0].Category != remediation.CategoryPRCandidate {
			t.Errorf("item = %s/%s", p.LanguageItems[0].Category, p.LanguageItems[0].Reason)
		}
	})
}

// fakeReader stands in for the GitHub reader; the stage under test never
// calls it.
type fakeReader struct{ remediation.GitHubReader }

// fakeRecords is a pull request store that holds one file.
type fakeRecords struct{ remediation.PRStoreFile }

func (f fakeRecords) Lock() (func() error, error)                  { return func() error { return nil }, nil }
func (f fakeRecords) Load() (remediation.PRStoreFile, bool, error) { return f.PRStoreFile, true, nil }
func (f fakeRecords) Save(remediation.PRStoreFile) error           { return nil }
