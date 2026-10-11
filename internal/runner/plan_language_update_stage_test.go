package runner

import (
	"context"
	"errors"
	"strings"
	"testing"

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

// fakeReader stands in for the GitHub reader; the stage under test never
// calls it.
type fakeReader struct{ remediation.GitHubReader }

// fakeRecords is a pull request store that holds one file.
type fakeRecords struct{ remediation.PRStoreFile }

func (f fakeRecords) Lock() (func() error, error)                  { return func() error { return nil }, nil }
func (f fakeRecords) Load() (remediation.PRStoreFile, bool, error) { return f.PRStoreFile, true, nil }
func (f fakeRecords) Save(remediation.PRStoreFile) error           { return nil }
