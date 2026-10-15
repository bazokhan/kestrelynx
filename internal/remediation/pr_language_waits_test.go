package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var waitsNow = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

// waitsItem is a dependency update candidate for the repository o/r.
func waitsItem(key string) LanguageItem {
	return LanguageItem{
		Key: key, Manager: ManagerNpm, Category: CategoryDependencyUpdateCandidate, Reason: ReasonUpdateCandidateInSource,
		Source: SourceRecord{Repository: "o/r", BaseBranch: "main", Directory: ".", Files: []SourceFile{
			{Path: "package-lock.json", BlobSHA: "b"}, {Path: "package.json", BlobSHA: "a"},
		}},
		Packages: []LanguagePackage{{Name: "t", Ecosystem: "node-pkg", Installed: "1.0.0", SelectionLowerBound: "2.0.0", Action: ActionUpdate}},
	}
}

func waitsStore(t *testing.T, waits ...LangWaitRecord) PRStore {
	t.Helper()
	s := PRStore{Dir: t.TempDir()}
	if err := s.Save(PRStoreFile{NextSeq: 1, LangWaits: waits}); err != nil {
		t.Fatal(err)
	}
	return s
}

func waitRecordFor(it LanguageItem, kind string, count int) LangWaitRecord {
	return LangWaitRecord{
		Repo: it.Source.Repository, BaseBranch: it.Source.BaseBranch, LockPath: "package-lock.json",
		InputFingerprint: LanguageInputFingerprint(it), Kind: kind, Count: count, LastSeenAt: waitsNow.Add(-time.Hour),
	}
}

func loadWaits(t *testing.T, s PRStore) []LangWaitRecord {
	t.Helper()
	f, found, err := s.Load()
	if err != nil || !found {
		t.Fatalf("load: %v %v", found, err)
	}
	return f.LangWaits
}

func TestBindPutsAnItemOffUntilTheRetryTime(t *testing.T) {
	it := waitsItem("deps:o/r@main:.#npm")
	rec := waitRecordFor(it, releaseAgeWait, 1)
	rec.RetryAfter = waitsNow.Add(time.Hour)
	store := waitsStore(t, rec)

	plan := &Plan{LanguageItems: []LanguageItem{it}}
	order, bound := BindProposedLanguageUpdatesAt(plan, store, waitsNow)
	got := plan.LanguageItems[0]
	if len(order) != 0 || bound != 0 {
		t.Fatalf("order = %v, bound = %d: an item that waits is not run", order, bound)
	}
	wantCategory(t, got, CategoryDeferred, ReasonReleaseTooNew)
	if got.RetryAfter == nil || !got.RetryAfter.Equal(rec.RetryAfter) || got.inputFingerprint != rec.InputFingerprint || got.waitIntent != nil {
		t.Errorf("retry = %v, fingerprint = %q, intent = %+v", got.RetryAfter, got.inputFingerprint, got.waitIntent)
	}
	if b, _ := json.Marshal(got); !json.Valid(b) || !strings.Contains(string(b), `"retry_after":"2026-10-15T13:00:00Z"`) {
		t.Errorf("record = %s", b)
	}

	// Seen again, the item waits on; its record is marked, nothing else changes.
	if err := RecordLanguageWaits(context.Background(), store, plan, waitsNow); err != nil {
		t.Fatal(err)
	}
	if w := loadWaits(t, store); len(w) != 1 || w[0].Count != 1 || !w[0].LastSeenAt.Equal(waitsNow) {
		t.Errorf("waits = %+v", w)
	}

	// After the time, it runs from the start.
	plan = &Plan{LanguageItems: []LanguageItem{it}}
	order, _ = BindProposedLanguageUpdatesAt(plan, store, waitsNow.Add(2*time.Hour))
	if len(order) != 1 || plan.LanguageItems[0].Category != CategoryDependencyUpdateCandidate || plan.LanguageItems[0].priorWait == nil {
		t.Errorf("order = %v, item = %+v", order, plan.LanguageItems[0])
	}
}

func TestBindPrecedence(t *testing.T) {
	it := waitsItem("deps:o/r@main:.#npm")
	fp := LanguageInputFingerprint(it)
	future := waitsNow.Add(time.Hour)

	t.Run("a pull request made from the same inputs wins over a wait", func(t *testing.T) {
		wait := waitRecordFor(it, releaseAgeWait, 2)
		wait.RetryAfter = future
		store := PRStore{Dir: t.TempDir()}
		pr := PRRecord{
			Repo: "o/r", Kind: prKindLanguage, UpdateKey: "k", Number: 7, BaseBranch: "main", Path: "package-lock.json", State: PRStateOpen,
			TargetKey: TargetKeyOf(prKindLanguage, 0, "main", "package-lock.json", []string{"."}),
			Lang:      &LangRecord{Manager: string(ManagerNpm), InputFingerprint: fp},
		}
		if err := store.Save(PRStoreFile{NextSeq: 1, PRs: []PRRecord{pr}, LangWaits: []LangWaitRecord{wait}}); err != nil {
			t.Fatal(err)
		}
		plan := &Plan{LanguageItems: []LanguageItem{it}}
		order, bound := BindProposedLanguageUpdatesAt(plan, store, waitsNow)
		got := plan.LanguageItems[0]
		if len(order) != 0 || bound != 1 {
			t.Fatalf("order = %v, bound = %d", order, bound)
		}
		wantCategory(t, got, CategoryPRCandidate, ReasonUpdateAlreadyProposed)
		if got.waitIntent == nil || !got.waitIntent.Clear {
			t.Fatalf("intent = %+v", got.waitIntent)
		}
		if err := RecordLanguageWaits(context.Background(), store, plan, waitsNow); err != nil {
			t.Fatal(err)
		}
		if w := loadWaits(t, store); len(w) != 0 {
			t.Errorf("the wait stayed: %+v", w)
		}
	})
	t.Run("a stop of the chain update is noted and the item runs", func(t *testing.T) {
		wait := waitRecordFor(it, releaseAgeWait, 1)
		wait.RetryAfter = future
		stop := waitRecordFor(it, chainStoppedKind, 0)
		stop.StopReason = ReasonChainItemBudget
		store := waitsStore(t, wait, stop)
		plan := &Plan{LanguageItems: []LanguageItem{it}}
		order, _ := BindProposedLanguageUpdatesAt(plan, store, waitsNow)
		got := plan.LanguageItems[0]
		if len(order) != 1 || got.chainStopped == nil || got.chainStopped.StopReason != ReasonChainItemBudget || got.Category != CategoryDependencyUpdateCandidate {
			t.Errorf("order = %v, item = %s %+v", order, got.Category, got.chainStopped)
		}
	})
	t.Run("a wait for a budget is not a deferral", func(t *testing.T) {
		store := waitsStore(t, waitRecordFor(it, budgetLookupWait, 2))
		plan := &Plan{LanguageItems: []LanguageItem{it}}
		order, _ := BindProposedLanguageUpdatesAt(plan, store, waitsNow)
		if len(order) != 1 || plan.LanguageItems[0].priorWait == nil || plan.LanguageItems[0].priorWait.Count != 2 {
			t.Errorf("order = %v, prior = %+v", order, plan.LanguageItems[0].priorWait)
		}
	})
	t.Run("the fingerprint is taken before packages turn manual", func(t *testing.T) {
		plan := &Plan{LanguageItems: []LanguageItem{it}}
		BindProposedLanguageUpdatesAt(plan, nil, waitsNow)
		got := &plan.LanguageItems[0]
		if got.inputFingerprint != fp {
			t.Fatalf("fingerprint = %q", got.inputFingerprint)
		}
		manualPackage(&got.Packages[0], ReasonDependentsLimit, "x")
		if LanguageInputFingerprint(*got) == fp {
			t.Fatal("the fingerprint of the changed item is the same, so this test shows nothing")
		}
		if got.inputFingerprint != fp {
			t.Error("the fingerprint followed the packages")
		}
	})
	t.Run("an item with another lockfile has its own waits", func(t *testing.T) {
		other := it
		other.Source.BaseBranch = "dev"
		store := waitsStore(t, waitRecordFor(other, releaseAgeWait, 1))
		plan := &Plan{LanguageItems: []LanguageItem{it}}
		if order, _ := BindProposedLanguageUpdatesAt(plan, store, waitsNow); len(order) != 1 || plan.LanguageItems[0].priorWait != nil {
			t.Errorf("order = %v, prior = %+v", order, plan.LanguageItems[0].priorWait)
		}
	})
}

func TestRecordLanguageWaitsTransitions(t *testing.T) {
	it := waitsItem("deps:o/r@main:.#npm")
	fp := LanguageInputFingerprint(it)
	seen := func(intent *langWaitIntent) *Plan {
		c := it
		c.inputFingerprint, c.waitIntent = fp, intent
		return &Plan{LanguageItems: []LanguageItem{c}}
	}
	record := func(t *testing.T, s PRStore, intent *langWaitIntent) []LangWaitRecord {
		t.Helper()
		if err := RecordLanguageWaits(context.Background(), s, seen(intent), waitsNow); err != nil {
			t.Fatal(err)
		}
		return loadWaits(t, s)
	}
	t.Run("a first stop makes a record, the same kind counts, another kind starts again", func(t *testing.T) {
		s := waitsStore(t)
		w := record(t, s, &langWaitIntent{Kind: budgetLookupWait})
		if len(w) != 1 || w[0].Kind != budgetLookupWait || w[0].Count != 1 || w[0].LockPath != "package-lock.json" || !w[0].LastSeenAt.Equal(waitsNow) || w[0].InputFingerprint != fp {
			t.Fatalf("waits = %+v", w)
		}
		if w = record(t, s, &langWaitIntent{Kind: budgetLookupWait}); len(w) != 1 || w[0].Count != 2 {
			t.Fatalf("waits = %+v", w)
		}
		if w = record(t, s, &langWaitIntent{Kind: budgetBytesWait}); len(w) != 1 || w[0].Kind != budgetBytesWait || w[0].Count != 1 {
			t.Fatalf("waits = %+v", w)
		}
		retry := waitsNow.Add(72 * time.Hour)
		if w = record(t, s, &langWaitIntent{Kind: releaseAgeWait, RetryAfter: retry}); len(w) != 1 || w[0].Kind != releaseAgeWait || !w[0].RetryAfter.Equal(retry) || w[0].Count != 1 {
			t.Fatalf("waits = %+v", w)
		}
		if w = record(t, s, &langWaitIntent{Clear: true}); len(w) != 0 {
			t.Fatalf("the wait was not cleared: %+v", w)
		}
	})
	t.Run("a stop replaces the wait and stays while the item is in the plan", func(t *testing.T) {
		s := waitsStore(t, waitRecordFor(it, budgetTimeWait, 2))
		w := record(t, s, &langWaitIntent{Stop: true, StopReason: ReasonChainItemBudget})
		if len(w) != 1 || w[0].Kind != chainStoppedKind || w[0].StopReason != ReasonChainItemBudget {
			t.Fatalf("waits = %+v", w)
		}
		// An item that ends another way does not clear a stop.
		if w = record(t, s, &langWaitIntent{Clear: true}); len(w) != 1 || w[0].Kind != chainStoppedKind {
			t.Fatalf("waits = %+v", w)
		}
		if w = record(t, s, nil); len(w) != 1 || !w[0].LastSeenAt.Equal(waitsNow) {
			t.Fatalf("waits = %+v", w)
		}
	})
	t.Run("records no item asked for in 30 days are removed, the others kept", func(t *testing.T) {
		old := waitRecordFor(waitsItem("other"), budgetTimeWait, 1)
		old.InputFingerprint = "old"
		old.LastSeenAt = waitsNow.Add(-31 * 24 * time.Hour)
		oldStop := old
		oldStop.InputFingerprint, oldStop.Kind, oldStop.StopReason = "oldstop", chainStoppedKind, ReasonChainItemBudget
		recent := old
		recent.InputFingerprint, recent.LastSeenAt = "recent", waitsNow.Add(-29*24*time.Hour)
		s := waitsStore(t, old, oldStop, recent)
		w := record(t, s, nil)
		if len(w) != 1 || w[0].InputFingerprint != "recent" {
			t.Fatalf("waits = %+v", w)
		}
	})
	t.Run("an item with no lockfile is skipped", func(t *testing.T) {
		c := it
		c.Source.Files = nil
		c.inputFingerprint, c.waitIntent = fp, &langWaitIntent{Kind: budgetTimeWait}
		s := waitsStore(t)
		if err := RecordLanguageWaits(context.Background(), s, &Plan{LanguageItems: []LanguageItem{c}}, waitsNow); err != nil {
			t.Fatal(err)
		}
		if w := loadWaits(t, s); len(w) != 0 {
			t.Errorf("waits = %+v", w)
		}
	})
}

// hookStore runs hooks around the lock of a store and counts its calls.
type hookStore struct {
	PRStore
	onLock  func()
	saveErr error
	locks   int
	saves   int
}

func (h *hookStore) Lock() (func() error, error) {
	h.locks++
	unlock, err := h.PRStore.Lock()
	if err == nil && h.onLock != nil {
		h.onLock()
	}
	return unlock, err
}

func (h *hookStore) Save(f PRStoreFile) error {
	h.saves++
	if h.saveErr != nil {
		return h.saveErr
	}
	return h.PRStore.Save(f)
}

func TestRecordLanguageWaitsKeepsWhatAnotherWriterSaved(t *testing.T) {
	it := waitsItem("deps:o/r@main:.#npm")
	fp := LanguageInputFingerprint(it)
	base := waitsStore(t)
	other := waitRecordFor(waitsItem("other"), budgetTimeWait, 1)
	other.InputFingerprint, other.LastSeenAt = "someone-else", waitsNow
	h := &hookStore{PRStore: base}
	// Between the lock and the load, another writer saves a record and a
	// pull request record.
	h.onLock = func() {
		f, _, _ := base.Load()
		f.LangWaits = append(f.LangWaits, other)
		f.NextSeq = 5
		if err := base.Save(f); err != nil {
			t.Error(err)
		}
	}
	c := it
	c.inputFingerprint, c.waitIntent = fp, &langWaitIntent{Kind: budgetLookupWait}
	if err := RecordLanguageWaits(context.Background(), h, &Plan{LanguageItems: []LanguageItem{c}}, waitsNow); err != nil {
		t.Fatal(err)
	}
	f, _, _ := base.Load()
	if len(f.LangWaits) != 2 || f.NextSeq != 5 {
		t.Fatalf("waits = %+v, next = %d: what the other writer saved is lost", f.LangWaits, f.NextSeq)
	}
}

func TestRecordLanguageWaitsTakesNoLockWhenThereIsNothingToWrite(t *testing.T) {
	it := waitsItem("deps:o/r@main:.#npm")
	h := &hookStore{PRStore: waitsStore(t)}
	c := it
	c.inputFingerprint, c.waitIntent = LanguageInputFingerprint(it), &langWaitIntent{Clear: true}
	if err := RecordLanguageWaits(context.Background(), h, &Plan{LanguageItems: []LanguageItem{c}}, waitsNow); err != nil {
		t.Fatal(err)
	}
	if h.locks != 0 || h.saves != 0 {
		t.Errorf("locks = %d, saves = %d", h.locks, h.saves)
	}
	// A plan with no item that has a fingerprint is left alone, a missing store
	// included.
	if err := RecordLanguageWaits(context.Background(), nil, &Plan{LanguageItems: []LanguageItem{it}}, waitsNow); err != nil {
		t.Errorf("err = %v", err)
	}
}

func TestWaitThatCannotBeSavedSettlesTheItem(t *testing.T) {
	it := waitsItem("deps:o/r@main:.#npm")
	deferred := func() *Plan {
		c := it
		c.inputFingerprint = LanguageInputFingerprint(it)
		fb := c
		fb.Packages = append([]LanguagePackage(nil), c.Packages...)
		manualPackage(&fb.Packages[0], ReasonDependentsLimit, waitNotRecordedDetail(budgetTimeWait))
		fb.Category, fb.Reason = CategoryManual, ReasonDependentsLimit
		c.waitIntent, c.waitFallback = &langWaitIntent{Kind: budgetTimeWait}, &fb
		deferItem(&c, ReasonChainItemBudget, "x")
		other := waitsItem("untouched")
		other.inputFingerprint = LanguageInputFingerprint(other)
		return &Plan{LanguageItems: []LanguageItem{c, other}}
	}
	check := func(t *testing.T, err error) {
		t.Helper()
		p := deferred()
		ApplyWaitSaveFailure(p, err)
		got := p.LanguageItems[0]
		wantCategory(t, got, CategoryManual, ReasonDependentsLimit)
		if got.waitIntent != nil || got.waitFallback != nil || got.Packages[0].Reason != ReasonDependentsLimit || !strings.Contains(got.Packages[0].Detail, err.Error()) {
			t.Errorf("item = %+v", got)
		}
		if p.LanguageItems[1].Category != CategoryDependencyUpdateCandidate {
			t.Errorf("another item was changed: %s", p.LanguageItems[1].Category)
		}
	}
	t.Run("no store", func(t *testing.T) {
		err := RecordLanguageWaits(context.Background(), nil, deferred(), waitsNow)
		if !errors.Is(err, errNoWaitStore) {
			t.Fatalf("err = %v", err)
		}
		check(t, err)
	})
	t.Run("no record file yet", func(t *testing.T) {
		err := RecordLanguageWaits(context.Background(), PRStore{Dir: t.TempDir()}, deferred(), waitsNow)
		if !errors.Is(err, errNoWaitStore) {
			t.Fatalf("err = %v", err)
		}
		check(t, err)
	})
	t.Run("the save fails", func(t *testing.T) {
		h := &hookStore{PRStore: waitsStore(t), saveErr: errors.New("disk full")}
		err := RecordLanguageWaits(context.Background(), h, deferred(), waitsNow)
		if err == nil || err.Error() != "disk full" {
			t.Fatalf("err = %v", err)
		}
		check(t, err)
	})
	t.Run("the lock is held", func(t *testing.T) {
		s := waitsStore(t)
		unlock, err := s.Lock()
		if err != nil {
			t.Fatal(err)
		}
		defer unlock()
		err = RecordLanguageWaits(context.Background(), s, deferred(), waitsNow)
		if !errors.Is(err, ErrPRStoreLocked) {
			t.Fatalf("err = %v", err)
		}
		check(t, err)
	})
	t.Run("the time to save ran out", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := RecordLanguageWaits(ctx, waitsStore(t), deferred(), waitsNow)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
		check(t, err)
	})
	t.Run("a wait that was saved is not settled", func(t *testing.T) {
		p := deferred()
		if err := RecordLanguageWaits(context.Background(), waitsStore(t), p, waitsNow); err != nil {
			t.Fatal(err)
		}
		if p.LanguageItems[0].Category != CategoryDeferred {
			t.Errorf("category = %s", p.LanguageItems[0].Category)
		}
	})
}

func TestWaitIsSavedAfterTheWorkDeadlineEnded(t *testing.T) {
	// The stop for running out of time is counted with a context that does not
	// end with the item's: the save is given its own.
	it := waitsItem("deps:o/r@main:.#npm")
	work, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	<-work.Done()
	saveCtx, cancelSave := context.WithTimeout(context.WithoutCancel(work), 15*time.Second)
	defer cancelSave()
	s := waitsStore(t)
	c := it
	c.inputFingerprint, c.waitIntent = LanguageInputFingerprint(it), &langWaitIntent{Kind: budgetTimeWait}
	if err := RecordLanguageWaits(saveCtx, s, &Plan{LanguageItems: []LanguageItem{c}}, waitsNow); err != nil {
		t.Fatal(err)
	}
	if w := loadWaits(t, s); len(w) != 1 || w[0].Kind != budgetTimeWait {
		t.Errorf("waits = %+v", w)
	}
}

func TestChainStopsAfterThreeStopsAcrossPasses(t *testing.T) {
	// Three passes in a row stop for the same limit of the item: the first two
	// put the item off, the third stops the chain update for these inputs, and
	// the passes after settle the item without trying it.
	h := newChainHarness(t, []string{"minimist", "pinned"}, func(n int) string { return chainLock("1.0.0", "2.0.0", "1.2.8") })
	store := waitsStore(t)
	up, err := NewLangUpdater(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	ran := 0
	up.chainRunners = map[DependencyManager]chainRunner{ManagerPnpm: func(context.Context, *updateRun, *chainScope) *updateFailure { ran++; return nil }}
	up.itemBudget = func() *itemBudget { b := newItemBudget(); b.maxContainers = 1; return b }
	pass := func(n int) LanguageItem {
		item := h.item
		item.Packages = append([]LanguagePackage(nil), h.item.Packages...)
		plan := &Plan{LanguageItems: []LanguageItem{item}}
		now := waitsNow.Add(time.Duration(n) * time.Hour)
		order, _ := BindProposedLanguageUpdatesAt(plan, store, now)
		RunLanguageUpdatesInOrder(context.Background(), up.Run, plan, order)
		if err := RecordLanguageWaits(context.Background(), store, plan, now); err != nil {
			t.Fatal(err)
		}
		return plan.LanguageItems[0]
	}
	for n := 1; n <= 2; n++ {
		it := pass(n)
		wantCategory(t, it, CategoryDeferred, ReasonChainItemBudget)
		if w := loadWaits(t, store); len(w) != 1 || w[0].Kind != budgetContainerWait || w[0].Count != n {
			t.Fatalf("pass %d: waits = %+v", n, w)
		}
	}
	it := pass(3)
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if pin := packageOf(t, it, "pinned"); pin.Reason != ReasonDependentsLimit {
		t.Errorf("pinned = %+v", pin)
	}
	if w := loadWaits(t, store); len(w) != 1 || w[0].Kind != chainStoppedKind || w[0].StopReason != ReasonChainItemBudget {
		t.Fatalf("waits = %+v", w)
	}
	for n := 4; n <= 5; n++ {
		it = pass(n)
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if pin := packageOf(t, it, "pinned"); pin.Reason != ReasonDependentsLimit {
			t.Errorf("pass %d: pinned = %+v", n, pin)
		}
		if w := loadWaits(t, store); len(w) != 1 || w[0].Kind != chainStoppedKind || !w[0].LastSeenAt.Equal(waitsNow.Add(time.Duration(n)*time.Hour)) {
			t.Fatalf("pass %d: waits = %+v", n, w)
		}
	}
	if ran != 0 {
		t.Errorf("the chain update ran %d times", ran)
	}
}

func TestRunOfAChainThatEndsClearsTheWait(t *testing.T) {
	h := newChainHarness(t, []string{"pinned"}, nil)
	it := h.item
	rec := waitRecordFor(it, budgetLookupWait, 2)
	rec.LockPath = "pnpm-lock.yaml"
	store := waitsStore(t, rec)
	up, _ := NewLangUpdater(h.cfg)
	up.chainRunners = map[DependencyManager]chainRunner{ManagerPnpm: failRunner(manualFailure(ReasonSourceIntroduced, "x"))}
	plan := &Plan{LanguageItems: []LanguageItem{it}}
	order, _ := BindProposedLanguageUpdatesAt(plan, store, waitsNow)
	RunLanguageUpdatesInOrder(context.Background(), up.Run, plan, order)
	if err := RecordLanguageWaits(context.Background(), store, plan, waitsNow); err != nil {
		t.Fatal(err)
	}
	if w := loadWaits(t, store); len(w) != 0 {
		t.Errorf("a wait stayed after the chain update ended: %+v", w)
	}
}

func TestPRStoreValidatesWaitRecords(t *testing.T) {
	ok := LangWaitRecord{Repo: "o/r", BaseBranch: "main", LockPath: "l", InputFingerprint: "f", Kind: budgetTimeWait, LastSeenAt: waitsNow}
	stop := ok
	stop.Kind = chainStoppedKind
	s := PRStore{Dir: t.TempDir()}
	if err := s.Save(PRStoreFile{NextSeq: 1, LangWaits: []LangWaitRecord{ok, stop}}); err != nil {
		t.Fatalf("a wait and a stop for the same inputs: %v", err)
	}
	bad := map[string]func(w *LangWaitRecord){
		"no fingerprint": func(w *LangWaitRecord) { w.InputFingerprint = "" },
		"no repository":  func(w *LangWaitRecord) { w.Repo = "" },
		"no lockfile":    func(w *LangWaitRecord) { w.LockPath = "" },
		"unknown kind":   func(w *LangWaitRecord) { w.Kind = "later" },
	}
	for name, mut := range bad {
		w := ok
		mut(&w)
		if err := (PRStoreFile{NextSeq: 1, LangWaits: []LangWaitRecord{w}}).validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := (PRStoreFile{NextSeq: 1, LangWaits: []LangWaitRecord{ok, ok}}).validate(); err == nil {
		t.Error("two waits for the same inputs were accepted")
	}
	if err := (PRStoreFile{NextSeq: 1, LangWaits: []LangWaitRecord{stop, stop}}).validate(); err == nil {
		t.Error("two stops for the same inputs were accepted")
	}
	// The format version is not changed, and a file with the field loads.
	if PRStoreVersion != 1 {
		t.Errorf("PRStoreVersion = %d", PRStoreVersion)
	}
	if _, found, err := s.Load(); err != nil || !found {
		t.Errorf("load: %v %v", found, err)
	}
	// A build that does not know the field reads the file and drops it.
	var old struct {
		Version int `json:"version"`
	}
	data, _ := os.ReadFile(filepath.Join(s.Dir, "prs.json"))
	if err := json.Unmarshal(data, &old); err != nil || old.Version != PRStoreVersion {
		t.Errorf("old reader: %+v %v", old, err)
	}
}
