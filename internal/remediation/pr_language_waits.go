package remediation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// langWaitRetention is how long a wait record stays when no item with its
// inputs is in the plan.
const langWaitRetention = 30 * 24 * time.Hour

// waitNotRecorded starts the detail of a package whose wait could not be
// recorded; ApplyWaitSaveFailure adds the error to it.
const waitNotRecorded = "the wait could not be recorded"

// errNoWaitStore: there is no pull request record to keep a wait in, or the
// file does not exist yet.
var errNoWaitStore = errors.New("remediation: there is no pull request record file to keep the waits of dependency updates in")

// langWaitIntent is what a pass found out about an item's waiting, for
// RecordLanguageWaits to keep. Kind is why the item is put off (the wait
// kinds of LangWaitRecord); Clear says the item's wait is over (it was run,
// or tied to a pull request); Stop says this was the third pass in a row to
// stop for the same kind, so the chain update is not tried again for the
// inputs, and StopReason is why.
type langWaitIntent struct {
	Kind       string
	RetryAfter time.Time
	Clear      bool
	Stop       bool
	StopReason Reason
}

// RecordLanguageWaits keeps what the update stage found out about the waits of
// its items in the pull request records: it marks the records of the items
// that were in the plan, clears the waits that are over, counts the passes
// that stopped for the same reason, turns the third into a stop of the chain
// update, and removes the records no item has asked for in 30 days.
//
// It takes the record lock, reads the records again and changes only the
// records of the items of this plan before it saves, as MarkPROperationsDelivered
// does, so what another writer saved in the meantime is kept. It is called on
// every way out of the update stage that follows BindProposedLanguageUpdates,
// whether or not anything was run. It returns an error when the waits that
// must be kept could not be (see ApplyWaitSaveFailure).
func RecordLanguageWaits(ctx context.Context, store PRStorage, plan *Plan, now time.Time) error {
	var items []*LanguageItem
	need := false
	for i := range plan.LanguageItems {
		it := &plan.LanguageItems[i]
		if it.inputFingerprint == "" || languageLockPath(*it) == "" {
			continue
		}
		items = append(items, it)
		if w := it.waitIntent; w != nil && (w.Kind != "" || w.Stop) {
			need = true
		}
	}
	if len(items) == 0 {
		return nil
	}
	if store == nil {
		if need {
			return errNoWaitStore
		}
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !need {
		// Nothing is to be written unless the records already hold waits.
		if f, found, err := store.Load(); err != nil || !found || len(f.LangWaits) == 0 {
			return nil
		}
	}
	unlock, err := store.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	file, found, err := store.Load()
	if err != nil {
		return err
	}
	if !found {
		if need {
			return errNoWaitStore
		}
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	file.LangWaits = applyLanguageWaits(file.LangWaits, items, now)
	return store.Save(file)
}

// applyLanguageWaits returns the records after the items' intents.
func applyLanguageWaits(recs []LangWaitRecord, items []*LanguageItem, now time.Time) []LangWaitRecord {
	find := func(it *LanguageItem, stop bool) int {
		for i, w := range recs {
			if w.isStop() == stop && w.sameItem(it.Source.Repository, it.Source.BaseBranch, languageLockPath(*it), it.inputFingerprint) {
				return i
			}
		}
		return -1
	}
	remove := func(i int) { recs = append(recs[:i], recs[i+1:]...) }
	for _, it := range items {
		if i := find(it, true); i >= 0 {
			recs[i].LastSeenAt = now
		}
		ti := find(it, false)
		if ti >= 0 {
			recs[ti].LastSeenAt = now
		}
		w := it.waitIntent
		switch {
		case w == nil:
		case w.Clear:
			if ti >= 0 {
				remove(ti)
			}
		case w.Stop:
			if ti >= 0 {
				remove(ti)
			}
			if find(it, true) < 0 {
				recs = append(recs, LangWaitRecord{
					Repo: it.Source.Repository, BaseBranch: it.Source.BaseBranch, LockPath: languageLockPath(*it),
					InputFingerprint: it.inputFingerprint, Kind: chainStoppedKind, StopReason: w.StopReason, LastSeenAt: now,
				})
			}
		case w.Kind != "":
			switch {
			case ti >= 0 && recs[ti].Kind == w.Kind:
				recs[ti].Count++
				recs[ti].RetryAfter = w.RetryAfter
			case ti >= 0:
				recs[ti].Kind, recs[ti].Count, recs[ti].RetryAfter = w.Kind, 1, w.RetryAfter
			default:
				recs = append(recs, LangWaitRecord{
					Repo: it.Source.Repository, BaseBranch: it.Source.BaseBranch, LockPath: languageLockPath(*it),
					InputFingerprint: it.inputFingerprint, Kind: w.Kind, RetryAfter: w.RetryAfter, Count: 1, LastSeenAt: now,
				})
			}
		}
	}
	kept := recs[:0:0]
	for _, w := range recs {
		if !w.LastSeenAt.IsZero() && now.Sub(w.LastSeenAt) <= langWaitRetention {
			kept = append(kept, w)
		}
	}
	return kept
}

// ApplyWaitSaveFailure settles the items that were put off for a wait that
// could not be recorded. A wait that is not counted would put the item off
// again and again, so each such item is given its fallback outcome instead:
// the result that passed every check, or the packages that were held back
// handed to a person with the reason dependents_update_limit. An unchecked
// result is never adopted.
func ApplyWaitSaveFailure(plan *Plan, err error) {
	for i := range plan.LanguageItems {
		it := &plan.LanguageItems[i]
		w := it.waitIntent
		if w == nil || w.Kind == "" || it.Category != CategoryDeferred {
			continue
		}
		fb := it.waitFallback
		if fb == nil {
			continue
		}
		out := *fb
		out.Packages = append([]LanguagePackage(nil), fb.Packages...)
		why := ": " + clip(err.Error(), 200)
		if strings.HasPrefix(out.Detail, waitNotRecorded) {
			out.Detail += why
		}
		for j := range out.Packages {
			if strings.HasPrefix(out.Packages[j].Detail, waitNotRecorded) {
				out.Packages[j].Detail += why
			}
		}
		out.inputFingerprint, out.waitIntent, out.waitFallback = it.inputFingerprint, nil, nil
		*it = out
	}
}

// waitNotRecordedDetail is the detail given to what could not wait.
func waitNotRecordedDetail(kind string) string {
	return fmt.Sprintf("%s (%s)", waitNotRecorded, kind)
}
