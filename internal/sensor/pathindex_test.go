package sensor

import (
	"testing"
	"time"
)

func recordN(idx *pathIndex, mntNs uint32, from, to uint64) {
	for i := from; i < to; i++ {
		idx.record(mntNs, testRoot, testRootDevRaw, testRootIno, i, 1, "/f")
	}
}

func hasEntry(idx *pathIndex, mntNs uint32, i uint64) bool {
	_, ok := idx.lookup(mntNs, testRoot, testRootIno, i, 1)
	return ok
}

// TestPathIndexFairness_BurstEvictsOnlyOwnNamespace confirms one mount
// namespace's burst of once-only opens pushes out only its own entries.
func TestPathIndexFairness_BurstEvictsOnlyOwnNamespace(t *testing.T) {
	var idx pathIndex
	idx.maxEntries = 10
	recordN(&idx, 2, 0, 3) // the neighbour: 3 entries, all older than the burst
	recordN(&idx, 1, 0, 1000)

	for i := uint64(0); i < 3; i++ {
		if !hasEntry(&idx, 2, i) {
			t.Errorf("neighbour namespace entry %d was evicted by another namespace's burst", i)
		}
	}
	if got := idx.byNs[1].order.Len(); got != 7 {
		t.Errorf("bursting namespace holds %d entries, want 7", got)
	}
	if len(idx.byKey) != 10 {
		t.Errorf("len(byKey) = %d, want 10", len(idx.byKey))
	}
}

func TestPathIndexFairness_LRUWithinNamespace(t *testing.T) {
	var idx pathIndex
	idx.maxEntries = 6
	recordN(&idx, 2, 100, 102)
	recordN(&idx, 1, 0, 4)
	for i := uint64(4); i < 200; i++ {
		if !hasEntry(&idx, 1, 0) {
			t.Fatalf("looked-up entry evicted after %d inserts in its own namespace", i)
		}
		recordN(&idx, 1, i, i+1)
	}
	if hasEntry(&idx, 1, 1) {
		t.Error("never-looked-up entry survived the burst")
	}
	if !hasEntry(&idx, 2, 100) || !hasEntry(&idx, 2, 101) {
		t.Error("neighbour namespace lost entries")
	}
}

func TestPathIndexFairness_OnEvictReceivesEvictedKeys(t *testing.T) {
	var idx pathIndex
	idx.maxEntries = 4
	var evicted []evictedPathKey
	idx.onEvict = func(k evictedPathKey) { evicted = append(evicted, k) }
	recordN(&idx, 2, 0, 1)
	recordN(&idx, 1, 0, 6) // 7 entries over a cap of 4: evicts namespace 1's entries 0, 1 and 2

	if len(evicted) != 3 {
		t.Fatalf("len(evicted) = %d, want 3: %+v", len(evicted), evicted)
	}
	for i, k := range evicted {
		want := evictedPathKey{mntNsID: 1, rawRootDev: testRootDevRaw, rootIno: testRootIno, dev: uint64(i), ino: 1}
		if k != want {
			t.Errorf("evicted[%d] = %+v, want %+v", i, k, want)
		}
	}
}

// TestPathIndexFairness_TieGoesToOldestNamespace covers the equal-size case.
func TestPathIndexFairness_TieGoesToOldestNamespace(t *testing.T) {
	var idx pathIndex
	idx.maxEntries = 2
	recordN(&idx, 1, 0, 1)
	recordN(&idx, 2, 0, 1)
	recordN(&idx, 3, 0, 1) // all size 1 after insert; ns 1 holds the oldest entry
	if idx.byNs[1] != nil {
		t.Error("emptied namespace left in byNs")
	}
	if hasEntry(&idx, 1, 0) || !hasEntry(&idx, 2, 0) || !hasEntry(&idx, 3, 0) {
		t.Error("tie did not evict the namespace with the oldest least-recently-used entry")
	}
}

func TestPathIndexPruneMountNamespace_NoOnEvictAndStaysConsistent(t *testing.T) {
	var idx pathIndex
	idx.maxEntries = 6
	calls := 0
	idx.onEvict = func(evictedPathKey) { calls++ }
	recordN(&idx, 1, 0, 3)
	recordN(&idx, 2, 0, 3)

	idx.pruneMountNamespace(1)
	idx.pruneMountNamespace(99) // unknown namespace: no-op

	if calls != 0 {
		t.Errorf("onEvict called %d times by prune, want 0", calls)
	}
	if len(idx.byKey) != 3 || idx.byNs[1] != nil || idx.byNs[2].order.Len() != 3 {
		t.Fatalf("table inconsistent after prune: byKey=%d", len(idx.byKey))
	}
	for i := uint64(0); i < 3; i++ {
		if hasEntry(&idx, 1, i) || !hasEntry(&idx, 2, i) {
			t.Errorf("entry %d wrong after prune", i)
		}
	}
	// Reuse the pruned namespace and overflow: eviction still works.
	recordN(&idx, 1, 10, 20)
	if len(idx.byKey) != 6 {
		t.Errorf("len(byKey) = %d, want 6", len(idx.byKey))
	}
	if calls != 7 {
		t.Errorf("onEvict calls = %d, want 7", calls)
	}
	total := 0
	for _, ns := range idx.byNs {
		total += ns.order.Len()
	}
	if total != len(idx.byKey) {
		t.Errorf("namespace lists hold %d entries, byKey %d", total, len(idx.byKey))
	}
}

func TestPathIndexFairness_BurstIntoFullTableIsFast(t *testing.T) {
	var idx pathIndex
	for ns := uint32(1); ns <= 100; ns++ {
		recordN(&idx, ns, 0, 600)
	}
	recordN(&idx, 1000, 0, 5000) // table now full
	start := time.Now()
	recordN(&idx, 1001, 100_000, 160_000)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("60,000-insert burst took %v", d)
	}
	if len(idx.byKey) != maxPathIndexEntries {
		t.Errorf("len(byKey) = %d, want %d", len(idx.byKey), maxPathIndexEntries)
	}
	if got := idx.byNs[1].order.Len(); got != 600 {
		t.Errorf("small namespace holds %d entries, want 600", got)
	}
}

func TestPathIndexStale_UnusedNamespaceEvictedBeforeLargest(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	var idx pathIndex
	idx.now = func() time.Time { return clock }
	idx.maxEntries = 6
	recordN(&idx, 2, 0, 2) // small namespace, never used again
	clock = clock.Add(pathIndexStaleAfter + time.Second)
	recordN(&idx, 1, 0, 4) // fills the table
	var evicted []evictedPathKey
	idx.onEvict = func(k evictedPathKey) { evicted = append(evicted, k) }

	recordN(&idx, 1, 4, 5) // 7 entries: the stale ns 2 entry goes, not ns 1's
	if len(evicted) != 1 || evicted[0].mntNsID != 2 || evicted[0].dev != 0 {
		t.Fatalf("evicted = %+v, want ns 2 dev 0", evicted)
	}
	recordN(&idx, 1, 5, 6)
	if len(evicted) != 2 || evicted[1].mntNsID != 2 || evicted[1].dev != 1 {
		t.Fatalf("evicted = %+v, want ns 2 dev 1 second", evicted)
	}
	if idx.byNs[2] != nil {
		t.Error("stale namespace left in byNs after its last entry was evicted")
	}
}

func TestPathIndexStale_FreshNamespaceStillProtected(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	var idx pathIndex
	idx.now = func() time.Time { return clock }
	idx.maxEntries = 6
	recordN(&idx, 2, 0, 2)
	clock = clock.Add(pathIndexStaleAfter - time.Second)
	recordN(&idx, 1, 0, 100)
	if !hasEntry(&idx, 2, 0) || !hasEntry(&idx, 2, 1) {
		t.Error("entries younger than pathIndexStaleAfter were evicted by another namespace's burst")
	}
	if got := idx.byNs[1].order.Len(); got != 4 {
		t.Errorf("bursting namespace holds %d entries, want 4", got)
	}
}

func TestPathIndexStale_LookupRefreshesAge(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	var idx pathIndex
	idx.now = func() time.Time { return clock }
	idx.maxEntries = 4
	recordN(&idx, 2, 0, 1)
	clock = clock.Add(pathIndexStaleAfter - time.Second)
	if !hasEntry(&idx, 2, 0) {
		t.Fatal("entry missing")
	}
	clock = clock.Add(2 * time.Second) // stale by insert time, fresh by lookup time
	recordN(&idx, 1, 0, 10)
	if !hasEntry(&idx, 2, 0) {
		t.Error("a recently looked-up entry was treated as stale")
	}
}
