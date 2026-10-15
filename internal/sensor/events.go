// This file is the observer loop's own consumer of decoded eBPF events (see
// eventreader.go for how one reaches loop's own eventCh at all): resolving
// an event's cgroup ID to a generation, confirming its own mount namespace
// actually matches that generation's own confirmed mount view, resolving a
// success event's (mount namespace, dev, inode) to a path via the events
// this Sensor correlates them from, and folding the result into the same
// recordExecutable/recordOSPackage-lookup machinery sampling already uses —
// nothing here invents a second attribution pipeline.
package sensor

import (
	"container/list"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/ebpf"
)

// pathKey identifies "the same file, seen from the same root" for path-
// correlation purposes: a (mount namespace, root identity, dev, inode)
// quadruple. Root identity is part of this key, not just mount namespace,
// because the path a fentry/security_file_open event reports (bpf_d_path)
// is rendered relative to the *opening task's own root* at that exact
// moment — two tasks in the same mount namespace can still see different
// roots via chroot(2), and would get two different, both individually
// correct, path strings for the exact same (dev, inode). Without root in
// this key, a path recorded from inside a chroot could be handed back to a
// later success event confirmed under a completely different (e.g. init's
// own, unchrooted) root, crediting that event's own package attribution to
// a path string that never actually named that file from that root's own
// point of view.
type pathKey struct {
	mntNsID uint32
	rootDev string
	rootIno uint64
	dev     uint64
	ino     uint64
}

// maxPathIndexEntries bounds pathIndex's total size across all mount
// namespaces: a defensive cap against unbounded growth over a long session.
// Once crossed, an entry unused for longer than pathIndexStaleAfter is
// evicted first; failing that, the least-recently-used entry of whichever
// mount namespace currently holds the most entries is (see pathIndex's own
// doc comment for why the victim is chosen per namespace, and why this must
// be a true LRU within a namespace, unlike cgroupRoute's own plain-FIFO
// maxCgroupRouteEntries cap).
// ASSUMED: large enough that a legitimately still-in-use path (a shared
// library actively being mmap'd, say) is never pushed out by an unrelated
// burst of once-only opens in the same container; revisit once real-world
// dogfooding shows otherwise.
const maxPathIndexEntries = 65_536

// pathIndexStaleAfter is how long an entry can go without being recorded or
// looked up before the cap may evict it ahead of the fairness rule. It
// matches bpf/kestrelynx.c's KL_DEDUP_WINDOW_NS: once that long has passed
// the kernel's own kl_dedup_path suppression for the file has expired too, so
// the next open of it is sent again and re-teaches this table the path (and
// onEvict deletes the kernel-side key at eviction anyway). Without this, a
// small mount namespace that will never be used again (a container that
// exited before discovery, an excluded one) would never be the largest and so
// would hold its entries forever.
const pathIndexStaleAfter = 10 * time.Minute

// pathIndex is loop's own correlation table from pathKey to the path a
// fentry/security_file_open event most recently reported for it — what
// lets an exec_success/mmap_success event (which carries a numeric dev/inode
// but never a path; see bpf/kestrelynx.c's own header comment) be resolved
// to a container-relative path at all. Read and written only by loop's own
// goroutine.
//
// Capacity is enforced per mount namespace, not as one global LRU, in two
// steps. Once the table holds more than its capacity in total, the entry
// pushed out is, first, the least-recently-used entry overall if it has gone
// unused for longer than pathIndexStaleAfter (so a namespace nobody will use
// again ages out); otherwise it is the least-recently-used entry of the mount
// namespace that currently holds the most entries (ties go to the namespace
// whose own least-recently-used entry is oldest, so the choice is
// deterministic). One container opening tens of
// thousands of distinct files (a scanner extracting image layers, say) can
// therefore only push out its own once-only entries; a global LRU would let
// that burst evict a neighbouring container's entries too, and that
// container's exec_success/mmap_success events would then find no path, with
// the short-lived processes needed for the maps fallback already gone.
//
// A restarted container's old mount namespace is deliberately not pruned at
// once: late events of the ended generation may still need its paths, and
// resolving them would otherwise fall to the maps fallback with the old
// processes already gone. Its entries are reclaimed by the stale-first rule
// once they have gone unused for pathIndexStaleAfter.
//
// Within a namespace the order is a true LRU, not a plain FIFO the way
// cgroupRoute's own maxCgroupRouteEntries cap is (see that field's own doc
// comment on why a FIFO is an acceptable trade there): every lookup promotes
// the entry it hits to most-recently-used, so a library actually being
// mmap'd again and again survives a burst of once-only opens on unrelated
// files around it (a container indexing many on-disk segments, say), and it
// is exactly those once-only entries that get pushed out first instead.
//
// Cost: record, lookup and pruneMountNamespace's per-entry work are O(1);
// every eviction scans the namespaces once to find the largest, so a burst of
// n inserts over a full table costs O(n * namespaces). Namespaces here are
// live containers' mount namespaces (tens to hundreds), keeping a 60,000
// insert burst to a few million cheap steps, well under a second.
//
// A container that opens far more distinct files than its share of this
// table's capacity within one bpf/kestrelynx.c KL_DEDUP_WINDOW_NS window can
// still evict a path this table needs again before the kernel's own
// kl_dedup_path suppression for that same file has expired — the kernel would
// then go on suppressing a resend of a path this table has already forgotten,
// for the rest of that window, with no way for either side to notice the
// other has moved on. onEvict exists to close exactly that gap: set (by
// Session.deletePathSeenKey) once eBPF is actually attached, it deletes the
// matching kl_dedup_path entry the moment this table forgets a path, so the
// kernel resends it the very next time that file is opened instead of
// staying silent for the rest of its own suppression window. Left nil in a
// test that never exercises eviction.
type pathIndex struct {
	byKey map[pathKey]*list.Element // Element.Value is always *pathIndexEntry
	byNs  map[uint32]*pathIndexNs   // only namespaces holding at least one entry
	// tick is a counter bumped on every insert and promotion; each entry
	// records the value at its own last use, so the least-recently-used
	// entries of two namespaces can be compared without a clock.
	tick uint64
	// now is the clock used to stamp entries and judge staleness; nil means
	// time.Now. A unit test overrides it to age entries without sleeping.
	now func() time.Time
	// maxEntries overrides maxPathIndexEntries when nonzero — a unit test's
	// own way of forcing eviction after only a handful of insertions, the
	// same purpose LoadWithRingBufferBytes's own ring-buffer-size override
	// serves for kl_events.
	maxEntries int
	onEvict    func(evictedPathKey)
}

// pathIndexNs is one mount namespace's own share of a pathIndex: its entries
// in recency order, so Len() is that namespace's entry count.
type pathIndexNs struct {
	order *list.List // most-recently-used at Front, least at Back
}

// pathIndexEntry is one pathIndex.byKey element's own list.Element.Value.
// rawRootDev is the one raw kernel value pathKey itself cannot supply back:
// pathKey.rootDev is already rendered into its own human-readable
// "major:minor" form (formatKernelDev) for Go-side lookup identity, but
// deleting the matching bpf/kestrelynx.c kl_dedup_path entry needs the exact
// kernel-internal dev_t encoding that map's own key was built from instead
// (kestrelynxebpfKlPathKey.RootDev) — kept here, alongside the key's own
// already-raw mntNsID/rootIno/dev/ino, rather than reconstructed from the
// formatted string.
type pathIndexEntry struct {
	key        pathKey
	path       string
	rawRootDev uint64
	ns         *pathIndexNs // the namespace list this entry sits in
	used       uint64       // pathIndex.tick at this entry's last insert or promotion
	usedAt     time.Time    // pathIndex.clock() at that same moment
}

// evictedPathKey is what pathIndex's own onEvict hook receives once an entry
// is pushed out: every raw value bpf/kestrelynx.c's own kl_path_key needs, so
// the caller (Session.deletePathSeenKey) can delete the matching
// kl_dedup_path entry without needing to know anything about pathIndex's own
// internal layout.
type evictedPathKey struct {
	mntNsID    uint32
	rawRootDev uint64
	rootIno    uint64
	dev        uint64
	ino        uint64
}

// limit returns p's own effective capacity: maxEntries if a test has
// overridden it, maxPathIndexEntries otherwise.
func (p *pathIndex) limit() int {
	if p.maxEntries > 0 {
		return p.maxEntries
	}
	return maxPathIndexEntries
}

// clock returns the current time from p.now, or time.Now if unset.
func (p *pathIndex) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// touch promotes el to most-recently-used within its own namespace.
func (p *pathIndex) touch(el *list.Element) {
	entry := el.Value.(*pathIndexEntry)
	p.tick++
	entry.used = p.tick
	entry.usedAt = p.clock()
	entry.ns.order.MoveToFront(el)
}

// record stores path for the given (mount namespace, root identity, dev,
// inode) tuple, promoting it to most-recently-used whether this is a fresh
// insert or an update of an already-recorded key. rawRootDev is the same
// tuple's root device in the kernel's own encoding (an eBPF event's own
// RootDev field, unformatted) — see pathIndexEntry's own doc comment for why
// this table keeps it at all.
func (p *pathIndex) record(mntNsID uint32, rootDev string, rawRootDev, rootIno, dev, ino uint64, path string) {
	if path == "" {
		return
	}
	key := pathKey{mntNsID: mntNsID, rootDev: rootDev, rootIno: rootIno, dev: dev, ino: ino}
	if p.byKey == nil {
		p.byKey = map[pathKey]*list.Element{}
		p.byNs = map[uint32]*pathIndexNs{}
	}
	if el, exists := p.byKey[key]; exists {
		entry := el.Value.(*pathIndexEntry)
		entry.path = path
		entry.rawRootDev = rawRootDev
		p.touch(el)
		return
	}
	ns := p.byNs[mntNsID]
	if ns == nil {
		ns = &pathIndexNs{order: list.New()}
		p.byNs[mntNsID] = ns
	}
	p.tick++
	el := ns.order.PushFront(&pathIndexEntry{key: key, path: path, rawRootDev: rawRootDev, ns: ns, used: p.tick, usedAt: p.clock()})
	p.byKey[key] = el
	for len(p.byKey) > p.limit() {
		p.evictLeastRecentlyUsed()
	}
}

// evictLeastRecentlyUsed removes one entry and, if p.onEvict is set, hands it
// the raw values needed to delete the matching kernel-side suppression entry
// too — see pathIndex's own doc comment for why that second step matters. One
// pass over p.byNs finds both the namespace holding the most entries (ties:
// the one whose own least-recently-used entry is oldest) and the namespace
// whose least-recently-used entry is oldest overall. If that oldest entry is
// older than pathIndexStaleAfter it is the one removed; otherwise the
// largest namespace's least-recently-used entry is.
func (p *pathIndex) evictLeastRecentlyUsed() {
	var (
		victimID, oldestID uint32
		victim, oldest     *pathIndexNs
	)
	for id, ns := range p.byNs {
		back := ns.order.Back().Value.(*pathIndexEntry)
		if oldest == nil || back.used < oldest.order.Back().Value.(*pathIndexEntry).used {
			oldestID, oldest = id, ns
		}
		if victim == nil {
			victimID, victim = id, ns
			continue
		}
		n, vn := ns.order.Len(), victim.order.Len()
		if n > vn || (n == vn && back.used < victim.order.Back().Value.(*pathIndexEntry).used) {
			victimID, victim = id, ns
		}
	}
	if victim == nil {
		return
	}
	if p.clock().Sub(oldest.order.Back().Value.(*pathIndexEntry).usedAt) > pathIndexStaleAfter {
		victimID, victim = oldestID, oldest
	}
	back := victim.order.Back()
	victim.order.Remove(back)
	entry := back.Value.(*pathIndexEntry)
	delete(p.byKey, entry.key)
	if victim.order.Len() == 0 {
		delete(p.byNs, victimID)
	}
	if p.onEvict != nil {
		p.onEvict(evictedPathKey{
			mntNsID:    entry.key.mntNsID,
			rawRootDev: entry.rawRootDev,
			rootIno:    entry.key.rootIno,
			dev:        entry.key.dev,
			ino:        entry.key.ino,
		})
	}
}

// lookup resolves (mntNsID, rootDev, rootIno, dev, ino) to the path most
// recently recorded for it, promoting that entry to most-recently-used in
// the same step — a hit here is exactly the "this path is still in active
// use" signal pathIndex's own LRU eviction relies on.
func (p *pathIndex) lookup(mntNsID uint32, rootDev string, rootIno, dev, ino uint64) (string, bool) {
	el, ok := p.byKey[pathKey{mntNsID: mntNsID, rootDev: rootDev, rootIno: rootIno, dev: dev, ino: ino}]
	if !ok {
		return "", false
	}
	p.touch(el)
	return el.Value.(*pathIndexEntry).path, true
}

// pruneMountNamespace removes every entry keyed under mntNsID — this table's
// own routine cleanup once a generation whose mount namespace this is has
// ended (see reconcileGenerations' own call site), working alongside (not
// replacing) maxPathIndexEntries' own safety-net cap. Cost is proportional
// to that namespace's own entry count, not the whole table's.
//
// Deliberately never calls onEvict, unlike evictLeastRecentlyUsed: by the
// time this runs, mntNsID's own generation is confirmed gone and its mount
// namespace will never produce another FILE_OPEN/EXEC_OPEN/exec_success/
// mmap_success event again (a fresh container gets a fresh mount namespace
// of its own), so nothing could ever benefit from forcing the kernel to
// resend a path under one of these exact keys — unlike an entry
// evictLeastRecentlyUsed pushes out, which a still-live container can go on
// opening at any time. The kernel's own kl_dedup_path is itself an
// LRU_HASH map, already bounded and already self-evicting regardless of
// what this call does or does not delete. Calling onEvict here too would
// only add one extra bpf_map_delete_elem syscall per surviving entry to
// every container's own exit — for a container that opened many thousands
// of distinct files (an index with many segments, say — exactly the load
// this table's own eviction bug was found under), for no observable
// benefit.
func (p *pathIndex) pruneMountNamespace(mntNsID uint32) {
	ns := p.byNs[mntNsID]
	if ns == nil {
		return
	}
	for el := ns.order.Front(); el != nil; el = el.Next() {
		delete(p.byKey, el.Value.(*pathIndexEntry).key)
	}
	delete(p.byNs, mntNsID)
}

// pendingRouteEvent is one usage-evidence eBPF event (exec_success or
// mmap_success) this Sensor could not yet place in any generation at all —
// its cgroup ID is not yet classified at all, or it names a container this
// session has not yet registered any generation for, or the generation a
// candidate search finds has not yet been confirmed alive (see
// resolveEventGeneration's own doc comment for all three). Held at the
// Session level (not per-generation — which generation it belongs to is
// exactly what is unknown) until retryPendingRouteEvents resolves it,
// discards it (a confirmed non-container/excluded cgroup, or a container
// this session has never once registered a generation for — see
// eventRouteOutcome's own doc comment), or pendingRouteEventTTL expires it.
//
// path and lossOnly both default to their zero values for a freshly arrived
// event (the ordinary case: path resolution has not even been attempted
// yet, and dispatchRoutedEvent must still run the full
// resolvePathAndDispatch path-then-dispatch sequence once a generation is
// confirmed). applyPathResolveResult sets one or the other instead, for an
// event whose maps-fallback lookup already completed before route
// resolution could: path non-empty means the lookup already found this
// event's own path, so dispatchRoutedEvent goes straight to
// dispatchUsageEvent with it rather than repeating a resolvePathAndDispatch
// that would just miss the correlation table again and redo the same maps
// read; lossOnly true means the lookup itself found no matching entry at
// all, so there is nothing left to ever dispatch — only a loss to charge to
// whichever generation this event is eventually confirmed to belong to (see
// dispatchRoutedEvent).
type pendingRouteEvent struct {
	ev         ebpf.Event
	kind       evidence.EvidenceKind
	isExec     bool
	path       string
	lossOnly   bool
	receivedAt time.Time
}

// maxPendingRouteEvents and pendingRouteEventTTL bound the Session-wide
// pending-route queue: past either, an event still unresolved is decided by
// classifyUnattributedExpiry's own three-tier rule (events.go) — charged to
// a specific, already-known generation if one is available (tier 1), scoped
// to one plausible candidate by mount namespace if not (tier 2), or, only
// once a discovery pass that started after this event arrived has actually
// completed, folded into the Sensor-wide s.eventsUnclassified total without
// downgrading any generation's own coverage at all (tier 3). Never guessed
// wrong the way charging an arbitrary generation's own events_lost would
// risk being in exactly the restart case this queue exists to get right.
// ASSUMED values: generous enough for the startup race (a discovery pass
// completing, a cgroup_mkdir being processed, or this generation's own
// candidate being confirmed alive by genconfirm.go, all ordinarily well
// under this) without holding events indefinitely for a cgroup this Sensor
// will never resolve.
const (
	maxPendingRouteEvents = 4096
	pendingRouteEventTTL  = 30 * time.Second
)

// pendingLossDelta is one eBPF ring-buffer loss-counter increase
// (attributeEventLossDeltas' own per-cgroup delta) whose cgroup ID this
// session could not resolve to a specific, live generation at the moment it
// was observed — held at the Session level exactly the way a
// pendingRouteEvent is (see that type's own doc comment), so a container
// this session simply has not discovered yet gets the same fair chance a
// specific event's own pendingRouteEvent already gets, rather than being
// folded into eventsUnclassified the instant it is first seen. Resolved by
// retryPendingLossDeltas, or forced out early by queuePendingLossDelta's own
// cap (see applyForcedGapEviction).
type pendingLossDelta struct {
	cgroupID   uint64
	delta      int64
	receivedAt time.Time
	// lostSince is the previous counter read: the loss in delta happened
	// after it (see Session.lastLossCounterReadAt).
	lostSince time.Time
}

// maxPendingLossDeltas bounds the Session-wide pendingLossDeltas queue, the
// same way maxPendingRouteEvents bounds pendingRouteEvents — deliberately
// the same value: both queues exist for the same reason (a cgroup this
// session cannot yet classify), just fed by different sources (a specific
// eBPF event vs. an aggregate per-cgroup ring-buffer counter).
const maxPendingLossDeltas = maxPendingRouteEvents

// initialEventsCoverage reports the events_coverage value a generation
// discovered right now, with the given init starttime (boot-relative clock
// ticks — InitProcess.Starttime's own unit), should start at, and whether
// that value is CoveragePartial specifically because of
// s.forcedGapWatermarkTicks rather than the ordinary since_start/partial
// split (watermarkProtected) — the caller (reconcileGenerations) uses this
// to also mark the new generation Incomplete, sticky, from the moment it is
// created: CoveragePartial alone does not itself block a not_observed
// verdict once this generation's own index and a post-ready sample both
// complete (see evidence.GenerationEligibleForNotObserved, which only
// blocks the OS class on StateInitializing/StateParseFailed, never on
// EventsCoverage), so without this, a package the watermark-protected loss
// was itself evidence for could still end up judged not_observed once this
// generation looks otherwise fully observed.
//
//   - CoverageNone when this session's own eBPF never attached at all.
//   - CoveragePartial (watermarkProtected) when s.forcedGapWatermarkTicks
//     (see applyForcedGapEviction) has ever been set and initStarttime is
//     at or before it: this container was not even discovered yet at the
//     moment some other, unclassifiable loss had to be forced out of a
//     pending queue without waiting for discovery — it is exactly as
//     unprovably innocent of that loss as a live generation
//     applyForcedGapEviction already downgrades directly, and gets the
//     same treatment the instant it is finally discovered. Checked before
//     the ordinary since_start/partial split below, since a container can
//     satisfy both this and that split's own since_start condition at once
//     (started after eBPF attached, but also at or before a later
//     forced-eviction watermark) — the watermark's own protection must win
//     in that case.
//   - CoverageSinceStart when eBPF is attached and this container's own
//     init started *after* the boot-relative instant eBPF attached
//     (s.attachedAtBootTicks, captured once at startup — see that field's
//     own doc comment): eBPF was already watching before this container
//     could have done anything at all.
//   - CoveragePartial (not watermarkProtected) when eBPF is attached but
//     this container's own init started at or before that instant: the
//     container was already running when eBPF attached, so whatever it did
//     between its own real start and eBPF's attach could not have been
//     observed — discovery merely noticing the container just now (which is
//     when this function actually runs) says nothing about when it
//     actually started.
func (s *Session) initialEventsCoverage(initStarttime int64) (coverage evidence.EventsCoverage, watermarkProtected bool) {
	if s.eventsStatus != evidence.EventsOK {
		return evidence.CoverageNone, false
	}
	if s.forcedGapWatermarkSet && initStarttime <= s.forcedGapWatermarkTicks {
		return evidence.CoveragePartial, true
	}
	if initStarttime > s.attachedAtBootTicks {
		return evidence.CoverageSinceStart, false
	}
	return evidence.CoveragePartial, false
}

// applyEvent is the sole entry point loop uses to fold one decoded eBPF
// event into Session/generationState. It is never called from any goroutine
// but loop's own.
func (s *Session) applyEvent(ev ebpf.Event) {
	switch ev.Kind {
	case ebpf.EventCgroupMkdir:
		s.applyCgroupMkdirEvent(ev)
	case ebpf.EventFileOpen, ebpf.EventExecOpen:
		s.pathIdx.record(uint32(ev.MountNamespaceID), formatKernelDev(ev.RootDev), ev.RootDev, ev.RootIno, ev.Dev, ev.Ino, ev.Path)
	case ebpf.EventMmapOpen:
		// An attempt, not usage evidence, and it carries no path
		// (security_mmap_file cannot call bpf_d_path) — nothing to
		// correlate or attribute (see bpf/kestrelynx.c's own comment on
		// this attach point).
	case ebpf.EventExecSuccess:
		s.applyUsageEvent(ev, evidence.KindExecEvent, true)
	case ebpf.EventMmapSuccess:
		s.applyUsageEvent(ev, evidence.KindLibraryLoadEvent, false)
	}
}

// applyCgroupMkdirEvent records a newly created cgroup in s.cgroupRoute (see
// cgroupRoute.applyCgroupMkdir — this classifies the cgroup one way or
// another once its own ancestry is known) and, only once it actually became
// classified, gives every event still waiting in the pending-route queue a
// chance to resolve against the newly grown table, since one of them may
// have been waiting on exactly this cgroup ID or one of its now-known
// descendants.
//
// ev.Path being empty or ev.PathTruncated being true (bpf_probe_read_kernel_str
// failed outright, or the cgroup's own path did not fit kl_cgroup_mkdir's
// fixed 256-byte buffer — see bpf/kestrelynx.c) is never treated as this
// cgroup's own real path: cgroupRoute.ancestorLookup climbs an unrecognized
// path's prefixes down to and including the cgroup root itself (path ""),
// which scanCgroupTree's own initial walk always classifies as a confirmed
// non-container — an empty or truncated path would therefore ancestor-match
// that same root entry and wrongly confirm this cgroup non-container, purely
// because its own real path could not be read, rather than because it
// actually is one. This cgroup is left entirely unclassified instead: any
// pendingRouteEvent already naming it keeps waiting (routeUnresolved) the
// same as any other cgroup ID this Sensor has simply not classified yet at
// all, until either a later, non-truncated cgroup_mkdir/scan classifies it
// or its own pendingRouteEventTTL expires it as an unattributable loss.
func (s *Session) applyCgroupMkdirEvent(ev ebpf.Event) {
	if ev.Path == "" || ev.PathTruncated {
		return
	}
	_, known := s.cgroupRoute.applyCgroupMkdir(ev.CgroupID, ev.Path)
	if known {
		s.retryPendingRouteEvents(s.now())
	}
}

// applyUsageEvent handles an exec_success or mmap_success event: resolve it
// to a generation and route it accordingly (see routeEvent) — queuing it,
// dispatching a liveness confirmation, dispatching it outright, or
// discarding it, depending on eventRouteOutcome.
func (s *Session) applyUsageEvent(ev ebpf.Event, kind evidence.EvidenceKind, isExec bool) {
	if s.isHostRootEvent(ev) {
		return
	}
	item := pendingRouteEvent{ev: ev, kind: kind, isExec: isExec, receivedAt: s.now()}
	g, outcome := s.resolveEventGeneration(ev.CgroupID, ev.StartBoottimeNs, ev.TGID, uint32(ev.MountNamespaceID))
	s.routeEvent(g, outcome, item)
}

// routeEvent is resolveEventGeneration's own common dispatch tail, shared by
// every call site that resolves an event (or a queued pendingRouteEvent, or
// a maps-fallback answer) to an outcome: dispatch it now (routeResolved),
// start confirming its candidate's liveness (routeUnconfirmed), discard it
// silently (routeDiscard, routeGapLoss — the latter already fully recorded
// by resolveEventGeneration itself), or queue it for a later retry
// (routeUnresolved, routePending). Never TTL-aware on its own — see
// finalizeRoutedItem for the wrapper every call site handling an
// already-queued or already-async-answered item must use instead.
func (s *Session) routeEvent(g *generationState, outcome eventRouteOutcome, item pendingRouteEvent) {
	switch outcome {
	case routeResolved:
		s.dispatchRoutedEvent(g, item)
	case routeDiscard, routeGapLoss:
		// routeDiscard: a confirmed non-container cgroup, or one belonging
		// to an operator-excluded container. routeGapLoss: already counted
		// and its own bounding generations already marked partial by
		// resolveEventGeneration itself (see that outcome's own doc
		// comment). Neither is ever queued.
	case routeUnconfirmed:
		s.submitGenConfirmRequest(genConfirmRequest{g: g, item: item})
	default: // routeUnresolved, routePending
		s.queuePendingRouteEvent(item)
	}
}

// classifyUnattributedExpiry decides, for a pendingRouteEvent whose own
// pendingRouteEventTTL has elapsed (finalizeRoutedItem), or for a
// pendingLossDelta being retried (retryPendingLossDeltas, wrapped as a
// pendingRouteEvent carrying only a cgroup ID — see that type's own doc
// comment), without resolveEventGeneration ever proving it belongs to a
// specific generation, which of three tiers applies:
//
//  1. outcome is routeResolved or routeUnconfirmed and g is non-nil: this
//     event's own cgroup already resolves to a real, live, already-known
//     generation right now (whether or not a fresh liveness check has
//     confirmed it) — chargeable to that generation specifically
//     (generationState.recordEventLoss), exactly as an already-fully-proven
//     loss already is.
//  2. Otherwise (the cgroup is still unclassified, or names a container
//     this session has never registered a generation for at all —
//     routePending): if this event's own mount namespace matches exactly
//     one currently-live generation's own already-confirmed mount view
//     (generationState.mntNsID), that generation is a plausible enough
//     candidate to narrow this event's own uncertainty to just it, without
//     ever claiming it as a provable loss the way tier 1 is — see
//     generationState.markCoveragePartial's own doc comment on why this
//     never advances eventsLost.
//  3. Neither: this event genuinely cannot be tied to anything this session
//     currently knows about. Counted via recordUnclassifiedEventLoss rather
//     than silently discarded, but never before a discovery pass that
//     started after this event's own receivedAt has actually completed
//     (ready reports false until then) — a container's own cgroup is very
//     often classified only once a discovery pass actually reseeds it (see
//     cgroupRoute's own doc comment on why tp_btf/cgroup_mkdir's own event
//     delivery cannot be relied on alone), so giving up before that pass has
//     even run once since this event arrived would risk permanently
//     miscounting a real, live container's own event as noise purely
//     because discovery had not yet had its first chance to see it.
//
// A caller that cannot itself keep waiting for readiness at all (queuePendingRouteEvent's
// own eviction path, and pendingLossDeltas' own equivalent cap) never calls
// this function — see applyForcedGapEviction instead, which is what forcing
// a decision before readiness actually requires: not a worse guess at these
// same three tiers, but downgrading every live generation this loss could
// still possibly belong to, plus a watermark protecting one not even
// discovered yet.
func (s *Session) classifyUnattributedExpiry(g *generationState, outcome eventRouteOutcome, item pendingRouteEvent) (target *generationState, tier int, ready bool) {
	if (outcome == routeResolved || outcome == routeUnconfirmed) && g != nil {
		return g, 1, true
	}
	if mnt := uint32(item.ev.MountNamespaceID); mnt != 0 {
		var match *generationState
		matches := 0
		for _, cand := range s.generations {
			if cand.ended || cand.mntNsID == 0 || cand.mntNsID != mnt {
				continue
			}
			match = cand
			matches++
		}
		if matches == 1 {
			return match, 2, true
		}
	}
	if s.lastCompletedDiscoveryStartedAt.After(item.receivedAt) {
		return nil, 3, true
	}
	return nil, 3, false
}

// finalizeRoutedItem is the TTL-aware wrapper every call site acting on an
// already-queued pendingRouteEvent or an already-answered async result
// (genconfirm.go's applyGenConfirmResult, pathresolve.go's
// applyPathResolveResult) must use instead of routeEvent directly: item's
// own original receivedAt (never re-stamped by any of these — see
// pendingRouteEvent's own doc comment) is checked against
// pendingRouteEventTTL here, so an item is never dispatched, confirmed, or
// kept waiting purely because whichever async answer or retry happens to
// notice it is already past its own age limit — the same discipline
// routeEvent's own callers used to each reimplement individually.
// routeDiscard and routeGapLoss are age-independent (routeEvent's own doc
// comment) and always pass straight through regardless.
func (s *Session) finalizeRoutedItem(g *generationState, outcome eventRouteOutcome, item pendingRouteEvent, now time.Time) {
	if outcome == routeDiscard || outcome == routeGapLoss {
		s.routeEvent(g, outcome, item)
		return
	}
	if now.Sub(item.receivedAt) <= pendingRouteEventTTL {
		s.routeEvent(g, outcome, item)
		return
	}
	// Expired. Age is checked regardless of whether resolution itself would
	// have succeeded this round — an item is not kept alive, or dispatched,
	// indefinitely purely because it happens to resolve on whichever async
	// answer or retry finally notices it is already too old. What happens
	// next is classifyUnattributedExpiry's own three-tier classification:
	// tier 3 without a qualifying discovery pass yet is "not ready", not
	// "expired" — this item keeps waiting exactly as if its own TTL had not
	// elapsed at all.
	target, tier, ready := s.classifyUnattributedExpiry(g, outcome, item)
	if !ready {
		s.routeEvent(g, outcome, item)
		return
	}
	switch tier {
	case 1:
		target.recordEventLoss(1)
	case 2:
		target.markCoveragePartial()
	case 3:
		s.recordUnclassifiedEventLoss(1)
	}
}

// dispatchRoutedEvent is the common tail every route to a *confirmed*
// generation shares, once resolveEventGeneration (directly, or via
// genconfirm.go's own liveness check) has actually vouched for it: a
// lossOnly item (applyPathResolveResult's own maps-fallback-found-nothing
// case) only ever charges the loss, since there was never a path to
// dispatch in the first place; an item with a path already resolved
// (likewise from applyPathResolveResult, but this time the maps-fallback
// lookup already succeeded before the generation itself could be confirmed)
// goes straight to dispatchUsageEvent instead of re-attempting path
// resolution from scratch; every other item — a freshly arrived event, or
// one that only just got past the pending-route queue — still needs its own
// path resolved first, via resolvePathAndDispatch.
func (s *Session) dispatchRoutedEvent(g *generationState, item pendingRouteEvent) {
	if item.lossOnly {
		g.recordEventLoss(1)
		return
	}
	if item.path != "" {
		s.dispatchUsageEvent(g, item.path, item.ev, item.kind, item.isExec)
		return
	}
	s.resolvePathAndDispatch(g, item.ev, item.kind, item.isExec, item.receivedAt)
}

// eventRouteOutcome is resolveEventGeneration's own answer, distinguishing
// six cases a caller must treat differently:
//
//   - routeResolved: a specific generation was found, and this event's own
//     process start nanosecond s_ns is directly *proven* to fall within
//     that generation's own confirmed-alive window
//     (generationState.lastAliveNs) — see this function's own doc comment
//     for what that proves, why it needs no further confirmation at all
//     even for an already-ended generation, and why this comparison never
//     rounds s_ns down to a clock tick the way an earlier version of this
//     function did. Also used for the zero-startBoottimeNs aggregate case.
//     The accompanying *generationState is non-nil.
//   - routeUnconfirmed: this event's own container ID has a known generation
//     (the *latest* one this session knows of for it) whose own start is not
//     later than s_ns, but no generation's own proven-alive window
//     (routeResolved's own condition) covers s_ns — this session has not yet
//     confirmed, via a live procfs read right now (not by trusting an
//     earlier one; see genconfirm.go), that this candidate's own init PID is
//     still actually alive at or after s_ns. The accompanying
//     *generationState is non-nil and names the candidate to confirm, not
//     (yet) a generation safe to attribute anything to.
//   - routeDiscard: cgroupID is confirmed to name no container evidence
//     should ever be attributed through at all (a host process's own
//     cgroup, or one belonging to an operator-excluded container ID) —
//     never queued, never counted as a loss.
//   - routeUnresolved: cgroupID names a real, non-excluded container this
//     session has registered at least one generation for, but none of them
//     could even be a candidate at all right now (s_ns is older than every
//     known generation's own start). Worth continuing to wait for (an
//     earlier generation than any currently known might still be
//     discovered); counted as an unattributable loss if pendingRouteEventTTL
//     passes first.
//   - routePending: cgroupID names a real, non-excluded container, but this
//     session has never registered even one generation for it at all — out
//     of this stage's own scope (see pendingRouteEvent's own doc comment on
//     why this is discarded, not counted, once its own TTL passes).
//   - routeGapLoss: s_ns can be proven to belong to no generation this
//     session knows about at all — either it falls strictly between two
//     known generations' own proof (an intermediate generation this session
//     never discovered at all could have parented it instead), or it falls
//     inside some candidate generation's own starttime tick without
//     independent proof that this event's own process is that generation's
//     own init itself (see this function's own doc comment on the
//     tick-boundary case). Already fully recorded (as a loss, downgrading
//     only this one container's own generations to partial) by
//     resolveEventGeneration itself before returning, the only place with
//     the exact bounding generations in hand; the caller does nothing
//     further with it. Never resolvable on a later retry, so a caller must
//     never re-queue it, and must never count it as a loss a second time
//     (see queuePendingRouteEvent's own doc comment on why its own eviction
//     path excludes this outcome specifically).
type eventRouteOutcome int

const (
	routeResolved eventRouteOutcome = iota
	routeUnconfirmed
	routeDiscard
	routeUnresolved
	routePending
	routeGapLoss
)

// resolveEventGeneration resolves cgroupID to the container ID it belongs
// to (or confirms it belongs to none, or is excluded — see eventRouteOutcome),
// then decides which of this session's own generations for that container ID
// (live or recently ended, within the 7-day retention window —
// endedRetention) this event's own process — identified only by its start
// nanosecond s_ns (startBoottimeNs itself, the raw boot-relative nanosecond
// bpf/kestrelynx.c's kl_exec_success/kl_mmap_success report via
// task_struct's start_boottime, never rounded to a clock tick) — can be
// *proven*, not guessed, to belong to.
//
// Exactly one generation is ever alive for a given container ID at a time
// (a same-ID restart always ends the old one first — see
// reconcileGenerations), so the proof this function relies on is: if some
// generation G's own init was confirmed alive (by an ordinary sample, or by
// genconfirm.go's own dedicated check) at some boot-relative nanosecond t,
// then it was certainly still alive at every earlier nanosecond back to its
// own start too — s_ns <= t is proof this exact process could have been
// (and, since only one generation is ever alive for this container ID at
// once, must have been) G's own. lastAliveNs holds the highest such t this
// session has ever confirmed for G (see that field's own doc comment);
// checking s_ns <= G.lastAliveNs is exactly this proof, entirely at
// nanosecond precision — an earlier version of this function instead
// rounded both sides down to a shared 10ms clock tick (bootNsToTicks) before
// comparing, which could not tell a confirmation and a process that started
// after it apart if both merely happened to round into the same tick (e.g.
// a confirmation at 10.001s and a post-restart process at 10.009s both
// floor to tick 1000) — and it applies equally to an already-ended G: ending
// does not un-confirm a fact this session already established while it was
// still alive.
//
// The lower bound — s_ns must not be older than G's own start — has the
// opposite precision problem: InitProcess.Starttime is only ever available
// in clock ticks at all (/proc/<pid>/stat has no finer unit), so the
// earliest G could possibly have started is ticksToNs(G.init.Starttime), a
// floor that may understate G's own real start by up to one whole tick. An
// s_ns that falls inside G's own starttime tick
// (ticksToNs(G.init.Starttime) <= s_ns < ticksToNs(G.init.Starttime+1)) is
// therefore never resolved to G by default, even when no other generation is
// in the picture at all: an earlier version of this function tried to prove
// the absence of an overlapping predecessor instead, by checking whether the
// generation immediately before G (for this same container ID) had its own
// lastAliveNs already short of that tick's own start — but a generation's
// lastAliveNs falling short of some instant is only the highest nanosecond
// this session happened to confirm it alive at, never proof it had actually
// ended by then; it could easily have kept running, uninterrupted and simply
// unconfirmed, right up to (or into) G's own starttime tick, without
// contradicting "only one generation is ever alive for a given container ID
// at a time" at all. That check is gone.
//
// The one exception this function still accepts inside G's own starttime
// tick is independent proof that this event's own process *is* G's own init
// itself, not merely some other process that happens to share that same
// 10ms window: the event's own TGID equals G.init.PID, and the event's own
// s_ns, floored to a clock tick, equals G.init.Starttime. Two distinct
// processes can never share both the same PID and the same starttime tick,
// so this is exact proof, independent of any other generation's own state —
// and it is the one thing that keeps a container's own main program from
// permanently registering as an unattributable loss purely because its own
// first exec/mmap necessarily lands in its own init's own starttime tick.
// Every other process that merely starts within that same 10ms window — a
// short-lived helper forked moments after the container's own init, say —
// is counted as a gap loss instead (see routeGapLoss): this is deliberately
// conservative, never guessed.
//
// If no known generation's own proof already covers s_ns, only one further
// possibility can still be resolved without guessing: s_ns might belong to
// the *latest* generation this session knows of for this container ID,
// sometime after the last instant that generation was actually confirmed
// alive — but only if s_ns is not older than that generation's own start
// tick. This is routeUnconfirmed: the caller must dispatch a live procfs
// check (genconfirm.go) before trusting it, since an unnoticed restart could
// have already superseded it.
//
// Critically, a *known, later* generation existing is never enough on its
// own to resolve an s_ns that falls before it and after every other known
// generation's own proof: it proves a restart happened at some point before
// that later generation's own start, but not that no *other*, still
// undiscovered generation existed in between (a container that restarted
// twice in quick succession between two of this session's own discovery
// passes, say). Such an s_ns can never be proven to belong to any generation
// this session knows about — see routeGapLoss.
//
// This is exact, boot-relative-only arithmetic; it deliberately never
// projects into wall-clock time to compare against a generation's own
// startedAt/endedAt. Those two fields are recorded only once a discovery
// pass actually notices the container — which can lag the container's own
// real start (and therefore this exact process's own real start) by up to
// one whole --interval — so filtering candidates by that wall-clock window
// instead would routinely, and incorrectly, reject the very generation this
// match exists to find.
//
// A zero startBoottimeNs (never expected from kl_exec_success/
// kl_mmap_success, which always set it, but not asserted here; used by
// reconcileEventLossCounters' own per-cgroup aggregate attribution, which
// has no single event to take a process start time from) skips this whole
// proof procedure, falling back to whichever generation for this container
// ID is currently live and returning it as routeResolved directly: an
// aggregate ring-buffer counter increase is already an approximate signal,
// not a specific process's own usage evidence, so the same precision this
// function otherwise insists on would buy nothing here.
// mntNSID is the event's own mount namespace ID, or 0 when the caller has no
// single event to take one from at all (reconcileEventLossCounters' own
// per-cgroup aggregate — see its own call site). A nonzero mntNSID equal to
// s.hostMntNSID (this observer's own host/PID-1 mount namespace, resolved
// once at startup — see Run's own doc comment) is routeDiscard, checked
// before even the cgroup lookup below: a real Docker container's own
// workload always execs inside a mount namespace that container's own
// creation already unshared away from the host's — see
// docker-compose.sensor.yml's own pid: host, which shares only the PID
// namespace, never the mount one — so an event reporting the host's own
// mount namespace can never be a container's own usage evidence, regardless
// of which cgroup it happens to carry. This is what a short-lived host-side
// helper process (runc/containerd's own namespace-setup stages, an
// unrelated system service, a `docker build` intermediate container's own
// toolchain churn — none of them ever becoming a cgroup this session's own
// cgroupRoute can classify as a tracked container, since none of them are
// one) would otherwise route through: routeUnresolved/routePending, queued,
// and — once its own pendingRouteEventTTL expires with the cgroup still
// unclassified — folded into every currently-tracked container's own
// events_coverage as an unattributable, global downgrade to partial, despite
// having nothing to do with any of them (confirmed directly: a lone Sensor
// against a lone, otherwise idle target container observes exactly this
// churn, entirely host-mount-namespace-scoped, well within the first
// several seconds of the session).
func (s *Session) resolveEventGeneration(cgroupID uint64, startBoottimeNs uint64, tgid uint64, mntNSID uint32) (*generationState, eventRouteOutcome) {
	if mntNSID != 0 && s.hostMntNSID != 0 && mntNSID == s.hostMntNSID {
		return nil, routeDiscard
	}
	containerID, known := s.cgroupRoute.lookup(cgroupID)
	if !known {
		// Worth an early discovery pass, not just waiting for the next
		// regular one: reconcileCgroupRoute's own stat-based reseeding
		// (computeCgroupSeeds) is what actually classifies most cgroups on
		// a host where tp_btf/cgroup_mkdir's own event delivery cannot be
		// relied on alone (see cgroupRoute's own doc comment) — the sooner
		// that runs, the sooner an event genuinely worth classifying (a
		// real, just-started container) gets its chance, rather than
		// waiting out this cgroup's own pendingRouteEventTTL for nothing.
		s.requestEarlyDiscovery(s.now())
		return nil, routeUnresolved
	}
	if containerID == "" || matchesExcludedID(containerID, s.cfg.ExcludeIDs) {
		return nil, routeDiscard
	}

	if startBoottimeNs == 0 {
		for _, g := range s.generations {
			if !g.ended && g.container.ID == containerID {
				return g, routeResolved
			}
		}
		return nil, routeUnresolved
	}

	eventNs := startBoottimeNs
	var gens []*generationState
	for _, g := range s.generations {
		if g.container.ID == containerID {
			gens = append(gens, g)
		}
	}
	if len(gens) == 0 {
		return nil, routePending
	}

	// withinOwnStartTick reports whether eventNs falls inside g's own
	// starttime tick — the one clock tick /proc's own reporting cannot place
	// g's own real start any more precisely within (see this function's own
	// doc comment on the lower bound).
	withinOwnStartTick := func(g *generationState) bool {
		tickStart := ticksToNs(g.init.Starttime)
		return eventNs >= tickStart && eventNs < tickStart+nsPerClockTick
	}

	// provenToBeInitItself reports whether this event's own TGID and start
	// time together are independent proof that this event's own process *is*
	// g's own init, not merely some other process that happens to share g's
	// own starttime tick: the event's own TGID names exactly g.init.PID, and
	// eventNs, floored to a clock tick, equals g.init.Starttime exactly. Two
	// distinct processes can never share both the same PID and the same
	// starttime tick, so this holds regardless of g.lastAliveNsOK and
	// regardless of any other generation's own state — see this function's
	// own doc comment for why this is the one exception accepted inside a
	// candidate's own starttime tick.
	provenToBeInitItself := func(g *generationState) bool {
		return int(tgid) == g.init.PID && bootNsToTicks(eventNs) == g.init.Starttime
	}

	// 1. Direct proof, per candidate g:
	//   - eventNs inside g's own starttime tick: only provenToBeInitItself
	//     resolves it (see this function's own doc comment); anything else
	//     in that same 10ms window falls through to routeGapLoss below,
	//     never guessed from any other generation's own confirmed state.
	//   - eventNs at or after the tick following g's own start: g's own
	//     confirmed-alive window (lastAliveNs, ns-precision) resolves it,
	//     the only case this function ever trusts without a fresh liveness
	//     check, and the only one that can resolve an already-ended
	//     generation.
	for _, g := range gens {
		if withinOwnStartTick(g) {
			if provenToBeInitItself(g) {
				return g, routeResolved
			}
			continue
		}
		if g.lastAliveNsOK && eventNs >= ticksToNs(g.init.Starttime) && eventNs <= g.lastAliveNs {
			return g, routeResolved
		}
	}

	// 2. No generation's own window covers it. Find best (the highest-
	// Starttime generation that could still chronologically have parented
	// this process at all, i.e. its own starttime tick starts at or before
	// eventNs) and latest (the highest-Starttime generation known at all,
	// regardless of eventNs) — these coincide exactly when the only
	// candidate whose own start doesn't already rule it out is also the
	// newest generation this session knows of for this container ID.
	var best, latest *generationState
	for _, g := range gens {
		if latest == nil || g.init.Starttime > latest.init.Starttime {
			latest = g
		}
		if ticksToNs(g.init.Starttime) <= eventNs && (best == nil || g.init.Starttime > best.init.Starttime) {
			best = g
		}
	}

	if best == nil {
		// eventNs predates every known generation's own start tick for this
		// container ID — an earlier generation this session has simply not
		// discovered yet could still be found (and, if it is still alive,
		// confirmed) by a future discovery pass; unlike routeGapLoss below,
		// this is genuinely worth waiting for.
		s.requestEarlyDiscovery(s.now())
		return nil, routeUnresolved
	}

	// eventNs inside best's own starttime tick was already checked for
	// provenToBeInitItself by step 1's own loop above (best is drawn from
	// gens, which that loop ran over in full); reaching this point means
	// that proof did not hold, so this event's own process cannot be told
	// apart from a short-lived, non-init process that merely started within
	// 10ms of best's own startup — never resolvable to best, and never
	// resolvable on a later retry either, since best's own starttime tick is
	// fixed forever.
	if withinOwnStartTick(best) {
		s.recordContainerGapLoss(gens)
		return nil, routeGapLoss
	}

	if best == latest {
		// best is the latest generation known at all for this container ID,
		// and eventNs is past its own starttime tick: still potentially its
		// current instance, just not yet proven alive this recently.
		return best, routeUnconfirmed
	}

	// best != latest: a known, strictly later generation already exists,
	// proving a restart happened at some point after best's own last
	// confirmed-alive nanosecond and before latest's own start — but not
	// that no *other*, still undiscovered generation existed in between (a
	// container restarted twice between two of this session's own
	// discovery passes, say). eventNs cannot be proven to belong to best,
	// to latest, or to anything else this session knows about. This can
	// never be resolved on a later retry either: best has already ended (a
	// later generation is known to exist), so its own lastAliveNs can never
	// advance again. Recorded once, right here — the only place with the
	// exact bounding generations for this one container in hand — and
	// never queued.
	s.recordContainerGapLoss(gens)
	return nil, routeGapLoss
}

// isHostRootEvent reports whether ev came from a process whose root
// directory is still the real host's own (see Session.hostRootDev): runtime
// setup that has not entered the container's root filesystem yet, never
// usage evidence for any container. Such an event is dropped outright, the
// same as an event from the host's own mount namespace, and is never
// counted as a loss: it could not have attributed anything to begin with.
func (s *Session) isHostRootEvent(ev ebpf.Event) bool {
	return s.hostRootDev != "" && ev.RootIno == s.hostRootIno && formatKernelDev(ev.RootDev) == s.hostRootDev
}

// recordContainerGapLoss counts one event lost to a routeGapLoss gap (see
// resolveEventGeneration's own doc comment): added to the Sensor-wide
// unattributable total, same as any other unattributable loss, but
// downgrading only gens — every generation this session has ever held for
// the one container ID the gap belongs to (its current live one, if any,
// and every one observed spanning the gap) — to partial, never every
// generation this session holds: no other container's own events are in
// question here at all. Unlike downgradeContainerPartial (used by
// genconfirm.go's own pool-capacity paths), this never sets Incomplete: a
// routeGapLoss is a proven, permanent fact about a specific gap, not a
// still-open doubt.
func (s *Session) recordContainerGapLoss(gens []*generationState) {
	s.unattributedEventsLost++
	for _, g := range gens {
		if g.eventsCoverage == evidence.CoverageSinceStart {
			g.eventsCoverage = evidence.CoveragePartial
		}
	}
}

// downgradeContainerPartial marks every generation this session holds for
// containerID (live or ended) partial and Incomplete — the same
// containerID-only scope recordContainerGapLoss already uses, but also
// setting Incomplete (recordContainerGapLoss deliberately does not: a
// routeGapLoss is a proven, permanent fact about a specific gap, never
// resolvable differently on a later retry, whereas this is a genuine,
// still-open doubt). Used by genconfirm.go's own three pool-capacity-
// exhaustion paths: req.g (or res.g) is already a real, known candidate for
// a real container, so a Sensor-side capacity failure to confirm it in time
// is scoped to that one container's own generations, never every
// generation this session holds — see markCoveragePartial, which this is
// a per-generation, containerID-scoped application of.
func (s *Session) downgradeContainerPartial(containerID string) {
	for _, g := range s.generations {
		if g.container.ID == containerID {
			g.markCoveragePartial()
		}
	}
}

// dispatchUsageEvent is the common tail every route to a confirmed
// generation shares (a freshly resolved event, a pending-route event that
// just resolved, or an async maps-fallback answer) once a generation and a
// path are both known.
//
// The mount-view check runs first, before anything else is recorded: an
// event whose own mount namespace and root filesystem identity do not both
// match this generation's own confirmed ones (g.mntNsID/g.rootDev/g.rootIno,
// populated once a real sample resolves them — see applySampleResult) — or
// that cannot be checked at all because this generation has not confirmed
// either yet — is never used to attribute anything. A different mount
// namespace, or a chroot within the very same one, can make the same
// numeric (dev, inode) name a completely different file than the one init's
// own package-database index describes; recording it as evidence either for
// a language-package executable or for an OS-package candidate would risk
// crediting the wrong file's package. The generation is marked incomplete
// instead, withdrawing not_observed the same way any other discarded
// observation does, without guessing.
//
// recordExecutable happens next, unconditionally (when isExec), regardless
// of whether this generation's own package-database index is ready yet:
// language-package judgement reads gen.Executables directly and does not
// depend on the OS index at all, so nothing about it should ever wait on
// OS index readiness. Only the OS-package candidate submission that follows
// depends on index state — queued (recordPendingEvent) if the index is not
// ready yet, submitted immediately otherwise.
func (s *Session) dispatchUsageEvent(g *generationState, path string, ev ebpf.Event, kind evidence.EvidenceKind, isExec bool) {
	if !g.matchesMountView(uint32(ev.MountNamespaceID), formatKernelDev(ev.RootDev), ev.RootIno) {
		if g.mntNsID == 0 {
			// Not yet confirmed at all — never actually checked mismatch,
			// since a generation discovered from an already-running process
			// can have its very first usage event arrive before the sample
			// that would confirm matchesMountView's own two sides ever runs
			// (see recordPendingMountViewEvent's own doc comment). Held for
			// a later retry instead of guessed at now; applySampleResult
			// replays every held item through this same function once this
			// generation's own mount view is actually confirmed, at which
			// point this branch can genuinely decide instead of assuming a
			// mismatch.
			g.recordPendingMountViewEvent(pendingMountViewEvent{path: path, ev: ev, kind: kind, isExec: isExec, receivedAt: s.now()})
			return
		}
		// g.mntNsID != 0: this generation's own mount view is already
		// confirmed, and it genuinely does not match this event's own — a
		// real cross-mount-namespace/cross-root event (see
		// matchesMountView's own doc comment), not merely an unconfirmed
		// one, so there is nothing further to wait for here.
		g.markIncomplete("mount_view_mismatch", fmt.Sprintf("event_mntns=%d g_mntns=%d event_root=%s:%d", ev.MountNamespaceID, g.mntNsID, formatKernelDev(ev.RootDev), ev.RootIno))
		return
	}

	now := s.now()
	dev := formatKernelDev(ev.Dev)
	obs := s.eventObservation(ev, path, now)

	if isExec {
		g.recordExecutable(path, dev, ev.Ino, kind, now, &obs)
	}

	if g.idxState != indexReady {
		g.recordPendingEvent(pendingEventItem{
			path: path, dev: dev, inode: ev.Ino, kind: kind,
			obs: obs, receivedAt: now,
		})
		return
	}

	s.submitEventCandidate(g, path, dev, ev.Ino, kind, obs, now)
}

// drainPendingMountViewEvents replays every item g.pendingMountViewEvents
// holds through dispatchUsageEvent again, now that this generation's own
// mount view has just been confirmed for the first time (see
// applySampleResult's own call site) — each one gets a genuine
// matchesMountView decision this time, never a repeat of the same "not yet
// confirmed" branch (g.mntNsID is nonzero by the time this runs). Clears the
// queue unconditionally: whatever each item's own outcome turns out to be
// (attributed normally, or now genuinely marked incomplete), it is not
// re-queued a second time.
func (s *Session) drainPendingMountViewEvents(g *generationState) {
	if len(g.pendingMountViewEvents) == 0 {
		return
	}
	items := g.pendingMountViewEvents
	g.pendingMountViewEvents = nil
	for _, item := range items {
		s.dispatchUsageEvent(g, item.path, item.ev, item.kind, item.isExec)
	}
}

// submitEventCandidate builds the one-path candidateBatch a single eBPF
// usage event contributes and submits it exactly the way
// applySampleResult/submitCandidateBatches already submits a sample's own
// candidates — including g's own cached usrmerge-alias table
// (g.mergedUsrDirs, populated by the same detectMergedUsrDirs call a sample
// worker already performs; see applySampleResult), so a path recorded under
// one usrmerge spelling still resolves against a package database that
// recorded the other, exactly as the sampling path already does — and
// queuing behind an already-outstanding lookup (g.pendingLookup) rather
// than ever issuing a second one concurrently, per the same rule
// submitCandidateBatches' own callers already follow.
func (s *Session) submitEventCandidate(g *generationState, path, dev string, inode uint64, kind evidence.EvidenceKind, obs evidence.ProcessObservation, now time.Time) {
	batch := candidateBatch{
		candidates: map[string][]sampleCandidate{
			path: {{kind: kind, dev: dev, inode: inode, obs: obs}},
		},
		mergedUsrDirs: g.mergedUsrDirs,
		verified:      []string{path},
		observedAt:    now,
		epoch:         g.idxEpoch,
		basis:         g.idxBasis,
	}
	if g.pendingLookup != nil {
		if !g.canQueueCandidateBatch(batch) {
			g.candidatesLostPermanently = true
			return
		}
		g.queuedCandidates = append(g.queuedCandidates, batch)
		return
	}
	s.submitCandidateBatches(g, g.idxEpoch, []candidateBatch{batch})
}

// eventObservation builds the ProcessObservation a usage event contributes:
// Exe is the resolved path itself (the executed or mapped file, matching
// what a sampling-derived observation's own Exe already means for its
// candidate), EffectiveUID/CapEff come straight from the event's own
// kernel-reported identity, Userns compares the event's user namespace ID
// against this observer's own, and Listeners is always empty — an event
// alone never observes a listening socket, which the main body's own
// exposure judgement already reads an empty Listeners as unknown for.
func (s *Session) eventObservation(ev ebpf.Event, path string, now time.Time) evidence.ProcessObservation {
	return evidence.ProcessObservation{
		Exe:          path,
		EffectiveUID: int(ev.EUID),
		Userns:       s.eventInDistinctUserNS(ev),
		CapEff:       formatCapEff(ev.CapEffective),
		LastSeen:     now,
	}
}

// formatCapEff renders a raw cap_effective bitmask the same fixed-width,
// zero-padded lowercase hex form /proc/<pid>/status's own "CapEff:" line
// uses (procfs.ParseStatus reports that string verbatim), so an event-
// derived ProcessObservation's CapEff compares equal to a sampling-derived
// one for the exact same capability set (see mergeProcessObservation's own
// same-sample/same-process dedup, which compares CapEff as a plain string).
func formatCapEff(capEffective uint64) string {
	return fmt.Sprintf("%016x", capEffective)
}

// eventInDistinctUserNS reports whether ev's own user namespace ID differs
// from this observer's own — the event-derived equivalent of
// ownsDistinctUserNS, which compares the same fact for a sampled process
// via its /proc/<pid>/ns/user link instead. ev.UserNamespaceID is 0 when the
// BPF side could not resolve it at all (bpf/kestrelynx.c's
// kl_current_user_ns_id); treated as "could not determine", never as "same
// namespace" or "different namespace" — the same conservative default
// ownsDistinctUserNS applies when its own input is unavailable.
func (s *Session) eventInDistinctUserNS(ev ebpf.Event) bool {
	if ev.UserNamespaceID == 0 || s.ownUserNSInode == 0 {
		return false
	}
	return uint32(ev.UserNamespaceID) != s.ownUserNSInode
}

// parseUserNSInode extracts the numeric inode from a /proc/<pid>/ns/user
// symlink target of the form "user:[<inode>]" (ownNamespaceLink("user")'s
// own return shape), for comparison against an eBPF event's
// UserNamespaceID (a bare inode number, not a link string).
func parseUserNSInode(link string) (uint32, bool) {
	return parseNSLinkInode("user:[", link)
}

// parseMntNSInode extracts the numeric inode from a /proc/<pid>/ns/mnt
// symlink target of the form "mnt:[<inode>]" (mountBasis.mntNS's own shape,
// via procfs.Handle.NSLink("mnt")), for recording on a generationState (see
// generationState.mntNsID) and later pruning s.pathIdx by it once that
// generation ends.
func parseMntNSInode(link string) (uint32, bool) {
	return parseNSLinkInode("mnt:[", link)
}

// parseNSLinkInode extracts the numeric inode from a /proc/<pid>/ns/<kind>
// symlink target of the form "<prefix><inode>]" — prefix already includes
// the opening "[" (e.g. "user:[", "mnt:["), so only the closing "]" needs
// checking separately.
func parseNSLinkInode(prefix, link string) (uint32, bool) {
	const suffix = "]"
	if !strings.HasPrefix(link, prefix) || !strings.HasSuffix(link, suffix) {
		return 0, false
	}
	n, err := strconv.ParseUint(link[len(prefix):len(link)-len(suffix)], 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

// queuePendingRouteEvent appends item to s.pendingRouteEvents, evicting the
// oldest entry first if the queue is already at maxPendingRouteEvents. The
// evicted entry is re-resolved before deciding what its own eviction counts
// as: routeDiscard (a host cgroup, or an operator-excluded container) is
// never counted at all — not this session's own observation being affected.
// routeGapLoss is likewise excluded, but for a different reason: unlike
// routeDiscard, it is *not* loss-free — but resolveEventGeneration itself
// already recorded that loss, scoped to only the one container's own
// generations (recordContainerGapLoss), the moment it produced this
// outcome, so counting it again here would double it. An outcome
// classifyUnattributedExpiry's own tier 1 would recognize (the cgroup
// already resolves to a real, live generation right now) is charged to it
// directly, exactly as an ordinary retry would. Everything else is forced
// out before this queue slot can wait for a qualifying discovery pass the
// way an ordinary TTL expiry (finalizeRoutedItem) would — see
// applyForcedGapEviction for why that case cannot simply reuse
// classifyUnattributedExpiry's own tier 2/3 the way a patient retry can.
func (s *Session) queuePendingRouteEvent(item pendingRouteEvent) {
	if len(s.pendingRouteEvents) >= maxPendingRouteEvents {
		oldest := s.pendingRouteEvents[0]
		s.pendingRouteEvents = s.pendingRouteEvents[1:]
		g, outcome := s.resolveEventGeneration(oldest.ev.CgroupID, oldest.ev.StartBoottimeNs, oldest.ev.TGID, uint32(oldest.ev.MountNamespaceID))
		switch {
		case outcome == routeDiscard || outcome == routeGapLoss:
			// Neither counted — see this function's own doc comment.
		case (outcome == routeResolved || outcome == routeUnconfirmed) && g != nil:
			g.recordEventLoss(1)
		default:
			// The event happened before it was received; a generation that
			// ended within one pending-route TTL before that could still
			// have produced it and been marked ended by a discovery pass
			// the loop applied first.
			s.applyForcedGapEviction(uint32(oldest.ev.MountNamespaceID), 1, oldest.receivedAt.Add(-pendingRouteEventTTL))
		}
	}
	s.pendingRouteEvents = append(s.pendingRouteEvents, item)
}

// applyFallbackLoss settles loss counted by the kernel's Sensor-wide
// fallback counter (kl_lost_events): loss that happened while the per-cgroup
// counter map was full, or with no cgroup ID at all. Nothing identifies
// whose events were lost, not even a mount namespace, so it is treated
// exactly like a forced eviction of an event with no known owner: every live
// generation is downgraded and the watermark protects generations not
// discovered yet.
func (s *Session) applyFallbackLoss(delta int64, lostSince time.Time) {
	if delta <= 0 {
		return
	}
	s.applyForcedGapEviction(0, delta, lostSince)
}

// applyForcedGapEviction handles one usage-evidence loss forced out of a
// pending queue (queuePendingRouteEvent's own cap above, and
// pendingLossDeltas' own equivalent cap in queuePendingLossDelta) before a
// discovery pass that started after it arrived has ever had a chance to
// run — the one case classifyUnattributedExpiry's own tier-3 readiness gate
// exists to prevent, forced open anyway because a queue slot must be freed
// right now. Silently folding it into eventsUnclassified alone (the old
// behavior) is not safe here: the usage evidence this loss represents can
// only ever belong to one of two things — a live generation whose own mount
// view either already matches it or has not yet been confirmed at all, or a
// container this session has not even discovered yet — and every one of
// those is protected instead of guessed away:
//
//   - "Live" below also covers a generation that has ended but was alive
//     at some point after lostSince (see couldOwnLossSince): it stays in
//     the published evidence, so loss it may own must downgrade it too.
//   - mntNSID == 0 (the loss being evicted carries no single event's own
//     mount namespace at all — an aggregate kernel loss-counter delta, from
//     pendingLossDeltas): there is nothing at all to narrow by, so every
//     live generation is downgraded, confirmed mount view or not — an
//     already-confirmed generation is exactly as unprovably innocent of an
//     unattributed kernel-wide counter as one whose own view is still
//     unconfirmed.
//   - mntNSID != 0 (a specific event's own mount namespace is known):
//     every live generation whose own confirmed mount view
//     (generationState.mntNsID) matches mntNSID is downgraded, and every
//     live generation whose own mount view is not yet confirmed at all is
//     downgraded too — this loss's own mount namespace, once that
//     generation's view is confirmed, could still turn out to be exactly
//     it, so not yet knowing rules nothing out. A confirmed generation
//     whose own mount namespace demonstrably does not match is left alone.
//   - this exact instant (in boot ticks) is recorded as
//     s.forcedGapWatermarkTicks (a high-water mark, never decreased): a
//     container not even discovered yet is invisible to both rules above
//     (there is no generationState for it to mark), but if it turns out,
//     once finally discovered, to have started at or before this
//     watermark, it gets the exact same downgrade from the moment it is
//     created — see initialEventsCoverage's own watermark check.
//   - delta is also counted in s.eventsUnclassified, independent of
//     whichever of the above did or did not apply: that bookkeeping is
//     deliberately separate from any coverage downgrade (see
//     recordUnclassifiedEventLoss's own doc comment).
func (s *Session) applyForcedGapEviction(mntNSID uint32, delta int64, lostSince time.Time) {
	for _, cand := range s.generations {
		if !cand.couldOwnLossSince(lostSince) {
			continue
		}
		if mntNSID == 0 || cand.mntNsID == 0 || cand.mntNsID == mntNSID {
			cand.markCoveragePartial()
		}
	}

	if ticks, err := bootTicksNow(); err == nil && ticks > s.forcedGapWatermarkTicks {
		s.forcedGapWatermarkTicks = ticks
		s.forcedGapWatermarkSet = true
	}

	s.recordUnclassifiedEventLoss(delta)
}

// retryPendingRouteEvents attempts to resolve every still-queued
// pendingRouteEvent again. A confirmed-discardable one (routeDiscard) is
// dropped immediately, at any age, and never counted. Otherwise, TTL is
// checked before resolution is allowed to win: a still-fresh item that
// resolves outright (routeResolved) is dispatched via dispatchRoutedEvent, a
// still-fresh one that only reaches routeUnconfirmed is handed to
// genconfirm.go's own liveness check instead of being dispatched yet, but an
// item is never dispatched purely because it happens to resolve (or even
// become confirmable) on whichever retry finally notices it is already past
// pendingRouteEventTTL — age is checked regardless of the resolution outcome
// that same round. Once expired, finalizeRoutedItem's own call to
// classifyUnattributedExpiry decides what happens (see that function's own
// doc comment for the three-tier rule). Everything still within its own TTL
// and not yet resolved or confirmable stays queued for the next retry.
func (s *Session) retryPendingRouteEvents(now time.Time) {
	if len(s.pendingRouteEvents) == 0 {
		return
	}
	pending := s.pendingRouteEvents
	s.pendingRouteEvents = nil
	for _, item := range pending {
		g, outcome := s.resolveEventGeneration(item.ev.CgroupID, item.ev.StartBoottimeNs, item.ev.TGID, uint32(item.ev.MountNamespaceID))
		s.finalizeRoutedItem(g, outcome, item, now)
	}
}

// queuePendingLossDelta appends item to s.pendingLossDeltas, evicting the
// oldest entry first if the queue is already at maxPendingLossDeltas —
// exactly like queuePendingRouteEvent, but for an aggregate per-cgroup
// ring-buffer loss delta (attributeEventLossDeltas) rather than a specific
// event. An eviction this queue is forced into before a discovery pass that
// started after it arrived has ever had a chance to run goes through
// applyForcedGapEviction (mntNSID=0: an aggregate counter carries no single
// event's own mount namespace at all), never a bare, ungated unclassified
// count.
func (s *Session) queuePendingLossDelta(item pendingLossDelta) {
	if len(s.pendingLossDeltas) >= maxPendingLossDeltas {
		oldest := s.pendingLossDeltas[0]
		s.pendingLossDeltas = s.pendingLossDeltas[1:]
		g, outcome := s.resolveEventGeneration(oldest.cgroupID, 0, 0, 0)
		switch {
		case outcome == routeDiscard:
			// Not this session's own observation at all — see
			// attributeEventLossDeltas' own doc comment.
		case outcome == routeResolved && g != nil:
			g.recordEventLoss(oldest.delta)
		default:
			s.applyForcedGapEviction(0, oldest.delta, oldest.lostSince)
		}
	}
	s.pendingLossDeltas = append(s.pendingLossDeltas, item)
}

// retryPendingLossDeltas attempts to resolve every still-queued
// pendingLossDelta again, exactly the three-tier way retryPendingRouteEvents/
// finalizeRoutedItem resolve a pendingRouteEvent once its own TTL elapses —
// reused directly via classifyUnattributedExpiry, wrapping each delta as a
// pendingRouteEvent carrying only its own cgroup ID (MountNamespaceID stays
// its zero value, so tier 2's own mount-namespace match never applies here,
// exactly as attributeEventLossDeltas' own doc comment already notes for
// this aggregate, no-single-event data). Unlike pendingRouteEvent's own TTL,
// there is no age limit here at all: a loss delta with no cgroup ID this
// session can resolve at all only ever advances via tier 3's own readiness
// gate (a discovery pass that started after it arrived completing), which
// this retries on every call rather than waiting out a fixed duration first.
func (s *Session) retryPendingLossDeltas(now time.Time) {
	if len(s.pendingLossDeltas) == 0 {
		return
	}
	pending := s.pendingLossDeltas
	s.pendingLossDeltas = nil
	for _, item := range pending {
		g, outcome := s.resolveEventGeneration(item.cgroupID, 0, 0, 0)
		routeItem := pendingRouteEvent{ev: ebpf.Event{CgroupID: item.cgroupID}, receivedAt: item.receivedAt}
		target, tier, ready := s.classifyUnattributedExpiry(g, outcome, routeItem)
		if !ready {
			s.pendingLossDeltas = append(s.pendingLossDeltas, item)
			continue
		}
		switch tier {
		case 1:
			target.recordEventLoss(item.delta)
		case 2:
			target.markCoveragePartial()
		case 3:
			s.recordUnclassifiedEventLoss(item.delta)
		}
	}
}

// recordUnclassifiedEventLoss counts n eBPF events (or aggregate kernel
// loss-counter deltas) classifyUnattributedExpiry's own tier 3 gave up on:
// genuinely unclassifiable, and only after a discovery pass that started
// after each one arrived has already completed. Deliberately never folded
// into s.eventsLost and never downgrades any generation's own
// eventsCoverage at all — see eventsUnclassified's own doc comment on why
// mixing the two would make an otherwise fully-observed generation's own
// since_start/lost=0 evidence self-contradictory. A high value here is
// itself the operator-visible signal that this session's own cgroup
// classification (cgroup_mkdir and/or discovery's own reseeding) is not
// keeping up, without corrupting any generation's own coverage over it.
func (s *Session) recordUnclassifiedEventLoss(n int64) {
	if n <= 0 {
		return
	}
	s.eventsUnclassified += n
}

// reconcileEventLossCounters reads the eBPF ring buffer's own loss counters
// (kl_lost_by_cgroup, kl_lost_events) and attributes the increase since the
// last call: a per-cgroup counter's own increase is charged to whichever
// generation that cgroup ID currently resolves to (recordEventLoss,
// advancing that generation's own events_lost) when resolve confirms one
// outright (routeResolved). An increase belonging to a cgroup resolve
// confirms is discardable (routeDiscard — a host process's own cgroup, or an
// operator-excluded container) is not this session's own observation being
// affected at all, so it is not counted anywhere at all. Every other
// increase (no cgroup ID to even attempt tier 1 with, or a cgroup this
// session still cannot resolve to a live generation) is folded into
// s.eventsUnclassified instead — deliberately never s.eventsLost and never
// a coverage downgrade for any generation at all (see
// recordUnclassifiedEventLoss's own doc comment) — since there is no
// specific event here to try classifyUnattributedExpiry's own tier 2
// (mount-namespace) fallback against, only a bare cgroup ID.
func (s *Session) reconcileEventLossCounters() {
	if s.ebpfHandle == nil {
		return
	}
	byCgroup, err := s.ebpfHandle.LostEventsByCgroup()
	byCgroupErr := err
	if byCgroupErr != nil {
		byCgroup = nil
	}
	fallback, err := s.ebpfHandle.LostEvents()
	fallbackErr := err
	if fallbackErr != nil {
		fallback = s.lastLostFallback
	}

	// No specific process/event context is available for an aggregate
	// per-cgroup ring-buffer counter (it is not any one event), so
	// resolveEventGeneration is called with startBoottimeNs=0: its own
	// simpler live-generation fallback, not the tick-based disambiguation a
	// specific process's own start time would otherwise support.
	resolve := func(cgroupID uint64) (*generationState, eventRouteOutcome) {
		return s.resolveEventGeneration(cgroupID, 0, 0, 0)
	}
	now := s.now()
	// Every delta still queued from an earlier call gets its own retry
	// first, using whatever classification progress has happened since —
	// before this round's own freshly-observed deltas (unclassifiedNow,
	// pending) are folded in below.
	s.retryPendingLossDeltas(now)
	unclassifiedNow, pending := attributeEventLossDeltas(byCgroup, fallback, s.lastLostByCgroup, s.lastLostFallback, resolve)
	s.applyFallbackLoss(unclassifiedNow, s.lastLossCounterReadAt)
	for _, p := range pending {
		s.queuePendingLossDelta(pendingLossDelta{cgroupID: p.cgroupID, delta: p.delta, receivedAt: now, lostSince: s.lastLossCounterReadAt})
		// A discovery pass sooner than sampleTicker's own cadence would
		// provide one is what actually has a chance of classifying this
		// delta's own cgroup at all — every generation this session holds
		// publishes Incomplete for as long as anything sits in
		// pendingLossDeltas (see buildSnapshot's own doc comment), so
		// shortening that exposure window matters here the same way it does
		// for resolveEventGeneration's own unresolved-cgroup case.
		s.requestEarlyDiscovery(now)
	}

	// Logged only when either counter's own current value has actually
	// changed since the last call — the evidence file's own events_lost is
	// deliberately a single blended total (see buildSnapshot's own doc
	// comment); the kernel-side share alone is reported as events.kernel_lost,
	// and this line additionally splits that share into its per-cgroup and
	// fallback counters, for an operator (or an integration test, which has
	// no other way to read this Sensor's own BPF maps directly, running as a
	// separate process in a separate container) reading this Sensor's own
	// stderr.
	var byCgroupTotal, prevByCgroupTotal uint64
	for _, c := range byCgroup {
		byCgroupTotal += c
	}
	for _, c := range s.lastLostByCgroup {
		prevByCgroupTotal += c
	}
	if byCgroupTotal != prevByCgroupTotal || fallback != s.lastLostFallback {
		fmt.Fprintf(os.Stderr, "kestrelynx sensor: ebpf kernel loss counters: by_cgroup_total=%d fallback=%d\n", byCgroupTotal, fallback)
	}
	s.lastLostByCgroup, s.lastLostFallback, s.kernelLost = mergeKernelLossReads(s.lastLostByCgroup, byCgroup, byCgroupErr, s.lastLostFallback, fallback, fallbackErr)
	s.lastLossCounterReadAt = now
}

// mergeKernelLossReads folds one read of the kernel's loss counters into the
// previous state and returns the new per-cgroup map, the new fallback value
// and the kernel-side loss total (see kernelLossTotal). A per-cgroup key
// missing from the new read keeps its last-read value, and a failed read
// (byCgroupErr or fallbackErr non-nil) leaves the corresponding previous
// value in place, so the total never decreases within a session. prev is
// updated in place when non-nil.
func mergeKernelLossReads(prev, read map[uint64]uint64, readErr error, prevFallback, fallback uint64, fallbackErr error) (map[uint64]uint64, uint64, int64) {
	if readErr != nil {
		read = nil
	}
	if fallbackErr != nil {
		fallback = prevFallback
	}
	if prev == nil && len(read) > 0 {
		prev = map[uint64]uint64{}
	}
	for cgroupID, count := range read {
		prev[cgroupID] = count
	}
	return prev, fallback, kernelLossTotal(prev, fallback)
}

// kernelLossTotal is the number of events the kernel failed to put into the
// ring buffer so far: every per-cgroup loss counter plus the fallback
// counter, saturating at the largest int64 rather than wrapping negative.
func kernelLossTotal(byCgroup map[uint64]uint64, fallback uint64) int64 {
	const maxInt64 = uint64(1<<63 - 1)
	if fallback > maxInt64 {
		return int64(maxInt64)
	}
	total := fallback
	for _, c := range byCgroup {
		if c > maxInt64-total {
			return int64(maxInt64)
		}
		total += c
	}
	return int64(total)
}

// pendingCgroupLoss is one attributeEventLossDeltas' own per-cgroup delta
// that could not be attributed to a specific generation immediately —
// returned to the caller (reconcileEventLossCounters) to hold as a
// pendingLossDelta rather than being finalized as unclassified on the spot;
// see attributeEventLossDeltas' own doc comment for why immediate
// finalization is exactly the bug this type exists to avoid.
type pendingCgroupLoss struct {
	cgroupID uint64
	delta    int64
}

// attributeEventLossDeltas is reconcileEventLossCounters' own pure
// attribution logic, factored out so it can be exercised directly with
// fabricated counters and a fake resolve function, without a real
// *ebpf.Handle (which needs CAP_BPF/CAP_PERFMON to construct at all). See
// reconcileEventLossCounters' own doc comment for what it computes and why.
//
// Returns two things. unclassifiedNow is the fallback counter's own delta
// (kl_lost_events, which carries no cgroup ID breakdown at all, so it can
// never become classifiable no matter how long this session waits) —
// finalized immediately, for the caller to fold into its own running
// s.eventsUnclassified via recordUnclassifiedEventLoss, same as before.
// pending is every per-cgroup delta that resolve could not attribute to a
// specific generation outright (routeResolved) this round: rather than also
// being finalized here on the spot (the previous behavior, and the bug this
// signature change fixes — a cgroup this session simply has not discovered
// yet was given no chance at all to become classified before being folded
// into eventsUnclassified permanently), the caller queues each one as a
// pendingLossDelta and gives it the same discovery-wait retryPendingRouteEvents
// already gives a specific event's own pendingRouteEvent. A routeDiscard
// delta appears in neither return value: it is deliberately excluded, since
// it is not this session's own observation being affected at all, and must
// not make an otherwise-healthy container's own evidence look less complete
// than it actually is.
func attributeEventLossDeltas(
	byCgroup map[uint64]uint64, fallback uint64,
	prevByCgroup map[uint64]uint64, prevFallback uint64,
	resolve func(cgroupID uint64) (*generationState, eventRouteOutcome),
) (unclassifiedNow int64, pending []pendingCgroupLoss) {
	for cgroupID, count := range byCgroup {
		prev := prevByCgroup[cgroupID]
		if count <= prev {
			continue
		}
		delta := int64(count - prev)
		g, outcome := resolve(cgroupID)
		switch outcome {
		case routeResolved:
			g.recordEventLoss(delta)
		case routeDiscard:
			// Not this session's own observation at all — see this
			// function's own doc comment.
		default:
			pending = append(pending, pendingCgroupLoss{cgroupID: cgroupID, delta: delta})
		}
	}

	if fallback > prevFallback {
		// kl_lost_events carries no cgroup ID breakdown at all — it can
		// never become classifiable, so it is returned for the caller to
		// settle immediately (see applyFallbackLoss) rather than queued.
		unclassifiedNow += int64(fallback - prevFallback)
	}
	return unclassifiedNow, pending
}

// applyEventVerificationResult folds one sample worker's own
// verifiedEvents/lostEventItems (see sampleResult's own doc comment) into g:
// a verified item's own OS-package candidate is submitted exactly the way a
// freshly arrived event's is (submitEventCandidate — the index is known
// ready, or the worker would never have been given these items at all, see
// startSampleWorker; recordExecutable already happened when the event was
// first dispatched, per dispatchUsageEvent's own doc comment, so it is not
// repeated here), a lost one advances eventsLost/downgrades eventsCoverage.
// Either way it is removed from g.pendingEvents by seq — never a wholesale
// replacement, since a new event can arrive (and be queued) while this
// exact sample worker was in flight.
//
// Every item is checked against g.pendingEvents' own *current* contents
// (stillPending) before being applied at all: the worker that produced res
// was dispatched against a snapshot of g.pendingEvents taken at that time
// (sampleJob.pendingEvents), and loop's own expirePendingEvents can have
// already aged an item out of it — counting it as lost there — while this
// exact worker was still in flight. Applying a verification answer for an
// item no longer in g.pendingEvents at all would either resurrect one loop
// already gave up on, or double-count a loss already charged once.
// stillPending also excludes an item still physically present in
// g.pendingEvents but already past its own pendingEventTTL as of right
// now, even though expirePendingEvents has not swept it yet — a worker
// started just before an item's own TTL, but only answering after crossing
// it, must not have its answer adopted as if it arrived in time; the next
// expirePendingEvents sweep counts that item as lost instead.
//
// Called only from applySampleResult, and only once that caller has already
// confirmed res's own basis still matches g's currently-ready index (see
// applySampleResult's own doc comment on why that check must run first) —
// never for a sample whose root has since been invalidated.
func (s *Session) applyEventVerificationResult(g *generationState, res sampleResult) {
	if len(res.verifiedEvents) == 0 && len(res.lostEventItems) == 0 {
		return
	}
	now := s.now()
	stillPending := make(map[uint64]bool, len(g.pendingEvents))
	for _, item := range g.pendingEvents {
		if now.Sub(item.receivedAt) > pendingEventTTL {
			// Still physically present in g.pendingEvents (the periodic
			// expirePendingEvents sweep, once per discovery pass, has not
			// reached it yet), but already past its own TTL as of right now:
			// a verification result answering for this exact item — dispatched
			// against a snapshot taken before it expired, but only returning
			// after crossing that TTL itself — must not be applied as if it
			// were still timely. Leaving it out of stillPending here defers
			// it to the next expirePendingEvents sweep, which will count it
			// as lost exactly once, rather than adopting a stale result now.
			continue
		}
		stillPending[item.seq] = true
	}

	processed := make(map[uint64]bool, len(res.verifiedEvents)+len(res.lostEventItems))
	for _, item := range res.verifiedEvents {
		if !stillPending[item.seq] {
			continue
		}
		processed[item.seq] = true
		s.submitEventCandidate(g, item.path, item.dev, item.inode, item.kind, item.obs, now)
	}
	var lost int64
	for _, item := range res.lostEventItems {
		if !stillPending[item.seq] {
			continue
		}
		processed[item.seq] = true
		lost++
	}
	if lost > 0 {
		g.recordEventLoss(lost)
	}
	if len(processed) == 0 {
		return
	}

	kept := g.pendingEvents[:0]
	for _, item := range g.pendingEvents {
		if !processed[item.seq] {
			kept = append(kept, item)
		}
	}
	g.pendingEvents = kept
}
