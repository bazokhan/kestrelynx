package sensor

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/ebpf"
)

// newTestSessionForEvents is newTestSession with the extra channels events.go
// and genconfirm.go need (dbJobCh is already sized by newTestSession itself).
func newTestSessionForEvents() *Session {
	s := newTestSession()
	s.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	s.pathResolveCh = make(chan pathResolveResult, 4)
	s.genConfirmCh = make(chan genConfirmResult, 4)
	return s
}

// testRootDevRaw and testRootIno are a fixed root-filesystem identity for
// every test that exercises matchesMountView's own root check: that check
// requires an event's own RootDev/RootIno to positively
// match the target generation's own g.rootDev/g.rootIno, so any test whose
// event is meant to actually attribute sets both sides to these same
// values — see newReadyGeneration, which sets the generation side.
// testRootDevRaw is the raw kernel-internal dev_t an ebpf.Event.RootDev
// field carries; formatKernelDev(testRootDevRaw) is what g.rootDev (set from
// a sample's own mountBasis, in the unrelated userspace/glibc encoding, but
// rendered through the same "MM:mm" string form — see kerneldev.go) is
// compared against.
const (
	testRootDevRaw = uint64(1)<<kernelDevMinorBits | 1
	testRootIno    = uint64(1)
)

// testRoot/testRootB are two distinct, fixed root identities most
// pathIndex-related tests use as a neutral placeholder (testRoot on both
// sides of a record/lookup pair, unless a test is specifically exercising
// root-distinction — see TestPathIndexDistinguishesRoots). testRootBDevRaw is
// testRootB's own raw counterpart, the same way testRootDevRaw is testRoot's
// (formatKernelDev(testRootBDevRaw) == testRootB) — needed wherever a test
// calls pathIndex.record under testRootB, which now takes the root's raw
// kernel encoding alongside its formatted form (see pathIndexEntry's own doc
// comment).
const (
	testRoot        = "01:01"
	testRootB       = "02:02"
	testRootBDevRaw = uint64(2)<<kernelDevMinorBits | 2
)

func TestPathIndexRecordAndLookup(t *testing.T) {
	var idx pathIndex
	if _, ok := idx.lookup(1, testRoot, 1, 2, 3); ok {
		t.Fatal("lookup on empty index found something")
	}
	idx.record(1, testRoot, testRootDevRaw, 1, 2, 3, "/usr/bin/example")
	got, ok := idx.lookup(1, testRoot, 1, 2, 3)
	if !ok || got != "/usr/bin/example" {
		t.Errorf("lookup(1,2,3) = (%q, %v), want (\"/usr/bin/example\", true)", got, ok)
	}
	// A different mount namespace for the same (dev, inode) is a different
	// key entirely: the same numeric dev/inode in two different mount
	// namespaces is not guaranteed to name the same file.
	if _, ok := idx.lookup(2, testRoot, 1, 2, 3); ok {
		t.Error("lookup with a different mount namespace ID found the other namespace's entry")
	}
}

// TestPathIndexDistinguishesRoots fixes the chroot misattribution this
// stage's own key change exists to close: the same (mount namespace, dev,
// inode) recorded under two different roots (e.g. a chroot's own view versus
// init's unchrooted one) must never let a lookup under one root return the
// path recorded under the other, even though both name the exact same
// physical file.
func TestPathIndexDistinguishesRoots(t *testing.T) {
	var idx pathIndex
	idx.record(1, testRoot, testRootDevRaw, 1, 5, 6, "/bin/tool")
	idx.record(1, testRootB, testRootBDevRaw, 1, 5, 6, "/jail/bin/tool")

	if got, ok := idx.lookup(1, testRoot, 1, 5, 6); !ok || got != "/bin/tool" {
		t.Errorf("lookup under testRoot = (%q, %v), want (\"/bin/tool\", true)", got, ok)
	}
	if got, ok := idx.lookup(1, testRootB, 1, 5, 6); !ok || got != "/jail/bin/tool" {
		t.Errorf("lookup under testRootB = (%q, %v), want (\"/jail/bin/tool\", true)", got, ok)
	}
	// A root this index has never seen for this (dev, inode) must not fall
	// back to either recorded entry.
	if _, ok := idx.lookup(1, "03:03", 1, 5, 6); ok {
		t.Error("lookup under an unrecorded root resolved anyway")
	}
}

func TestPathIndexEviction(t *testing.T) {
	var idx pathIndex
	for i := 0; i < maxPathIndexEntries+10; i++ {
		idx.record(1, testRoot, testRootDevRaw, 1, uint64(i), 1, "/x")
	}
	if len(idx.byKey) > maxPathIndexEntries {
		t.Errorf("pathIndex size = %d, want <= %d", len(idx.byKey), maxPathIndexEntries)
	}
	if _, ok := idx.lookup(1, testRoot, 1, 0, 1); ok {
		t.Error("oldest entry still present after eviction should have removed it")
	}
	newest := uint64(maxPathIndexEntries + 9)
	if _, ok := idx.lookup(1, testRoot, 1, newest, 1); !ok {
		t.Error("most recently inserted entry was evicted, want it to survive")
	}
}

func TestPathIndexPruneMountNamespace(t *testing.T) {
	var idx pathIndex
	idx.record(1, testRoot, testRootDevRaw, 1, 10, 1, "/a")
	idx.record(1, testRoot, testRootDevRaw, 1, 20, 2, "/b")
	idx.record(2, testRoot, testRootDevRaw, 1, 10, 1, "/c") // same (dev, ino) as the first, different mnt ns

	idx.pruneMountNamespace(1)

	if _, ok := idx.lookup(1, testRoot, 1, 10, 1); ok {
		t.Error("lookup(1,10,1) still resolves after pruning mount namespace 1")
	}
	if _, ok := idx.lookup(1, testRoot, 1, 20, 2); ok {
		t.Error("lookup(1,20,2) still resolves after pruning mount namespace 1")
	}
	if got, ok := idx.lookup(2, testRoot, 1, 10, 1); !ok || got != "/c" {
		t.Errorf("lookup(2,10,1) = (%q, %v), want (\"/c\", true) -- a different mount namespace must survive pruning", got, ok)
	}
	if idx.byNs[1] != nil {
		t.Error("byNs still references pruned mount namespace 1")
	}
	if len(idx.byKey) != 1 {
		t.Errorf("len(byKey) = %d, want 1", len(idx.byKey))
	}
}

// TestPathIndexLRU_FrequentlyUsedPathSurvivesChurn confirms pathIndex is a
// true LRU, not the plain-FIFO cap cgroupRoute's own maxCgroupRouteEntries
// uses: a path this table is repeatedly asked about (a shared library
// mmap'd again and again) must outlive a steady stream of once-only,
// never-looked-up-again entries around it (a container opening many on-disk
// segments, say), even with a capacity small enough that a plain FIFO would
// have evicted it almost immediately.
func TestPathIndexLRU_FrequentlyUsedPathSurvivesChurn(t *testing.T) {
	var idx pathIndex
	idx.maxEntries = 2
	idx.record(1, testRoot, testRootDevRaw, testRootIno, 100, 100, "/usr/lib/libused.so")

	for i := uint64(0); i < 50; i++ {
		if _, ok := idx.lookup(1, testRoot, testRootIno, 100, 100); !ok {
			t.Fatalf("frequently used entry evicted after %d unrelated insertions", i)
		}
		// One unrelated, once-only data-file open, filling this index's only
		// other slot -- with a true LRU, this can never be what evicts the
		// entry just looked up above, since that lookup just made it the
		// most recently used one.
		idx.record(1, testRoot, testRootDevRaw, testRootIno, 1000+i, 1, "/data/segment")
	}

	if got, ok := idx.lookup(1, testRoot, testRootIno, 100, 100); !ok || got != "/usr/lib/libused.so" {
		t.Errorf("lookup(100,100) = (%q, %v), want (\"/usr/lib/libused.so\", true)", got, ok)
	}
}

// TestPathIndexEviction_CallsOnEvictWithRawKernelValues confirms pathIndex's
// own eviction path hands onEvict exactly the raw values needed to delete
// the matching bpf/kestrelynx.c kl_dedup_path entry (see
// Session.deletePathSeenKey, this hook's own production caller) -- never
// pathKey's own Go-formatted rootDev string, which the kernel's own map key
// cannot be built from.
func TestPathIndexEviction_CallsOnEvictWithRawKernelValues(t *testing.T) {
	var idx pathIndex
	idx.maxEntries = 1
	var evicted []evictedPathKey
	idx.onEvict = func(k evictedPathKey) { evicted = append(evicted, k) }

	idx.record(1, testRoot, testRootDevRaw, testRootIno, 100, 100, "/usr/lib/liba.so")
	if len(evicted) != 0 {
		t.Fatalf("onEvict called before any entry was actually evicted: %+v", evicted)
	}

	idx.record(1, testRoot, testRootDevRaw, testRootIno, 200, 200, "/usr/lib/libb.so")

	if len(evicted) != 1 {
		t.Fatalf("len(evicted) = %d, want 1", len(evicted))
	}
	want := evictedPathKey{mntNsID: 1, rawRootDev: testRootDevRaw, rootIno: testRootIno, dev: 100, ino: 100}
	if evicted[0] != want {
		t.Errorf("evicted[0] = %+v, want %+v", evicted[0], want)
	}
}

// TestPathIndexEvictionHypothesis_KernelDedupSurvivesUserspaceEviction
// reproduces, at this package's own level (no real kernel, no real
// container), the incomplete=true failure mode a real host was observed
// producing: a file whose own path pathIndex has since evicted (an unrelated
// burst of other opens crossed its own capacity) can still be within the
// kernel's own bpf/kestrelynx.c KL_DEDUP_WINDOW_NS suppression for its own
// FILE_OPEN record, so a later open of that exact file is never resent at
// all -- the mmap_success event that follows it then has no path anywhere to
// resolve to, is counted as a loss, and marks its own generation incomplete,
// sticky, even though the file itself was opened again perfectly normally.
//
// kernelSuppressed stands in for kl_dedup_path itself: openFile only
// actually delivers a FILE_OPEN event (and so only actually records a path)
// the first time a given key is not already marked suppressed, mirroring
// kl_path_seen/kl_path_mark's own real behavior.
func TestPathIndexEvictionHypothesis_KernelDedupSurvivesUserspaceEviction(t *testing.T) {
	const targetDev, targetIno = uint64(100), uint64(100)

	run := func(t *testing.T, deleteKernelKeyOnEvict bool) *generationState {
		s := newTestSessionForEvents()
		g := newReadyGeneration(s, 1, strings64('a'))
		s.pathIdx.maxEntries = 2

		kernelSuppressed := map[evictedPathKey]bool{}
		openFile := func(dev, ino uint64) {
			k := evictedPathKey{mntNsID: 1, rawRootDev: testRootDevRaw, rootIno: testRootIno, dev: dev, ino: ino}
			if kernelSuppressed[k] {
				return // the kernel's own suppression window is still open
			}
			s.applyEvent(ebpf.Event{
				Kind: ebpf.EventFileOpen, MountNamespaceID: 1,
				RootDev: testRootDevRaw, RootIno: testRootIno,
				Dev: dev, Ino: ino, Path: "/usr/lib/libtarget.so",
			})
			kernelSuppressed[k] = true
		}
		if deleteKernelKeyOnEvict {
			s.pathIdx.onEvict = func(k evictedPathKey) { delete(kernelSuppressed, k) }
		}

		openFile(targetDev, targetIno) // the library this generation will later mmap
		openFile(200, 200)             // an unrelated once-only data-file open ...
		openFile(300, 300)             // ... and another, evicting the library's own entry (least recently used)

		// The container's real workload opens the exact same library again
		// (a second worker process, say) -- whether this reaches userspace
		// at all depends entirely on whether the kernel still thinks it has
		// already sent this exact path.
		openFile(targetDev, targetIno)

		s.applyEvent(ebpf.Event{
			Kind: ebpf.EventMmapSuccess, CgroupID: 1, MountNamespaceID: 1,
			RootDev: testRootDevRaw, RootIno: testRootIno, Dev: targetDev, Ino: targetIno,
		})
		return g
	}

	t.Run("without deleting the kernel key: repeat open stays suppressed, path lost", func(t *testing.T) {
		g := run(t, false)
		if !g.incomplete {
			t.Error("incomplete = false, want true")
		}
		if g.eventsLost != 1 {
			t.Errorf("eventsLost = %d, want 1", g.eventsLost)
		}
	})

	t.Run("deleting the kernel key on eviction: repeat open resends the path, no loss", func(t *testing.T) {
		g := run(t, true)
		if g.incomplete {
			t.Error("incomplete = true, want false")
		}
		if g.eventsLost != 0 {
			t.Errorf("eventsLost = %d, want 0", g.eventsLost)
		}
	})
}

func TestParseMntNSInode(t *testing.T) {
	n, ok := parseMntNSInode("mnt:[4026531840]")
	if !ok || n != 4026531840 {
		t.Errorf("parseMntNSInode = (%d, %v), want (4026531840, true)", n, ok)
	}
	if _, ok := parseMntNSInode("user:[4026531837]"); ok {
		t.Error("parseMntNSInode accepted a non-mnt namespace link")
	}
}

// TestReconcileGenerations_ContainerRemovalPrunesRouteTablesNotRestart
// confirms the pruning wiring is scoped correctly: a container confirmed
// gone entirely has its cgroupRoute/pathIdx entries cleaned up, but a
// same-ID restart (which keeps the same underlying cgroup) must not have
// its mapping pruned out from under the new generation.
func TestReconcileGenerations_ContainerRemovalPrunesRouteTablesNotRestart(t *testing.T) {
	s := newTestSessionForEvents()
	cidRemoved := strings64('w')
	cidRestarted := strings64('y')

	s.cgroupRoute.set(100, "/system.slice/docker-"+cidRemoved+".scope", cidRemoved)
	s.cgroupRoute.set(200, "/system.slice/docker-"+cidRestarted+".scope", cidRestarted)
	s.pathIdx.record(1, testRoot, testRootDevRaw, 1, 1, 1, "/removed")
	s.pathIdx.record(2, testRoot, testRootDevRaw, 1, 2, 2, "/restarted")

	removedGen := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cidRemoved}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	removedGen.mntNsID = 1
	restartedGen := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cidRestarted}, InitProcess{PID: 2, Starttime: 2}, s.now(), evidence.CoverageSinceStart)
	restartedGen.mntNsID = 2
	s.generations[removedGen.key()] = removedGen
	s.generations[restartedGen.key()] = restartedGen

	// A discovery pass in which cidRemoved no longer appears at all, and
	// cidRestarted appears with a new init (a restart).
	groups := map[string]containerGroup{
		cidRestarted: {ContainerID: cidRestarted, Init: InitProcess{PID: 3, Starttime: 3}},
	}
	s.reconcileGenerations(groups, s.now())

	if _, ok := s.cgroupRoute.lookup(100); ok {
		t.Error("cgroupRoute still resolves cgroup 100 after its container was confirmed removed")
	}
	if _, ok := s.pathIdx.lookup(1, testRoot, 1, 1, 1); ok {
		t.Error("pathIdx still resolves the removed generation's own mount namespace after removal")
	}
	if got, ok := s.cgroupRoute.lookup(200); !ok || got != cidRestarted {
		t.Errorf("cgroupRoute.lookup(200) = (%q, %v), want (%q, true) -- a same-ID restart must keep its cgroup mapping", got, ok, cidRestarted)
	}
	if _, ok := s.pathIdx.lookup(2, testRoot, 1, 2, 2); !ok {
		t.Error("pathIdx no longer resolves the restarted generation's own mount namespace -- a same-ID restart must not prune it")
	}
}

func TestApplyEventFileOpenRecordsPath(t *testing.T) {
	s := newTestSessionForEvents()
	s.applyEvent(ebpf.Event{Kind: ebpf.EventFileOpen, MountNamespaceID: 7, Dev: 8, Ino: 9, Path: "/lib/libc.so.6"})
	got, ok := s.pathIdx.lookup(7, formatKernelDev(0), 0, 8, 9)
	if !ok || got != "/lib/libc.so.6" {
		t.Errorf("pathIdx.lookup(7,8,9) = (%q, %v), want (\"/lib/libc.so.6\", true)", got, ok)
	}
}

func TestApplyEventExecOpenRecordsPath(t *testing.T) {
	s := newTestSessionForEvents()
	s.applyEvent(ebpf.Event{Kind: ebpf.EventExecOpen, MountNamespaceID: 1, Dev: 2, Ino: 3, Path: "/usr/bin/curl"})
	got, ok := s.pathIdx.lookup(1, formatKernelDev(0), 0, 2, 3)
	if !ok || got != "/usr/bin/curl" {
		t.Errorf("pathIdx.lookup(1,2,3) = (%q, %v), want (\"/usr/bin/curl\", true)", got, ok)
	}
}

func TestApplyEventMmapOpenIsANoop(t *testing.T) {
	s := newTestSessionForEvents()
	s.applyEvent(ebpf.Event{Kind: ebpf.EventMmapOpen, CgroupID: 1, Dev: 2, Ino: 3})
	if len(s.pendingRouteEvents) != 0 || len(s.generations) != 0 {
		t.Error("mmap_open (an attempt event) must not queue or attribute anything")
	}
}

func TestApplyUsageEventQueuesPendingRouteWhenCgroupUnknown(t *testing.T) {
	s := newTestSessionForEvents()
	s.applyEvent(ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 999, Dev: 1, Ino: 1})
	if len(s.pendingRouteEvents) != 1 {
		t.Fatalf("len(pendingRouteEvents) = %d, want 1", len(s.pendingRouteEvents))
	}
	if s.pendingRouteEvents[0].kind != evidence.KindExecEvent || !s.pendingRouteEvents[0].isExec {
		t.Errorf("queued item = %+v, want kind=KindExecEvent isExec=true", s.pendingRouteEvents[0])
	}
}

// newReadyGeneration creates a generationState already resolved for
// containerID, with an index that is ready (so applyUsageEvent's fresh-event
// path attributes immediately rather than queuing on pendingEvents),
// registers it on s along with the cgroup route mapping cgroupID ->
// containerID, and gives it a confirmed mount namespace (1 — matching every
// event this test file constructs with MountNamespaceID: 1) and root
// identity (testRootDevRaw/testRootIno, formatted the way a real sample's
// own mountBasis would be — matching every event this test file constructs
// with RootDev: testRootDevRaw, RootIno: testRootIno), so
// resolveEventGeneration's own matchesMountView check passes without every
// test needing to set them individually. Every event this helper's own
// caller then constructs with a zero StartBoottimeNs takes
// resolveEventGeneration's own zero-startBoottimeNs path (see that
// function's own doc comment) and so never needs genconfirm.go's own
// liveness check at all, regardless of InitProcess.PID/Starttime here being
// fake, non-running values.
func newReadyGeneration(s *Session, cgroupID uint64, containerID string) *generationState {
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: containerID}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	g.idxState = indexReady
	g.packageDB.Status = evidence.DBStatusOK
	g.mntNsID = 1
	g.rootDev = formatKernelDev(testRootDevRaw)
	g.rootIno = testRootIno
	g.lastVerifiedAt = s.now()
	s.generations[g.key()] = g
	s.cgroupRoute.set(cgroupID, "/system.slice/docker-"+containerID+".scope", containerID)
	return g
}

func TestApplyUsageEventPathUnknownRecordsLoss(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('a')
	g := newReadyGeneration(s, 42, cid)

	s.applyEvent(ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 42, Dev: 5, Ino: 6, MountNamespaceID: 1})

	if g.eventsLost != 1 {
		t.Errorf("eventsLost = %d, want 1", g.eventsLost)
	}
	if !g.incomplete {
		t.Error("incomplete = false, want true after a path-unknown success event")
	}
	if g.eventsCoverage != evidence.CoveragePartial {
		t.Errorf("eventsCoverage = %q, want partial", g.eventsCoverage)
	}
}

// TestApplyUsageEvent_ChrootOpenPathNeverReusedForDifferentRootExec covers
// the chroot misattribution pathKey's own root-identity fields exist to
// close: a file opened from inside a chroot records its own path relative
// to that
// chroot's root; a later exec of the exact same physical file (same dev,
// inode), but from init's own unchrooted root, must never be handed back
// that chroot-relative path string — pathIndex only ever returns a path
// recorded under the *same* root the success event's own root actually
// confirms (see pathKey's own doc comment). Since the correlation table has
// no entry under init's own root for this (dev, inode), this is a
// path-unknown event — TGID is left 0, so it resolves immediately (no
// maps-fallback) as a recorded loss, never as an executable at the wrong
// path.
func TestApplyUsageEvent_ChrootOpenPathNeverReusedForDifferentRootExec(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('4')
	g := newReadyGeneration(s, 80, cid) // g's own root is testRootDevRaw/testRootIno

	chrootRootDev := rawKernelDevFor(t, "09:09")
	s.applyEvent(ebpf.Event{
		Kind: ebpf.EventFileOpen, MountNamespaceID: 1, RootDev: chrootRootDev, RootIno: 99,
		Dev: 5, Ino: 6, Path: "/bin/tool",
	})

	s.applyEvent(ebpf.Event{
		Kind: ebpf.EventExecSuccess, CgroupID: 80, MountNamespaceID: 1,
		RootDev: testRootDevRaw, RootIno: testRootIno, Dev: 5, Ino: 6,
	})

	if _, ok := g.executables["/bin/tool"]; ok {
		t.Error("executables[/bin/tool] recorded -- a path recorded under a different root must never be reused for this exec")
	}
	if g.eventsLost != 1 {
		t.Errorf("eventsLost = %d, want 1 (path-unknown under init's own root)", g.eventsLost)
	}
}

func TestApplyUsageEventQueuesPendingIndexWhenNotReady(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('b')
	g := newReadyGeneration(s, 43, cid)
	g.idxState = indexIdle // not ready yet

	s.applyEvent(ebpf.Event{Kind: ebpf.EventFileOpen, MountNamespaceID: 1, RootDev: testRootDevRaw, RootIno: testRootIno, Dev: 10, Ino: 11, Path: "/usr/bin/trivy"})
	s.applyEvent(ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 43, MountNamespaceID: 1, RootDev: testRootDevRaw, RootIno: testRootIno, Dev: 10, Ino: 11, EUID: 65532})

	if len(g.pendingEvents) != 1 {
		t.Fatalf("len(pendingEvents) = %d, want 1", len(g.pendingEvents))
	}
	item := g.pendingEvents[0]
	if item.path != "/usr/bin/trivy" || item.inode != 11 || item.kind != evidence.KindExecEvent {
		t.Errorf("pendingEvents[0] = %+v, unexpected", item)
	}
	if g.eventsLost != 0 || g.incomplete {
		t.Error("queuing for a not-yet-ready index must not itself count as a loss")
	}
	// recordExecutable happens immediately regardless of index readiness: it
	// must already be recorded even though the OS-package candidate is
	// still queued.
	if _, ok := g.executables["/usr/bin/trivy"]; !ok {
		t.Error("executables[/usr/bin/trivy] not recorded even though the OS index is not ready yet")
	}
}

// TestApplyUsageEvent_QueuesBeforeMountViewConfirmedThenAttributes covers
// dispatchUsageEvent's own distinction between "this generation's mount view
// has never been confirmed by any sample yet" and "confirmed, but genuinely
// a different view": a usage event that arrives before the former is held
// (generationState.pendingMountViewEvents), not guessed at as a mismatch —
// a container discovered from an already-running process can have its very
// first exec/mmap arrive before its own first sample ever runs. The held
// event gets its own genuine matchesMountView decision once
// applySampleResult confirms this generation's own mount view for the first
// time.
func TestApplyUsageEvent_QueuesBeforeMountViewConfirmedThenAttributes(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('m')
	g := newReadyGeneration(s, 90, cid)
	// Simulate a generation discovered from an already-running process,
	// before any sample has resolved its own mount view yet.
	g.mntNsID = 0
	g.rootDev = ""
	g.rootIno = 0

	s.applyEvent(ebpf.Event{Kind: ebpf.EventFileOpen, MountNamespaceID: 1, RootDev: testRootDevRaw, RootIno: testRootIno, Dev: 30, Ino: 31, Path: "/usr/bin/trivy"})
	s.applyEvent(ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 90, MountNamespaceID: 1, RootDev: testRootDevRaw, RootIno: testRootIno, Dev: 30, Ino: 31, EUID: 65532})

	if g.incomplete {
		t.Error("incomplete = true before this generation's own mount view was ever confirmed, want false (held, not guessed)")
	}
	if len(g.pendingMountViewEvents) != 1 {
		t.Fatalf("len(pendingMountViewEvents) = %d, want 1", len(g.pendingMountViewEvents))
	}
	if _, ok := g.executables["/usr/bin/trivy"]; ok {
		t.Error("executables[/usr/bin/trivy] recorded before this generation's own mount view was ever confirmed")
	}

	// The first sample confirms this generation's own mount view, matching
	// the held event's own — it now gets its real, informed decision.
	s.applySampleResult(g, sampleResult{
		basis: mountBasis{ok: true, mntNS: "mnt:[1]", rootDev: formatKernelDev(testRootDevRaw), rootIno: testRootIno},
	})

	if len(g.pendingMountViewEvents) != 0 {
		t.Errorf("len(pendingMountViewEvents) = %d, want 0 once this generation's own mount view was confirmed", len(g.pendingMountViewEvents))
	}
	if g.incomplete {
		t.Error("incomplete = true, want false: the held event's own mount view actually matches once judged for real")
	}
	if _, ok := g.executables["/usr/bin/trivy"]; !ok {
		t.Error("executables[/usr/bin/trivy] not recorded after the held event was replayed against the now-confirmed mount view")
	}
}

// TestApplyUsageEvent_MountViewConfirmedMismatchNeverQueues covers the other
// half of the same distinction: once a generation's own mount view actually
// is confirmed, an event that genuinely does not match it is decided right
// away (incomplete), never held for a retry that could never change the
// answer.
func TestApplyUsageEvent_MountViewConfirmedMismatchNeverQueues(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('n')
	g := newReadyGeneration(s, 91, cid) // mntNsID/rootDev/rootIno already confirmed to 1/testRoot

	otherRootDev := rawKernelDevFor(t, "09:09")
	s.applyEvent(ebpf.Event{Kind: ebpf.EventFileOpen, MountNamespaceID: 1, RootDev: otherRootDev, RootIno: 99, Dev: 30, Ino: 31, Path: "/bin/tool"})
	s.applyEvent(ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 91, MountNamespaceID: 1, RootDev: otherRootDev, RootIno: 99, Dev: 30, Ino: 31})

	if len(g.pendingMountViewEvents) != 0 {
		t.Errorf("len(pendingMountViewEvents) = %d, want 0: this generation's own mount view was already confirmed, so this is a real mismatch, not an unknown", len(g.pendingMountViewEvents))
	}
	if !g.incomplete {
		t.Error("incomplete = false, want true: a genuinely different root must never be attributed")
	}
	if _, ok := g.executables["/bin/tool"]; ok {
		t.Error("executables[/bin/tool] recorded despite a confirmed mount-view mismatch")
	}
}

func TestApplyUsageEventSubmitsCandidateWhenIndexReady(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('c')
	g := newReadyGeneration(s, 44, cid)

	s.applyEvent(ebpf.Event{Kind: ebpf.EventFileOpen, MountNamespaceID: 1, RootDev: testRootDevRaw, RootIno: testRootIno, Dev: 20, Ino: 21, Path: "/usr/bin/trivy"})
	s.applyEvent(ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 44, MountNamespaceID: 1, RootDev: testRootDevRaw, RootIno: testRootIno, Dev: 20, Ino: 21, EUID: 65532, CapEffective: 0})

	select {
	case job := <-s.dbJobCh:
		if job.kind != dbJobLookup || job.genKey != g.key() {
			t.Errorf("submitted dbJob = %+v, want kind=dbJobLookup genKey=%q", job, g.key())
		}
		if len(job.paths) != 1 || job.paths[0] != "/usr/bin/trivy" {
			t.Errorf("submitted dbJob.paths = %v, want [/usr/bin/trivy]", job.paths)
		}
	default:
		t.Fatal("no dbJob submitted, want a lookup job for the resolved path")
	}
	if g.pendingLookup == nil {
		t.Error("pendingLookup = nil, want set after submitting a lookup job")
	}
	exe, ok := g.executables["/usr/bin/trivy"]
	if !ok {
		t.Fatal("executables[/usr/bin/trivy] not recorded for an exec_success event")
	}
	if _, ok := exe.Kinds[evidence.KindExecEvent]; !ok {
		t.Error("executable's Kinds missing KindExecEvent")
	}
}

func TestApplyUsageEventMmapSuccessDoesNotRecordExecutable(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('d')
	g := newReadyGeneration(s, 45, cid)

	s.applyEvent(ebpf.Event{Kind: ebpf.EventFileOpen, MountNamespaceID: 1, RootDev: testRootDevRaw, RootIno: testRootIno, Dev: 30, Ino: 31, Path: "/lib/libssl.so.3"})
	s.applyEvent(ebpf.Event{Kind: ebpf.EventMmapSuccess, CgroupID: 45, MountNamespaceID: 1, RootDev: testRootDevRaw, RootIno: testRootIno, Dev: 30, Ino: 31})

	if _, ok := g.executables["/lib/libssl.so.3"]; ok {
		t.Error("a library-load event must never be recorded as an executable")
	}
	select {
	case job := <-s.dbJobCh:
		if len(job.paths) != 1 || job.paths[0] != "/lib/libssl.so.3" {
			t.Errorf("submitted dbJob.paths = %v, want the mapped library's path", job.paths)
		}
	default:
		t.Fatal("no dbJob submitted for the mmap_success event's own OS-package lookup")
	}
}

func TestApplyUsageEventQueuesBehindPendingLookup(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('e')
	g := newReadyGeneration(s, 46, cid)
	g.pendingLookup = &pendingLookup{epoch: g.idxEpoch}

	s.applyEvent(ebpf.Event{Kind: ebpf.EventFileOpen, MountNamespaceID: 1, RootDev: testRootDevRaw, RootIno: testRootIno, Dev: 40, Ino: 41, Path: "/usr/bin/git"})
	s.applyEvent(ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 46, MountNamespaceID: 1, RootDev: testRootDevRaw, RootIno: testRootIno, Dev: 40, Ino: 41})

	select {
	case job := <-s.dbJobCh:
		t.Fatalf("dbJob %+v submitted while a lookup was already pending, want it queued instead", job)
	default:
	}
	if len(g.queuedCandidates) != 1 {
		t.Fatalf("len(queuedCandidates) = %d, want 1", len(g.queuedCandidates))
	}
}

func TestApplyCgroupMkdirEventRetriesPendingRouteEvents(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('f')
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	g.idxState = indexReady
	g.packageDB.Status = evidence.DBStatusOK
	g.mntNsID = 1
	g.rootDev = formatKernelDev(testRootDevRaw)
	g.rootIno = testRootIno
	g.lastVerifiedAt = s.now()
	s.generations[g.key()] = g

	// The cgroup for this container is not yet known when the exec_success
	// event arrives, so it is queued.
	s.applyEvent(ebpf.Event{Kind: ebpf.EventFileOpen, MountNamespaceID: 1, RootDev: testRootDevRaw, RootIno: testRootIno, Dev: 50, Ino: 51, Path: "/usr/bin/node"})
	s.applyEvent(ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 47, MountNamespaceID: 1, RootDev: testRootDevRaw, RootIno: testRootIno, Dev: 50, Ino: 51})
	if len(s.pendingRouteEvents) != 1 {
		t.Fatalf("len(pendingRouteEvents) = %d, want 1 before the cgroup is known", len(s.pendingRouteEvents))
	}

	// cgroup_mkdir now tells this Sensor which container cgroup 47 belongs
	// to; this alone must retry and resolve the queued event.
	s.applyEvent(ebpf.Event{Kind: ebpf.EventCgroupMkdir, CgroupID: 47, Path: "/system.slice/docker-" + cid + ".scope"})

	if len(s.pendingRouteEvents) != 0 {
		t.Errorf("len(pendingRouteEvents) = %d, want 0 after the cgroup resolved", len(s.pendingRouteEvents))
	}
	if _, ok := g.executables["/usr/bin/node"]; !ok {
		t.Error("the retried event was never attributed to the now-known generation")
	}
}

// TestReconcileCgroupRoute_ClassifiesUnknownCgroupAndRetriesQueue mirrors
// TestApplyCgroupMkdirEventRetriesPendingRouteEvents above, but classifying
// the cgroup via discovery's own reseeding (reconcileCgroupRoute,
// computeCgroupSeeds) instead of a live tp_btf/cgroup_mkdir event — the
// path that actually matters on a host where cgroup_mkdir's own event
// delivery cannot be relied on at all. reconcileCgroupRoute itself never
// retries the queue (see its own doc comment on why); this test calls
// retryPendingRouteEvents explicitly afterward, standing in for
// applyDiscoveryResult's own dispatchWork call.
func TestReconcileCgroupRoute_ClassifiesUnknownCgroupAndRetriesQueue(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('u')
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	g.idxState = indexReady
	g.packageDB.Status = evidence.DBStatusOK
	g.mntNsID = 1
	g.rootDev = formatKernelDev(testRootDevRaw)
	g.rootIno = testRootIno
	g.lastVerifiedAt = s.now()
	s.generations[g.key()] = g
	// Deliberately never calls s.cgroupRoute.set at all -- simulating
	// tp_btf/cgroup_mkdir never firing for this container's own cgroup.

	s.applyEvent(ebpf.Event{Kind: ebpf.EventFileOpen, MountNamespaceID: 1, RootDev: testRootDevRaw, RootIno: testRootIno, Dev: 50, Ino: 51, Path: "/usr/bin/node"})
	s.applyEvent(ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 900, MountNamespaceID: 1, RootDev: testRootDevRaw, RootIno: testRootIno, Dev: 50, Ino: 51})
	if len(s.pendingRouteEvents) != 1 {
		t.Fatalf("len(pendingRouteEvents) = %d, want 1 before the cgroup is known", len(s.pendingRouteEvents))
	}

	s.reconcileCgroupRoute([]cgroupSeed{{ino: 900, path: "/system.slice/docker-" + cid + ".scope", containerID: cid}})
	s.retryPendingRouteEvents(s.now())

	if len(s.pendingRouteEvents) != 0 {
		t.Errorf("len(pendingRouteEvents) = %d, want 0 after reconcileCgroupRoute classified it and retryPendingRouteEvents ran", len(s.pendingRouteEvents))
	}
	if _, ok := g.executables["/usr/bin/node"]; !ok {
		t.Error("the retried event was never attributed to the now-known generation")
	}
}

// TestReconcileCgroupRoute_PruneThenRediscoveryRestoresMapping confirms
// pruning a container's own cgroupRoute entries (a container discovery
// briefly lost track of) does not prevent it from being re-seeded correctly
// the moment discovery finds it again.
func TestReconcileCgroupRoute_PruneThenRediscoveryRestoresMapping(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('v')
	s.reconcileCgroupRoute([]cgroupSeed{{ino: 1000, path: "/system.slice/docker-" + cid + ".scope", containerID: cid}})
	if got, ok := s.cgroupRoute.lookup(1000); !ok || got != cid {
		t.Fatalf("lookup(1000) after first seed = (%q, %v), want (%q, true)", got, ok, cid)
	}

	s.cgroupRoute.pruneContainer(cid)
	if _, ok := s.cgroupRoute.lookup(1000); ok {
		t.Fatalf("lookup(1000) still resolves right after pruning")
	}

	s.reconcileCgroupRoute([]cgroupSeed{{ino: 1000, path: "/system.slice/docker-" + cid + ".scope", containerID: cid}})
	if got, ok := s.cgroupRoute.lookup(1000); !ok || got != cid {
		t.Errorf("lookup(1000) after rediscovery = (%q, %v), want (%q, true) -- pruning must not be permanent", got, ok, cid)
	}
}

// TestReconcileCgroupRoute_RestartGetsFreshInodeMapping confirms the fixed
// cgroupmap.go doc comment's own claim: a restarted container keeps its
// containerID but gets a genuinely new cgroup inode (docker stop rmdir's
// the old scope; docker start creates a new one) -- reconcileCgroupRoute
// must give that new inode its own entry without disturbing (or needing to
// touch) the old, now-stale one at all.
func TestReconcileCgroupRoute_RestartGetsFreshInodeMapping(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('w')
	scope := "/system.slice/docker-" + cid + ".scope"
	s.reconcileCgroupRoute([]cgroupSeed{{ino: 2000, path: scope, containerID: cid}})

	// The restart: a new inode, same path, same container ID.
	s.reconcileCgroupRoute([]cgroupSeed{{ino: 2001, path: scope, containerID: cid}})

	if got, ok := s.cgroupRoute.lookup(2001); !ok || got != cid {
		t.Errorf("lookup(2001) (the post-restart inode) = (%q, %v), want (%q, true)", got, ok, cid)
	}
	if got, ok := s.cgroupRoute.lookup(2000); !ok || got != cid {
		t.Errorf("lookup(2000) (the pre-restart inode) = (%q, %v), want (%q, true) -- the old entry is stale but must not be actively broken by the new one", got, ok, cid)
	}
}

// TestReconcileCgroupRoute_ContradictionCounted confirms a seed
// disagreeing with cgroupRoute's own existing classification for the same
// inode is counted (diagnostic only) but always adopts the newest seed's
// own answer regardless -- see reconcileCgroupRoute's own doc comment.
func TestReconcileCgroupRoute_ContradictionCounted(t *testing.T) {
	s := newTestSessionForEvents()
	s.reconcileCgroupRoute([]cgroupSeed{{ino: 3000, path: "/user.slice", containerID: ""}})
	if s.cgroupRouteContradictions != 0 {
		t.Fatalf("cgroupRouteContradictions = %d, want 0 before any disagreement", s.cgroupRouteContradictions)
	}

	cid := strings64('x')
	s.reconcileCgroupRoute([]cgroupSeed{{ino: 3000, path: "/user.slice", containerID: cid}})
	if s.cgroupRouteContradictions != 1 {
		t.Errorf("cgroupRouteContradictions = %d, want 1", s.cgroupRouteContradictions)
	}
	if got, ok := s.cgroupRoute.lookup(3000); !ok || got != cid {
		t.Errorf("lookup(3000) = (%q, %v), want (%q, true) -- the newest seed's own answer is always adopted", got, ok, cid)
	}
}

// TestApplyCgroupMkdirEvent_TruncatedOrEmptyPathNeverClassifies confirms
// neither an empty path nor a truncated one is ever handed to
// cgroupRoute.applyCgroupMkdir at all: either would risk ancestor-matching
// the cgroup root itself and wrongly confirming a real container's own
// cgroup as a non-container purely because its own path could not be read
// in full — see applyCgroupMkdirEvent's own doc comment. A pendingRouteEvent
// already queued for that cgroup ID must keep waiting, never be discarded as
// routeDiscard.
func TestApplyCgroupMkdirEvent_TruncatedOrEmptyPathNeverClassifies(t *testing.T) {
	s := newTestSessionForEvents()
	s.applyEvent(ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 48})
	if len(s.pendingRouteEvents) != 1 {
		t.Fatalf("len(pendingRouteEvents) = %d, want 1 before any cgroup_mkdir arrives", len(s.pendingRouteEvents))
	}

	s.applyEvent(ebpf.Event{Kind: ebpf.EventCgroupMkdir, CgroupID: 48, Path: ""})
	if _, known := s.cgroupRoute.lookup(48); known {
		t.Error("cgroupRoute classified cgroup 48 from an empty path, want it to stay unclassified")
	}

	s.applyEvent(ebpf.Event{Kind: ebpf.EventCgroupMkdir, CgroupID: 48, Path: "/system.slice/docker-truncated", PathTruncated: true})
	if _, known := s.cgroupRoute.lookup(48); known {
		t.Error("cgroupRoute classified cgroup 48 from a truncated path, want it to stay unclassified")
	}

	if len(s.pendingRouteEvents) != 1 {
		t.Errorf("len(pendingRouteEvents) = %d, want 1 (still unresolved, never discarded as routeDiscard)", len(s.pendingRouteEvents))
	}
}

// TestQueuePendingRouteEventDropsOldestAtCap covers applyForcedGapEviction's
// own full safety net, not merely "an evicted item is counted somewhere": a
// forced eviction, before any discovery pass has ever had a chance to
// classify the evicted cgroups, cannot prove they belong to nothing at all
// — so it downgrades every live generation it cannot rule out (g's own
// mount view is never confirmed in this test, so it qualifies), records a
// watermark protecting a container not even discovered yet, and still
// counts every eviction in eventsUnclassified regardless.
func TestQueuePendingRouteEventDropsOldestAtCap(t *testing.T) {
	s := newTestSessionForEvents()
	s.eventsStatus = evidence.EventsOK
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('s')}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	s.generations[g.key()] = g

	beforeTicks, err := bootTicksNow()
	if err != nil {
		t.Fatalf("bootTicksNow: %v", err)
	}

	for i := 0; i < maxPendingRouteEvents+5; i++ {
		s.queuePendingRouteEvent(pendingRouteEvent{ev: ebpf.Event{CgroupID: uint64(i)}, receivedAt: s.now()})
	}

	afterTicks, err := bootTicksNow()
	if err != nil {
		t.Fatalf("bootTicksNow: %v", err)
	}

	if len(s.pendingRouteEvents) != maxPendingRouteEvents {
		t.Fatalf("len(pendingRouteEvents) = %d, want %d", len(s.pendingRouteEvents), maxPendingRouteEvents)
	}
	if s.pendingRouteEvents[0].ev.CgroupID != 5 {
		t.Errorf("oldest surviving entry has CgroupID %d, want 5 (the first 5 should have been dropped)", s.pendingRouteEvents[0].ev.CgroupID)
	}
	if s.eventsUnclassified != 5 {
		t.Errorf("eventsUnclassified = %d, want 5 (one per dropped entry) -- counted regardless of whatever coverage downgrade also happened", s.eventsUnclassified)
	}

	// g's own mount view was never confirmed (no sample has run): any one of
	// the 5 evicted events could still turn out to have been its own, so
	// safety requires downgrading it rather than guessing it out.
	if g.eventsCoverage != evidence.CoveragePartial {
		t.Errorf("eventsCoverage = %q, want partial -- g's own mount view is unconfirmed, so it cannot be ruled out as the evicted events' own generation", g.eventsCoverage)
	}
	if !g.incomplete {
		t.Errorf("incomplete = false, want true (markCoveragePartial's own side effect)")
	}
	if g.eventsLost != 0 {
		t.Errorf("eventsLost = %d, want 0 -- a forced-safety downgrade is not a specific, countable loss the way tier 1 is", g.eventsLost)
	}

	// A container not even discovered yet is protected too, via the
	// watermark this eviction recorded.
	if !s.forcedGapWatermarkSet {
		t.Fatalf("forcedGapWatermarkSet = false after a forced eviction, want true")
	}
	if s.forcedGapWatermarkTicks < beforeTicks || s.forcedGapWatermarkTicks > afterTicks {
		t.Errorf("forcedGapWatermarkTicks = %d, want within [%d, %d] (the instant the eviction actually happened)", s.forcedGapWatermarkTicks, beforeTicks, afterTicks)
	}
	if got, watermarkProtected := s.initialEventsCoverage(s.forcedGapWatermarkTicks); got != evidence.CoveragePartial || !watermarkProtected {
		t.Errorf("initialEventsCoverage(watermark) = (%q, %v), want (partial, true) -- a generation discovered later, whose own init started at or before the watermark, must never claim since_start", got, watermarkProtected)
	}
	if got, watermarkProtected := s.initialEventsCoverage(afterTicks + 1_000_000_000); got != evidence.CoverageSinceStart || watermarkProtected {
		t.Errorf("initialEventsCoverage(well after the watermark) = (%q, %v), want (since_start, false) -- the watermark must not blanket-downgrade every future generation regardless of when it actually started", got, watermarkProtected)
	}
}

// TestRetryPendingRouteEvents_ExpiryCountsAsUnclassifiedOnceDiscoveryHasRun
// covers classifyUnattributedExpiry's own tier 3: an item whose cgroup is
// still unclassified when its own TTL elapses is only ever counted (never
// silently discarded) once a discovery pass that started after it arrived
// has actually completed -- reconcileCgroupRoute's own reseeding is the
// primary way a cgroup ever gets classified on a host where tp_btf/
// cgroup_mkdir's own event delivery cannot be relied on, so this readiness
// gate is what keeps an event from being given up on before discovery even
// had its first chance to classify it.
func TestRetryPendingRouteEvents_ExpiryCountsAsUnclassifiedOnceDiscoveryHasRun(t *testing.T) {
	s := newTestSessionForEvents()
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('t')}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	s.generations[g.key()] = g

	base := s.now()
	s.pendingRouteEvents = []pendingRouteEvent{
		{ev: ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 1}, kind: evidence.KindExecEvent, isExec: true, receivedAt: base},
	}
	// A discovery pass that started after this item arrived has already
	// completed.
	s.lastCompletedDiscoveryStartedAt = base.Add(time.Second)

	s.retryPendingRouteEvents(base.Add(pendingRouteEventTTL + 2*time.Second))

	if len(s.pendingRouteEvents) != 0 {
		t.Errorf("len(pendingRouteEvents) = %d, want 0 (expired, and a fresh discovery pass had already run)", len(s.pendingRouteEvents))
	}
	if s.eventsUnclassified != 1 {
		t.Errorf("eventsUnclassified = %d, want 1", s.eventsUnclassified)
	}
	if g.eventsCoverage != evidence.CoverageSinceStart {
		t.Errorf("eventsCoverage = %q, want unchanged at since_start -- an unrelated generation's own coverage must never be downgraded by this", g.eventsCoverage)
	}
}

// TestRetryPendingRouteEvents_ExpiryWithoutFreshDiscoveryKeepsWaiting is the
// companion to the test above: without a discovery pass that started after
// the item arrived having completed yet, pendingRouteEventTTL having
// elapsed is not enough -- the item is "not ready to decide", not
// "expired", and keeps waiting rather than being counted (or discarded) at
// all.
func TestRetryPendingRouteEvents_ExpiryWithoutFreshDiscoveryKeepsWaiting(t *testing.T) {
	s := newTestSessionForEvents()
	base := s.now()
	s.pendingRouteEvents = []pendingRouteEvent{
		{ev: ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 1}, kind: evidence.KindExecEvent, isExec: true, receivedAt: base},
	}
	// s.lastCompletedDiscoveryStartedAt is left at its zero value: no
	// discovery pass has completed at all since this item arrived.
	s.retryPendingRouteEvents(base.Add(pendingRouteEventTTL + time.Hour))

	if len(s.pendingRouteEvents) != 1 {
		t.Errorf("len(pendingRouteEvents) = %d, want 1 -- must keep waiting for a discovery pass that started after it arrived", len(s.pendingRouteEvents))
	}
	if s.eventsUnclassified != 0 {
		t.Errorf("eventsUnclassified = %d, want 0 -- not ready to be counted yet", s.eventsUnclassified)
	}
}

// TestPendingRouteEventGating_UnconfirmedMountViewMarksIncomplete confirms
// that a pendingRouteEvent whose own cgroup cannot be classified at all
// right now (never seen, or evicted from cgroupRoute) still marks
// Incomplete a live generation whose own mount view is not yet confirmed at
// all (nothing to rule it out on yet) — but never an already-ended
// generation. See the companion test below for the narrower half of the
// same rule once a generation's own mount view *is* confirmed.
func TestPendingRouteEventGating_UnconfirmedMountViewMarksIncomplete(t *testing.T) {
	s := newTestSessionForEvents()
	live := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('5')}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	ended := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('6')}, InitProcess{PID: 2, Starttime: 2}, s.now(), evidence.CoverageSinceStart)
	ended.ended = true
	s.generations[live.key()] = live
	s.generations[ended.key()] = ended

	// Cgroup 999 is never registered anywhere in s.cgroupRoute at all.
	s.pendingRouteEvents = []pendingRouteEvent{{ev: ebpf.Event{CgroupID: 999}, receivedAt: s.now()}}

	incomplete := s.pendingRouteEventGating()
	if !incomplete[live.container.ID] {
		t.Error("live generation not marked incomplete, want true -- its own mount view is not yet confirmed at all")
	}
	if incomplete[ended.container.ID] {
		t.Error("an already-ended generation must never be marked incomplete by this at all")
	}

	// End-to-end through buildSnapshot itself, not just pendingRouteEventGating
	// combined by hand above.
	snap := s.buildSnapshot(evidence.SensorOK)
	for _, g := range snap.Generations {
		switch g.Container.ID {
		case live.container.ID:
			if !g.Incomplete {
				t.Error("buildSnapshot: live generation Incomplete = false, want true")
			}
		case ended.container.ID:
			if g.Incomplete {
				t.Error("buildSnapshot: ended generation Incomplete = true, want false")
			}
		}
	}
}

// TestPendingRouteEventGating_ConfirmedMountViewOnlyMarksMatchingGeneration
// covers the narrower half of the same rule: once a live generation's own
// mount view is confirmed, an unclassified pendingRouteEvent only marks it
// Incomplete if its own mount namespace actually matches — never a
// different, equally-confirmed generation this item demonstrably cannot
// belong to.
func TestPendingRouteEventGating_ConfirmedMountViewOnlyMarksMatchingGeneration(t *testing.T) {
	s := newTestSessionForEvents()
	matching := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('y')}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	matching.mntNsID = 42
	other := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('z')}, InitProcess{PID: 2, Starttime: 2}, s.now(), evidence.CoverageSinceStart)
	other.mntNsID = 99
	s.generations[matching.key()] = matching
	s.generations[other.key()] = other

	s.pendingRouteEvents = []pendingRouteEvent{{ev: ebpf.Event{CgroupID: 999, MountNamespaceID: 42}, receivedAt: s.now()}}

	incomplete := s.pendingRouteEventGating()
	if !incomplete[matching.container.ID] {
		t.Error("matching generation not marked incomplete, want true")
	}
	if incomplete[other.container.ID] {
		t.Error("other generation marked incomplete, want false -- its own confirmed mount namespace does not match this item's own")
	}
}

// TestBuildSnapshot_PendingKernelLossMarksEveryLiveGenerationIncompleteNotSticky
// covers this round's fix: a kernel per-cgroup ring-buffer loss delta this
// session cannot yet resolve (pendingLossDeltas) carries no mount namespace
// at all — unlike a pendingRouteEvent, there is nothing here to narrow which
// live generation it might belong to (see pendingRouteEventGating's own
// tier-2-style narrowing, which needs at least a mount namespace to work
// with) — so every live generation, confirmed mount view or not, must
// publish Incomplete for as long as anything sits in pendingLossDeltas at
// all. Not sticky: the moment the queue empties (resolved, or finalized by
// the existing three-tier rule), the next snapshot reverts on its own.
func TestBuildSnapshot_PendingKernelLossMarksEveryLiveGenerationIncompleteNotSticky(t *testing.T) {
	s := newTestSessionForEvents()
	live := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('k')}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	live.mntNsID = 1 // confirmed -- must still be marked; a kernel loss carries no mnt ns to narrow by
	ended := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('l')}, InitProcess{PID: 2, Starttime: 2}, s.now(), evidence.CoverageSinceStart)
	ended.ended = true
	s.generations[live.key()] = live
	s.generations[ended.key()] = ended

	s.pendingLossDeltas = []pendingLossDelta{{cgroupID: 700, delta: 1, receivedAt: s.now()}}

	snap := s.buildSnapshot(evidence.SensorOK)
	for _, g := range snap.Generations {
		switch g.Container.ID {
		case live.container.ID:
			if !g.Incomplete {
				t.Error("live generation Incomplete = false while pendingLossDeltas is non-empty, want true")
			}
		case ended.container.ID:
			if g.Incomplete {
				t.Error("an already-ended generation must never be marked incomplete by this at all")
			}
		}
	}

	// The pending delta clears (resolved, or finalized) -- Incomplete must
	// revert on its own, the next snapshot, not stay sticky.
	s.pendingLossDeltas = nil
	snap2 := s.buildSnapshot(evidence.SensorOK)
	for _, g := range snap2.Generations {
		if g.Container.ID == live.container.ID && g.Incomplete {
			t.Error("live generation Incomplete = true after pendingLossDeltas emptied, want false (not sticky)")
		}
	}
}

func TestGenerationExpirePendingEvents(t *testing.T) {
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('g')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0), evidence.CoverageSinceStart)
	old := time.Unix(0, 0)
	g.recordPendingEvent(pendingEventItem{path: "/a", receivedAt: old})
	fresh := old.Add(pendingEventTTL / 2)
	g.recordPendingEvent(pendingEventItem{path: "/b", receivedAt: fresh})

	g.expirePendingEvents(old.Add(pendingEventTTL + time.Second))

	if len(g.pendingEvents) != 1 || g.pendingEvents[0].path != "/b" {
		t.Errorf("pendingEvents = %+v, want only /b to survive", g.pendingEvents)
	}
	if g.eventsLost != 1 {
		t.Errorf("eventsLost = %d, want 1 (the expired /a)", g.eventsLost)
	}
	if g.eventsCoverage != evidence.CoveragePartial {
		t.Errorf("eventsCoverage = %q, want partial", g.eventsCoverage)
	}
}

func TestGenerationRecordPendingEventCap(t *testing.T) {
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('h')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0), evidence.CoverageSinceStart)
	for i := 0; i < maxPendingEventsPerGeneration+1; i++ {
		g.recordPendingEvent(pendingEventItem{path: "/x", receivedAt: time.Unix(int64(i), 0)})
	}
	if len(g.pendingEvents) != maxPendingEventsPerGeneration {
		t.Errorf("len(pendingEvents) = %d, want %d", len(g.pendingEvents), maxPendingEventsPerGeneration)
	}
	if g.eventsLost != 1 {
		t.Errorf("eventsLost = %d, want 1 (the one dropped for exceeding the cap)", g.eventsLost)
	}
}

func TestAttributeEventLossDeltasPerCgroup(t *testing.T) {
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('i')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0), evidence.CoverageSinceStart)
	resolve := func(cgroupID uint64) (*generationState, eventRouteOutcome) {
		if cgroupID == 7 {
			return g, routeResolved
		}
		return nil, routeUnresolved
	}
	unclassifiedNow, pending := attributeEventLossDeltas(
		map[uint64]uint64{7: 5, 9: 2}, 0,
		map[uint64]uint64{7: 2}, 0,
		resolve,
	)
	if g.eventsLost != 3 {
		t.Errorf("eventsLost = %d, want 3 (5-2, attributed to cgroup 7's generation)", g.eventsLost)
	}
	if unclassifiedNow != 0 {
		t.Errorf("unclassifiedNow = %d, want 0 -- cgroup 9's own delta is not resolvable yet, but must be queued (pending), not finalized on the spot", unclassifiedNow)
	}
	if want := []pendingCgroupLoss{{cgroupID: 9, delta: 2}}; !reflect.DeepEqual(pending, want) {
		t.Errorf("pending = %+v, want %+v (cgroup 9's own delta, which resolve could not attribute to anything yet)", pending, want)
	}
	if g.eventsCoverage != evidence.CoveragePartial {
		t.Errorf("eventsCoverage = %q, want partial", g.eventsCoverage)
	}
}

// TestAttributeEventLossDeltasDiscardNeverCounts confirms that a per-cgroup
// delta resolve confirms is routeDiscard (a host process's own cgroup, or an
// operator-excluded container) contributes to neither the returned
// unclassified total nor any generation's own coverage -- it is not this
// session's own observation being affected at all, so it must not make an
// otherwise fully-since_start container look partial.
func TestAttributeEventLossDeltasDiscardNeverCounts(t *testing.T) {
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('3')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0), evidence.CoverageSinceStart)
	resolve := func(uint64) (*generationState, eventRouteOutcome) { return nil, routeDiscard }

	unclassifiedNow, pending := attributeEventLossDeltas(map[uint64]uint64{7: 5}, 0, map[uint64]uint64{7: 2}, 0, resolve)

	if unclassifiedNow != 0 {
		t.Errorf("unclassifiedNow = %d, want 0 -- a routeDiscard delta is not this session's own observation at all", unclassifiedNow)
	}
	if len(pending) != 0 {
		t.Errorf("pending = %+v, want empty -- a routeDiscard delta must never be queued either", pending)
	}
	if g.eventsCoverage != evidence.CoverageSinceStart {
		t.Errorf("eventsCoverage = %q, want unchanged at since_start -- a routeDiscard delta must never mark any generation partial", g.eventsCoverage)
	}
	if g.eventsLost != 0 {
		t.Errorf("eventsLost = %d, want 0", g.eventsLost)
	}
}

// TestAttributeEventLossDeltasFallbackIsAlwaysUnclassified confirms that
// kl_lost_events (the fallback counter with no per-cgroup breakdown at all)
// can never be tier 1 (there is no cgroup ID to resolve against anything)
// and therefore never touches any generation's own coverage or eventsLost —
// only the returned unclassified total, which the caller folds into
// s.eventsUnclassified (recordUnclassifiedEventLoss), never s.eventsLost.
func TestAttributeEventLossDeltasFallbackIsAlwaysUnclassified(t *testing.T) {
	g1 := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('j')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0), evidence.CoverageSinceStart)
	g2 := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('k')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0), evidence.CoverageSinceStart)

	unclassifiedNow, pending := attributeEventLossDeltas(nil, 3, nil, 1, func(uint64) (*generationState, eventRouteOutcome) { return nil, routeUnresolved })

	if unclassifiedNow != 2 {
		t.Errorf("unclassifiedNow = %d, want 2 (3-1, the fallback counter's own delta -- finalized immediately, unlike a per-cgroup delta)", unclassifiedNow)
	}
	if len(pending) != 0 {
		t.Errorf("pending = %+v, want empty -- byCgroup is empty, so there is nothing to queue", pending)
	}
	if g1.eventsCoverage != evidence.CoverageSinceStart || g2.eventsCoverage != evidence.CoverageSinceStart {
		t.Error("the fallback counter carries no cgroup ID at all -- it must never downgrade any generation's own coverage")
	}
	if g1.eventsLost != 0 || g2.eventsLost != 0 {
		t.Error("must not advance any one generation's own events_lost either")
	}
}

// TestRetryPendingLossDeltas_WithoutFreshDiscoveryKeepsWaiting covers the
// core of this round's fix to attributeEventLossDeltas/reconcileEventLossCounters:
// a per-cgroup kernel loss delta this session cannot yet resolve to a
// specific generation must not be finalized as unclassified the moment it
// is first observed — it keeps waiting, exactly the way a specific event's
// own pendingRouteEvent already does, until a discovery pass that started
// after it arrived has actually completed.
func TestRetryPendingLossDeltas_WithoutFreshDiscoveryKeepsWaiting(t *testing.T) {
	s := newTestSessionForEvents()
	base := s.now()
	s.pendingLossDeltas = []pendingLossDelta{{cgroupID: 42, delta: 3, receivedAt: base}}
	// s.lastCompletedDiscoveryStartedAt is left at its zero value: no
	// discovery pass has completed at all since this delta arrived.

	s.retryPendingLossDeltas(base.Add(time.Hour))

	if len(s.pendingLossDeltas) != 1 {
		t.Errorf("len(pendingLossDeltas) = %d, want 1 -- must keep waiting for a discovery pass that started after it arrived", len(s.pendingLossDeltas))
	}
	if s.eventsUnclassified != 0 {
		t.Errorf("eventsUnclassified = %d, want 0 -- not ready to be counted yet", s.eventsUnclassified)
	}
}

// TestRetryPendingLossDeltas_CountsAsUnclassifiedOnceDiscoveryHasRun is the
// companion to the test above: once a discovery pass that started after the
// delta arrived has completed, and the cgroup still cannot be resolved to
// anything, it is finally counted -- and only in eventsUnclassified, never
// as a specific generation's own eventsLost or a coverage downgrade.
func TestRetryPendingLossDeltas_CountsAsUnclassifiedOnceDiscoveryHasRun(t *testing.T) {
	s := newTestSessionForEvents()
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('u')}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	s.generations[g.key()] = g

	base := s.now()
	s.pendingLossDeltas = []pendingLossDelta{{cgroupID: 42, delta: 3, receivedAt: base}}
	s.lastCompletedDiscoveryStartedAt = base.Add(time.Second)

	s.retryPendingLossDeltas(base.Add(time.Hour))

	if len(s.pendingLossDeltas) != 0 {
		t.Errorf("len(pendingLossDeltas) = %d, want 0 (resolved -- a fresh discovery pass had already run)", len(s.pendingLossDeltas))
	}
	if s.eventsUnclassified != 3 {
		t.Errorf("eventsUnclassified = %d, want 3", s.eventsUnclassified)
	}
	if g.eventsCoverage != evidence.CoverageSinceStart || g.eventsLost != 0 {
		t.Errorf("g = %+v, want untouched -- an unrelated generation's own coverage/eventsLost must never be affected by this", g)
	}
}

// TestRetryPendingLossDeltas_ResolvesToLiveGenerationOnceClassified covers
// tier 1 for a pendingLossDelta: once the cgroup this delta names resolves
// to a real, live generation (e.g. reconcileCgroupRoute classified it in
// the meantime), a retry charges that generation's own eventsLost directly
// -- never eventsUnclassified -- exactly as an already-resolved cgroup
// already does in attributeEventLossDeltas itself.
func TestRetryPendingLossDeltas_ResolvesToLiveGenerationOnceClassified(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('v')
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	s.generations[g.key()] = g

	base := s.now()
	s.pendingLossDeltas = []pendingLossDelta{{cgroupID: 42, delta: 3, receivedAt: base}}
	// The cgroup becomes classified in the meantime -- no discovery-pass
	// completion needed at all for tier 1, unlike tier 3.
	s.cgroupRoute.set(42, "/system.slice/docker-"+cid+".scope", cid)

	s.retryPendingLossDeltas(base)

	if len(s.pendingLossDeltas) != 0 {
		t.Errorf("len(pendingLossDeltas) = %d, want 0 (resolved outright)", len(s.pendingLossDeltas))
	}
	if g.eventsLost != 3 {
		t.Errorf("eventsLost = %d, want 3", g.eventsLost)
	}
	if s.eventsUnclassified != 0 {
		t.Errorf("eventsUnclassified = %d, want 0 -- a cgroup that resolves outright is never unclassified", s.eventsUnclassified)
	}
}

// TestApplyForcedGapEviction_ConfirmedMountViewMatchOnly covers item (a) of
// applyForcedGapEviction's own safety net: a live generation whose own
// mount view is already confirmed only gets downgraded when it actually
// matches mntNSID -- an equally-confirmed generation with a different mount
// namespace is not this loss's own generation and must be left alone,
// exactly like classifyUnattributedExpiry's own tier 2 exact-match rule.
func TestApplyForcedGapEviction_ConfirmedMountViewMatchOnly(t *testing.T) {
	s := newTestSessionForEvents()
	matching := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('m')}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	matching.mntNsID = 42
	other := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('o')}, InitProcess{PID: 2, Starttime: 2}, s.now(), evidence.CoverageSinceStart)
	other.mntNsID = 99
	s.generations[matching.key()] = matching
	s.generations[other.key()] = other

	s.applyForcedGapEviction(42, 1, time.Time{})

	if matching.eventsCoverage != evidence.CoveragePartial {
		t.Errorf("matching.eventsCoverage = %q, want partial -- its own confirmed mount namespace matches", matching.eventsCoverage)
	}
	if other.eventsCoverage != evidence.CoverageSinceStart {
		t.Errorf("other.eventsCoverage = %q, want unchanged at since_start -- its own confirmed mount namespace does not match", other.eventsCoverage)
	}
	if s.eventsUnclassified != 1 {
		t.Errorf("eventsUnclassified = %d, want 1", s.eventsUnclassified)
	}
}

// TestApplyForcedGapEviction_ZeroMountNamespaceProtectsConfirmedGenerationsToo
// covers this round's fix: mntNSID == 0 (an aggregate kernel loss-counter
// delta, carrying no single event's own mount namespace at all) leaves
// nothing at all to narrow by, so even a live generation whose own mount
// view is already confirmed must be downgraded — unlike the mntNSID != 0
// case (TestApplyForcedGapEviction_ConfirmedMountViewMatchOnly above), where
// a confirmed generation is only downgraded if its own mount namespace
// actually matches.
func TestApplyForcedGapEviction_ZeroMountNamespaceProtectsConfirmedGenerationsToo(t *testing.T) {
	s := newTestSessionForEvents()
	confirmed := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('n')}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	confirmed.mntNsID = 42
	unconfirmed := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('p')}, InitProcess{PID: 2, Starttime: 2}, s.now(), evidence.CoverageSinceStart)
	s.generations[confirmed.key()] = confirmed
	s.generations[unconfirmed.key()] = unconfirmed

	s.applyForcedGapEviction(0, 1, time.Time{})

	if confirmed.eventsCoverage != evidence.CoveragePartial || !confirmed.incomplete {
		t.Errorf("confirmed = {coverage=%q incomplete=%v}, want {partial, true} -- an already-confirmed mount view is not enough to rule out an aggregate loss with no mount namespace of its own to compare against", confirmed.eventsCoverage, confirmed.incomplete)
	}
	if unconfirmed.eventsCoverage != evidence.CoveragePartial || !unconfirmed.incomplete {
		t.Errorf("unconfirmed = {coverage=%q incomplete=%v}, want {partial, true}", unconfirmed.eventsCoverage, unconfirmed.incomplete)
	}
	if s.eventsUnclassified != 1 {
		t.Errorf("eventsUnclassified = %d, want 1", s.eventsUnclassified)
	}
}

func TestInitialEventsCoverage(t *testing.T) {
	s := newTestSessionForEvents()
	s.eventsStatus = evidence.EventsUnavailable
	if got, watermarkProtected := s.initialEventsCoverage(9999); got != evidence.CoverageNone || watermarkProtected {
		t.Errorf("initialEventsCoverage(9999) = (%q, %v), want (none, false) when eventsStatus is unavailable", got, watermarkProtected)
	}

	s.eventsStatus = evidence.EventsOK
	s.attachedAtBootTicks = 1000
	if got, watermarkProtected := s.initialEventsCoverage(1001); got != evidence.CoverageSinceStart || watermarkProtected {
		t.Errorf("initialEventsCoverage(1001) = (%q, %v), want (since_start, false) when init started after attach (tick 1000)", got, watermarkProtected)
	}
	if got, watermarkProtected := s.initialEventsCoverage(1000); got != evidence.CoveragePartial || watermarkProtected {
		t.Errorf("initialEventsCoverage(1000) = (%q, %v), want (partial, false) when init started at the same tick as attach", got, watermarkProtected)
	}
	if got, watermarkProtected := s.initialEventsCoverage(999); got != evidence.CoveragePartial || watermarkProtected {
		t.Errorf("initialEventsCoverage(999) = (%q, %v), want (partial, false) when init started before attach", got, watermarkProtected)
	}
}

func TestParseUserNSInode(t *testing.T) {
	n, ok := parseUserNSInode("user:[4026531837]")
	if !ok || n != 4026531837 {
		t.Errorf("parseUserNSInode = (%d, %v), want (4026531837, true)", n, ok)
	}
	if _, ok := parseUserNSInode("mnt:[4026531840]"); ok {
		t.Error("parseUserNSInode accepted a non-user namespace link")
	}
	if _, ok := parseUserNSInode(""); ok {
		t.Error("parseUserNSInode accepted an empty string")
	}
}

func TestEventInDistinctUserNS(t *testing.T) {
	s := newTestSessionForEvents()
	s.ownUserNSInode = 4026531837
	if s.eventInDistinctUserNS(ebpf.Event{UserNamespaceID: 4026531837}) {
		t.Error("same user namespace inode reported as distinct")
	}
	if !s.eventInDistinctUserNS(ebpf.Event{UserNamespaceID: 4026532000}) {
		t.Error("different user namespace inode not reported as distinct")
	}
	if s.eventInDistinctUserNS(ebpf.Event{UserNamespaceID: 0}) {
		t.Error("UserNamespaceID 0 (could not determine) must default to false, not true")
	}
}

// TestEventDrivenOSPackage_LaterHighPrivilegeProcessUpdatesObservations
// exercises the whole event-to-attribution wiring end to end: two
// exec_success events for the same file, one from an unprivileged process
// and a later one (e.g. after a setuid exec) from EUID 0, must both survive
// in the resulting OSPackageEvidence's Observations rather than the second
// simply replacing the first — a file used later by a higher-privileged
// process must update, not overwrite, its own recorded exposure/privilege
// combinations.
func TestEventDrivenOSPackage_LaterHighPrivilegeProcessUpdatesObservations(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('n')
	g := newReadyGeneration(s, 50, cid)

	s.applyEvent(ebpf.Event{Kind: ebpf.EventFileOpen, MountNamespaceID: 1, RootDev: testRootDevRaw, RootIno: testRootIno, Dev: 60, Ino: 61, Path: "/usr/sbin/nginx"})
	s.applyEvent(ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 50, MountNamespaceID: 1, RootDev: testRootDevRaw, RootIno: testRootIno, Dev: 60, Ino: 61, EUID: 1000})

	var job dbJob
	select {
	case job = <-s.dbJobCh:
	default:
		t.Fatal("no dbJob submitted for the first exec_success event")
	}

	// A second exec_success for the exact same file, now as EUID 0 (e.g.
	// after execing a setuid binary) — submitted while the first lookup is
	// still outstanding, so it must queue rather than issue a second
	// concurrent lookup (see TestApplyUsageEventQueuesBehindPendingLookup).
	s.applyEvent(ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 50, MountNamespaceID: 1, RootDev: testRootDevRaw, RootIno: testRootIno, Dev: 60, Ino: 61, EUID: 0})
	if len(g.queuedCandidates) != 1 {
		t.Fatalf("len(queuedCandidates) = %d, want 1 (the second event queued behind the first lookup)", len(g.queuedCandidates))
	}

	// The parser answers the first lookup.
	fatal := s.applyDBResult(dbResult{
		kind: dbJobLookup, genKey: job.genKey, epoch: job.epoch, seq: job.seq,
		owners: map[string]lookupOutcome{"/usr/sbin/nginx": {owners: []lookupOwner{{Name: "nginx", Version: "1.24.0"}}}},
	})
	if fatal != nil {
		t.Fatalf("applyDBResult: %v", fatal)
	}

	// flushQueuedCandidates must have submitted the second (queued) batch
	// as a fresh lookup.
	select {
	case job2 := <-s.dbJobCh:
		fatal := s.applyDBResult(dbResult{
			kind: dbJobLookup, genKey: job2.genKey, epoch: job2.epoch, seq: job2.seq,
			owners: map[string]lookupOutcome{"/usr/sbin/nginx": {owners: []lookupOwner{{Name: "nginx", Version: "1.24.0"}}}},
		})
		if fatal != nil {
			t.Fatalf("applyDBResult (second): %v", fatal)
		}
	default:
		t.Fatal("no second dbJob submitted for the queued candidate batch")
	}

	pkg, ok := g.osPackages[pkgKey{Name: "nginx", Version: "1.24.0"}]
	if !ok {
		t.Fatal("nginx not recorded as an OS package in use")
	}
	if len(pkg.Observations) != 2 {
		t.Fatalf("len(Observations) = %d, want 2 (EUID 1000 and EUID 0 both retained)", len(pkg.Observations))
	}
	sawRoot, sawUnprivileged := false, false
	for _, obs := range pkg.Observations {
		switch obs.EffectiveUID {
		case 0:
			sawRoot = true
		case 1000:
			sawUnprivileged = true
		}
	}
	if !sawRoot || !sawUnprivileged {
		t.Errorf("Observations = %+v, want one with EUID 0 and one with EUID 1000", pkg.Observations)
	}
}

func TestApplyUsageEventMmapPathUnknownRecordsLoss(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('o')
	g := newReadyGeneration(s, 51, cid)

	s.applyEvent(ebpf.Event{Kind: ebpf.EventMmapSuccess, CgroupID: 51, MountNamespaceID: 1, Dev: 70, Ino: 71})

	if g.eventsLost != 1 || !g.incomplete {
		t.Errorf("eventsLost=%d incomplete=%v, want 1/true for a path-unknown mmap_success", g.eventsLost, g.incomplete)
	}
}

// TestResolveEventGeneration_ZeroStartBoottimeFallsBackToLive documents the
// defensive fallback resolveEventGeneration takes when it has no process
// start time to disambiguate with at all (never expected in practice, since
// kl_exec_success/kl_mmap_success always report one) — the same simple
// "whichever generation for this container ID is currently live" rule this
// function always applied before it could take a process start time into
// account.
func TestResolveEventGeneration_ZeroStartBoottimeFallsBackToLive(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('p')
	oldGen := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	s.generations[oldGen.key()] = oldGen
	s.endGeneration(oldGen, s.now())
	newGen := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: 2, Starttime: 2}, s.now(), evidence.CoverageSinceStart)
	s.generations[newGen.key()] = newGen
	s.cgroupRoute.set(52, "/system.slice/docker-"+cid+".scope", cid)

	// The zero-startBoottimeNs path skips the tick-based proof entirely (see
	// resolveEventGeneration's own doc comment): it is only ever used for
	// the aggregate per-cgroup loss-counter attribution, which has no
	// single event to take a process start time from at all.
	g, outcome := s.resolveEventGeneration(52, 0, 0, 0)
	if outcome != routeResolved || g != newGen {
		t.Errorf("resolveEventGeneration(52, 0, 0) = (%v, %v), want (newGen, routeResolved)", g, outcome)
	}
}

// TestResolveEventGeneration_HostMountNamespaceEventNeverAttributes covers
// the host-mount-namespace discard added alongside the H1/H3 fixes: an event
// reporting the Sensor's own known host mount namespace (s.hostMntNSID) must
// route as routeDiscard even when its own cgroup ID is a real, already-known,
// perfectly resolvable container — a real Docker container's own workload
// never execs inside the host's own mount namespace (see
// resolveEventGeneration's own doc comment), so this can never be that
// container's own usage evidence regardless of which cgroup it carries.
func TestResolveEventGeneration_HostMountNamespaceEventNeverAttributes(t *testing.T) {
	s := newTestSessionForEvents()
	s.hostMntNSID = 4026531840
	cid := strings64('h')
	gen := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	s.generations[gen.key()] = gen
	s.cgroupRoute.set(60, "/system.slice/docker-"+cid+".scope", cid)

	if g, outcome := s.resolveEventGeneration(60, 0, 0, s.hostMntNSID); outcome != routeDiscard || g != nil {
		t.Errorf("resolveEventGeneration with mntNSID == hostMntNSID = (%v, %v), want (nil, routeDiscard)", g, outcome)
	}

	// A different mount namespace for the exact same cgroup still resolves
	// normally — this is not a blanket "ignore this cgroup" rule, only a
	// per-event mount-namespace check.
	if g, outcome := s.resolveEventGeneration(60, 0, 0, s.hostMntNSID+1); outcome != routeResolved || g != gen {
		t.Errorf("resolveEventGeneration with a distinct mntNSID = (%v, %v), want (gen, routeResolved)", g, outcome)
	}

	// mntNSID == 0 (the aggregate per-cgroup loss-counter caller, which has
	// no single event to take one from at all) always skips this check.
	if g, outcome := s.resolveEventGeneration(60, 0, 0, 0); outcome != routeResolved || g != gen {
		t.Errorf("resolveEventGeneration with mntNSID 0 = (%v, %v), want (gen, routeResolved)", g, outcome)
	}
}

// TestRetryPendingRouteEvents_RestartStragglerAttributesToOldGeneration
// covers a pending event that arrives spanning a same-container-ID restart:
// a pendingRouteEvent whose own process started (per its start_boottime_ns,
// converted to clock ticks) *before* the new generation's own init did must
// still attribute to the *old* (already-ended) generation once the restart
// has happened and the retry runs — never to the new one just because it is
// the one currently live. oldGen.lastAliveNs is set past the straggler's own
// process start nanosecond — standing in for a real sample that confirmed
// oldGen's own init still alive that recently, before the restart — which is
// what actually proves this attribution under resolveEventGeneration's own
// rule (s_ns <= lastAliveNs); a known later generation existing is not, by
// itself, proof of anything about an earlier instant (see
// TestResolveEventGeneration_UnprovableGapNeverAttributesToBoundingGeneration
// for that case). This is deliberately exercised with oldGen's own init
// naming a PID (1) that is almost certainly not this test's own real
// process, and no genConfirmFn double at all: resolveEventGeneration's own
// direct proof needs no liveness confirmation dispatched at all, so this
// test would hang if it ever needed one.
func TestRetryPendingRouteEvents_RestartStragglerAttributesToOldGeneration(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('p')
	// oldGen's own init started at tick 1000; newGen's at tick 5000 (a
	// restart, well after old's own init).
	oldGen := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: 1, Starttime: 1000}, s.now(), evidence.CoverageSinceStart)
	oldGen.lastVerifiedAt = s.now()
	// A real sample confirmed oldGen's own init still alive (with matching
	// starttime) up to tick 2500's own nanosecond, before the restart below
	// — the only thing that makes the straggler's own tick 2000 provable at
	// all (see resolveEventGeneration's own doc comment: s_ns <=
	// lastAliveNs): a known *later* generation existing is not by itself
	// proof of anything about tick 2000 specifically (see the sibling
	// TestResolveEventGeneration_Unprovable* test for the case where no such
	// confirmation exists).
	oldGen.lastAliveNs = uint64(2500) * nsPerClockTick
	oldGen.lastAliveNsOK = true
	s.generations[oldGen.key()] = oldGen

	// The straggler process itself started at tick 2000 — after oldGen's own
	// init, before newGen's, and within oldGen's own confirmed-alive window
	// — so it can only ever have been oldGen's own process. Its own success
	// event arrives before the cgroup is known, so it queues.
	strayEventStartTicks := int64(2000)
	ev := ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 52, StartBoottimeNs: uint64(strayEventStartTicks) * nsPerClockTick}
	s.applyEvent(ev)
	if len(s.pendingRouteEvents) != 1 {
		t.Fatalf("len(pendingRouteEvents) = %d, want 1", len(s.pendingRouteEvents))
	}

	// The container restarts before the event resolves: oldGen ends, a new
	// generation for the same container ID (init starttime 5000) takes its
	// place — exactly what reconcileGenerations does for a same-ID restart —
	// and only then does the cgroup mapping actually arrive.
	s.endGeneration(oldGen, s.now())
	newGen := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: 2, Starttime: 5000}, s.now(), evidence.CoverageSinceStart)
	newGen.idxState = indexReady
	newGen.packageDB.Status = evidence.DBStatusOK
	newGen.lastVerifiedAt = s.now()
	s.generations[newGen.key()] = newGen
	s.cgroupRoute.set(52, "/system.slice/docker-"+cid+".scope", cid)

	s.retryPendingRouteEvents(s.now())

	// Resolved and dispatched immediately — newGen is a known successor, so
	// no genConfirmRequest is ever dispatched for this straggler at all.
	if len(s.pendingRouteEvents) != 0 {
		t.Fatalf("len(pendingRouteEvents) = %d, want 0 (resolved outright)", len(s.pendingRouteEvents))
	}
	select {
	case res := <-s.genConfirmCh:
		t.Fatalf("genConfirmResult %+v dispatched, want none -- oldGen is bounded by the already-known newGen", res)
	default:
	}

	if newGen.eventsLost != 0 {
		t.Errorf("newGen.eventsLost = %d, want 0 -- a straggler from before its own init started must never be attributed to the new generation", newGen.eventsLost)
	}
	if oldGen.eventsLost == 0 {
		t.Error("oldGen.eventsLost = 0, want the path-unknown loss correctly attributed to the old (ended) generation the process actually started under")
	}
}

// TestRetryPendingRouteEvents_PostRestartEventAttributesToNewGeneration is
// RestartStragglerAttributesToOldGeneration's own control case: a process
// that started *after* the new generation's own init must attribute to the
// new generation, not the old one, confirming the disambiguation actually
// depends on the event's own process start time rather than always
// preferring whichever generation is oldest or newest.
func TestRetryPendingRouteEvents_PostRestartEventAttributesToNewGeneration(t *testing.T) {
	s := newTestSessionForEvents()
	s.genConfirmFn = func(int, int64) bool { return true } // see the sibling test's own comment on why
	cid := strings64('p')
	oldGen := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	s.generations[oldGen.key()] = oldGen
	s.endGeneration(oldGen, s.now())
	newGen := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: 2, Starttime: 5}, s.now(), evidence.CoverageSinceStart)
	newGen.idxState = indexReady
	newGen.packageDB.Status = evidence.DBStatusOK
	newGen.lastVerifiedAt = s.now()
	s.generations[newGen.key()] = newGen

	// This process started at tick 6 — after newGen's own init. The ticks
	// are kept tiny because the confirmation below reads the real
	// CLOCK_BOOTTIME: its answer only covers this event once the host has
	// been up longer than the event's own start time.
	ev := ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 53, StartBoottimeNs: uint64(6) * nsPerClockTick}
	waitUntilBootNsPast(t, ev.StartBoottimeNs)
	s.applyEvent(ev)
	if len(s.pendingRouteEvents) != 1 {
		t.Fatalf("len(pendingRouteEvents) = %d, want 1", len(s.pendingRouteEvents))
	}

	s.cgroupRoute.set(53, "/system.slice/docker-"+cid+".scope", cid)
	s.retryPendingRouteEvents(s.now())

	select {
	case res := <-s.genConfirmCh:
		if res.g != newGen {
			t.Fatalf("genConfirmResult.g = %v, want newGen -- the only candidate whose own init preceded this process", res.g)
		}
		s.applyGenConfirmResult(res)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for genconfirm.go's own answer")
	}

	if oldGen.eventsLost != 0 {
		t.Errorf("oldGen.eventsLost = %d, want 0", oldGen.eventsLost)
	}
	if newGen.eventsLost == 0 {
		t.Error("newGen.eventsLost = 0, want the path-unknown loss attributed to the new generation, whose init actually preceded this process")
	}
}

// TestResolveEventGeneration_UnprovableGapNeverAttributesToBoundingGeneration
// covers the counter-example to a "known successor bounds it" shortcut:
// container cid has a known generation A (init started
// at tick 1000, confirmed alive only up to tick 1500) and a known, later
// generation C (init started at tick 5000) — but an entirely undiscovered
// generation B could have started and ended anywhere between tick 1500 and
// 5000 without this session ever learning of it (a restart this session's
// own discovery missed twice in a row, between two of its own passes). An
// event whose own process started at tick 3000 — inside that gap — must
// never be attributed to A: A's own known start time makes it chronologically
// possible, but this session never actually confirmed A was still alive that
// recently, and C's own later existence proves nothing about tick 3000
// specifically. This must resolve to routeGapLoss, counted once as an
// unattributable loss and downgrading only A and C (this one container's own
// generations) to partial — never resolved by guessing, and never marking
// every generation this session holds the way a routeUnresolved/
// routeUnconfirmed expiry's own global downgrade does.
func TestResolveEventGeneration_UnprovableGapNeverAttributesToBoundingGeneration(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('6')
	otherCid := strings64('7')

	a := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: 1, Starttime: 1000}, s.now(), evidence.CoverageSinceStart)
	a.lastAliveNs = uint64(1500) * nsPerClockTick
	a.lastAliveNsOK = true
	a.ended = true
	c := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: 2, Starttime: 5000}, s.now(), evidence.CoverageSinceStart)
	s.generations[a.key()] = a
	s.generations[c.key()] = c
	s.cgroupRoute.set(200, "/system.slice/docker-"+cid+".scope", cid)

	// An unrelated container's own generation must never be touched by this
	// container's own gap.
	other := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: otherCid}, InitProcess{PID: 3, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	s.generations[other.key()] = other

	gapEventTicks := int64(3000)
	g, outcome := s.resolveEventGeneration(200, uint64(gapEventTicks)*nsPerClockTick, 999, 0)

	if outcome != routeGapLoss || g != nil {
		t.Fatalf("resolveEventGeneration = (%v, %v), want (nil, routeGapLoss)", g, outcome)
	}
	if s.unattributedEventsLost != 1 {
		t.Errorf("unattributedEventsLost = %d, want 1", s.unattributedEventsLost)
	}
	if a.eventsCoverage != evidence.CoveragePartial {
		t.Errorf("a.eventsCoverage = %q, want partial", a.eventsCoverage)
	}
	if c.eventsCoverage != evidence.CoveragePartial {
		t.Errorf("c.eventsCoverage = %q, want partial", c.eventsCoverage)
	}
	if other.eventsCoverage != evidence.CoverageSinceStart {
		t.Errorf("other.eventsCoverage = %q, want unchanged at since_start -- a gap in cid's own history must never touch an unrelated container", other.eventsCoverage)
	}

	// Never resolvable on a later retry either: re-resolving the exact same
	// event again must reach the same conclusion, not silently succeed
	// because a.lastAliveNs or c.init.Starttime happens to be read again.
	if _, outcome2 := s.resolveEventGeneration(200, uint64(gapEventTicks)*nsPerClockTick, 999, 0); outcome2 != routeGapLoss {
		t.Errorf("second resolveEventGeneration call = %v, want routeGapLoss again", outcome2)
	}
	if s.unattributedEventsLost != 2 {
		t.Errorf("unattributedEventsLost = %d, want 2 after a second, independent gap event", s.unattributedEventsLost)
	}
}

// TestResolveEventGeneration_SameTickBoundaryNeverConfirmsOldGeneration
// covers the exact numeric example a same-tick boundary produces: an old
// generation P is confirmed alive at real boot time 10.001s; a new
// generation N (the restart) actually starts at 10.009s — both floor to the
// same 10ms clock tick (1000), the only precision /proc's own starttime
// field can report N's own start at. An event naming some other process's
// start (10.009s, ns-exact from the eBPF event's own start_boottime_ns,
// TGID matching neither P's nor N's own init PID) must never be confirmed to
// P: P's own lastAliveNs (10.001s) is strictly less than the event's own
// nanosecond (10.009s), so nanosecond-precision comparison alone already
// refuses that match. Nor can it be attributed to N: it falls inside N's own
// starttime tick without independent proof it is N's own init itself (see
// resolveEventGeneration's own doc comment), so it is routeGapLoss
// regardless of where P's own lastAliveNs happens to fall — P's own last
// confirmed-alive instant is only ever proof P was alive at that instant,
// never proof P had already ended by any particular later time, so it
// cannot make N's own candidacy any less resolvable than it otherwise is.
func TestResolveEventGeneration_SameTickBoundaryNeverConfirmsOldGeneration(t *testing.T) {
	const sharedTick = 1000       // 10.000s at 100 ticks/sec
	const mismatchedTGID = 999999 // never equals p's or n's own init PID

	newScenario := func(s *Session, cid string, cgroupID uint64) (p, n *generationState) {
		p = newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: 1, Starttime: 500}, s.now(), evidence.CoverageSinceStart)
		p.ended = true
		p.lastAliveNs = 10_001_000_000 // confirmed alive at real 10.001s
		p.lastAliveNsOK = true
		n = newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: 2, Starttime: sharedTick}, s.now(), evidence.CoverageSinceStart)
		s.generations[p.key()] = p
		s.generations[n.key()] = n
		s.cgroupRoute.set(cgroupID, "/system.slice/docker-"+cid+".scope", cid)
		return p, n
	}

	t.Run("P's own confirmation reaches into N's own tick", func(t *testing.T) {
		s := newTestSessionForEvents()
		cid := strings64('a')
		p, n := newScenario(s, cid, 400)

		const nEventNs = 10_009_000_000 // some other process, inside N's own tick
		g, outcome := s.resolveEventGeneration(400, nEventNs, mismatchedTGID, 0)

		if g == p {
			t.Fatal("resolveEventGeneration attributed a post-restart event to the old generation P -- exactly the tick-truncation bug this rule exists to close")
		}
		if outcome != routeGapLoss {
			t.Errorf("outcome = %v, want routeGapLoss (inside N's own starttime tick, not proven to be N's own init)", outcome)
		}
		if p.eventsCoverage != evidence.CoveragePartial || n.eventsCoverage != evidence.CoveragePartial {
			t.Error("both P and N must be marked partial by this gap")
		}
	})

	// P's own last confirmation falling *before* N's own starttime tick even
	// begins (10.000s) does not make this event any more attributable to N:
	// that only proves P was alive at 9.995s, never that P had already ended
	// by the time N's own tick began. A previous version of this function
	// treated this as proof of no overlap and confirmed the event to N
	// (routeUnconfirmed) -- unsound, since P could have kept running,
	// unconfirmed, right up to (or past) N's own start. It must resolve to
	// routeGapLoss instead, exactly as when P's own confirmation reaches
	// into N's own tick.
	t.Run("P's own last confirmation before N's own tick still does not attribute to N", func(t *testing.T) {
		s := newTestSessionForEvents()
		cid := strings64('b')
		p, _ := newScenario(s, cid, 401)
		p.lastAliveNs = 9_995_000_000 // confirmed alive at 9.995s, before tick 1000 starts at 10.000s

		const nEventNs = 10_009_000_000
		g, outcome := s.resolveEventGeneration(401, nEventNs, mismatchedTGID, 0)

		if g != nil || outcome != routeGapLoss {
			t.Errorf("resolveEventGeneration = (%v, %v), want (nil, routeGapLoss) -- P's own last confirmation being before N's own tick is not proof P had already ended by then", g, outcome)
		}
	})
}

// TestResolveEventGeneration_ConfirmedSuccessorStillGapLossWithinOwnTick
// reproduces the counter-example to the discarded "previous generation's own
// lastAliveNs falls short of the tick start" exception directly: A's own
// last confirmed-alive instant (9.995s) predates B's own starttime tick (B's
// init starts at 10.008s, flooring to tick 1000 = 10.000s) -- exactly what
// the old exception treated as proof A must have already ended by then. It
// is not: A's own process could easily have kept running, unconfirmed,
// right up to (or past) 10.008s without contradicting "only one generation
// is alive for a given container ID at a time" at all. A late-arriving event
// naming one of A's own (non-init) processes, started at 10.001s -- inside
// B's own starttime tick -- must never be attributed to B, even once B is
// later confirmed alive at 11.000s: the discarded rule's own arithmetic
// (10.000 <= 10.001 <= 11.000) would have accepted that match.
func TestResolveEventGeneration_ConfirmedSuccessorStillGapLossWithinOwnTick(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('d')

	a := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: 1, Starttime: 100}, s.now(), evidence.CoverageSinceStart)
	a.lastAliveNs = 9_995_000_000 // A's own last confirmation, 9.995s
	a.lastAliveNsOK = true
	a.ended = true
	b := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: 2, Starttime: 1000}, s.now(), evidence.CoverageSinceStart) // 10.008s floors to tick 1000
	b.lastAliveNs = 11_000_000_000                                                                                                                         // B's own confirmation, 11.000s
	b.lastAliveNsOK = true
	s.generations[a.key()] = a
	s.generations[b.key()] = b
	s.cgroupRoute.set(600, "/system.slice/docker-"+cid+".scope", cid)

	const stragglerEventNs = 10_001_000_000 // one of A's own processes, 10.001s
	const stragglerTGID = 42                // neither A's own init PID (1) nor B's own init PID (2)
	g, outcome := s.resolveEventGeneration(600, stragglerEventNs, stragglerTGID, 0)

	if g == b {
		t.Fatal("resolveEventGeneration attributed A's own straggler event to B, using B's own later confirmation as if it proved B already existed at 10.001s")
	}
	if outcome != routeGapLoss {
		t.Errorf("outcome = %v, want routeGapLoss", outcome)
	}
}

// TestResolveEventGeneration_InitItselfProvenWithinOwnStartTick confirms the
// one exception resolveEventGeneration accepts inside a candidate's own
// starttime tick: a container's own main program's own exec_success/
// mmap_success event necessarily carries the exact same TGID as its own
// init's own PID, with a start time inside its own init's own starttime
// tick, since it *is* that same init process. Without this exception, that
// event could never be attributed to its own generation at all -- a freshly
// discovered generation is never confirmed alive before its own very first
// observed event.
func TestResolveEventGeneration_InitItselfProvenWithinOwnStartTick(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('e')

	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: 7, Starttime: 2000}, s.now(), evidence.CoverageSinceStart)
	// Never confirmed alive yet -- this is g's own very first event.
	s.generations[g.key()] = g
	s.cgroupRoute.set(700, "/system.slice/docker-"+cid+".scope", cid)

	const initEventNs = 20_003_000_000 // inside tick 2000 (20.000s..20.010s)
	gotG, outcome := s.resolveEventGeneration(700, initEventNs, 7, 0)

	if outcome != routeResolved || gotG != g {
		t.Fatalf("resolveEventGeneration = (%v, %v), want (g, routeResolved) -- init's own exec/mmap event, same TGID and same starttime tick as its own generation's init, must resolve outright", gotG, outcome)
	}
}

// TestQueuePendingRouteEvent_GapLossEvictionNotDoubleCounted fixes the
// eviction path double-counting a routeGapLoss item: resolveEventGeneration
// itself already records a gap's own loss (scoped to that one container's
// own generations) the moment it produces that outcome, so re-resolving an
// evicted oldest item and finding routeGapLoss again must never charge a
// second, separate unattributable loss (routeGapLoss is excluded from
// queuePendingRouteEvent's own classifyUnattributedExpiry call entirely,
// for exactly this reason).
func TestQueuePendingRouteEvent_GapLossEvictionNotDoubleCounted(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('c')
	a := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: 1, Starttime: 1000}, s.now(), evidence.CoverageSinceStart)
	a.lastAliveNs = uint64(1500) * nsPerClockTick
	a.lastAliveNsOK = true
	c := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: 2, Starttime: 5000}, s.now(), evidence.CoverageSinceStart)
	s.generations[a.key()] = a
	s.generations[c.key()] = c
	s.cgroupRoute.set(300, "/system.slice/docker-"+cid+".scope", cid)

	// A container with no live generation registered at all: an unrelated
	// generation this gap must never touch, and a live one to confirm this
	// test's own routeUnresolved filler items never themselves reach
	// routeGapLoss and confound the count.
	unrelated := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('d')}, InitProcess{PID: 3, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	s.generations[unrelated.key()] = unrelated

	// gapItem's own process started at tick 3000 -- inside the unprovable gap
	// between a (proven alive only to tick 1500) and c (known, but starting
	// at tick 5000) -- see TestResolveEventGeneration_UnprovableGap* for the
	// same shape resolved directly.
	gapItem := pendingRouteEvent{ev: ebpf.Event{CgroupID: 300, StartBoottimeNs: uint64(3000) * nsPerClockTick}, receivedAt: s.now()}
	s.queuePendingRouteEvent(gapItem)

	// Fill the queue with maxPendingRouteEvents more items, all naming
	// cgroup IDs this session has never seen at all (routeUnresolved, not
	// routeGapLoss), so gapItem itself is the one evicted, oldest-first, on
	// the very last of these appends.
	for i := 0; i < maxPendingRouteEvents; i++ {
		s.queuePendingRouteEvent(pendingRouteEvent{ev: ebpf.Event{CgroupID: uint64(10_000 + i)}, receivedAt: s.now()})
	}

	if s.unattributedEventsLost != 1 {
		t.Errorf("unattributedEventsLost = %d, want exactly 1 -- gapItem's own loss is recorded once, by resolveEventGeneration itself, at the moment the eviction path re-resolves it and gets routeGapLoss back; the eviction path's own classifyUnattributedExpiry call must not also fire for that same outcome", s.unattributedEventsLost)
	}
	if a.eventsCoverage != evidence.CoveragePartial || c.eventsCoverage != evidence.CoveragePartial {
		t.Error("a and c (the gap's own bounding generations) must still be marked partial")
	}
	if unrelated.eventsCoverage != evidence.CoverageSinceStart {
		t.Error("an unrelated container's own generation must never be touched by this gap")
	}
}

// TestApplyGenConfirmResult_StaleConfirmationNeverAppliesToPostRestartEvent
// covers a restart race: a confirmation is dispatched against
// oldGen's own init; before its answer is applied, oldGen's own container
// restarts and a new, post-restart usage event (naming the same, still-only-
// known oldGen as its own candidate, since the restart has not been
// discovered yet) coalesces onto that same outstanding confirmation
// (submitGenConfirmRequest). The confirmation then succeeds — it genuinely
// checked oldGen's own init before the restart happened — but the coalesced
// event's own process start nanosecond is *after* the confirmation's own
// checkNs, so it must never be dispatched to oldGen on the strength of an
// answer that does not actually cover it; it must be routed fresh instead
// (here, requeued via a fresh confirmation request, since oldGen is still
// the only known generation for this container and this event's own start
// is beyond oldGen's own just-advanced lastAliveNs).
func TestApplyGenConfirmResult_StaleConfirmationNeverAppliesToPostRestartEvent(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('8')
	oldGen := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: os.Getpid(), Starttime: mustStarttime(t, os.Getpid())}, s.now(), evidence.CoverageSinceStart)
	s.generations[oldGen.key()] = oldGen
	s.cgroupRoute.set(210, "/system.slice/docker-"+cid+".scope", cid)

	// Started a few ticks after oldGen's own init, well clear of its own
	// starttime tick, so this item's own proof rests on lastAliveNs alone
	// (TGID=0, so it could never be proven to be oldGen's own init itself
	// were it inside that tick instead).
	preConfirmItem := pendingRouteEvent{
		ev:   ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 210, StartBoottimeNs: uint64(oldGen.init.Starttime+5) * nsPerClockTick},
		kind: evidence.KindExecEvent, isExec: true, receivedAt: s.now(),
	}
	waitUntilBootNsPast(t, preConfirmItem.ev.StartBoottimeNs)
	s.submitGenConfirmRequest(genConfirmRequest{g: oldGen, item: preConfirmItem})
	if oldGen.pendingConfirms != 1 {
		t.Fatalf("pendingConfirms = %d, want 1", oldGen.pendingConfirms)
	}

	// The restart: this session has not discovered it yet (oldGen is still
	// the only known generation), so the post-restart process's own event
	// resolves right back to oldGen as its own still-unconfirmed candidate,
	// and coalesces onto the confirmation already outstanding for it.
	// Its own process start tick is set far beyond any real checkNs the
	// dispatched confirmation below could possibly report (bootNsNow reads
	// real, current CLOCK_BOOTTIME, which can never reach an instant this
	// far in its own future).
	const postRestartTicksAheadOfNow = 1_000_000_000 // ~115 days of ticks
	postRestartTicks := oldGen.init.Starttime + postRestartTicksAheadOfNow
	postRestartItem := pendingRouteEvent{
		ev:   ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 210, StartBoottimeNs: uint64(postRestartTicks) * nsPerClockTick},
		kind: evidence.KindExecEvent, isExec: true, receivedAt: s.now(),
	}
	s.submitGenConfirmRequest(genConfirmRequest{g: oldGen, item: postRestartItem})
	if len(oldGen.genConfirmWaiters) != 1 {
		t.Fatalf("len(genConfirmWaiters) = %d, want 1 (coalesced onto the same outstanding confirmation)", len(oldGen.genConfirmWaiters))
	}

	select {
	case res := <-s.genConfirmCh:
		if !res.confirmed {
			t.Fatal("confirmed = false, want true for this test's own real, live process")
		}
		s.applyGenConfirmResult(res)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for genconfirm.go's own answer")
	}

	// The pre-restart item is proven (its own tick is within what this
	// confirmation just established) and dispatched -- TGID=0, so it lands
	// as oldGen's own recorded loss.
	if oldGen.eventsLost != 1 {
		t.Errorf("oldGen.eventsLost = %d, want 1 (only the pre-restart item, dispatched via direct proof)", oldGen.eventsLost)
	}
	// The post-restart item must never have been attributed to oldGen: it is
	// still beyond oldGen's own (just-advanced) lastAliveNs, so it is
	// routed fresh — still the only known generation, so routeUnconfirmed
	// again, requeued as a fresh confirmation request rather than ever
	// counted against oldGen directly.
	postRestartNs := uint64(postRestartTicks) * nsPerClockTick
	if !oldGen.lastAliveNsOK || postRestartNs <= oldGen.lastAliveNs {
		t.Fatalf("test's own precondition failed: postRestartNs (%d) must exceed oldGen.lastAliveNs (%d, ok=%v) after confirmation, or this test proves nothing", postRestartNs, oldGen.lastAliveNs, oldGen.lastAliveNsOK)
	}
	if oldGen.pendingConfirms != 1 {
		t.Errorf("pendingConfirms = %d, want 1 (the post-restart item's own fresh confirmation request)", oldGen.pendingConfirms)
	}
	if len(s.pendingRouteEvents) != 0 {
		t.Errorf("len(pendingRouteEvents) = %d, want 0 (the post-restart item went to a fresh confirmation, not the pending queue)", len(s.pendingRouteEvents))
	}
}

// TestRetryPendingRouteEvents_ExpiredButResolvedChargesSpecificGeneration
// fixes the gap where an item that would still resolve correctly, but only
// on a retry after its own pendingRouteEventTTL has already passed, used to
// be dispatched anyway (resolution taking priority over its own age). It
// must instead be treated as expired — but since the correct generation is
// actually known at that point, the loss is charged to it specifically,
// never folded into the session-wide unattributable total.
func TestRetryPendingRouteEvents_ExpiredButResolvedChargesSpecificGeneration(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('x')
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	g.lastVerifiedAt = s.now()
	s.generations[g.key()] = g
	s.cgroupRoute.set(60, "/system.slice/docker-"+cid+".scope", cid)

	base := s.now()
	s.pendingRouteEvents = []pendingRouteEvent{
		{ev: ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 60}, kind: evidence.KindExecEvent, isExec: true, receivedAt: base},
	}
	s.retryPendingRouteEvents(base.Add(pendingRouteEventTTL + time.Second))

	if len(s.pendingRouteEvents) != 0 {
		t.Fatalf("len(pendingRouteEvents) = %d, want 0", len(s.pendingRouteEvents))
	}
	if g.eventsLost != 1 {
		t.Errorf("g.eventsLost = %d, want 1 -- the correct generation is known, so the loss must be charged to it specifically", g.eventsLost)
	}
	if s.unattributedEventsLost != 0 {
		t.Errorf("unattributedEventsLost = %d, want 0 -- a resolvable-but-expired item must never be folded into the unattributable total", s.unattributedEventsLost)
	}
}

func TestDispatchWork_ExpiresPendingEventsEvenForEndedGeneration(t *testing.T) {
	s := newTestSessionForEvents()
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('y')}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	old := s.now()
	g.recordPendingEvent(pendingEventItem{path: "/a", receivedAt: old})
	g.ended = true
	endedAt := s.now()
	g.endedAt = &endedAt
	s.generations[g.key()] = g

	s.now = func() time.Time { return old.Add(pendingEventTTL + time.Second) }
	s.dispatchWork(s.now())

	if len(g.pendingEvents) != 0 {
		t.Errorf("pendingEvents = %+v, want expired even though the generation has already ended", g.pendingEvents)
	}
	if g.eventsLost != 1 {
		t.Errorf("eventsLost = %d, want 1 (the expired pending event)", g.eventsLost)
	}
}

func TestFormatCapEffMatchesProcfsWidth(t *testing.T) {
	got := formatCapEff(0x1FFFFFFFFF)
	if len(got) != 16 {
		t.Errorf("formatCapEff length = %d, want 16 (matches /proc/<pid>/status's CapEff width)", len(got))
	}
	if got != "0000001fffffffff" {
		t.Errorf("formatCapEff(0x1FFFFFFFFF) = %q, want %q", got, "0000001fffffffff")
	}
}

// TestApplyUsageEvent_HostRootEventNeverCountsAsGapLoss covers container
// runtime setup: a process in the container's own cgroup, started inside the
// container init's own starttime tick but not the init itself, whose root is
// still the host's own root (runc's setup stages before pivot_root). Its
// events can never be evidence for the container, so they must be dropped
// outright rather than counted as an unprovable gap loss that downgrades the
// generation to partial. The same event from a process whose root is not the
// host's still counts as a gap loss.
func TestApplyUsageEvent_HostRootEventNeverCountsAsGapLoss(t *testing.T) {
	s := newTestSessionForEvents()
	s.hostRootDev, s.hostRootIno = "08:30", 2
	cid := strings64('8')

	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, InitProcess{PID: 10, Starttime: 1000}, s.now(), evidence.CoverageSinceStart)
	s.generations[g.key()] = g
	s.cgroupRoute.set(300, "/system.slice/docker-"+cid+".scope", cid)

	ev := ebpf.Event{
		Kind:            ebpf.EventMmapSuccess,
		CgroupID:        300,
		TGID:            11,
		StartBoottimeNs: 1000*nsPerClockTick + 5,
		RootDev:         8<<20 | 0x30,
		RootIno:         2,
	}
	s.applyUsageEvent(ev, evidence.KindLibraryLoadEvent, false)
	if s.unattributedEventsLost != 0 {
		t.Fatalf("unattributedEventsLost = %d after a host-root event, want 0", s.unattributedEventsLost)
	}
	if g.eventsCoverage != evidence.CoverageSinceStart {
		t.Fatalf("eventsCoverage = %q after a host-root event, want since_start", g.eventsCoverage)
	}

	ev.RootDev, ev.RootIno = 0x54, 972938
	s.applyUsageEvent(ev, evidence.KindLibraryLoadEvent, false)
	if s.unattributedEventsLost != 1 {
		t.Fatalf("unattributedEventsLost = %d after a container-root event in the init's own start tick, want 1", s.unattributedEventsLost)
	}
	if g.eventsCoverage != evidence.CoveragePartial {
		t.Fatalf("eventsCoverage = %q after an unprovable container-root event, want partial", g.eventsCoverage)
	}
}

// TestApplyFallbackLoss_DowngradesEveryLiveGenerationAndSetsWatermark covers
// loss the kernel could only count in its Sensor-wide fallback counter (the
// per-cgroup map was full): nothing names an owner, so every live
// generation, confirmed mount view or not, must stop claiming complete
// coverage, and a generation discovered later that started before now must
// be protected by the watermark. A zero delta changes nothing.
func TestApplyFallbackLoss_DowngradesEveryLiveGenerationAndSetsWatermark(t *testing.T) {
	s := newTestSessionForEvents()
	confirmed := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('q')}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	confirmed.mntNsID = 42
	s.generations[confirmed.key()] = confirmed

	s.applyFallbackLoss(0, time.Time{})
	if confirmed.eventsCoverage != evidence.CoverageSinceStart || confirmed.incomplete || s.forcedGapWatermarkSet {
		t.Fatalf("zero fallback delta changed state: coverage=%q incomplete=%v watermarkSet=%v", confirmed.eventsCoverage, confirmed.incomplete, s.forcedGapWatermarkSet)
	}

	s.applyFallbackLoss(3, time.Time{})
	if confirmed.eventsCoverage != evidence.CoveragePartial || !confirmed.incomplete {
		t.Errorf("confirmed = {coverage=%q incomplete=%v}, want {partial, true}", confirmed.eventsCoverage, confirmed.incomplete)
	}
	if !s.forcedGapWatermarkSet {
		t.Errorf("forcedGapWatermarkSet = false, want true so a not-yet-discovered generation is protected")
	}
	if s.eventsUnclassified != 3 {
		t.Errorf("eventsUnclassified = %d, want 3", s.eventsUnclassified)
	}
}

// TestApplyFallbackLoss_EndedGenerationAliveDuringLossIsDowngraded covers a
// generation whose end was applied between two loss-counter reads: it was
// alive while the loss could have happened and stays in the published
// evidence, so it must not keep claiming since_start. The discovery pass
// that ended it started before the previous read, which is what endedAt
// records; the decision must rest on when the end was applied instead. A
// generation whose end was applied before the previous read cannot own the
// loss and is left alone.
func TestApplyFallbackLoss_EndedGenerationAliveDuringLossIsDowngraded(t *testing.T) {
	s := newTestSessionForEvents()
	base := s.now()
	discoveryStart := base
	prevRead := base.Add(5 * time.Second)

	endedAfter := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('r')}, InitProcess{PID: 1, Starttime: 1}, base, evidence.CoverageSinceStart)
	endedBefore := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('s')}, InitProcess{PID: 2, Starttime: 2}, base, evidence.CoverageSinceStart)
	s.generations[endedAfter.key()] = endedAfter
	s.generations[endedBefore.key()] = endedBefore

	// endedBefore: its end is applied before the previous counter read.
	s.now = func() time.Time { return base.Add(2 * time.Second) }
	s.endGeneration(endedBefore, discoveryStart)
	// endedAfter: the same discovery pass (started before the previous
	// read) is applied only after it.
	s.now = func() time.Time { return base.Add(10 * time.Second) }
	s.endGeneration(endedAfter, discoveryStart)

	if !endedAfter.endedAt.Before(prevRead) {
		t.Fatalf("test setup: endedAt = %v, want before the previous read %v to exercise the ordering", endedAfter.endedAt, prevRead)
	}

	s.applyFallbackLoss(2, prevRead)

	if endedAfter.eventsCoverage != evidence.CoveragePartial || !endedAfter.incomplete {
		t.Errorf("endedAfter = {coverage=%q incomplete=%v}, want {partial, true} -- its end was applied after the previous counter read", endedAfter.eventsCoverage, endedAfter.incomplete)
	}
	if endedBefore.eventsCoverage != evidence.CoverageSinceStart || endedBefore.incomplete {
		t.Errorf("endedBefore = {coverage=%q incomplete=%v}, want unchanged -- its end was applied before the loss interval began", endedBefore.eventsCoverage, endedBefore.incomplete)
	}
}

func TestKernelLossTotal(t *testing.T) {
	if got := kernelLossTotal(nil, 0); got != 0 {
		t.Errorf("kernelLossTotal(nil, 0) = %d, want 0", got)
	}
	if got := kernelLossTotal(map[uint64]uint64{7: 5, 9: 2}, 3); got != 10 {
		t.Errorf("kernelLossTotal = %d, want 10 (5+2 per-cgroup plus 3 fallback)", got)
	}
	if got := kernelLossTotal(map[uint64]uint64{7: 1 << 63}, 0); got != 1<<63-1 {
		t.Errorf("kernelLossTotal per-cgroup overflow = %d, want saturation at max int64", got)
	}
	if got := kernelLossTotal(map[uint64]uint64{7: 1<<63 - 1}, 1); got != 1<<63-1 {
		t.Errorf("kernelLossTotal sum overflow = %d, want saturation at max int64", got)
	}
	if got := kernelLossTotal(nil, 1<<63); got != 1<<63-1 {
		t.Errorf("kernelLossTotal fallback overflow = %d, want saturation at max int64", got)
	}
}

func TestMergeKernelLossReads(t *testing.T) {
	boom := errors.New("read failed")
	var prev map[uint64]uint64
	var fb uint64
	var total int64
	step := func(read map[uint64]uint64, readErr error, fallback uint64, fbErr error, want int64) {
		t.Helper()
		prev, fb, total = mergeKernelLossReads(prev, read, readErr, fb, fallback, fbErr)
		if total != want {
			t.Fatalf("total = %d, want %d (map %v, fallback %d)", total, want, prev, fb)
		}
	}
	step(map[uint64]uint64{7: 5, 9: 2}, nil, 3, nil, 10)
	// Consecutive read: counters grow.
	step(map[uint64]uint64{7: 6, 9: 2}, nil, 3, nil, 11)
	// Per-cgroup read fails: total holds, not 0 or fallback alone.
	step(nil, boom, 3, nil, 11)
	// Recovery: increments after the failure are reflected.
	step(map[uint64]uint64{7: 8, 9: 2}, nil, 3, nil, 13)
	// Fallback read fails: the reported fallback value is ignored.
	step(map[uint64]uint64{7: 8, 9: 2}, nil, 0, boom, 13)
	// Shrinking map: key 7 vanished and keeps its last value, 9 grows.
	step(map[uint64]uint64{9: 4}, nil, 3, nil, 15)
	// Saturation survives later reads.
	step(map[uint64]uint64{9: 1 << 63}, nil, 3, nil, 1<<63-1)
	step(map[uint64]uint64{9: 1 << 63}, nil, 3, nil, 1<<63-1)
}

// TestBuildSnapshotCarriesKernelLost pins that the snapshot reports the
// kernel-side total separately, leaving lost and unclassified as they were.
func TestBuildSnapshotCarriesKernelLost(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	s := &Session{now: func() time.Time { return now }, cfg: Config{Interval: 30 * time.Second}}
	s.kernelLost = kernelLossTotal(map[uint64]uint64{7: 5, 9: 2}, 3)
	s.unattributedEventsLost = 4
	s.eventsUnclassified = 1

	snap := s.buildSnapshot(evidence.SensorOK)
	if snap.Sensor.Events.KernelLost != 10 {
		t.Errorf("KernelLost = %d, want 10", snap.Sensor.Events.KernelLost)
	}
	if snap.Sensor.Events.Lost != 4 || snap.Sensor.Events.Unclassified != 1 {
		t.Errorf("Lost/Unclassified = %d/%d, want 4/1 (unchanged by kernel_lost)", snap.Sensor.Events.Lost, snap.Sensor.Events.Unclassified)
	}
	body, err := json.Marshal(snap.Sensor.Events)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"kernel_lost":10`) {
		t.Errorf("events JSON %s lacks kernel_lost:10", body)
	}
}
