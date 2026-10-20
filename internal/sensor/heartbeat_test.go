package sensor

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// TestHeartbeatPeriod covers heartbeatPeriod's own rule directly: the
// heartbeat ticker's period never exceeds --interval itself, only the
// production 60-second ceiling once --interval grows past it.
func TestHeartbeatPeriod(t *testing.T) {
	const floor = 60 * time.Second
	cases := []struct {
		interval time.Duration
		want     time.Duration
	}{
		{10 * time.Second, 10 * time.Second},
		{30 * time.Second, 30 * time.Second},
		{60 * time.Second, 60 * time.Second},
		{300 * time.Second, 60 * time.Second},
	}
	for _, c := range cases {
		if got := heartbeatPeriod(c.interval, floor); got != c.want {
			t.Errorf("heartbeatPeriod(%s, %s) = %s, want %s", c.interval, floor, got, c.want)
		}
	}
}

// TestHeartbeatCadence_NeverLooksStaleAtAnyIntervalBoundary fixes the
// property evidence.IsStale actually cares about: for --interval set to
// each of the boundary values --interval itself allows (its own minimum,
// 10s; its own maximum, 300s; and the 30s/60s values astride this
// package's own heartbeat ceiling), a Sensor writing on heartbeatPeriod's
// own cadence — with no extra
// sample-triggered write ever helping (the worst case; a real Sensor also
// writes immediately whenever a sample result is applied, which can only
// shorten the real gap below what this test checks) — must never have its
// evidence file look stale under evidence.StalenessThreshold, checked at
// the single worst possible moment of every cycle: the instant right
// before the next heartbeat would land.
func TestHeartbeatCadence_NeverLooksStaleAtAnyIntervalBoundary(t *testing.T) {
	boundaries := []time.Duration{10 * time.Second, 30 * time.Second, 60 * time.Second, 300 * time.Second}
	base := time.Unix(1_700_000_000, 0)

	for _, interval := range boundaries {
		t.Run(interval.String(), func(t *testing.T) {
			period := heartbeatPeriod(interval, heartbeatInterval)
			intervalSeconds := int(interval / time.Second)
			threshold := evidence.StalenessThreshold(intervalSeconds)
			if period >= threshold {
				t.Fatalf("heartbeatPeriod(%s) = %s, want strictly under StalenessThreshold(%s) = %s", interval, period, interval, threshold)
			}

			for cycle := 0; cycle < 20; cycle++ {
				heartbeatAt := base.Add(time.Duration(cycle) * period)
				worstNow := heartbeatAt.Add(period).Add(-time.Nanosecond)
				if evidence.IsStale(heartbeatAt, worstNow, intervalSeconds) {
					t.Fatalf("cycle %d: IsStale(heartbeatAt=%v, now=%v, intervalSeconds=%d) = true, want false — "+
						"a heartbeat every %s must never look stale under a %s threshold",
						cycle, heartbeatAt, worstNow, intervalSeconds, period, threshold)
				}
			}
		})
	}
}

// TestLoop_ShortIntervalDrivesHeartbeatFasterThanFloor confirms loop
// actually wires heartbeatPeriod's "interval is shorter" branch, not just
// that the pure function computes it correctly: with --interval well under
// the (test-shortened) heartbeat floor, heartbeat_at must advance on
// --interval's own faster cadence, not the floor's slower one.
// TestLoop_HeartbeatTickerUpdatesWithoutSampling (session_test.go) already
// covers the opposite branch (--interval longer than the floor).
func TestLoop_ShortIntervalDrivesHeartbeatFasterThanFloor(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/" + evidence.FileName
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open evidence file: %v", err)
	}
	defer f.Close()

	const shortInterval = 15 * time.Millisecond
	const slowFloor = 10 * time.Second // stands in for production's 60s ceiling
	// testWindow is only an upper bound: the loop is stopped as soon as the
	// writes this test looks for have arrived, so a slow machine waits longer
	// without making the test flaky, and the floor alone cannot write more
	// than once within it.
	const testWindow = 3 * time.Second
	const wantWrites = 3

	s := &Session{
		// cfg.Interval is deliberately sub-second here purely to keep this
		// test fast — evidence.Snapshot.Sensor.IntervalSeconds (an integer
		// number of whole seconds) would truncate that to 0 and fail
		// evidence's own [10,300] validation, so this test counts writer
		// activity directly rather than reading the file back through
		// evidence.NewReader the way a real consumer would.
		cfg:              Config{EvidenceDir: dir, Interval: shortInterval, ExcludeIDs: []string{"nonexistent-container-id-prefix"}},
		now:              time.Now,
		evidenceFD:       int(f.Fd()),
		sessionID:        "test",
		sessionStartedAt: time.Now(),
		generations:      map[string]*generationState{},
		dbJobCh:          make(chan dbJob, dbJobChCapacity),
		dbResultCh:       make(chan dbResult, dbJobChCapacity),
		sampleResCh:      make(chan sampleEnvelope, maxConcurrentSampleWorkers*2),
		writerCh:         make(chan writerJob, 1),
		writerReportCh:   make(chan writeReport, 1),
		heartbeatEvery:   slowFloor,
		// No containers are found, so every write counted below comes from
		// the heartbeat and none from a sample of whatever runs on this
		// machine.
		discoverFn: func() (map[string]containerGroup, []cgroupSeed, int, error) {
			return map[string]containerGroup{}, nil, 0, nil
		},
	}
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		runWriter(s.evidenceFD, s.writerCh, s.writerReportCh)
	}()
	var writes int32
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for range s.writerReportCh {
			atomic.AddInt32(&writes, 1)
		}
	}()
	// Stop both goroutines before the evidence file is closed, so neither
	// outlives the test and the writer never writes to a closed descriptor.
	// The loop has returned by then, so nothing sends on writerCh any more,
	// and once the writer has exited nothing sends on writerReportCh.
	defer func() {
		close(s.writerCh)
		<-writerDone
		close(s.writerReportCh)
		<-readerDone
	}()

	ctx, cancel := context.WithTimeout(context.Background(), testWindow)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.loop(ctx, evidence.SensorOK) }()
	poll := time.NewTicker(5 * time.Millisecond)
	defer poll.Stop()
	for atomic.LoadInt32(&writes) < wantWrites && ctx.Err() == nil {
		<-poll.C
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("loop: %v", err)
	}

	// heartbeatPeriod(shortInterval, slowFloor) == shortInterval (15ms), so
	// the heartbeat ticker fires every 15ms. The 10s floor could not have
	// produced more than one write within the 3s window on its own, so
	// several writes prove --interval's own faster cadence drove them, not
	// the floor.
	got := atomic.LoadInt32(&writes)
	if got < wantWrites {
		t.Errorf("writer received %d snapshots in %v, want several — --interval's own %v cadence should be driving the heartbeat here, not the slower %v floor", got, testWindow, shortInterval, slowFloor)
	}
}

// TestHandleSampleEnvelope_ResultTriggersImmediateSnapshot covers the
// second half of this round's own fix: applying one generation's sample
// result submits a snapshot immediately, without waiting for the next
// heartbeat tick at all.
func TestHandleSampleEnvelope_ResultTriggersImmediateSnapshot(t *testing.T) {
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1}, time.Now(), evidence.CoverageNone)
	s := &Session{
		now:            time.Now,
		cfg:            Config{Interval: time.Hour},
		generations:    map[string]*generationState{g.key(): g},
		writerCh:       make(chan writerJob, 1),
		writerReportCh: make(chan writeReport, 1),
	}

	s.handleSampleEnvelope(sampleEnvelope{kind: sampleEnvResult, genKey: g.key(), result: sampleResult{genKey: g.key(), attempted: 1, succeeded: 1}})

	select {
	case job := <-s.writerCh:
		if len(job.snap.Generations) != 1 {
			t.Errorf("snapshot has %d generations, want 1", len(job.snap.Generations))
		}
	default:
		t.Fatal("no snapshot was submitted to the writer after applying a sample result")
	}
}
