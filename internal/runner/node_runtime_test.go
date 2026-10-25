package runner

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// fakeNodeRuntime records when it was refreshed relative to scans. A name
// other than "" is appended to the event, to tell refreshers apart.
type fakeNodeRuntime struct {
	events *[]string
	err    error
	name   string
}

func (f fakeNodeRuntime) Refresh(context.Context) error {
	*f.events = append(*f.events, strings.TrimSpace("refresh "+f.name))
	return f.err
}

// eventScanner records each scan in the same log as fakeNodeRuntime.
type eventScanner struct {
	events *[]string
	scan   scanner.ImageScan
}

func (e eventScanner) Scan(_ context.Context, target scanner.ScanTarget) scanner.ImageScan {
	*e.events = append(*e.events, "scan "+target.Subject.Ref)
	s := e.scan
	s.Image = target.Subject.Ref
	return s
}

func TestRunOnce_NodeRuntimeRefreshedOnceBeforeScans(t *testing.T) {
	var events []string
	r := Runner{
		Lister:            fakeLister{containers: refs("a:1", "b:1")},
		Scanner:           eventScanner{events: &events},
		Notifier:          &fakeNotifier{},
		Now:               clock,
		RuntimeRefreshers: []RuntimeRefresher{fakeNodeRuntime{events: &events}},
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	want := []string{"refresh", "scan a:1", "scan b:1"}
	if len(events) != len(want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("events = %v, want %v", events, want)
		}
	}
}

func TestRunOnce_RuntimeRefreshersCalledInOrder(t *testing.T) {
	var events []string
	r := Runner{
		Lister:   fakeLister{containers: refs("a:1")},
		Scanner:  eventScanner{events: &events},
		Notifier: &fakeNotifier{},
		Now:      clock,
		RuntimeRefreshers: []RuntimeRefresher{
			fakeNodeRuntime{events: &events, name: "node"},
			fakeNodeRuntime{events: &events, name: "python", err: errors.New("offline")},
			fakeNodeRuntime{events: &events, name: "third"},
		},
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	want := []string{"refresh node", "refresh python", "refresh third", "scan a:1"}
	if strings.Join(events, "|") != strings.Join(want, "|") {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestRunOnce_NodeRuntimeRefreshFailureContinues(t *testing.T) {
	var events []string
	notif := &fakeNotifier{}
	r := Runner{
		Lister:            fakeLister{containers: refs("a:1")},
		Scanner:           eventScanner{events: &events},
		Notifier:          notif,
		Now:               clock,
		RuntimeRefreshers: []RuntimeRefresher{fakeNodeRuntime{events: &events, err: errors.New("offline")}},
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(events) != 2 || events[1] != "scan a:1" {
		t.Errorf("events = %v, want the scan to follow a failed refresh", events)
	}
}

func TestRunOnce_NodeRuntimeNilIsNotCalled(t *testing.T) {
	var events []string
	r := Runner{
		Lister:   fakeLister{containers: refs("a:1")},
		Scanner:  eventScanner{events: &events},
		Notifier: &fakeNotifier{},
		Now:      clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(events) != 1 || events[0] != "scan a:1" {
		t.Errorf("events = %v, want only the scan", events)
	}
}

func TestRunOnce_RuntimeUncheckedForcesNotification(t *testing.T) {
	uncheckedScan := scanner.ImageScan{RuntimeUnchecked: []string{inventory.NodeRuntimePackage}}
	for _, diff := range []bool{false, true} {
		var events []string
		notif := &fakeNotifier{}
		r := Runner{
			Lister:        fakeLister{containers: refs("node:22")},
			Scanner:       eventScanner{events: &events, scan: uncheckedScan},
			Notifier:      notif,
			FullReportDay: NoFullReport,
			Now:           clock,
		}
		if diff {
			r.Store = &fakeStore{}
		}
		if err := r.RunOnce(context.Background()); err != nil {
			t.Fatalf("RunOnce (diff=%v): %v", diff, err)
		}
		if !notif.called {
			t.Errorf("diff=%v: an unchecked runtime must send a notification even with nothing else to report", diff)
			continue
		}
		if got := notif.msg.Report.RuntimeUnchecked; len(got) != 1 || got[0] != (analyze.RuntimeUncheckedRef{Image: "node:22", Package: inventory.NodeRuntimePackage}) {
			t.Errorf("diff=%v: Report.RuntimeUnchecked = %v", diff, got)
		}
	}
}
