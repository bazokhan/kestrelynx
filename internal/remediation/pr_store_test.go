package remediation

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPRStoreRoundTripAndMissing(t *testing.T) {
	s := PRStore{Dir: filepath.Join(t.TempDir(), "state")}
	if _, found, err := s.Load(); err != nil || found {
		t.Fatalf("missing: found=%v err=%v", found, err)
	}
	at := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	f := PRStoreFile{NextSeq: 3, DeliveredSeq: 1, InitializedAt: at,
		Repos:      []RepoInit{{Repo: testRepo, RepoID: 1, InitializedAt: at}},
		PRs:        []PRRecord{{Repo: testRepo, RepoID: 1, Number: 4, UpdateKey: "u", State: PRStateOpen, CreatedAt: at, UpdatedAt: at}},
		Attempts:   []AttemptRecord{{AttemptKey: "a", UpdateKey: "u", Repo: testRepo, Status: AttemptPRCreated, CreatedAt: at, UpdatedAt: at}},
		Operations: []OperationEvent{{Seq: 1, ID: "op-1", At: at, Phase: PhaseIntent}, {Seq: 2, ID: "op-1", At: at, Phase: PhaseResult, Result: ResultOK}},
	}
	if err := s.Save(f); err != nil {
		t.Fatal(err)
	}
	got, found, err := s.Load()
	f.Version = PRStoreVersion
	if err != nil || !found || !reflect.DeepEqual(got, f) {
		t.Errorf("round trip: %v %v\n got %+v\nwant %+v", found, err, got, f)
	}
	entries, _ := os.ReadDir(s.Dir)
	if len(entries) != 1 {
		t.Errorf("directory holds %d entries", len(entries))
	}
}

func TestPRStoreNeverOverwritesUnreadable(t *testing.T) {
	for name, content := range map[string]string{
		"corrupt":         "{not json",
		"unknown version": `{"version":99,"next_seq":1}`,
		"bad sequence":    `{"version":1,"next_seq":2,"operations":[{"seq":5,"id":"x"}]}`,
		"bad delivered":   `{"version":1,"next_seq":2,"delivered_seq":7}`,
	} {
		t.Run(name, func(t *testing.T) {
			s := PRStore{Dir: t.TempDir()}
			p := filepath.Join(s.Dir, "prs.json")
			if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, _, err := s.Load(); err == nil {
				t.Error("load accepted it")
			}
			if name == "unknown version" {
				if _, _, err := s.Load(); !errors.Is(err, ErrPRStoreVersion) {
					t.Errorf("err = %v", err)
				}
			}
			if err := s.Save(PRStoreFile{NextSeq: 1}); err == nil {
				t.Error("save replaced it")
			}
			if b, _ := os.ReadFile(p); string(b) != content {
				t.Error("the file changed")
			}
		})
	}
}

func TestPRStoreLockIsExclusive(t *testing.T) {
	s := PRStore{Dir: filepath.Join(t.TempDir(), "state")}
	unlock, err := s.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lock(); !errors.Is(err, ErrPRStoreLocked) {
		t.Errorf("second lock: %v", err)
	}
	if err := MarkPROperationsDelivered(s, 1); !errors.Is(err, ErrPRStoreLocked) {
		t.Errorf("delivery marking under the lock: %v", err)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	unlock2, err := s.Lock()
	if err != nil {
		t.Fatalf("lock after unlock: %v", err)
	}
	unlock2()
}

func TestMarkPROperationsDelivered(t *testing.T) {
	s := PRStore{Dir: t.TempDir()}
	if err := MarkPROperationsDelivered(s, 3); err != nil {
		t.Errorf("missing file: %v", err)
	}
	if _, found, _ := s.Load(); found {
		t.Error("marking created a record file")
	}
	f := PRStoreFile{NextSeq: 4, Operations: []OperationEvent{{Seq: 1, ID: "a"}, {Seq: 2, ID: "a"}, {Seq: 3, ID: "b"}}}
	if err := s.Save(f); err != nil {
		t.Fatal(err)
	}
	if err := MarkPROperationsDelivered(s, 2); err != nil {
		t.Fatal(err)
	}
	got, _, _ := s.Load()
	if got.DeliveredSeq != 2 {
		t.Errorf("delivered = %d", got.DeliveredSeq)
	}
	ops, last := got.undelivered()
	if len(ops) != 1 || last != 3 {
		t.Errorf("undelivered %+v last %d", ops, last)
	}
	// Never moves back, never past what was issued.
	MarkPROperationsDelivered(s, 1)
	MarkPROperationsDelivered(s, 99)
	if got, _, _ := s.Load(); got.DeliveredSeq != 3 {
		t.Errorf("delivered = %d", got.DeliveredSeq)
	}
}

func TestTrimOperationsKeepsUndeliveredAndUnsettled(t *testing.T) {
	f := PRStoreFile{NextSeq: 1, Attempts: []AttemptRecord{{AttemptKey: "open", UpdateKey: "u", Repo: "r", Status: AttemptRefCreated}}}
	for i := 0; i < maxOperationEvents; i++ {
		key := "done"
		if i%10 == 0 {
			key = "open"
		}
		f.Operations = append(f.Operations, OperationEvent{Seq: f.NextSeq, ID: "x", AttemptKey: key})
		f.NextSeq++
	}
	f.DeliveredSeq = 500
	if !f.trimOperations(20) {
		t.Fatal("no room although delivered events of settled attempts exist")
	}
	if len(f.Operations) != maxOperationEvents-20 {
		t.Errorf("kept %d", len(f.Operations))
	}
	for _, op := range f.Operations[:5] {
		if op.AttemptKey != "open" && op.Seq <= 22 {
			t.Errorf("trimmed out of order: kept %+v", op)
		}
	}
	// Room beyond what may be removed is refused.
	if f.trimOperations(maxOperationEvents) {
		t.Error("room reported for more events than can be removed")
	}
	for _, op := range f.Operations {
		if op.Seq > f.DeliveredSeq || op.AttemptKey == "open" {
			continue
		}
		t.Fatalf("a removable event survived a full trim: %+v", op)
	}
	for i := int64(501); i <= int64(maxOperationEvents); i++ {
		found := false
		for _, op := range f.Operations {
			found = found || op.Seq == i
		}
		if !found {
			t.Fatalf("undelivered event %d was removed", i)
		}
	}
	if !strings.HasPrefix(f.Operations[0].AttemptKey, "open") {
		t.Errorf("first kept = %+v", f.Operations[0])
	}
}
