package remediation

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PRStoreVersion is the format version of the pull request record file.
const PRStoreVersion = 1

// maxOperationEvents is how many operation events are kept. Only delivered
// events of settled attempts are ever removed to stay within it.
const maxOperationEvents = 1000

var (
	// ErrPRStoreVersion means the pull request record file has a format
	// version this build does not read.
	ErrPRStoreVersion = errors.New("remediation: unsupported pull request record version")
	// ErrPRStoreLocked means another process holds the pull request record
	// lock.
	ErrPRStoreLocked = errors.New("remediation: pull request records are locked by another process")
)

// RepoInit records that the pull requests of a repository were examined on
// GitHub and the records rebuilt before the first write to it.
type RepoInit struct {
	Repo          string    `json:"repo"`
	RepoID        int64     `json:"repo_id"`
	InitializedAt time.Time `json:"initialized_at"`
}

// PRStoreFile is the content of the pull request record file. It never holds
// a secret or a file's content.
type PRStoreFile struct {
	Version       int              `json:"version"`
	InitializedAt time.Time        `json:"initialized_at"`
	Repos         []RepoInit       `json:"repos"`
	PRs           []PRRecord       `json:"prs"`
	Attempts      []AttemptRecord  `json:"attempts"`
	Operations    []OperationEvent `json:"operations"`
	// NextSeq is the sequence number the next operation event gets;
	// DeliveredSeq the highest one delivered in a notification.
	NextSeq      int64 `json:"next_seq"`
	DeliveredSeq int64 `json:"delivered_seq"`
}

// PRStorage keeps the pull request records. Lock takes the single-writer
// lock; Load reports found false, with a nil error, only when there is no
// record file; Save replaces it atomically and never overwrites a file it
// cannot read.
type PRStorage interface {
	Lock() (unlock func() error, err error)
	Load() (PRStoreFile, bool, error)
	Save(PRStoreFile) error
}

// PRStore keeps the records in prs.json under a directory, with the lock
// file prs.lock next to it.
type PRStore struct {
	Dir string
}

var _ PRStorage = PRStore{}

func (s PRStore) path() string     { return filepath.Join(s.Dir, "prs.json") }
func (s PRStore) lockPath() string { return filepath.Join(s.Dir, "prs.lock") }

// Lock takes an exclusive, non-blocking lock on prs.lock. While it is held no
// other process (and no other Lock call in this one) can write the records.
// It is ErrPRStoreLocked when the lock is taken.
func (s PRStore) Lock() (func() error, error) {
	if s.Dir == "" {
		return nil, errors.New("lock pull request records: no directory")
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return nil, fmt.Errorf("create pull request record dir: %w", err)
	}
	return lockFile(s.lockPath())
}

// Load reads the records. A file that is unreadable, corrupt, of another
// version or internally inconsistent is an error, never an empty record.
func (s PRStore) Load() (PRStoreFile, bool, error) {
	data, err := os.ReadFile(s.path())
	if errors.Is(err, os.ErrNotExist) {
		return PRStoreFile{}, false, nil
	}
	if err != nil {
		return PRStoreFile{}, false, fmt.Errorf("read pull request records %s: %w", s.path(), err)
	}
	var f PRStoreFile
	if err := json.Unmarshal(data, &f); err != nil {
		return PRStoreFile{}, false, fmt.Errorf("parse pull request records %s: %w", s.path(), err)
	}
	if f.Version != PRStoreVersion {
		return PRStoreFile{}, false, fmt.Errorf("%w: %s has version %d, this build reads %d", ErrPRStoreVersion, s.path(), f.Version, PRStoreVersion)
	}
	if err := f.validate(); err != nil {
		return PRStoreFile{}, false, fmt.Errorf("pull request records %s: %w", s.path(), err)
	}
	return f, true, nil
}

// validate checks what the stage relies on: increasing sequence numbers
// below NextSeq, a delivered sequence that was issued, and identified
// records.
func (f PRStoreFile) validate() error {
	var last int64
	for _, op := range f.Operations {
		if op.Seq <= last || op.Seq >= f.NextSeq || op.ID == "" {
			return fmt.Errorf("operation events are out of sequence at %d", op.Seq)
		}
		last = op.Seq
	}
	if f.DeliveredSeq < 0 || f.DeliveredSeq > 0 && f.DeliveredSeq >= f.NextSeq {
		return fmt.Errorf("delivered sequence %d was never issued", f.DeliveredSeq)
	}
	for _, r := range f.PRs {
		if r.Number <= 0 || r.UpdateKey == "" || r.Repo == "" {
			return errors.New("a pull request record has no number, update key or repository")
		}
	}
	for _, a := range f.Attempts {
		if a.AttemptKey == "" || a.UpdateKey == "" || a.Repo == "" {
			return errors.New("an attempt record has no key or repository")
		}
	}
	return nil
}

// Save writes the records atomically (temporary file, sync, rename, then a
// sync of the directory). A failure at any step, the directory sync
// included, is an error. A file already there that cannot be loaded is
// never replaced.
func (s PRStore) Save(f PRStoreFile) error {
	if s.Dir == "" {
		return errors.New("save pull request records: no directory")
	}
	if _, _, err := s.Load(); err != nil {
		return fmt.Errorf("refusing to overwrite pull request records: %w", err)
	}
	f.Version = PRStoreVersion
	if err := f.validate(); err != nil {
		return fmt.Errorf("save pull request records: %w", err)
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal pull request records: %w", err)
	}
	return writeFileAtomic(s.path(), data, "pull request records")
}

// writeFileAtomic replaces path with data durably.
func writeFileAtomic(path string, data []byte, what string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s dir: %w", what, err)
	}
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create %s temp file: %w", what, err)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", what, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", what, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", what, err)
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return fmt.Errorf("chmod %s: %w", what, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace %s: %w", what, err)
	}
	ok = true
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open %s dir to sync: %w", what, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync %s dir: %w", what, err)
	}
	return nil
}

// MarkPROperationsDelivered records that the operation events up to seq were
// delivered in a notification. It takes the record lock, so it must not be
// called while the stage runs; a missing record file is left alone.
func MarkPROperationsDelivered(store PRStorage, seq int64) error {
	if seq <= 0 {
		return nil
	}
	unlock, err := store.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	f, found, err := store.Load()
	if err != nil || !found {
		return err
	}
	if seq >= f.NextSeq {
		seq = f.NextSeq - 1
	}
	if seq <= f.DeliveredSeq {
		return nil
	}
	f.DeliveredSeq = seq
	return store.Save(f)
}

// unsettledAttemptKeys are the attempts whose events must be kept: attempts
// not yet settled and pull requests with a replacement in progress.
func (f *PRStoreFile) unsettledAttemptKeys() map[string]bool {
	out := map[string]bool{}
	for _, a := range f.Attempts {
		if !a.Status.settled() {
			out[a.AttemptKey] = true
		}
	}
	for _, r := range f.PRs {
		for _, rp := range r.Replacing {
			if !rp.terminal() {
				out[r.AttemptKey] = true
			}
		}
	}
	return out
}

// trimOperations removes the oldest removable events (delivered, and not of
// an unsettled attempt) until room more events fit within the cap. It
// reports whether they fit.
func (f *PRStoreFile) trimOperations(room int) bool {
	excess := len(f.Operations) + room - maxOperationEvents
	if excess <= 0 {
		return true
	}
	keep := f.unsettledAttemptKeys()
	out := f.Operations[:0:0]
	for _, op := range f.Operations {
		if excess > 0 && op.Seq <= f.DeliveredSeq && (op.AttemptKey == "" || !keep[op.AttemptKey]) {
			excess--
			continue
		}
		out = append(out, op)
	}
	f.Operations = out
	return excess <= 0
}

// undelivered returns the events after the delivered sequence.
func (f *PRStoreFile) undelivered() ([]OperationEvent, int64) {
	var out []OperationEvent
	var last int64
	for _, op := range f.Operations {
		if op.Seq > f.DeliveredSeq {
			out = append(out, op)
			last = op.Seq
		}
	}
	return out, last
}
