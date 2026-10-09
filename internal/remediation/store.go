package remediation

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrPlanVersion means a stored plan has a format version this build does not
// read.
var ErrPlanVersion = errors.New("remediation: unsupported plan version")

// PlanStore keeps the latest Plan in one file. It is independent of the
// notification state: unlike that file, a plan file that is unreadable,
// corrupt or of another version is an error, never an empty plan, so a
// damaged record cannot be mistaken for a clean start.
type PlanStore struct {
	Path string
}

// DefaultPlanPath is the plan file under a state directory.
func DefaultPlanPath(stateDir string) string {
	return filepath.Join(stateDir, "remediation", "plan.json")
}

// Load reads the plan. found is false, with a nil error, only when the file
// does not exist.
func (s PlanStore) Load() (plan Plan, found bool, err error) {
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Plan{}, false, nil
	}
	if err != nil {
		return Plan{}, false, fmt.Errorf("read plan %s: %w", s.Path, err)
	}
	if err := json.Unmarshal(data, &plan); err != nil {
		return Plan{}, false, fmt.Errorf("parse plan %s: %w", s.Path, err)
	}
	if plan.Version != PlanVersion {
		return Plan{}, false, fmt.Errorf("%w: %s has version %d, this build reads %d", ErrPlanVersion, s.Path, plan.Version, PlanVersion)
	}
	return plan, true, nil
}

// Save writes the plan atomically: a temporary file in the same directory is
// written, synced and renamed over the target, so a crash leaves either the
// old file or the new one. The version is set to PlanVersion. Save returns an
// error without writing when a file already there cannot be loaded (see
// Load), and returns the error of the final directory sync if that fails.
func (s PlanStore) Save(plan Plan) error {
	if s.Path == "" {
		return errors.New("save plan: no path")
	}
	// An existing file that cannot be read back is never replaced: it may be
	// a record this build does not understand.
	if _, _, err := s.Load(); err != nil {
		return fmt.Errorf("refusing to overwrite plan: %w", err)
	}
	plan.Version = PlanVersion
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal plan: %w", err)
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create plan dir: %w", err)
	}
	f, err := os.CreateTemp(dir, filepath.Base(s.Path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create plan temp file: %w", err)
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
		return fmt.Errorf("write plan: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync plan: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close plan: %w", err)
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return fmt.Errorf("chmod plan: %w", err)
	}
	if err := os.Rename(tmp, s.Path); err != nil {
		return fmt.Errorf("replace plan: %w", err)
	}
	ok = true
	// Make the rename durable. The new file is already in place, so a failure
	// here is reported but the plan is readable.
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open plan dir to sync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync plan dir: %w", err)
	}
	return nil
}
