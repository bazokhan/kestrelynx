package remediation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// deliveredVersion is the format version of the delivered-plan record.
const deliveredVersion = 1

// Fingerprint identifies what a plan shows a reader: the category and reason
// of each item, the image identities and services, the candidate's reference
// and content, the comparison counts and the per-category totals. It leaves
// out everything that varies between runs without changing the message —
// times, scan IDs, error text, the order of items and the scan conditions —
// so two plans that read the same have the same fingerprint. The dependency
// units add what they show — their packages, versions, relation, actions,
// reasons, occurrence sets and the findings they came from — but not the
// commit or file hashes, which change without changing the message. A plan with no items has the empty fingerprint, the same as
// nothing delivered.
func Fingerprint(p Plan) string {
	if len(p.Items) == 0 && len(p.LanguageItems) == 0 {
		return ""
	}
	type image struct {
		Ref      string `json:"ref"`
		Entity   string `json:"entity,omitempty"`
		Config   string `json:"config,omitempty"`
		Manifest string `json:"manifest,omitempty"`
		Top      string `json:"top,omitempty"`
	}
	type item struct {
		Key        string       `json:"key"`
		Category   Category     `json:"category"`
		Reason     Reason       `json:"reason,omitempty"`
		Services   []ServiceRef `json:"services,omitempty"`
		Current    image        `json:"current"`
		Candidate  *image       `json:"candidate,omitempty"`
		Targets    int          `json:"targets,omitempty"`
		Resolved   int          `json:"resolved,omitempty"`
		Remaining  int          `json:"remaining,omitempty"`
		Introduced int          `json:"introduced,omitempty"`
	}
	type langPackage struct {
		Name        string        `json:"name"`
		Installed   string        `json:"installed"`
		Target      string        `json:"target,omitempty"`
		Relation    Relation      `json:"relation,omitempty"`
		Action      PackageAction `json:"action,omitempty"`
		Reason      Reason        `json:"reason,omitempty"`
		Occurrences []string      `json:"occurrences,omitempty"`
		Origins     []string      `json:"origins,omitempty"`
		CVEs        []string      `json:"cves,omitempty"`
		KEV         int           `json:"kev,omitempty"`
	}
	type langItem struct {
		Key       string            `json:"key"`
		Workloads []string          `json:"workloads"`
		Manager   DependencyManager `json:"manager,omitempty"`
		Category  Category          `json:"category"`
		Reason    Reason            `json:"reason,omitempty"`
		Packages  []langPackage     `json:"packages,omitempty"`
	}
	out := struct {
		Counts   map[Category]int `json:"counts"`
		Items    []item           `json:"items"`
		Language []langItem       `json:"language,omitempty"`
	}{Counts: map[Category]int{}}
	for _, li := range p.LanguageItems {
		fl := langItem{Key: li.Key, Workloads: append([]string(nil), li.Workloads...), Manager: li.Manager, Category: li.Category, Reason: li.Reason}
		sort.Strings(fl.Workloads)
		for _, pk := range li.Packages {
			lp := langPackage{Name: pk.Name, Installed: pk.Installed, Target: pk.SelectionLowerBound, Relation: pk.Relation,
				Action: pk.Action, Reason: pk.Reason, KEV: pk.KEVCount()}
			for _, o := range pk.Occurrences {
				lp.Occurrences = append(lp.Occurrences, fmt.Sprintf("%s\x00%s\x00%t\x00%s\x00%s\x00%s", o.Path, o.Version, o.Direct, o.Marker, o.Constraint, o.ManualReason))
			}
			sort.Strings(lp.Occurrences)
			for _, o := range pk.Origins {
				lp.Origins = append(lp.Origins, o.key())
			}
			sort.Strings(lp.Origins)
			for _, c := range pk.CVEs {
				lp.CVEs = append(lp.CVEs, c.VulnID)
			}
			fl.Packages = append(fl.Packages, lp)
		}
		sort.Slice(fl.Packages, func(i, j int) bool {
			a, b := fl.Packages[i], fl.Packages[j]
			if a.Name != b.Name {
				return a.Name < b.Name
			}
			return a.Installed < b.Installed
		})
		out.Language = append(out.Language, fl)
	}
	sort.Slice(out.Language, func(i, j int) bool { return out.Language[i].Key < out.Language[j].Key })
	for _, it := range p.Items {
		out.Counts[it.Category]++
		fi := item{
			Key:      it.Key,
			Category: it.Category,
			Reason:   it.Reason,
			Services: append([]ServiceRef(nil), it.Services...),
			Current:  image{Ref: it.Current.Ref, Entity: it.Current.Entity, Config: it.Current.ConfigDigest},
			Targets:  len(it.Targets),
		}
		sort.Slice(fi.Services, func(i, j int) bool {
			a, b := fi.Services[i], fi.Services[j]
			if a.Project != b.Project {
				return a.Project < b.Project
			}
			if a.Service != b.Service {
				return a.Service < b.Service
			}
			return a.Container < b.Container
		})
		if c := it.Candidate; c != nil {
			fi.Candidate = &image{Ref: c.Ref, Config: c.ConfigDigest, Manifest: c.ManifestDigest, Top: c.TopDigest}
		}
		if it.Comparison != nil {
			fi.Resolved, fi.Remaining, fi.Introduced = it.Comparison.Counts()
		}
		out.Items = append(out.Items, fi)
	}
	sort.Slice(out.Items, func(i, j int) bool {
		a, b := out.Items[i], out.Items[j]
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		return a.Category < b.Category
	})
	// encoding/json writes map keys in sorted order, so the bytes are stable.
	data, err := json.Marshal(out)
	if err != nil {
		// Only plain strings, ints and maps of them are marshalled.
		panic(fmt.Sprintf("remediation: fingerprint: %v", err))
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// StatusFingerprint extends a plan fingerprint with the plan's status: why no
// plan was produced (unavailable, a fixed code, "" when one was) and whether
// it could not be saved. Without a problem it is the plan fingerprint itself,
// so a healthy cycle is unaffected; with one it is a different value for each
// distinct problem, so a change of status is a change of what is delivered
// while the same problem repeated is not.
func StatusFingerprint(planFingerprint, unavailable string, notSaved bool) string {
	if unavailable == "" && !notSaved {
		return planFingerprint
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("plan=%s\x00unavailable=%s\x00not_saved=%t", planFingerprint, unavailable, notSaved)))
	return hex.EncodeToString(sum[:])
}

// DeliveredStore records the fingerprint of the last plan that was delivered
// in a notification. It sits next to the plan file and is independent of the
// notification state.
type DeliveredStore struct {
	Path string
}

// DefaultDeliveredPath is the delivered-plan file under the remediation
// storage directory.
func DefaultDeliveredPath(storageDir string) string {
	return filepath.Join(storageDir, "delivered.json")
}

type deliveredRecord struct {
	Version     int    `json:"version"`
	Fingerprint string `json:"fingerprint"`
}

// Load returns the delivered fingerprint; it is empty, with a nil error, when
// the file does not exist. An unreadable, corrupt or foreign-version file is
// an error.
func (s DeliveredStore) Load() (string, error) {
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read delivered plan %s: %w", s.Path, err)
	}
	var rec deliveredRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return "", fmt.Errorf("parse delivered plan %s: %w", s.Path, err)
	}
	if rec.Version != deliveredVersion {
		return "", fmt.Errorf("%w: %s has version %d, this build reads %d", ErrPlanVersion, s.Path, rec.Version, deliveredVersion)
	}
	return rec.Fingerprint, nil
}

// Save replaces the record atomically. A file already there is replaced even
// when it cannot be read: it only says what was last delivered, and keeping
// an unreadable one would announce the same plan every cycle.
func (s DeliveredStore) Save(fingerprint string) error {
	if s.Path == "" {
		return errors.New("save delivered plan: no path")
	}
	data, err := json.Marshal(deliveredRecord{Version: deliveredVersion, Fingerprint: fingerprint})
	if err != nil {
		return fmt.Errorf("marshal delivered plan: %w", err)
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create delivered plan dir: %w", err)
	}
	f, err := os.CreateTemp(dir, filepath.Base(s.Path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create delivered plan temp file: %w", err)
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
		return fmt.Errorf("write delivered plan: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync delivered plan: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close delivered plan: %w", err)
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return fmt.Errorf("chmod delivered plan: %w", err)
	}
	if err := os.Rename(tmp, s.Path); err != nil {
		return fmt.Errorf("replace delivered plan: %w", err)
	}
	ok = true
	return nil
}
