package remediation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func TestLangUpdateSourceCheckScansExactlyTheFiles(t *testing.T) {
	h := newHarness(t, "npm")
	var seen []map[string][]byte
	h.fs.fn = func(n int, files map[string][]byte) (scanner.FSScan, error) {
		seen = append(seen, files)
		return h.okFS(n, files)
	}
	it, _ := h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if len(seen) != 2 {
		t.Fatalf("%d scans", len(seen))
	}
	for i, files := range seen {
		if len(files) != 2 || string(files["package.json"]) != h.files["package.json"] {
			t.Errorf("scan %d files = %v", i, keysOf(files))
		}
	}
	if string(seen[0]["package-lock.json"]) != h.files["package-lock.json"] || string(seen[1]["package-lock.json"]) != string(h.after) {
		t.Error("the scans did not read the original and the updated lockfile")
	}
}

func keysOf(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestLangUpdateSourceCheckOutcomes(t *testing.T) {
	typ := "npm"
	before := func(pkgs [][2]string, vulns [][3]string) func(*harness) {
		return func(h *harness) {
			h.fs.fn = func(n int, f map[string][]byte) (scanner.FSScan, error) {
				if n == 0 {
					return fsReport(typ, pkgs, vulns), nil
				}
				return h.okFS(n, f)
			}
		}
	}
	after := func(pkgs [][2]string, vulns [][3]string) func(*harness) {
		return func(h *harness) {
			h.fs.fn = func(n int, f map[string][]byte) (scanner.FSScan, error) {
				if n == 0 {
					return h.okFS(n, f)
				}
				return fsReport(typ, pkgs, vulns), nil
			}
		}
	}
	fail := func(err error) func(*harness) {
		return func(h *harness) {
			h.fs.fn = func(n int, f map[string][]byte) (scanner.FSScan, error) { return scanner.FSScan{}, err }
		}
	}
	oldPkgs := [][2]string{{"mkdirp", "0.5.5"}, {"minimist", "1.2.5"}}
	newPkgs := [][2]string{{"mkdirp", "0.5.5"}, {"minimist", "1.2.8"}}
	oldVuln := [][3]string{{"minimist", "1.2.5", "CVE-2021-44906"}}
	cases := []struct {
		name   string
		setup  func(*harness)
		cat    Category
		reason Reason
	}{
		{"target not analysed before", before([][2]string{{"mkdirp", "0.5.5"}}, oldVuln), CategoryManual, ReasonSourceTargetNotDetectedBefore},
		{"target at another version before", before([][2]string{{"minimist", "1.2.4"}}, oldVuln), CategoryManual, ReasonSourceTargetNotDetectedBefore},
		{"target cve not reported before", before(oldPkgs, nil), CategoryManual, ReasonSourceTargetNotDetectedBefore},
		{"target not analysed after", after([][2]string{{"mkdirp", "0.5.5"}}, nil), CategoryManual, ReasonSourceTargetNotAnalysedAfter},
		{"target at another version after", after([][2]string{{"minimist", "1.2.9"}}, nil), CategoryManual, ReasonSourceTargetNotAnalysedAfter},
		{"target cve still reported", after(newPkgs, [][3]string{{"minimist", "1.2.8", "CVE-2021-44906"}}), CategoryManual, ReasonSourceTargetStillDetected},
		{"new finding", after(newPkgs, [][3]string{{"mkdirp", "0.5.5", "CVE-2099-0001"}}), CategoryManual, ReasonSourceIntroduced},
		{"scan conditions differ", fail(fmt.Errorf("x: %w", scanner.ErrConditionsDiffer)), CategoryNotComparable, ReasonConditionsDiffer},
		{"scan conditions unknown", fail(scanner.ErrConditionsUnknown), CategoryNotComparable, ReasonConditionsUnknown},
		{"scan fails", fail(errors.New("trivy exploded")), CategoryFailed, ReasonSourceScanFailed},
		{"conditions change between the scans", func(h *harness) {
			h.fs.fn = func(n int, f map[string][]byte) (scanner.FSScan, error) {
				r, err := h.okFS(n, f)
				if n == 1 {
					r.Conditions.VulnerabilityDBSHA = "other"
				}
				return r, err
			}
		}, CategoryNotComparable, ReasonConditionsDiffer},
		{"truncated package list", func(h *harness) {
			h.fs.fn = func(n int, f map[string][]byte) (scanner.FSScan, error) {
				r, err := h.okFS(n, f)
				r.Report.PackagesTruncated = true
				return r, err
			}
		}, CategoryNotComparable, ReasonSourceScanIncomplete},
		{"another result type is not the lockfile", func(h *harness) {
			h.fs.fn = func(n int, f map[string][]byte) (scanner.FSScan, error) {
				if n == 0 {
					return fsReport("pip", oldPkgs, oldVuln), nil
				}
				return h.okFS(n, f)
			}
		}, CategoryManual, ReasonSourceTargetNotDetectedBefore},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, "npm")
			c.setup(h)
			it, _ := h.run()
			wantCategory(t, it, c.cat, c.reason)
			if len(it.Artifacts) != 0 {
				t.Error("artifacts kept")
			}
			// The update ran and its result was inspected even though the item
			// is not proposed.
			if !it.UpdateExecuted || !it.PostUpdateCheckExecuted {
				t.Errorf("executed flags = %v %v", it.UpdateExecuted, it.PostUpdateCheckExecuted)
			}
			if it.SourceCheck == nil || it.SourceCheck.Passed {
				t.Errorf("source check = %+v", it.SourceCheck)
			}
		})
	}

	t.Run("an introduced finding that is KEV-listed", func(t *testing.T) {
		h := newHarness(t, "npm")
		after(newPkgs, [][3]string{{"mkdirp", "0.5.5", "CVE-2099-0001"}})(h)
		h.cfg.Intel = func(id string) (VulnIntel, bool) { return VulnIntel{KEV: id == "CVE-2099-0001"}, true }
		it, _ := h.run()
		wantCategory(t, it, CategoryManual, ReasonSourceIntroducedKEV)
		if got := it.SourceCheck.Introduced; len(got) != 1 || !got[0].KEV {
			t.Errorf("introduced = %+v", got)
		}
	})
	t.Run("remaining findings are kept and do not stop the item", func(t *testing.T) {
		h := newHarness(t, "npm")
		h.fs.fn = func(n int, f map[string][]byte) (scanner.FSScan, error) {
			if n == 0 {
				return fsReport(typ, oldPkgs, append([][3]string{{"mkdirp", "0.5.5", "CVE-2020-1"}}, oldVuln...)), nil
			}
			return fsReport(typ, newPkgs, [][3]string{{"mkdirp", "0.5.5", "CVE-2020-1"}}), nil
		}
		it, _ := h.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		sc := it.SourceCheck
		if len(sc.Remaining) != 1 || sc.Remaining[0].VulnID != "CVE-2020-1" || len(sc.Resolved) != 1 || sc.Resolved[0].VulnID != "CVE-2021-44906" || len(sc.Introduced) != 0 {
			t.Errorf("source check = %+v", sc)
		}
	})
	t.Run("deadline during the scan defers", func(t *testing.T) {
		h := newHarness(t, "npm")
		ctx, cancel := context.WithCancel(context.Background())
		h.fs.fn = func(n int, f map[string][]byte) (scanner.FSScan, error) {
			cancel()
			return scanner.FSScan{}, context.Canceled
		}
		it, _ := h.runCtx(ctx)
		wantCategory(t, it, CategoryDeferred, ReasonCycleDeadline)
		if strings.Contains(it.Detail, "trivy") {
			t.Error(it.Detail)
		}
	})
}

func TestLangUpdateSourceCheckPythonNamesAreNormalized(t *testing.T) {
	h := newHarness(t, "uv")
	h.fs.fn = func(n int, f map[string][]byte) (scanner.FSScan, error) {
		// Trivy may report the name in another spelling than the image does.
		if n == 0 {
			return fsReport("uv", [][2]string{{"URLLIB3", "1.26.4"}}, [][3]string{{"URLLIB3", "1.26.4", "CVE-2021-33503"}, {"URLLIB3", "1.26.4", "CVE-2023-43804"}}), nil
		}
		return fsReport("uv", [][2]string{{"Urllib3", "1.26.17"}}, nil), nil
	}
	it, _ := h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
}
