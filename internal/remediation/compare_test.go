package remediation

import (
	"errors"
	"reflect"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func candScan(h byte, fs []scanner.Finding, pk []scanner.ResultPackages) scanner.ImageScan {
	reg, _ := inventory.ParseDigest(inventory.DigestRegistry, "sha256:"+hex64(h))
	target := scanner.ScanTarget{Subject: inventory.ImageSubject{
		Ref: "app:1.2.4", Key: inventory.EntityKey{Digest: reg, Platform: linuxAmd64}, Resolved: true,
	}}
	return remoteScan(target, fs, pk)
}

func TestCompareEntryConditions(t *testing.T) {
	c := testConds("db1")
	base := func() ScanRecord {
		return ScanRecord{Scan: configScan("app:1.2.3", 'a', []scanner.Finding{finding("CVE-1", "libc", "1", "2", scanner.SeverityHigh)}, pkgs("libc", "1")), Conditions: c}
	}
	cand := func() ScanRecord {
		return ScanRecord{Scan: candScan('b', nil, pkgs("libc", "2")), Conditions: c}
	}
	mod := func(f func(b, c *ScanRecord)) (ScanRecord, ScanRecord) {
		b, cn := base(), cand()
		f(&b, &cn)
		return b, cn
	}
	cases := []struct {
		name   string
		mutate func(b, c *ScanRecord)
		want   Reason
	}{
		{"ok", func(b, c *ScanRecord) {}, ""},
		{"baseline failed", func(b, c *ScanRecord) { b.Scan.Err = errors.New("boom") }, ReasonScanFailed},
		{"candidate failed", func(b, c *ScanRecord) { c.Scan.Err = errors.New("boom") }, ReasonScanFailed},
		{"baseline not pinned", func(b, c *ScanRecord) { b.Scan.Pinned = false }, ReasonEntityUnverified},
		{"candidate unresolved", func(b, c *ScanRecord) { c.Scan.Subject.Resolved = false }, ReasonEntityUnverified},
		{"baseline conditions unknown", func(b, c *ScanRecord) { b.Conditions = scanner.ScanConditions{} }, ReasonConditionsUnknown},
		{"candidate conditions unknown", func(b, c *ScanRecord) { c.Conditions = scanner.ScanConditions{} }, ReasonConditionsUnknown},
		{"conditions differ", func(b, c *ScanRecord) { c.Conditions = testConds("db2") }, ReasonConditionsDiffer},
		{"baseline platform unknown", func(b, c *ScanRecord) { b.Scan.Platform = inventory.Platform{} }, ReasonPlatformUnknown},
		{"variant on candidate", func(b, c *ScanRecord) { c.Scan.Platform.Variant = "v8" }, ReasonVariantUnsupported},
		{"platform differs", func(b, c *ScanRecord) { c.Scan.Platform.Architecture = "arm64" }, ReasonPlatformDiffer},
		{"baseline packages missing", func(b, c *ScanRecord) { b.Scan.Packages = nil }, ReasonPackagesMissing},
		{"candidate packages missing", func(b, c *ScanRecord) { c.Scan.Packages = nil }, ReasonPackagesMissing},
		{"candidate packages truncated", func(b, c *ScanRecord) { c.Scan.PackagesTruncated = true }, ReasonPackagesTruncated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, cn := mod(tc.mutate)
			r := Compare(b, cn)
			if tc.want == "" {
				if !r.Comparable {
					t.Fatalf("not comparable: %s %s", r.Reason, r.Detail)
				}
				return
			}
			if r.Comparable || r.Reason != tc.want {
				t.Fatalf("comparable=%v reason=%q, want not comparable %q", r.Comparable, r.Reason, tc.want)
			}
			if len(r.Introduced) != 0 {
				t.Error("a non-comparable result claims introduced findings")
			}
			for _, v := range r.Verdicts {
				if v.Outcome != OutcomeUnknown {
					t.Errorf("verdict %s is %q in a non-comparable result", v.VulnID, v.Outcome)
				}
			}
			if r.Scope == "" {
				t.Error("scope is not stated")
			}
		})
	}
}

func TestCompareVerdicts(t *testing.T) {
	c := testConds("db1")
	f := func(vuln, pkg, ver string) scanner.Finding {
		return finding(vuln, pkg, ver, "9", scanner.SeverityHigh)
	}
	withPath := func(fd scanner.Finding, target, path string) scanner.Finding {
		fd.Target, fd.PkgPath = target, path
		return fd
	}
	low := finding("CVE-LOW", "libc", "1", "2", "LOW")
	baseFindings := []scanner.Finding{
		f("CVE-1", "libc", "1"),  // resolved: package updated
		f("CVE-2", "gone", "1"),  // resolved: package removed
		f("CVE-3", "multi", "1"), // two versions on the baseline
		f("CVE-3", "multi", "2"),
		f("CVE-4", "dup", "1"), // identical finding twice
		f("CVE-4", "dup", "1"),
		withPath(f("CVE-5", "lang", "1"), "a", "/x/a"), // moves between paths
		low,
	}
	baseFindings[6].Class, baseFindings[6].Type = inventory.ClassLang, "gobinary"
	candFindings := []scanner.Finding{
		f("CVE-3", "multi", "2"), // one version still carries it
		withPath(f("CVE-5", "lang", "1"), "b", "/y/b"),
		f("CVE-6", "newpkg", "3"), // introduced
	}
	candFindings[1].Class, candFindings[1].Type = inventory.ClassLang, "gobinary"
	b := ScanRecord{Scan: configScan("app:1.2.3", 'a', baseFindings, pkgs("libc", "1", "gone", "1", "multi", "1", "dup", "1")), Conditions: c}
	cd := ScanRecord{Scan: candScan('b', candFindings, pkgs("libc", "2", "multi", "2", "dup", "1")), Conditions: c}
	r := Compare(b, cd)
	if !r.Comparable {
		t.Fatalf("not comparable: %s", r.Reason)
	}
	byID := map[string]VulnVerdict{}
	for _, v := range r.Verdicts {
		byID[v.VulnID] = v
	}
	if _, ok := byID["CVE-LOW"]; ok {
		t.Error("a finding outside the scanned severity range was evaluated")
	}
	if len(byID) != 5 {
		t.Fatalf("verdict ids = %v", byID)
	}
	if v := byID["CVE-1"]; v.Outcome != OutcomeResolved || v.Disposition != DispositionVersionChanged {
		t.Errorf("CVE-1: %+v", v)
	}
	if v := byID["CVE-2"]; v.Outcome != OutcomeResolved || v.Disposition != DispositionRemoved {
		t.Errorf("CVE-2: %+v", v)
	}
	v3 := byID["CVE-3"]
	if v3.Outcome != OutcomeRemaining {
		t.Errorf("CVE-3 should remain when any occurrence remains: %+v", v3)
	}
	if got := Versions(v3.Before); !reflect.DeepEqual(got, []string{"1", "2"}) {
		t.Errorf("CVE-3 baseline versions = %v", got)
	}
	if got := Versions(v3.After); !reflect.DeepEqual(got, []string{"2"}) {
		t.Errorf("CVE-3 candidate versions = %v", got)
	}
	if v := byID["CVE-4"]; len(v.Before) != 1 || v.Outcome != OutcomeRemaining && v.Outcome != OutcomeResolved {
		t.Errorf("CVE-4 duplicates not merged: %+v", v)
	}
	if v := byID["CVE-4"]; v.Outcome != OutcomeResolved {
		t.Errorf("CVE-4: package kept, finding gone => resolved: %+v", v)
	} else if v.Disposition != DispositionSameVersion {
		t.Errorf("CVE-4 disposition = %q", v.Disposition)
	}
	v5 := byID["CVE-5"]
	if v5.Outcome != OutcomeRemaining || v5.Before[0].PkgPath != "/x/a" || v5.After[0].PkgPath != "/y/b" {
		t.Errorf("a moved occurrence must stay remaining with both sets: %+v", v5)
	}
	if len(r.Introduced) != 1 || r.Introduced[0].VulnID != "CVE-6" || r.Introduced[0].Outcome != OutcomeIntroduced || len(r.Introduced[0].Before) != 0 {
		t.Errorf("introduced = %+v", r.Introduced)
	}
	for _, v := range r.Verdicts {
		for _, in := range r.Introduced {
			if v.VulnID == in.VulnID && v.Package == in.Package {
				t.Errorf("%s is both a verdict and introduced", v.VulnID)
			}
		}
	}
	if r.Severities == nil || r.Scope == "" {
		t.Error("severity scope not stated")
	}
	resolved, remaining, introduced := r.Counts()
	if resolved != 3 || remaining != 2 || introduced != 1 {
		t.Errorf("counts = %d/%d/%d", resolved, remaining, introduced)
	}
}

func TestCompareSameCVEDifferentCoordinates(t *testing.T) {
	// An OS package and a language package that share a name are separate
	// coordinates.
	c := testConds("db1")
	os := finding("CVE-1", "openssl", "1", "2", scanner.SeverityHigh)
	lang := finding("CVE-1", "openssl", "1", "2", scanner.SeverityHigh)
	lang.Class, lang.Type = inventory.ClassLang, "cargo"
	b := ScanRecord{Scan: configScan("a:1.2.3", 'a', []scanner.Finding{os, lang}, pkgs("openssl", "1")), Conditions: c}
	cd := ScanRecord{Scan: candScan('b', []scanner.Finding{lang}, pkgs("openssl", "1")), Conditions: c}
	r := Compare(b, cd)
	got := map[inventory.PkgClass]Outcome{}
	for _, v := range r.Verdicts {
		got[v.Package.Class] = v.Outcome
	}
	if got[inventory.ClassOS] != OutcomeResolved || got[inventory.ClassLang] != OutcomeRemaining {
		t.Errorf("outcomes = %v", got)
	}
}

func langFinding(vuln, typ, pkg string) scanner.Finding {
	f := finding(vuln, pkg, "1", "2", scanner.SeverityHigh)
	f.Class, f.Type, f.Target, f.PkgPath = inventory.ClassLang, typ, "Node.js", "/app/node_modules/"+pkg+"/package.json"
	return f
}

func langPkgs(typ string, pairs ...string) []scanner.ResultPackages {
	rp := scanner.ResultPackages{Target: "Node.js", Class: inventory.ClassLang, Type: typ}
	for i := 0; i+1 < len(pairs); i += 2 {
		rp.Packages = append(rp.Packages, scanner.Package{Name: pairs[i], Version: pairs[i+1]})
	}
	return []scanner.ResultPackages{rp}
}

func TestCompareAnalysisScope(t *testing.T) {
	c := testConds("db1")
	osF := finding("CVE-OS", "libc", "1", "2", scanner.SeverityHigh)
	nodeF := langFinding("CVE-NODE", "node-pkg", "left-pad")
	basePk := append(pkgs("libc", "1"), langPkgs("node-pkg", "left-pad", "1")...)
	base := func(fs ...scanner.Finding) ScanRecord {
		return ScanRecord{Scan: configScan("app:1.2.3", 'a', fs, basePk), Conditions: c}
	}
	outcomeOf := func(r VerificationResult, id string) VulnVerdict {
		for _, v := range r.Verdicts {
			if v.VulnID == id {
				return v
			}
		}
		t.Fatalf("no verdict for %s", id)
		return VulnVerdict{}
	}

	t.Run("candidate lacks the whole node-pkg result", func(t *testing.T) {
		cand := ScanRecord{Scan: candScan('b', nil, pkgs("libc", "2")), Conditions: c}
		r := Compare(base(osF, nodeF), cand)
		if !r.Comparable {
			t.Fatal("OS-level comparison should still be possible")
		}
		if v := outcomeOf(r, "CVE-NODE"); v.Outcome != OutcomeUnknown || v.Reason != ReasonTypeNotAnalysed {
			t.Errorf("node verdict = %+v", v)
		}
		if v := outcomeOf(r, "CVE-OS"); v.Outcome != OutcomeResolved {
			t.Errorf("OS verdict = %+v", v)
		}
		d := Decide([]Target{{VulnID: "CVE-OS", Package: outcomeOf(r, "CVE-OS").Package}, {VulnID: "CVE-NODE", Package: outcomeOf(r, "CVE-NODE").Package}}, r, nil)
		if d.Propose || d.Kind != DecisionAnalysisIncomplete || d.Unknown != 1 || d.Resolved != 1 {
			t.Errorf("an unanalysed target must block adoption: %+v", d)
		}
	})
	t.Run("candidate analysed the type with partial content", func(t *testing.T) {
		cand := ScanRecord{Scan: candScan('b', nil, append(pkgs("libc", "2"), langPkgs("node-pkg", "other", "1")...)), Conditions: c}
		r := Compare(base(osF, nodeF), cand)
		if v := outcomeOf(r, "CVE-NODE"); v.Outcome != OutcomeResolved || v.Disposition != DispositionRemoved {
			t.Errorf("node verdict = %+v", v)
		}
	})
	t.Run("candidate analysed a different type only", func(t *testing.T) {
		cand := ScanRecord{Scan: candScan('b', nil, append(pkgs("libc", "2"), langPkgs("gobinary", "x", "1")...)), Conditions: c}
		if v := outcomeOf(Compare(base(nodeF), cand), "CVE-NODE"); v.Outcome != OutcomeUnknown {
			t.Errorf("verdict = %+v", v)
		}
	})
	t.Run("a remaining finding needs no coverage proof", func(t *testing.T) {
		cand := ScanRecord{Scan: candScan('b', []scanner.Finding{nodeF}, pkgs("libc", "2")), Conditions: c}
		if v := outcomeOf(Compare(base(nodeF), cand), "CVE-NODE"); v.Outcome != OutcomeRemaining {
			t.Errorf("verdict = %+v", v)
		}
	})
	t.Run("OS family unknown on the candidate", func(t *testing.T) {
		cs := candScan('b', nil, pkgs("libc", "2"))
		cs.OSFamily = ""
		r := Compare(base(osF), ScanRecord{Scan: cs, Conditions: c})
		if v := outcomeOf(r, "CVE-OS"); v.Outcome != OutcomeUnknown || v.Reason != ReasonTypeNotAnalysed {
			t.Errorf("verdict = %+v", v)
		}
	})
	t.Run("unrecognised package type", func(t *testing.T) {
		odd := langFinding("CVE-ODD", "mystery-pkg", "x")
		cand := ScanRecord{Scan: candScan('b', nil, pkgs("libc", "2")), Conditions: c}
		r := Compare(base(osF, odd), cand)
		if r.Comparable || r.Reason != ReasonUnknownPackageType {
			t.Errorf("result = %+v", r)
		}
	})
	t.Run("unrecognised type outside the severity range is ignored", func(t *testing.T) {
		odd := langFinding("CVE-ODD", "mystery-pkg", "x")
		odd.Severity = "LOW"
		cand := ScanRecord{Scan: candScan('b', nil, pkgs("libc", "2")), Conditions: c}
		if r := Compare(base(osF, odd), cand); !r.Comparable {
			t.Errorf("result = %+v", r)
		}
	})
}

func TestEntityStringNeverRendersZeroKey(t *testing.T) {
	if got := entityString(inventory.EntityKey{}); got != Unconfirmed {
		t.Errorf("zero key = %q", got)
	}
	if got := entityString(configKey('a')); got == Unconfirmed || got == "" {
		t.Errorf("valid key = %q", got)
	}
}

func TestCompareUnknownTypeOnCandidateSide(t *testing.T) {
	c := testConds("db1")
	base := ScanRecord{Scan: configScan("app:1.2.3", 'a', []scanner.Finding{finding("CVE-OS", "libc", "1", "2", scanner.SeverityHigh)}, pkgs("libc", "1")), Conditions: c}

	odd := langFinding("CVE-NEW", "mystery-pkg", "x")
	cand := ScanRecord{Scan: candScan('b', []scanner.Finding{odd}, pkgs("libc", "2")), Conditions: c}
	if r := Compare(base, cand); r.Comparable || r.Reason != ReasonUnknownPackageType {
		t.Errorf("candidate finding with unknown type: %+v", r)
	}

	cand = ScanRecord{Scan: candScan('b', nil, append(pkgs("libc", "2"), langPkgs("mystery-pkg", "x", "1")...)), Conditions: c}
	if r := Compare(base, cand); r.Comparable || r.Reason != ReasonUnknownPackageType {
		t.Errorf("candidate package list with unknown type: %+v", r)
	}

	low := langFinding("CVE-LOW", "mystery-pkg", "x")
	low.Severity = "LOW"
	cand = ScanRecord{Scan: candScan('b', []scanner.Finding{low}, pkgs("libc", "2")), Conditions: c}
	if r := Compare(base, cand); !r.Comparable {
		t.Errorf("an out-of-range candidate finding must not block: %+v", r)
	}
}
