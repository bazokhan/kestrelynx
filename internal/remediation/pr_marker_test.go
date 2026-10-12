package remediation

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func sampleMarker() PRMarker {
	m := PRMarker{V: 1, RepoID: 7, BaseBranch: "main", Path: "compose.yml", Locations: []string{"services.web.image"},
		CurrentRef: "nginx:1.25.3", CandidateTag: "1.25.4", CandidateDigest: topDigest('1'), BaseSHA: hex40('1'), HeadSHA: hex40('2'),
		InputBlobSHA: hex40('3'), Changes: []FileChange{{Path: "compose.yml", Mode: "100644", BlobSHA: hex40('4')}},
		FixTargets: []FixTarget{{Location: "services.web.image", VulnID: "CVE-1", Package: pkgCoord("libc")}}}
	m.TargetKey = TargetKey(m.RepoID, m.BaseBranch, m.Path, m.Locations)
	m.UpdateKey = UpdateKey(m.TargetKey, m.CurrentRef, m.CandidateTag, m.CandidateDigest)
	m.AttemptKey = AttemptKey(m.UpdateKey, m.BaseSHA, m.InputBlobSHA, m.Changes)
	return m
}

func TestMarkerRoundTripAndVerify(t *testing.T) {
	m := sampleMarker()
	body := "text\n\n" + encodeMarker(m)
	got, err := parsePRMarker(body)
	if err != nil || got.verify(7) != nil || got.AttemptKey != m.AttemptKey {
		t.Fatalf("parse %+v err %v", got, err)
	}
	if got.verify(8) == nil {
		t.Error("a marker of another repository verified")
	}
	tampered := m
	tampered.CandidateTag = "1.25.9"
	if got, _ := parsePRMarker(encodeMarker(tampered)); got.verify(7) == nil {
		t.Error("a tampered marker verified")
	}
	changed := m
	changed.Changes = []FileChange{{Path: "compose.yml", Mode: "100644", BlobSHA: hex40('5')}}
	if got, _ := parsePRMarker(encodeMarker(changed)); got.verify(7) == nil {
		t.Error("a marker whose changes do not give the attempt key verified")
	}
	if !m.branchMatches("kestrelynx/compose/web-1.25.4-"+m.AttemptKey[:12]) || m.branchMatches("kestrelynx/compose/web-1.25.4-000000000000") {
		t.Error("branch matching")
	}
	// The JSON cannot close the comment early.
	m.Path = "a-->b.yml"
	if enc := encodeMarker(m); strings.Count(enc, "-->") != 1 {
		t.Errorf("marker %s", enc)
	}
}

func TestMarkerStrictness(t *testing.T) {
	good := encodeMarker(sampleMarker())
	for name, body := range map[string]string{
		"missing":        "nothing here",
		"two":            good + "\n" + good,
		"unknown field":  strings.Replace(good, `{"v":1,`, `{"v":1,"extra":true,`, 1),
		"unknown v":      strings.Replace(good, `{"v":1,`, `{"v":2,`, 1),
		"truncated":      strings.TrimSuffix(good, `]} -->`) + " -->",
		"bad sha":        strings.Replace(good, hex40('2'), "zz", 1),
		"trailing":       strings.Replace(good, "} -->", "}{} -->", 1),
		"no repo id":     strings.Replace(good, `"repo_id":7`, `"repo_id":0`, 1),
		"bad mode":       strings.Replace(good, `"100644"`, `"120000"`, 1),
		"empty location": strings.Replace(good, `"locations":["services.web.image"]`, `"locations":[]`, 1),
	} {
		if _, err := parsePRMarker(body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A supersede marker is not a pull request marker.
	if _, err := parsePRMarker(supersedeComment(3, "https://github.com/x/y/pull/3", "u")); err != errMarkerMissing {
		t.Errorf("supersede marker read as a pull request marker: %v", err)
	}
}

func TestSupersedeMarker(t *testing.T) {
	c := supersedeComment(3, "https://github.com/x/y/pull/3", "uk")
	if !strings.HasPrefix(c, "Superseded by #3 (https://github.com/x/y/pull/3)") {
		t.Errorf("comment = %q", c)
	}
	if !hasSupersedeMarker(c, 3, "uk") || hasSupersedeMarker(c, 4, "uk") || hasSupersedeMarker(c, 3, "other") {
		t.Error("marker matching")
	}
	if supersededByIn(c) != 3 || supersededByIn("Superseded by #3") != 0 {
		t.Error("supersededByIn")
	}
}

func TestPRBodySanitizesExternalStrings(t *testing.T) {
	ev := &VerificationSummary{TrivyVersion: "0.71.2", Severities: []string{"HIGH"}, PlanGeneratedAt: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC),
		Items: []ItemEvidence{{
			Current:   ImageState{Ref: "nginx:1.25.3", ConfigDigest: "sha256:" + hex64('a'), DigestKindUnverified: true},
			Candidate: ImageState{Ref: "nginx:1.25.4", TopDigest: topDigest('1'), Platform: "linux/amd64"},
			Locations: []string{"services.web.image"},
			Resolved:  []VulnSummary{{VulnID: "CVE-1", Package: PackageCoord{Name: "evil`](http://x) @team\n# head <img src=x>"}, KEV: true, Priority: PriorityActNow}},
		}}}
	body, err := buildPRBody(prBodyInput{Repo: testRepo, BaseBranch: "main", BaseSHA: hex40('1'), Path: "compose.yml", Current: "nginx:1.25.3",
		Services: []string{"web"}, Locations: []string{"services.web.image"}, Workloads: []string{"compose/app/web"},
		Changes:      []ComposeChange{{Service: "web", Location: "services.web.image", Old: "nginx:1.25.3", New: "nginx:1.25.4"}},
		CandidateTag: "1.25.4", Evidence: ev, UpdateKey: "uk", AttemptKey: "ak", Marker: encodeMarker(sampleMarker())})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"\n# head", "`](http://x)"} {
		if strings.Contains(body, bad) {
			t.Errorf("body contains %q", bad)
		}
	}
	if !strings.Contains(body, "`evil'](http://x) @team # head <img src=x>`") {
		t.Errorf("package name not rendered as inline code:\n%s", body)
	}
	for _, want := range []string{"## What", "## Change", "## Verification",
		"is not confirmed", "in the CISA KEV catalog"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q", want)
		}
	}
	if _, err := parsePRMarker(body); err != nil {
		t.Errorf("marker: %v", err)
	}
}

func TestPRBodyLengthKeepsTheMarker(t *testing.T) {
	var vs []VulnSummary
	for i := 0; i < 5000; i++ {
		vs = append(vs, VulnSummary{VulnID: strings.Repeat("V", 200), Package: PackageCoord{Name: strings.Repeat("p", 250)}})
	}
	marker := encodeMarker(sampleMarker())
	text := strings.Repeat("line of text that is long enough\n", 3000)
	body, err := assembleBody(text, marker)
	if err != nil {
		t.Fatal(err)
	}
	if utf8.RuneCountInString(body) > maxPRBodyChars || !strings.HasSuffix(body, "\n"+marker) || !strings.Contains(body, "was cut") {
		t.Errorf("body of %d chars, ends with marker %v", utf8.RuneCountInString(body), strings.HasSuffix(body, marker))
	}
	// Lists are capped with a count of the rest.
	var b strings.Builder
	writeVulnList(&b, "Resolved", vs)
	if !strings.Contains(b.String(), "and 4970 more") {
		t.Error("list not capped")
	}
	if _, err := assembleBody("x", markerPrefix+strings.Repeat("a", maxPRBodyChars)+markerSuffix); err != errMarkerTooLarge {
		t.Errorf("oversized marker: %v", err)
	}
}
