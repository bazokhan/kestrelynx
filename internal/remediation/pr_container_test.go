package remediation

import (
	"strings"
	"testing"
)

// containerNoteMarker is a part of the note on the source of a container
// started outside Compose, in each wording.
var containerNoteMarker = map[BodyLanguage]string{
	BodyEN: "was not checked by KestreLynx",
	BodyJA: "KestreLynx は確かめていない",
}

func containerBodies(t *testing.T, lang BodyLanguage, workloads []string) (dockerfile, language string) {
	t.Helper()
	marker := encodeMarker(sampleMarker())
	var err error
	dockerfile, err = buildDockerfilePRBody(dockerfileBodyInput{
		Repo: testRepo, BaseBranch: "main", BaseSHA: hex40('1'), Path: "build/Dockerfile", Current: "app:2.0",
		Workloads: workloads, Stage: 1, Change: DockerfileChange{Stage: 1, Line: 3, Old: "debian:12.5", New: "debian:12.6"},
		CandidateTag: "12.6", Evidence: bodyFixtureEvidence(), UpdateKey: "uk2", AttemptKey: "ak2", Marker: marker,
		Language: lang,
	})
	if err != nil {
		t.Fatal(err)
	}
	in := languageBodyFixture(lang, marker, true)
	in.Workloads = workloads
	language, err = buildLanguagePRBody(in)
	if err != nil {
		t.Fatal(err)
	}
	return dockerfile, language
}

func TestPRBodyNoteForContainerWorkloads(t *testing.T) {
	for _, lang := range []BodyLanguage{BodyEN, BodyJA} {
		note := textFor(lang).SourceNote
		if note == "" || !strings.Contains(note, containerNoteMarker[lang]) {
			t.Fatalf("%s: note = %q", lang, note)
		}
		for name, workloads := range map[string][]string{
			"container only":            {"container/shop-api"},
			"container with Compose":    {"compose/app/web", "container/shop-api"},
			"container with Kubernetes": {"deployment/shop/web/app", "container/shop-api"},
		} {
			df, lp := containerBodies(t, lang, workloads)
			for kind, body := range map[string]string{"dockerfile": df, "language": lp} {
				if !strings.Contains(body, note) {
					t.Errorf("%s/%s/%s: the note is missing:\n%s", lang, name, kind, body)
				}
				if strings.Count(body, note) != 1 {
					t.Errorf("%s/%s/%s: the note appears %d times", lang, name, kind, strings.Count(body, note))
				}
			}
		}
	}
}

func TestPRBodyWithoutContainerWorkloadsHasNoNote(t *testing.T) {
	for _, lang := range []BodyLanguage{BodyEN, BodyJA} {
		note := textFor(lang).SourceNote
		for name, workloads := range map[string][]string{
			"Compose":                      {"compose/app/web"},
			"Kubernetes":                   {"deployment/shop/web/app"},
			"Kubernetes pod without owner": {"container/shop/pod/app"},
			"none":                         nil,
		} {
			df, lp := containerBodies(t, lang, workloads)
			if strings.Contains(df, note) || strings.Contains(lp, note) {
				t.Errorf("%s/%s: the note is in a body that names no container/<name> workload", lang, name)
			}
		}
	}
	// A Compose body is the same as before: none of the Compose body texts
	// mention the note.
	for _, lang := range []BodyLanguage{BodyEN, BodyJA} {
		if got := bodyFixtures(t, lang)["compose"]; strings.Contains(got, textFor(lang).SourceNote) {
			t.Errorf("%s: the Compose body has the note", lang)
		}
	}
}

// The note is in the first section, so the cut that removes the end of a long
// body leaves it.
func TestPRBodyNoteSurvivesCut(t *testing.T) {
	for _, lang := range []BodyLanguage{BodyEN, BodyJA} {
		t.Run(string(lang), func(t *testing.T) {
			ev := bodyFixtureEvidence()
			first := ev.Items[0]
			for i := 0; i < 200; i++ {
				ev.Items = append(ev.Items, first)
			}
			body, err := buildDockerfilePRBody(dockerfileBodyInput{
				Repo: testRepo, BaseBranch: "main", BaseSHA: hex40('1'), Path: "build/Dockerfile", Current: "app:2.0",
				Workloads: []string{"container/shop-api"}, Stage: 1, Change: DockerfileChange{Stage: 1, Line: 3, Old: "debian:12.5", New: "debian:12.6"},
				CandidateTag: "12.6", Evidence: ev, UpdateKey: "uk2", AttemptKey: "ak2", Marker: encodeMarker(sampleMarker()),
				Language: lang,
			})
			if err != nil {
				t.Fatal(err)
			}
			tx := textFor(lang)
			if !strings.Contains(body, tx.CutNote) {
				t.Fatalf("the body was not cut (%d bytes)", len(body))
			}
			if !strings.Contains(body, tx.SourceNote) {
				t.Error("the note was cut away")
			}
		})
	}
}

// A container started outside Compose goes through the Dockerfile pull request
// stage like a Compose service: the target key, the update key and the marker
// do not depend on the kind of workload, and the branch shows the name.
func TestPRStageDockerfileContainerWorkload(t *testing.T) {
	run := func(workload string, ref ServiceRef) (PRUnit, string, string) {
		h := newDFPRHarness(t)
		it := dfPlanItem("3.12.5-slim", '5', []string{"CVE-1", "CVE-2"}, []string{"CVE-3"})
		it.Workloads = []string{workload}
		it.Entities[0].Services = []ServiceRef{ref}
		res := h.run(dfPlan(it))
		u := onlyUnit(t, res)
		wantStatus(t, u, PRStatusCreated, "")
		pulls := h.gh.pulls(testRepo)
		if len(pulls) != 1 {
			t.Fatalf("pulls = %d", len(pulls))
		}
		return u, pulls[0].HeadRef, pulls[0].Body
	}
	cu, _, cbody := run("compose/app/svc", ServiceRef{Project: "app", Service: "svc", Container: "app-svc-1"})
	u, head, body := run("container/shop-api", ServiceRef{Container: "shop-api"})

	if !strings.HasPrefix(head, "kestrelynx/dockerfile/shop-api-3.12.5-slim-") {
		t.Errorf("branch = %q", head)
	}
	mc, err := parsePRMarker(cbody)
	if err != nil {
		t.Fatal(err)
	}
	m, err := parsePRMarker(body)
	if err != nil {
		t.Fatal(err)
	}
	if m.Kind != "dockerfile" || m.verify(testRepoID) != nil || !m.branchMatches(head) {
		t.Errorf("marker %+v", m)
	}
	if m.TargetKey != mc.TargetKey || m.UpdateKey != mc.UpdateKey {
		t.Errorf("keys differ from the Compose unit's: target %q / %q, update %q / %q", m.TargetKey, mc.TargetKey, m.UpdateKey, mc.UpdateKey)
	}
	if len(u.FixTargets) != len(cu.FixTargets) || u.CandidateTag != cu.CandidateTag {
		t.Errorf("units differ: %+v / %+v", u, cu)
	}
	if !strings.Contains(body, "`container/shop-api`") || !strings.Contains(body, textFor(BodyEN).SourceNote) {
		t.Errorf("the body lacks the workload or the note:\n%s", body)
	}
	if strings.Contains(cbody, textFor(BodyEN).SourceNote) {
		t.Error("the Compose body has the note")
	}
}
