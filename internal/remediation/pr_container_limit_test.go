package remediation

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// markerOfRunes is a marker line of exactly n runes.
func markerOfRunes(n int) string {
	return markerPrefix + strings.Repeat("a", n-len(markerPrefix)-len(markerSuffix)) + markerSuffix
}

// bodyWithMarker renders a Dockerfile or a language body for the workloads
// with a marker of the given length.
func bodyWithMarker(t *testing.T, kind string, lang BodyLanguage, workloads []string, markerLen int) (string, error) {
	t.Helper()
	marker := markerOfRunes(markerLen)
	if kind == "dockerfile" {
		return buildDockerfilePRBody(dockerfileBodyInput{
			Repo: testRepo, BaseBranch: "main", BaseSHA: hex40('1'), Path: "build/Dockerfile", Current: "app:2.0",
			Workloads: workloads, Stage: 1, Change: DockerfileChange{Stage: 1, Line: 3, Old: "debian:12.5", New: "debian:12.6"},
			CandidateTag: "12.6", Evidence: bodyFixtureEvidence(), UpdateKey: "uk2", AttemptKey: "ak2", Marker: marker, Language: lang,
		})
	}
	in := languageBodyFixture(lang, marker, true)
	in.Workloads = workloads
	return buildLanguagePRBody(in)
}

func longContainerNames(n int) []string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, "container/"+strings.Repeat("n", 240)+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	return out
}

// The note on the source of a container is never cut away: when the marker
// leaves less room than the part of the body up to and including the note, no
// body is made, and when it leaves enough, the cut keeps the note.
func TestPRBodyNoteIsReservedAgainstALargeMarker(t *testing.T) {
	workloads := longContainerNames(50)
	for _, kind := range []string{"dockerfile", "language"} {
		for _, lang := range []BodyLanguage{BodyEN, BodyJA} {
			t.Run(kind+"/"+string(lang), func(t *testing.T) {
				tx := textFor(lang)
				// With a small marker the body is whole; the head is what is up to
				// the note.
				whole, err := bodyWithMarker(t, kind, lang, workloads, 400)
				if err != nil {
					t.Fatal(err)
				}
				head := whole[:strings.Index(whole, tx.SourceNote)+len(tx.SourceNote)]
				keep := utf8.RuneCountInString(head)
				fixed := len("\n\n") + utf8.RuneCountInString(tx.CutNote)

				// Room for exactly the head: the body is cut after the note.
				body, err := bodyWithMarker(t, kind, lang, workloads, maxPRBodyChars-fixed-keep)
				if err != nil {
					t.Fatalf("room for the head: %v", err)
				}
				if !strings.Contains(body, tx.SourceNote) || !strings.Contains(body, tx.CutNote) || utf8.RuneCountInString(body) > maxPRBodyChars {
					t.Errorf("note kept %v, cut note %v, %d runes", strings.Contains(body, tx.SourceNote), strings.Contains(body, tx.CutNote), utf8.RuneCountInString(body))
				}

				// One rune less: no body.
				if body, err := bodyWithMarker(t, kind, lang, workloads, maxPRBodyChars-fixed-keep+1); err != errBodyHeadTooLarge {
					t.Errorf("room one rune short: err %v, body %d runes", err, utf8.RuneCountInString(body))
				}
			})
		}
	}
}

// A body that names no container is cut as before, however small the room.
func TestPRBodyWithoutContainerIsCutAsBefore(t *testing.T) {
	for _, kind := range []string{"dockerfile", "language"} {
		body, err := bodyWithMarker(t, kind, BodyEN, []string{"compose/app/web"}, maxPRBodyChars-600)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if !strings.Contains(body, textFor(BodyEN).CutNote) || utf8.RuneCountInString(body) > maxPRBodyChars {
			t.Errorf("%s: body not cut within the limit", kind)
		}
	}
}
