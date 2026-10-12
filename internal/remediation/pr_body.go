package remediation

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// maxPRBodyChars keeps the body under GitHub's limit with room to spare.
	maxPRBodyChars = 60000
	// maxListedVulns caps each vulnerability list of the body.
	maxListedVulns = 30
	// maxListedNames caps the lists of services and workloads.
	maxListedNames = 50
	// maxCodeChars caps one external string.
	maxCodeChars = 300
)

var errMarkerTooLarge = errors.New("the marker does not fit in a pull request body")

// prBodyInput is what a pull request body describes.
type prBodyInput struct {
	Repo, BaseBranch, BaseSHA, Path string
	Current                         string // the running reference
	Services, Locations, Workloads  []string
	AlsoRunning                     []ServiceRef
	Changes                         []ComposeChange
	CandidateTag                    string
	Evidence                        *VerificationSummary
	UpdateKey, AttemptKey           string
	Marker                          string
	Language                        BodyLanguage
}

// mdCode renders an external string as inline code: backticks become
// apostrophes and control characters spaces, so the string can neither end
// the code span nor start a line, and nothing in it is read as Markdown, a
// mention, a link or HTML. It is shortened to a bounded length.
func mdCode(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '`':
			return '\''
		case unicode.IsControl(r) || r == utf8.RuneError || r == ' ' || r == ' ':
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if rs := []rune(s); len(rs) > maxCodeChars {
		s = string(rs[:maxCodeChars]) + "..."
	}
	if s == "" {
		return "(empty)"
	}
	return "`" + s + "`"
}

func codeList(items []string, max int) string { return codeListIn(&enPRText, items, max) }

func codeListIn(t *prText, items []string, max int) string {
	shown := items
	if len(shown) > max {
		shown = shown[:max]
	}
	parts := make([]string, 0, len(shown))
	for _, s := range shown {
		parts = append(parts, mdCode(s))
	}
	out := strings.Join(parts, t.ListSep)
	if n := len(items) - len(shown); n > 0 {
		out += fmt.Sprintf(t.ListMore, n)
	}
	return out
}

func writeVulnList(b *strings.Builder, title string, vs []VulnSummary) {
	writeVulnListIn(&enPRText, b, title, vs)
}

func writeVulnListIn(t *prText, b *strings.Builder, title string, vs []VulnSummary) {
	fmt.Fprintf(b, t.ListTitle, title, len(vs))
	if len(vs) == 0 {
		b.WriteString(t.None)
		return
	}
	for i, v := range vs {
		if i == maxListedVulns {
			fmt.Fprintf(b, t.LineMore, len(vs)-maxListedVulns)
			break
		}
		fmt.Fprintf(b, t.VulnLine, mdCode(v.VulnID), mdCode(v.Package.Name), mdCode(string(v.Package.Ecosystem)), mdCode(string(v.Package.Class)))
		if v.Severity != "" {
			fmt.Fprintf(b, t.VulnSeverity, mdCode(v.Severity))
		}
		if v.KEV {
			b.WriteString(t.VulnKEV)
		}
		if v.Priority != PriorityNone {
			fmt.Fprintf(b, t.VulnPriority, mdCode(string(v.Priority)))
		}
		b.WriteString("\n")
	}
}

// buildPRBody renders the pull request body. The text is cut, at a line
// boundary, when it would pass the length limit; the marker line is always
// complete and always last.
func buildPRBody(in prBodyInput) (string, error) {
	t := textFor(in.Language)
	var b strings.Builder
	b.WriteString("## " + t.HeadWhat + "\n\n")
	fmt.Fprintf(&b, t.CWhat,
		len(in.Services), mdCode(in.Path), mdCode(in.Repo), mdCode(in.BaseBranch), mdCode(in.BaseSHA))
	fmt.Fprintf(&b, t.CRunning, mdCode(in.Current))
	fmt.Fprintf(&b, t.CServices, codeListIn(t, in.Services, maxListedNames))
	fmt.Fprintf(&b, t.CWorkloads, codeListIn(t, in.Workloads, maxListedNames))
	if len(in.AlsoRunning) > 0 {
		var names []string
		for _, s := range in.AlsoRunning {
			n := s.Container
			if s.Project != "" {
				n = s.Project + "/" + s.Service
				if s.Container != "" {
					n += " (" + s.Container + ")"
				}
			}
			names = append(names, n)
		}
		fmt.Fprintf(&b, t.CAlso, codeListIn(t, names, maxListedNames))
	}

	b.WriteString("\n## " + t.HeadChange + "\n\n")
	for _, c := range in.Changes {
		fmt.Fprintf(&b, t.CChange, mdCode(c.Location), mdCode(c.Old), mdCode(c.New))
	}

	b.WriteString("\n## " + t.HeadVerification + "\n")
	if ev := in.Evidence; ev != nil {
		for _, it := range ev.Items {
			b.WriteString("\n")
			fmt.Fprintf(&b, t.CVerRunning, mdCode(it.Current.Ref))
			if it.Current.ConfigDigest != "" {
				fmt.Fprintf(&b, t.ConfigDigest, mdCode(it.Current.ConfigDigest))
			}
			if it.Current.Platform != "" {
				fmt.Fprintf(&b, t.PlatformPart, mdCode(it.Current.Platform))
			}
			b.WriteString("\n")
			if it.Current.DigestKindUnverified {
				b.WriteString(t.DigestNote)
			}
			fmt.Fprintf(&b, t.CCandidate,
				mdCode(it.Candidate.Ref), mdCode(it.Candidate.TopDigest), mdCode(it.Candidate.ManifestDigest), mdCode(it.Candidate.ConfigDigest), mdCode(it.Candidate.Platform))
			fmt.Fprintf(&b, t.Locations, codeListIn(t, it.Locations, maxListedNames))
			fmt.Fprintf(&b, t.VerRecord,
				ev.PlanGeneratedAt.UTC().Format(time.RFC3339), mdCode(it.BaselineScan), mdCode(it.CandidateScan))
			fmt.Fprintf(&b, t.Counts, len(it.Resolved), len(it.Remaining), len(it.Introduced))
			writeVulnListIn(t, &b, t.TitleResolved, it.Resolved)
			writeVulnListIn(t, &b, t.TitleRemaining, it.Remaining)
			writeVulnListIn(t, &b, t.TitleIntroduced, it.Introduced)
		}
		b.WriteString("\n")
		fmt.Fprintf(&b, t.CScanned, mdCode(ev.TrivyVersion))
		if ev.VulnDBUpdatedAt != nil {
			fmt.Fprintf(&b, t.DBBuilt, ev.VulnDBUpdatedAt.UTC().Format(time.RFC3339))
		}
		fmt.Fprintf(&b, t.SeverityEnd, codeListIn(t, ev.Severities, 10))
		if ev.Scope != "" {
			fmt.Fprintf(&b, t.ScopeEnd, mdCode(ev.Scope))
		}
		b.WriteString("\n")
	}

	return assembleBodyText(b.String(), in.Marker, t.CutNote)
}

// assembleBody appends the marker to text, cutting text first if needed.
func assembleBody(text, marker string) (string, error) {
	return assembleBodyText(text, marker, enPRText.CutNote)
}

// assembleBodyText is assembleBody with the note that tells the text was cut.
func assembleBodyText(text, marker, cutNote string) (string, error) {
	markerLen := utf8.RuneCountInString(marker)
	if markerLen+len("\n\n")+utf8.RuneCountInString(cutNote) > maxPRBodyChars {
		return "", errMarkerTooLarge
	}
	if utf8.RuneCountInString(text)+len("\n")+markerLen <= maxPRBodyChars {
		return text + "\n" + marker, nil
	}
	room := maxPRBodyChars - markerLen - len("\n\n") - utf8.RuneCountInString(cutNote)
	rs := []rune(text)
	cut := string(rs[:room])
	if i := strings.LastIndexByte(cut, '\n'); i > 0 {
		cut = cut[:i+1]
	}
	return cut + cutNote + "\n" + marker, nil
}
