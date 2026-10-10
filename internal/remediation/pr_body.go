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

func codeList(items []string, max int) string {
	shown := items
	if len(shown) > max {
		shown = shown[:max]
	}
	parts := make([]string, 0, len(shown))
	for _, s := range shown {
		parts = append(parts, mdCode(s))
	}
	out := strings.Join(parts, ", ")
	if n := len(items) - len(shown); n > 0 {
		out += fmt.Sprintf(" and %d more", n)
	}
	return out
}

func writeVulnList(b *strings.Builder, title string, vs []VulnSummary) {
	fmt.Fprintf(b, "\n**%s (%d)**\n\n", title, len(vs))
	if len(vs) == 0 {
		b.WriteString("- none\n")
		return
	}
	for i, v := range vs {
		if i == maxListedVulns {
			fmt.Fprintf(b, "- and %d more\n", len(vs)-maxListedVulns)
			break
		}
		fmt.Fprintf(b, "- %s in %s (%s, %s)", mdCode(v.VulnID), mdCode(v.Package.Name), mdCode(string(v.Package.Ecosystem)), mdCode(string(v.Package.Class)))
		if v.Severity != "" {
			fmt.Fprintf(b, ", severity %s", mdCode(v.Severity))
		}
		if v.KEV {
			b.WriteString(", in the CISA KEV catalog")
		}
		if v.Priority != PriorityNone {
			fmt.Fprintf(b, ", priority %s", mdCode(string(v.Priority)))
		}
		b.WriteString("\n")
	}
}

// buildPRBody renders the pull request body. The text is cut, at a line
// boundary, when it would pass the length limit; the marker line is always
// complete and always last.
func buildPRBody(in prBodyInput) (string, error) {
	var b strings.Builder
	b.WriteString("## What\n\n")
	fmt.Fprintf(&b, "KestreLynx proposes a new image tag for %d Compose service(s) in %s of %s, against base branch %s at commit %s.\n\n",
		len(in.Services), mdCode(in.Path), mdCode(in.Repo), mdCode(in.BaseBranch), mdCode(in.BaseSHA))
	fmt.Fprintf(&b, "- Running image: %s\n", mdCode(in.Current))
	fmt.Fprintf(&b, "- Services edited: %s\n", codeList(in.Services, maxListedNames))
	fmt.Fprintf(&b, "- Workloads running them: %s\n", codeList(in.Workloads, maxListedNames))
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
		fmt.Fprintf(&b, "- Also running this image, not edited (no Compose mapping): %s\n", codeList(names, maxListedNames))
	}

	b.WriteString("\n## Change\n\n")
	for _, c := range in.Changes {
		fmt.Fprintf(&b, "- %s: %s to %s\n", mdCode(c.Location), mdCode(c.Old), mdCode(c.New))
	}

	b.WriteString("\n## Why this candidate\n\n")
	fmt.Fprintf(&b, "%s is the newest patch release in the complete tag listing that keeps the running tag's major and minor version, prefix and suffix.\n",
		mdCode(in.CandidateTag))

	b.WriteString("\n## Verification\n")
	if ev := in.Evidence; ev != nil {
		for _, it := range ev.Items {
			b.WriteString("\n")
			fmt.Fprintf(&b, "- Running: %s", mdCode(it.Current.Ref))
			if it.Current.ConfigDigest != "" {
				fmt.Fprintf(&b, ", config digest %s", mdCode(it.Current.ConfigDigest))
			}
			if it.Current.Platform != "" {
				fmt.Fprintf(&b, ", platform %s", mdCode(it.Current.Platform))
			}
			b.WriteString("\n")
			if it.Current.DigestKindUnverified {
				b.WriteString("  - The running digest comes from the container runtime; whether it is the image config digest or an index or manifest digest is not confirmed.\n")
			}
			fmt.Fprintf(&b, "- Candidate: %s, tag digest %s, platform manifest %s, config digest %s, platform %s\n",
				mdCode(it.Candidate.Ref), mdCode(it.Candidate.TopDigest), mdCode(it.Candidate.ManifestDigest), mdCode(it.Candidate.ConfigDigest), mdCode(it.Candidate.Platform))
			fmt.Fprintf(&b, "- Locations: %s\n", codeList(it.Locations, maxListedNames))
			fmt.Fprintf(&b, "- Verification record: plan generated at %s, baseline scan %s, candidate scan %s\n",
				ev.PlanGeneratedAt.UTC().Format(time.RFC3339), mdCode(it.BaselineScan), mdCode(it.CandidateScan))
			fmt.Fprintf(&b, "- Resolved %d, remaining %d, introduced %d\n", len(it.Resolved), len(it.Remaining), len(it.Introduced))
			writeVulnList(&b, "Resolved", it.Resolved)
			writeVulnList(&b, "Remaining", it.Remaining)
			writeVulnList(&b, "Introduced", it.Introduced)
		}
		b.WriteString("\n")
		fmt.Fprintf(&b, "Both images were scanned by Trivy %s", mdCode(ev.TrivyVersion))
		if ev.VulnDBUpdatedAt != nil {
			fmt.Fprintf(&b, " with the vulnerability database built at %s", ev.VulnDBUpdatedAt.UTC().Format(time.RFC3339))
		}
		fmt.Fprintf(&b, ". Severity range: %s.", codeList(ev.Severities, 10))
		if ev.Scope != "" {
			fmt.Fprintf(&b, " Scope: %s.", mdCode(ev.Scope))
		}
		b.WriteString("\n")
	}

	b.WriteString("\n## Not verified\n\n")
	b.WriteString("- Whether the application works with the new image\n")
	b.WriteString("- Continuous integration; opening this pull request may start the repository's CI\n")
	b.WriteString("- Deployment after merge: merging changes the file only, and running containers keep the old image until they are recreated\n")
	b.WriteString("- Vulnerabilities of severities outside the range above\n")

	b.WriteString("\n---\n\n")
	fmt.Fprintf(&b, "Opened by KestreLynx. Update key %s, attempt key %s.\n", mdCode(in.UpdateKey), mdCode(in.AttemptKey))

	return assembleBody(b.String(), in.Marker)
}

// assembleBody appends the marker to text, cutting text first if needed.
func assembleBody(text, marker string) (string, error) {
	const cutNote = "\n_The rest of this description was cut to fit the length limit._\n"
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
