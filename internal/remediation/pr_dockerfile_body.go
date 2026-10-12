package remediation

import (
	"fmt"
	"strings"
	"time"
)

// dockerfileBodyInput is what the body of a base image pull request
// describes.
type dockerfileBodyInput struct {
	Repo, BaseBranch, BaseSHA, Path string
	Current                         string // the base image the FROM names today
	Workloads                       []string
	Stage                           int
	Change                          DockerfileChange
	CandidateTag                    string
	Evidence                        *VerificationSummary
	UpdateKey, AttemptKey           string
	Marker                          string
	Language                        BodyLanguage
}

// buildDockerfilePRBody renders the body of a base image pull request. It
// keeps three images apart — the running image, the current base and the
// candidate base — and says that the comparison is of the two bases and that
// the image rebuilt from the new Dockerfile was not verified. The text is cut
// like buildPRBody's and ends with the marker.
func buildDockerfilePRBody(in dockerfileBodyInput) (string, error) {
	t := textFor(in.Language)
	var b strings.Builder
	b.WriteString("## " + t.HeadWhat + "\n\n")
	fmt.Fprintf(&b, t.DWhat, mdCode(in.Path), mdCode(in.Repo), mdCode(in.BaseBranch), mdCode(in.BaseSHA))
	fmt.Fprintf(&b, t.DBaseNow, mdCode(in.Current))
	fmt.Fprintf(&b, t.DEdited, in.Stage, in.Change.Line)
	fmt.Fprintf(&b, t.DWorkloads, codeListIn(t, in.Workloads, maxListedNames))

	b.WriteString("\n## " + t.HeadChange + "\n\n")
	fmt.Fprintf(&b, t.DChange, in.Change.Line, mdCode(in.Change.Old), mdCode(in.Change.New))

	b.WriteString("\n## " + t.HeadWhyCandidate + "\n\n")
	fmt.Fprintf(&b, t.DWhy, mdCode(in.CandidateTag))

	b.WriteString("\n## " + t.HeadVerification + "\n\n")
	b.WriteString(t.DIntro1)
	b.WriteString(t.DIntro2)
	b.WriteString(t.DIntro3)
	if ev := in.Evidence; ev != nil {
		for _, it := range ev.Items {
			b.WriteString("\n")
			fmt.Fprintf(&b, t.DRunning, mdCode(it.Current.Ref))
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
			if cb := it.CurrentBase; cb != nil {
				fmt.Fprintf(&b, t.DCurrentBase,
					mdCode(cb.Ref), mdCode(cb.TopDigest), mdCode(cb.ManifestDigest), mdCode(cb.ConfigDigest), mdCode(cb.Platform))
			}
			fmt.Fprintf(&b, t.DCandidateBase,
				mdCode(it.Candidate.Ref), mdCode(it.Candidate.TopDigest), mdCode(it.Candidate.ManifestDigest), mdCode(it.Candidate.ConfigDigest), mdCode(it.Candidate.Platform))
			if l := it.Layers; l != nil {
				fmt.Fprintf(&b, t.DLayer, mdCode(l.Status), l.BaseLayers, l.ImageLayers)
			}
			fmt.Fprintf(&b, t.DVerRec,
				ev.PlanGeneratedAt.UTC().Format(time.RFC3339), mdCode(it.BaselineScan), mdCode(it.CandidateScan))
			fmt.Fprintf(&b, t.DTargets, len(it.Resolved), len(it.Remaining))
			fmt.Fprintf(&b, t.DOther, len(it.OtherRemaining), len(it.Introduced))
			writeVulnListIn(t, &b, t.TitleResolved, it.Resolved)
			writeVulnListIn(t, &b, t.TitleRemainingTargeted, it.Remaining)
			writeVulnListIn(t, &b, t.TitleOtherRemaining, it.OtherRemaining)
			writeVulnListIn(t, &b, t.TitleIntroduced, it.Introduced)
		}
		b.WriteString("\n")
		fmt.Fprintf(&b, t.DScanned, mdCode(ev.TrivyVersion))
		if ev.VulnDBUpdatedAt != nil {
			fmt.Fprintf(&b, t.DBBuilt, ev.VulnDBUpdatedAt.UTC().Format(time.RFC3339))
		}
		fmt.Fprintf(&b, t.SeverityEnd, codeListIn(t, ev.Severities, 10))
		if ev.Scope != "" {
			fmt.Fprintf(&b, t.ScopeEnd, mdCode(ev.Scope))
		}
		b.WriteString("\n")
	}
	b.WriteString(t.DAttribution)

	b.WriteString("\n## " + t.HeadNotVerified + "\n\n")
	b.WriteString(t.DNVRebuilt)
	b.WriteString(t.DNVApp)
	b.WriteString(t.NVCI)
	b.WriteString(t.DNVDeploy)
	b.WriteString(t.NVSeverity)

	b.WriteString("\n---\n\n")
	fmt.Fprintf(&b, t.Footer, mdCode(in.UpdateKey), mdCode(in.AttemptKey))

	return assembleBodyText(b.String(), in.Marker, t.CutNote)
}
