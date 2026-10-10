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
}

// buildDockerfilePRBody renders the body of a base image pull request. It
// keeps three images apart — the running image, the current base and the
// candidate base — and says that the comparison is of the two bases and that
// the image rebuilt from the new Dockerfile was not verified. The text is cut
// like buildPRBody's and ends with the marker.
func buildDockerfilePRBody(in dockerfileBodyInput) (string, error) {
	var b strings.Builder
	b.WriteString("## What\n\n")
	fmt.Fprintf(&b, "KestreLynx proposes a newer tag for the base image of %s in %s, against base branch %s at commit %s.\n\n",
		mdCode(in.Path), mdCode(in.Repo), mdCode(in.BaseBranch), mdCode(in.BaseSHA))
	fmt.Fprintf(&b, "- Base image now: %s\n", mdCode(in.Current))
	fmt.Fprintf(&b, "- Edited: the FROM of stage %d, line %d\n", in.Stage, in.Change.Line)
	fmt.Fprintf(&b, "- Workloads built from it: %s\n", codeList(in.Workloads, maxListedNames))

	b.WriteString("\n## Change\n\n")
	fmt.Fprintf(&b, "- FROM on line %d: %s to %s\n", in.Change.Line, mdCode(in.Change.Old), mdCode(in.Change.New))

	b.WriteString("\n## Why this candidate\n\n")
	fmt.Fprintf(&b, "%s is the newest patch release in the complete tag listing that keeps the current tag's major and minor version, prefix and suffix.\n",
		mdCode(in.CandidateTag))

	b.WriteString("\n## Verification\n\n")
	b.WriteString("Three images are involved and are kept apart below: the running image, which supplies the findings and the layers they were found in; the current base image, the content of the tag the FROM names today; and the candidate base image. ")
	b.WriteString("The comparison is of the current base image with the candidate base image, on the findings the running image has in the base image's layers. ")
	b.WriteString("The image rebuilt from the new Dockerfile was not built or scanned.\n")
	if ev := in.Evidence; ev != nil {
		for _, it := range ev.Items {
			b.WriteString("\n")
			fmt.Fprintf(&b, "- Running image: %s", mdCode(it.Current.Ref))
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
			if cb := it.CurrentBase; cb != nil {
				fmt.Fprintf(&b, "- Current base image: %s, tag digest %s, platform manifest %s, config digest %s, platform %s\n",
					mdCode(cb.Ref), mdCode(cb.TopDigest), mdCode(cb.ManifestDigest), mdCode(cb.ConfigDigest), mdCode(cb.Platform))
			}
			fmt.Fprintf(&b, "- Candidate base image: %s, tag digest %s, platform manifest %s, config digest %s, platform %s\n",
				mdCode(it.Candidate.Ref), mdCode(it.Candidate.TopDigest), mdCode(it.Candidate.ManifestDigest), mdCode(it.Candidate.ConfigDigest), mdCode(it.Candidate.Platform))
			if l := it.Layers; l != nil {
				fmt.Fprintf(&b, "- Layer check: %s; the current base image has %d layer(s) and the running image %d. A match shows that the filesystem layers agree; it does not show how the image was built.\n",
					mdCode(l.Status), l.BaseLayers, l.ImageLayers)
			}
			fmt.Fprintf(&b, "- Verification record: plan generated at %s, scan of the current base %s, scan of the candidate base %s\n",
				ev.PlanGeneratedAt.UTC().Format(time.RFC3339), mdCode(it.BaselineScan), mdCode(it.CandidateScan))
			fmt.Fprintf(&b, "- Findings this update targets (fixed findings of the running image in the base image's layers): resolved %d, remaining %d\n", len(it.Resolved), len(it.Remaining))
			fmt.Fprintf(&b, "- Other findings of the compared base images that remain in the candidate base image: %d; introduced by the candidate base image: %d\n", len(it.OtherRemaining), len(it.Introduced))
			writeVulnList(&b, "Resolved", it.Resolved)
			writeVulnList(&b, "Remaining among the targeted findings", it.Remaining)
			writeVulnList(&b, "Other findings that remain in the candidate base image", it.OtherRemaining)
			writeVulnList(&b, "Introduced", it.Introduced)
		}
		b.WriteString("\n")
		fmt.Fprintf(&b, "Both base images were scanned by Trivy %s", mdCode(ev.TrivyVersion))
		if ev.VulnDBUpdatedAt != nil {
			fmt.Fprintf(&b, " with the vulnerability database built at %s", ev.VulnDBUpdatedAt.UTC().Format(time.RFC3339))
		}
		fmt.Fprintf(&b, ". Severity range: %s.", codeList(ev.Severities, 10))
		if ev.Scope != "" {
			fmt.Fprintf(&b, " Scope: %s.", mdCode(ev.Scope))
		}
		b.WriteString("\n")
	}
	b.WriteString("\nTrivy attributes a package to the lowest layer that holds that name and version, so a package installed again by a later instruction of the Dockerfile can still be attributed to a base image layer. A finding listed above is therefore matched to the base image, not proven to come from it.\n")

	b.WriteString("\n## Not verified\n\n")
	b.WriteString("- The image rebuilt from this Dockerfile: it is not built or scanned, and instructions after the FROM can change which findings it has\n")
	b.WriteString("- Whether the application works with the new base image\n")
	b.WriteString("- Continuous integration; opening this pull request may start the repository's CI\n")
	b.WriteString("- Deployment after merge: merging changes the file only, and running containers keep the old image until it is built again and they are recreated\n")
	b.WriteString("- Vulnerabilities of severities outside the range above\n")

	b.WriteString("\n---\n\n")
	fmt.Fprintf(&b, "Opened by KestreLynx. Update key %s, attempt key %s.\n", mdCode(in.UpdateKey), mdCode(in.AttemptKey))

	return assembleBody(b.String(), in.Marker)
}
