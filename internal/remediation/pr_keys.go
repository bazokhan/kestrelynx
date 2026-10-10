package remediation

import (
	"crypto/sha1" //nolint:gosec // git object IDs are SHA-1; the hash names content, it does not protect it
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/kitsunetrail/kestrelynx/internal/github"
)

// The keys of the pull request stage are hex SHA-256 digests of canonical
// JSON: struct fields in a fixed order and every set sorted, so the same
// inputs give the same key in any order. They never include times, job IDs
// or retry counts, so a retry or a later cycle computes the same key.
//
//   - The target key names what is edited: repository (by numeric ID, which
//     survives renames), base branch, file and image locations.
//   - The update key adds what the edit is: the running reference and the
//     candidate tag and top digest. One update is proposed at most once.
//   - The attempt key adds the inputs the commit was built from: base
//     commit, the file's blob before the edit and every changed file's blob
//     after it. A new base gives a new attempt of the same update.

// branchPrefix starts every branch this stage creates.
const branchPrefix = "kestrelynx/"

// composeBranchPrefix starts the branches of Compose updates.
const composeBranchPrefix = branchPrefix + "compose/"

// FileChange is one file of a commit: its path, mode and new blob.
type FileChange struct {
	Path    string `json:"path"`
	Mode    string `json:"mode"`
	BlobSHA string `json:"blob_sha"`
}

func hashCanonical(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		// Only strings, integers and slices of them are marshalled.
		panic(fmt.Sprintf("remediation: key: %v", err))
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// TargetKey identifies the image locations of one Compose file.
func TargetKey(repoID int64, baseBranch, path string, locations []string) string {
	return hashCanonical(struct {
		RepoID     int64    `json:"repo_id"`
		BaseBranch string   `json:"base_branch"`
		Kind       string   `json:"kind"`
		Path       string   `json:"path"`
		Locations  []string `json:"locations"`
	}{repoID, baseBranch, "compose", path, sortedCopy(locations)})
}

// UpdateKey identifies one proposed update of a target.
func UpdateKey(targetKey, currentRef, candidateTag, candidateDigest string) string {
	return hashCanonical(struct {
		TargetKey       string `json:"target_key"`
		CurrentRef      string `json:"current_ref"`
		CandidateTag    string `json:"candidate_tag"`
		CandidateDigest string `json:"candidate_digest"`
	}{targetKey, normalizedRef(currentRef), candidateTag, candidateDigest})
}

// AttemptKey identifies the content of one attempt of an update: the commit
// it builds, up to the commit's own metadata. Only paths and blobs of the
// changes take part; the mode is copied from the base.
func AttemptKey(updateKey, baseSHA, inputBlobSHA string, changes []FileChange) string {
	type change struct {
		Path    string `json:"path"`
		BlobSHA string `json:"blob_sha"`
	}
	cs := make([]change, 0, len(changes))
	for _, c := range changes {
		cs = append(cs, change{c.Path, c.BlobSHA})
	}
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Path != cs[j].Path {
			return cs[i].Path < cs[j].Path
		}
		return cs[i].BlobSHA < cs[j].BlobSHA
	})
	return hashCanonical(struct {
		UpdateKey    string   `json:"update_key"`
		BaseSHA      string   `json:"base_sha"`
		InputBlobSHA string   `json:"input_blob_sha"`
		Changes      []change `json:"changes"`
	}{updateKey, baseSHA, inputBlobSHA, cs})
}

// BranchName is the branch of an attempt:
// kestrelynx/compose/<display>-<tag>-<12 hex of the attempt key>. The display
// part is the first service (sorted) plus "-and-N" for N more, reduced to
// lower-case letters, digits and hyphens, and shortened when the whole name
// would be too long; nothing else is ever cut.
func BranchName(services []string, tag, attemptKey string) (string, error) {
	if len(attemptKey) < 12 {
		return "", fmt.Errorf("remediation: attempt key %q is too short", attemptKey)
	}
	ss := sortedCopy(services)
	display := "service"
	if len(ss) > 0 {
		display = ss[0]
		if len(ss) > 1 {
			display += fmt.Sprintf("-and-%d", len(ss)-1)
		}
	}
	display = branchSafe(display)
	if display == "" {
		display = "service"
	}
	// A tag holds only [A-Za-z0-9_.-]; a run of dots is the one thing in it
	// a branch name may not hold.
	for strings.Contains(tag, "..") {
		tag = strings.ReplaceAll(tag, "..", ".")
	}
	suffix := "-" + tag + "-" + attemptKey[:12]
	room := 255 - len(composeBranchPrefix) - len(suffix)
	if room < 1 {
		return "", fmt.Errorf("remediation: tag %q leaves no room for a branch name", tag)
	}
	if len(display) > room {
		display = strings.TrimRight(display[:room], "-")
		if display == "" {
			display = "s"
		}
	}
	name := composeBranchPrefix + display + suffix
	if !github.ValidBranch(name) {
		return "", fmt.Errorf("remediation: %q is not a valid branch name", name)
	}
	return name, nil
}

// branchSafe lower-cases s and turns every run of other characters into one
// hyphen, trimming hyphens at either end.
func branchSafe(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
			continue
		}
		if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.TrimRight(b.String(), "-")
}

// gitBlobSHA is the git object ID of a blob with the given content.
func gitBlobSHA(content []byte) string {
	h := sha1.New() //nolint:gosec // see import
	fmt.Fprintf(h, "blob %d\x00", len(content))
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

// composeUnitTitle is the pull request title and commit message.
func composeUnitTitle(imageRepo, tag, path string) string {
	t := fmt.Sprintf("Update %s to %s in %s", imageRepo, tag, path)
	t = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, t)
	if rs := []rune(t); len(rs) > 250 {
		t = string(rs[:250]) + "..."
	}
	return t
}
