package remediation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/github"
)

// A pull request body ends with one marker line, an HTML comment holding one
// line of JSON with everything needed to recompute the pull request's keys.
// It is how records are rebuilt from GitHub when the record file is lost and
// how an open pull request that is not in the records is recognized. A
// supersede comment carries its own, smaller marker.
const (
	markerPrefix = "<!-- kestrelynx:"
	markerSuffix = " -->"
	markerV      = 1
)

var (
	errMarkerMissing  = errors.New("the body has no kestrelynx marker")
	errMarkerMismatch = errors.New("the marker's keys do not recompute from its inputs")
)

// PRMarker is the marker of a pull request body.
type PRMarker struct {
	V               int          `json:"v"`
	RepoID          int64        `json:"repo_id"`
	BaseBranch      string       `json:"base_branch"`
	Path            string       `json:"path"`
	Locations       []string     `json:"locations"`
	CurrentRef      string       `json:"current_ref"`
	CandidateTag    string       `json:"candidate_tag"`
	CandidateDigest string       `json:"candidate_digest"`
	BaseSHA         string       `json:"base_sha"`
	HeadSHA         string       `json:"head_sha"`
	InputBlobSHA    string       `json:"input_blob_sha"`
	Changes         []FileChange `json:"changes"`
	TargetKey       string       `json:"target_key"`
	UpdateKey       string       `json:"update_key"`
	AttemptKey      string       `json:"attempt_key"`
	FixTargets      []FixTarget  `json:"fix_targets"`
}

// supersedeMarker is the marker of a supersede comment.
type supersedeMarker struct {
	V            int    `json:"v"`
	SupersededBy int    `json:"superseded_by"`
	UpdateKey    string `json:"update_key"`
}

// encodeMarker renders v as a marker line. encoding/json escapes <, > and &,
// so the JSON can never end the HTML comment early.
func encodeMarker(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("remediation: marker: %v", err))
	}
	return markerPrefix + string(data) + markerSuffix
}

// markerLines returns the JSON of every marker line in body.
func markerLines(body string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, markerPrefix) && strings.HasSuffix(line, markerSuffix) && len(line) >= len(markerPrefix)+len(markerSuffix) {
			out = append(out, line[len(markerPrefix):len(line)-len(markerSuffix)])
		}
	}
	return out
}

// strictDecode decodes exactly one JSON object with no unknown fields.
func strictDecode(data string, v any) error {
	dec := json.NewDecoder(strings.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the marker object")
	}
	return nil
}

// isSupersedeJSON reports whether a marker's JSON is a supersede marker.
func isSupersedeJSON(data string) bool {
	var probe map[string]json.RawMessage
	if json.Unmarshal([]byte(data), &probe) != nil {
		return false
	}
	_, ok := probe["superseded_by"]
	return ok
}

// parsePRMarker reads the one pull request marker of a body. A body without
// one is errMarkerMissing; more than one, malformed JSON, unknown fields, an
// unknown version or a missing or malformed field is an error.
func parsePRMarker(body string) (PRMarker, error) {
	var found []string
	for _, l := range markerLines(body) {
		if !isSupersedeJSON(l) {
			found = append(found, l)
		}
	}
	switch len(found) {
	case 0:
		return PRMarker{}, errMarkerMissing
	case 1:
	default:
		return PRMarker{}, fmt.Errorf("the body has %d kestrelynx markers", len(found))
	}
	var m PRMarker
	if err := strictDecode(found[0], &m); err != nil {
		return PRMarker{}, fmt.Errorf("the marker is malformed: %v", err)
	}
	if m.V != markerV {
		return PRMarker{}, fmt.Errorf("the marker has version %d, this build reads %d", m.V, markerV)
	}
	if err := m.wellFormed(); err != nil {
		return PRMarker{}, fmt.Errorf("the marker is malformed: %v", err)
	}
	return m, nil
}

func (m PRMarker) wellFormed() error {
	switch {
	case m.RepoID <= 0:
		return errors.New("no repository ID")
	case !github.ValidBranch(m.BaseBranch):
		return errors.New("invalid base branch")
	case !github.ValidPath(m.Path, false):
		return errors.New("invalid path")
	case len(m.Locations) == 0:
		return errors.New("no locations")
	case m.CurrentRef == "" || m.CandidateTag == "" || m.CandidateDigest == "":
		return errors.New("no reference, candidate tag or digest")
	case !isSHA(m.BaseSHA) || !isSHA(m.HeadSHA) || !isSHA(m.InputBlobSHA):
		return errors.New("a commit or blob SHA is malformed")
	case len(m.Changes) == 0:
		return errors.New("no changes")
	case m.TargetKey == "" || m.UpdateKey == "" || m.AttemptKey == "":
		return errors.New("a key is missing")
	}
	for _, c := range m.Changes {
		if !github.ValidPath(c.Path, false) || !isSHA(c.BlobSHA) || (c.Mode != "100644" && c.Mode != "100755") {
			return errors.New("a change is malformed")
		}
	}
	return nil
}

// verify recomputes the keys from the marker's inputs and checks that the
// marker belongs to the repository.
func (m PRMarker) verify(repoID int64) error {
	if m.RepoID != repoID {
		return fmt.Errorf("the marker names repository ID %d, the repository is %d", m.RepoID, repoID)
	}
	tk := TargetKey(m.RepoID, m.BaseBranch, m.Path, m.Locations)
	uk := UpdateKey(tk, m.CurrentRef, m.CandidateTag, m.CandidateDigest)
	ak := AttemptKey(uk, m.BaseSHA, m.InputBlobSHA, m.Changes)
	if tk != m.TargetKey || uk != m.UpdateKey || ak != m.AttemptKey {
		return errMarkerMismatch
	}
	return nil
}

// branchMatches reports whether a head ref is a branch of the marker's
// attempt: a Compose branch ending in the attempt key's 12 hex digits.
func (m PRMarker) branchMatches(ref string) bool {
	return len(m.AttemptKey) >= 12 && strings.HasPrefix(ref, composeBranchPrefix) && strings.HasSuffix(ref, "-"+m.AttemptKey[:12])
}

// supersedeComment is the comment posted on a pull request being replaced.
func supersedeComment(newNumber int, newURL, updateKey string) string {
	return fmt.Sprintf("Superseded by #%d (%s)\n\n%s", newNumber, newURL,
		encodeMarker(supersedeMarker{V: markerV, SupersededBy: newNumber, UpdateKey: updateKey}))
}

// hasSupersedeMarker reports whether a comment body carries the supersede
// marker for the given new pull request and update.
func hasSupersedeMarker(body string, newNumber int, updateKey string) bool {
	for _, l := range markerLines(body) {
		var m supersedeMarker
		if strictDecode(l, &m) == nil && m.V == markerV && m.SupersededBy == newNumber && m.UpdateKey == updateKey {
			return true
		}
	}
	return false
}

// supersededByIn returns the pull request number named by any supersede
// marker in body, 0 when there is none.
func supersededByIn(body string) int {
	for _, l := range markerLines(body) {
		var m supersedeMarker
		if strictDecode(l, &m) == nil && m.V == markerV && m.SupersededBy > 0 {
			return m.SupersededBy
		}
	}
	return 0
}

func isSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	return bytes.IndexFunc([]byte(s), func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') }) < 0
}
