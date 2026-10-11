package remediation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/kitsunetrail/kestrelynx/internal/github"
)

// languageNotInOpenPR reports whether the unit may go on: no open pull
// request of this tool for the same lockfile fixes something the unit does
// not fix. Such a pull request would be left open next to a new one that
// changes the same file, and the two would conflict, so the new one waits
// until it covers everything the old one does (then it replaces it). A pull
// request changed by someone else or known only by its marker is never
// replaced and does not hold the unit back. ok is false after the unit's
// status was set.
func (r *prRun) languageNotInOpenPR(c *unitCtx) bool {
	mine := map[string]bool{}
	for _, f := range c.u.lang.fixTargets {
		mine[f.key()] = true
	}
	for i := range r.file.PRs {
		old := &r.file.PRs[i]
		if old.RepoID != c.rs.info.ID || old.TargetKey != c.targetKey || old.State != PRStateOpen || old.UpdateKey == c.updateKey ||
			old.UserModified || old.MarkerOnly || len(old.FixTargets) == 0 {
			continue
		}
		missing := 0
		for _, f := range old.FixTargets {
			if !mine[f.key()] {
				missing++
			}
		}
		if missing > 0 {
			c.set(PRStatusDeferred, ReasonOpenPRNotInherited,
				fmt.Sprintf("pull request #%d for %s fixes %d finding(s) this update does not cover; a second pull request for the file would conflict with it", old.Number, c.u.path, missing))
			return false
		}
	}
	return true
}

// languageFiles returns the files the unit's commit changes, built from the
// item's artifacts, and the name of the set of input files the update was made
// from. Before it does, it checks that the artifacts are what the item
// recorded and that the base branch still holds every file the update was
// made from: when the base is not at the commit of the plan, every file the
// plan read must still have its blob, else the update is not written and the
// next cycle makes a new one. ok is false after the unit's status was set.
func (r *prRun) languageFiles(c *unitCtx, base string) (files []editedFile, inputSHA string, ok bool) {
	ld, rs := c.u.lang, c.rs
	var paths []string
	for p := range ld.artifacts {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		a := ld.artifacts[p]
		switch {
		case !github.ValidPath(p, false):
			c.set(PRStatusFailed, ReasonArtifactsUnusable, fmt.Sprintf("%q is not a path inside the repository", p))
			return nil, "", false
		case len(a.Content) == 0:
			c.set(PRStatusDeferred, ReasonArtifactContentMissing, fmt.Sprintf("the content of %s is not held; the next cycle updates again", p))
			return nil, "", false
		case int64(len(a.Content)) != a.Size || hex.EncodeToString(sum256(a.Content)) != a.SHA256:
			c.set(PRStatusFailed, ReasonArtifactsUnusable, fmt.Sprintf("the content of %s is not what the item recorded", p))
			return nil, "", false
		}
		if _, known := ld.sources[p]; !known {
			c.set(PRStatusFailed, ReasonArtifactsUnusable, fmt.Sprintf("%s is not among the files the plan read", p))
			return nil, "", false
		}
	}

	moved := ld.item.Source.CommitSHA == "" || ld.item.Source.CommitSHA != base
	var srcPaths []string
	for p := range ld.sources {
		srcPaths = append(srcPaths, p)
	}
	sort.Strings(srcPaths)
	modes := map[string]string{}
	for _, p := range srcPaths {
		src := ld.sources[p]
		art, isArtifact := ld.artifacts[p]
		if !moved && (!isArtifact || art.Mode != "") {
			continue
		}
		cur, err := r.s.cfg.Source.ReadFile(r.ctx, rs.name, base, p)
		if err != nil {
			var nr *github.NotRegularFileError
			switch {
			case errors.Is(err, github.ErrNotFound):
				c.set(PRStatusDeferred, ReasonSourceChanged, fmt.Sprintf("%s is gone from %s, which moved from %s to %s since the plan", p, c.u.baseBranch, ld.item.Source.CommitSHA, base))
			case errors.As(err, &nr), errors.Is(err, github.ErrLFSPointer), errors.Is(err, github.ErrTooLarge):
				c.set(PRStatusDeferred, ReasonSourceChanged, fmt.Sprintf("%s can no longer be used as the plan read it: %v", p, err))
			default:
				r.readFailure(c, "read "+p, err)
			}
			return nil, "", false
		}
		if cur.SHA != src.BlobSHA {
			c.set(PRStatusDeferred, ReasonSourceChanged, fmt.Sprintf("%s changed since the plan: %s moved from %s to %s", p, c.u.baseBranch, ld.item.Source.CommitSHA, base))
			return nil, "", false
		}
		modes[p] = cur.Mode
	}

	for _, p := range paths {
		a := ld.artifacts[p]
		blob := gitBlobSHA(a.Content)
		if blob == ld.sources[p].BlobSHA {
			continue // unchanged: not part of the commit
		}
		// The mode is the one the base has now. One that differs from the one
		// the update was made against means the file changed since the plan
		// (a content-identical file can have become executable), and writing
		// the old mode back would undo that, so the update waits.
		mode := modes[p]
		if cur, planned := modes[p], a.Mode; cur != "" && planned != "" && cur != planned {
			c.set(PRStatusDeferred, ReasonSourceChanged, fmt.Sprintf("%s has mode %s on %s now, not the %s it had when the update was made", p, cur, c.u.baseBranch, planned))
			return nil, "", false
		}
		if mode == "" {
			mode = a.Mode
		}
		switch mode {
		case "":
			mode = "100644"
		case "100644", "100755":
		default:
			c.set(PRStatusFailed, ReasonArtifactsUnusable, fmt.Sprintf("%s has mode %q, which a commit of this tool does not write", p, mode))
			return nil, "", false
		}
		files = append(files, editedFile{Path: p, Mode: mode, Content: a.Content, BlobSHA: blob})
	}
	if len(files) == 0 {
		c.set(PRStatusFailed, ReasonArtifactsUnusable, "no file of the update differs from the file it replaces")
		return nil, "", false
	}
	var inputs []SourceFile
	for _, p := range srcPaths {
		inputs = append(inputs, ld.sources[p])
	}
	return files, inputSetSHA(inputs), true
}

func sum256(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// DeferLanguageUpdates leaves every dependency update candidate of the plan
// undone with the given reason, for a cycle in which the update stage cannot
// run. It returns how many it deferred. The packages stay as planned.
func DeferLanguageUpdates(plan *Plan, reason Reason, detail string) int {
	n := 0
	for i := range plan.LanguageItems {
		it := &plan.LanguageItems[i]
		if it.Category == CategoryDependencyUpdateCandidate {
			it.Category, it.Reason, it.Detail = CategoryDeferred, reason, detail
			n++
		}
	}
	return n
}

// fileProposal is the record of the pull request of the repository that
// stands for an item with the fingerprint.
func (r *prRun) fileProposal(rs *repoState, it LanguageItem, fingerprint string) *PRRecord {
	return r.file.proposalFor(it, fingerprint, rs.info.ID)
}

// languageViewOfTied is what a tied item shows of its update: the item's
// packages as they run now and the versions the pull request moves them to,
// from its record. The major flag is worked out from those two versions here,
// not taken from what was stored.
func languageViewOfTied(it LanguageItem, rec *PRRecord) *PRLanguage {
	root := it.Source.Directory
	if root == "" {
		root = "."
	}
	v := &PRLanguage{Manager: string(it.Manager), Root: root, Packages: []PRLanguagePackage{}}
	if rec.Lang != nil {
		v.ManifestEdits = rec.Lang.ManifestEdits
	}
	for _, p := range updatedPackages(&it) {
		to := p.SelectionLowerBound
		if rec.Lang != nil {
			for _, e := range rec.Lang.Packages {
				if e.Ecosystem == p.Ecosystem && e.Name == p.matchName() {
					to = e.Adopted
					break
				}
			}
		}
		v.Packages = append(v.Packages, PRLanguagePackage{
			Name: p.Name, Ecosystem: p.Ecosystem, Relation: string(p.Relation), From: p.Installed, To: to,
			Major: majorChanged(p.Installed, to),
		})
	}
	return v
}

// addInputFingerprint writes the fingerprint of this cycle's inputs into the
// record of the pull request the unit's update matched, when the record has
// none: a pull request made before fingerprints existed would otherwise be
// updated again by the dependency stage in every cycle. Only the record is
// changed, never the pull request's description or marker.
//
// A fingerprint a record already has is kept. It names the inputs the pull
// request was made from; when the base has moved since, so that today's
// inputs differ while the update (and so its key) is the same, the older
// fingerprint stays true of the pull request, and replacing it would make the
// record claim inputs the pull request was not made from. The unit is then
// updated again each cycle until the pull request is replaced or merged.
//
// A record rebuilt from a marker is the exception. Its fingerprint came from
// text anyone with push access can write, so it is not kept: when this
// program has run the update itself and the record has the update key it
// computed, the same target key, repository ID and manager, the record gets
// this cycle's fingerprint and the InputVerified mark. From the next cycle it
// stands for the update. MarkerOnly and Recovered keep their meaning.
func (r *prRun) addInputFingerprint(c *unitCtx, rec *PRRecord) {
	u := c.u
	if u.lang == nil || u.lang.record == nil || u.lang.record.InputFingerprint == "" || rec.Lang == nil {
		return
	}
	fp := u.lang.record.InputFingerprint
	untrusted := (rec.MarkerOnly || rec.Recovered) && !rec.InputVerified
	switch {
	case untrusted:
		if rec.RepoID != c.rs.info.ID || rec.TargetKey != c.targetKey || rec.UpdateKey != c.updateKey || rec.Lang.Manager != string(u.lang.manager) {
			return
		}
	case rec.Lang.InputFingerprint != "":
		return
	}
	lang := *rec.Lang // not shared with the attempt it came from
	lang.InputFingerprint = fp
	rec.Lang = &lang
	if untrusted {
		rec.InputVerified = true
	}
	rec.UpdatedAt = r.now()
	r.save()
}
