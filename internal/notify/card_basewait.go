package notify

import (
	"path"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// baseWait says that a package finding lives in the base image of a
// Dockerfile-built image and that the fix plan found no newer tag of that base
// to move to, so the fix has to wait for a newer base release.
type baseWait struct {
	Name string // the base image's repository name without registry and path
	Tag  string
}

// baseWaitKey identifies one finding target of one running entity.
type baseWaitKey struct {
	image  string // the running image's reference
	entity string // the running entity's key as the plan records it
	vuln   string
	coord  remediation.PackageCoord
}

// baseWaitEntry is what the plan says about one key: the base it waits on
// and the base layers (diff IDs) its targets were reported in.
type baseWaitEntry struct {
	wait   baseWait
	layers map[string]bool
}

// baseWaitIndex finds, for a package group of a scanned image, whether this
// cycle's plan holds its fixable findings back for a newer base image. The
// nil index matches nothing.
type baseWaitIndex struct {
	byKey map[baseWaitKey][]*baseWaitEntry
}

// newBaseWaitIndex indexes the targets of the Dockerfile items that are
// no_candidate with reason no_newer_tag, one entity at a time (the entity
// must carry the same category and reason, a confirmed entity key and a
// current base to name). It returns nil when there is no plan or nothing to
// index.
func newBaseWaitIndex(info *PlanInfo) *baseWaitIndex {
	if info == nil || info.Plan == nil {
		return nil
	}
	var idx *baseWaitIndex
	for _, it := range info.Plan.DockerfileItems {
		if it.Category != remediation.CategoryNoCandidate || it.Reason != remediation.ReasonNoNewerTag {
			continue
		}
		for _, e := range it.Entities {
			if e.Category != remediation.CategoryNoCandidate || e.Reason != remediation.ReasonNoNewerTag ||
				e.CurrentBase == nil || e.Running.Ref == "" || e.Running.Entity == "" || e.Running.Entity == remediation.Unconfirmed {
				continue
			}
			name, tag := baseNameTag(*e.CurrentBase)
			if name == "" || tag == "" {
				continue
			}
			w := baseWait{Name: name, Tag: tag}
			for _, t := range e.Targets {
				if idx == nil {
					idx = &baseWaitIndex{byKey: map[baseWaitKey][]*baseWaitEntry{}}
				}
				k := baseWaitKey{image: e.Running.Ref, entity: e.Running.Entity, vuln: t.VulnID, coord: t.Package}
				var ent *baseWaitEntry
				for _, x := range idx.byKey[k] {
					if x.wait == w {
						ent = x
					}
				}
				if ent == nil {
					ent = &baseWaitEntry{wait: w, layers: map[string]bool{}}
					idx.byKey[k] = append(idx.byKey[k], ent)
				}
				for _, l := range t.Layers {
					ent.layers[l] = true
				}
			}
		}
	}
	return idx
}

// baseNameTag is the short name and the tag of a base image state: the last
// path element of its repository, so a registry host never shows.
func baseNameTag(s remediation.ImageState) (name, tag string) {
	ref := remediation.ParseImageRef(s.Ref)
	tag = s.Tag
	if tag == "" {
		tag = ref.Tag
	}
	if ref.Repository == "" {
		return "", ""
	}
	return path.Base(strings.TrimSuffix(ref.Repository, "/")), tag
}

// lookup returns the wait of group g of the scanned entity img. It matches
// only when all of these hold, so that in doubt the card stays as it is:
//   - the entity is confirmed and is the one the plan judged (same reference
//     and entity key);
//   - the group has at least one fixed finding, and every fixed finding of it
//     is a target of no-newer-tag entities that name one and the same base;
//   - every layer the group's findings were attributed to is a base layer
//     those targets were reported in, so a copy of the package in a later
//     layer, or one with no layer attribution, never qualifies.
func (x *baseWaitIndex) lookup(img analyze.ImageFindings, g analyze.PackageGroup) (baseWait, bool) {
	if x == nil || img.Image == "" || !img.Subject.Resolved || len(g.LayerDiffIDs) == 0 {
		return baseWait{}, false
	}
	entity := remediation.EntityKeyString(img.Subject.Key)
	if entity == remediation.Unconfirmed {
		return baseWait{}, false
	}
	coord := remediation.PackageCoord{Ecosystem: g.Ecosystem, Class: g.Class, Name: g.Package}
	var found baseWait
	base := map[string]bool{}
	fixed := 0
	for _, v := range g.Vulns {
		if v.Status != scanner.StatusFixed {
			continue
		}
		es := x.byKey[baseWaitKey{image: img.Image, entity: entity, vuln: v.ID, coord: coord}]
		if len(es) != 1 || (fixed > 0 && es[0].wait != found) {
			return baseWait{}, false
		}
		found = es[0].wait
		for l := range es[0].layers {
			base[l] = true
		}
		fixed++
	}
	if fixed == 0 {
		return baseWait{}, false
	}
	for _, l := range g.LayerDiffIDs {
		if l == "" || !base[l] {
			return baseWait{}, false
		}
	}
	return found, true
}
