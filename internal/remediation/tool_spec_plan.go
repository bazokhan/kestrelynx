package remediation

import (
	"errors"
	"path"

	"github.com/kitsunetrail/kestrelynx/internal/github"
)

// planToolSpec reads the files that declare which runtime and tool versions
// a unit wants and settles them with ResolveToolSpec. A file that exists is
// read, so its blob is part of the item's inputs; one that does not is
// recorded as absent, because adding it later changes what the update is made
// from. It returns false when the item has been given its outcome (manual,
// deferred or failed).
func (r *run) planToolSpec(it *LanguageItem, u *depUnit, groups []*findingGroup, entries []github.Entry, pair dependencyPair, manifest, lock []byte, sha string, read func(name string) ([]byte, bool)) bool {
	if pair.manager == ManagerPip {
		return true
	}
	in := ToolSpecInput{Manager: pair.manager, Manifest: manifest, Lock: lock, Files: map[string][]byte{}, Now: r.p.cfg.Now()}
	for _, name := range ToolSpecFileNames(pair.manager) {
		e, present := byName(entries, name)
		if !present {
			it.Source.Absent = append(it.Source.Absent, pathIn(u.dir, name))
			continue
		}
		if e.Type != github.EntryFile {
			unitManual(it, groups, ReasonDependencyFileUnusable, name+" is a "+string(e.Type))
			return false
		}
		content, ok := read(name)
		if !ok {
			return false
		}
		in.Files[name] = content
	}
	if pair.manager == ManagerUv {
		found, ok := r.uvTomlFiles(it, groups, u, entries, sha)
		if !ok {
			return false
		}
		in.UvToml = found
	}
	// A project that wants only a runtime past the end of its support is told
	// so, with the date, as an update would be.
	if spec, eol := declaredRuntimeEOL(in, in.Now); eol {
		unitManual(it, groups, ReasonRuntimeEndOfLife, RuntimeEndOfLifeText(spec))
		it.RuntimeEOL = runtimeEOLInfo(spec)
		return false
	}
	if _, uerr := ResolveToolSpec(in); uerr != nil {
		unitManual(it, groups, uerr.Reason, uerr.Detail)
		return false
	}
	return true
}

// uvTomlFiles looks for a uv.toml in the directory of the lockfile and in each
// directory above it up to the root of the repository, because uv reads the
// nearest one. It returns the paths of those that exist. The directories
// without one are recorded on the item as places the file was looked for and
// not found. ok is false when a listing failed and the item has been given its
// outcome.
func (r *run) uvTomlFiles(it *LanguageItem, groups []*findingGroup, u *depUnit, entries []github.Entry, sha string) (found []string, ok bool) {
	if _, present := byName(entries, uvTomlFileName); present {
		found = append(found, pathIn(u.dir, uvTomlFileName))
	} else {
		it.Source.Absent = append(it.Source.Absent, pathIn(u.dir, uvTomlFileName))
	}
	for dir := u.dir; dir != "." && dir != ""; {
		parent := path.Dir(dir)
		if parent == "" || parent == "/" {
			parent = "."
		}
		dir = parent
		if h := r.stopReason(); h != nil {
			r.deferUnit(it, groups, h.reason, h.detail)
			return nil, false
		}
		listing, err := r.p.cfg.GitHub.ListDirectory(r.ctx, u.repo, sha, dir)
		switch {
		case errors.Is(err, github.ErrNotFound):
			listing = nil
		case err != nil:
			r.sourceFailure(it, groups, err, false)
			return nil, false
		}
		if _, present := byName(listing, uvTomlFileName); present {
			found = append(found, pathIn(dir, uvTomlFileName))
			continue
		}
		it.Source.Absent = append(it.Source.Absent, pathIn(dir, uvTomlFileName))
	}
	return found, true
}
