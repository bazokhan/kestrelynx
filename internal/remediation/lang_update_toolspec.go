package remediation

import (
	"context"
	"errors"
	"path"

	"github.com/kitsunetrail/kestrelynx/internal/github"
)

// readToolSpecFiles reads again the files the runtime and the package manager
// are declared in, as the plan read them: a file the plan read must still be
// the blob it recorded, and one it looked for and did not find must still not
// exist, because either would change what the update is made from.
func (u *LangUpdater) readToolSpecFiles(ctx context.Context, it *LanguageItem, sf *sourceFiles) *updateFailure {
	if it.Manager == ManagerPip {
		return nil
	}
	src := it.Source
	lockDir := path.Dir(sf.lockPath)
	names := map[string]bool{}
	for _, n := range ToolSpecFileNames(it.Manager) {
		names[n] = true
	}
	if it.Manager == ManagerUv {
		names[uvTomlFileName] = true
	}
	for _, p := range src.Absent {
		if !names[path.Base(p)] {
			continue
		}
		_, err := u.cfg.GitHub.ReadFile(ctx, src.Repository, src.CommitSHA, p)
		var nr *github.NotRegularFileError
		switch {
		case errors.Is(err, github.ErrNotFound):
		case err == nil, errors.As(err, &nr), errors.Is(err, github.ErrLFSPointer), errors.Is(err, github.ErrTooLarge):
			return failedFailure(ReasonSourceChanged, "%s did not exist when the plan was made and does now", p)
		default:
			return readFailure(err, p)
		}
	}
	sf.specFiles = map[string][]byte{}
	for _, f := range src.Files {
		base := path.Base(f.Path)
		if f.Repository != "" || !names[base] {
			continue
		}
		got, err := u.cfg.GitHub.ReadFile(ctx, src.Repository, src.CommitSHA, f.Path)
		if err != nil {
			return readFailure(err, f.Path)
		}
		if got.SHA != f.BlobSHA || got.Path != f.Path {
			return failedFailure(ReasonSourceChanged, "%s is not the blob the plan was made from (%s, now %s)", f.Path, f.BlobSHA, got.SHA)
		}
		if base == uvTomlFileName {
			sf.uvToml = append(sf.uvToml, f.Path)
		} else if path.Dir(f.Path) == lockDir {
			sf.specFiles[base] = got.Content
		}
	}
	return nil
}
