package remediation

import (
	"context"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// runNpmChain is the chain update of an npm project: the lockfile with the
// entries of the packages being updated and of the packages that require a held
// back package taken out (and what is nested below them) is relocked by npm,
// which resolves them again from the ranges in package.json and in the
// registry's declarations, and the result is judged by the checks of the
// stage. The original input was checked as it is by the first update, so that
// check is not made again.
func runNpmChain(ctx context.Context, r *updateRun, scope *chainScope) *updateFailure {
	if r.baseOK == nil {
		return failedFailure(ReasonUpdateInputInvalid, "the original input was not found consistent by the first update, so the chain update has nothing to start from")
	}
	removal, problem := removeNpmEntries(ctx, r.src.lock, scope.Targets, scope.RAnc)
	if problem != nil {
		return problem.failure()
	}
	steps := []worker.Step{{ID: stepUpdate, Op: worker.OpNpmRelock}}
	inputs := map[string][]byte{"package.json": r.manifest, "package-lock.json": removal.lock}
	out, fail := r.exec(ctx, worker.ManagerNpm, inputs, steps, "chain")
	if fail != nil {
		return fail
	}
	return r.finishLockfile(ctx, out, nil, nil)
}
