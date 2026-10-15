package remediation

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// What one item may spend when its update goes on to re-resolve the packages
// that hold a package back: the containers, the registry lookups, the bytes
// received from the registry and the time. The limits are those of the whole
// item, the first update included, not of one attempt.
const (
	maxItemContainers = 4
	maxItemLookups    = 384
	maxItemBytes      = 96 << 20
	// itemWorkSlack is added to two container timeouts to make the time an
	// item may work for.
	itemWorkSlack = 2 * time.Minute
	// minContainerTime is the least time left for which a container is started.
	minContainerTime = 45 * time.Second
)

// Kinds of an item's wait. The budget kinds are the limit that stopped the
// item; releaseAgeWait is a release that is too new.
const (
	releaseAgeWait      = "release_age"
	budgetContainerWait = "budget_containers"
	budgetLookupWait    = "budget_lookups"
	budgetBytesWait     = "budget_bytes"
	budgetTimeWait      = "budget_time"
)

// itemBudgetError says which limit of the item a request ran into.
type itemBudgetError struct{ kind string }

func (e *itemBudgetError) Error() string {
	switch e.kind {
	case budgetContainerWait:
		return fmt.Sprintf("the item has used its %d work containers", maxItemContainers)
	case budgetLookupWait:
		return fmt.Sprintf("the item has used its %d registry lookups", maxItemLookups)
	case budgetBytesWait:
		return fmt.Sprintf("the item has received its %d MiB from the registries", maxItemBytes>>20)
	}
	return "the item has used its working time"
}

// itemBudget counts what an item has spent against its limits and what it has
// set aside for work still to come.
type itemBudget struct {
	containers, maxContainers int
	lookups, maxLookups       int
	bytes, maxBytes           int64
	// reserved are the amounts set aside by reserve and not yet spent.
	reservedContainers, reservedLookups int
	reservedBytes                       int64
	// workDeadline is zero until the work starts (see workCtx).
	workDeadline time.Time
	// workLimit, when not zero, replaces the time an item may work for.
	workLimit time.Duration
	now       func() time.Time
}

func newItemBudget() *itemBudget {
	return &itemBudget{maxContainers: maxItemContainers, maxLookups: maxItemLookups, maxBytes: maxItemBytes, now: time.Now}
}

// reserve sets the amounts aside for work still to come, and reports whether
// they fit in what is left. Nothing is set aside when they do not.
func (b *itemBudget) reserve(containers, lookups int, bytes int64) bool {
	if containers < 0 || lookups < 0 || bytes < 0 ||
		b.containers+b.reservedContainers+containers > b.maxContainers ||
		b.lookups+b.reservedLookups+lookups > b.maxLookups ||
		b.bytes+b.reservedBytes+bytes > b.maxBytes {
		return false
	}
	b.reservedContainers += containers
	b.reservedLookups += lookups
	b.reservedBytes += bytes
	return true
}

// which says which of the amounts a reserve of this size did not fit in, for
// the record of why an item waits.
func (b *itemBudget) which(containers, lookups int, bytes int64) string {
	switch {
	case b.containers+b.reservedContainers+containers > b.maxContainers:
		return budgetContainerWait
	case b.lookups+b.reservedLookups+lookups > b.maxLookups:
		return budgetLookupWait
	case b.bytes+b.reservedBytes+bytes > b.maxBytes:
		return budgetBytesWait
	}
	return budgetTimeWait
}

// spendContainer counts a container, taking it from what was set aside when
// something was.
func (b *itemBudget) spendContainer() error {
	if b.containers >= b.maxContainers {
		return &itemBudgetError{budgetContainerWait}
	}
	b.containers++
	if b.reservedContainers > 0 {
		b.reservedContainers--
	}
	return nil
}

// spendLookup counts a registry lookup.
func (b *itemBudget) spendLookup() error {
	if b.lookups >= b.maxLookups {
		return &itemBudgetError{budgetLookupWait}
	}
	b.lookups++
	if b.reservedLookups > 0 {
		b.reservedLookups--
	}
	return nil
}

// addBytes counts bytes received from a registry. The bytes are counted even
// when they are over the limit, since they were received.
func (b *itemBudget) addBytes(n int64) error {
	if n <= 0 {
		return nil
	}
	b.bytes += n
	if b.reservedBytes > 0 {
		b.reservedBytes -= min(n, b.reservedBytes)
	}
	if b.bytes > b.maxBytes {
		return &itemBudgetError{budgetBytesWait}
	}
	return nil
}

// workCtx starts the item's working time: the returned context ends two
// container timeouts and two minutes from now, or when the parent's does if
// that is sooner. Everything the chain does afterwards (jobs, lookups, scans)
// is given this context.
func (b *itemBudget) workCtx(parent context.Context, jobTimeout time.Duration) (context.Context, context.CancelFunc) {
	limit := 2*jobTimeout + itemWorkSlack
	if b.workLimit > 0 {
		limit = b.workLimit
	}
	deadline := b.now().Add(limit)
	if d, ok := parent.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	b.workDeadline = deadline
	return context.WithDeadline(parent, deadline)
}

// containerTimeout is the time a container may take: the job timeout, or what
// is left of ctx's deadline when that is less.
func containerTimeout(ctx context.Context, jobTimeout time.Duration) time.Duration {
	if d, ok := ctx.Deadline(); ok {
		if left := time.Until(d); left < jobTimeout {
			return left
		}
	}
	return jobTimeout
}

// errNoContainerTime: too little of the item's time is left to start a
// container.
var errNoContainerTime = &itemBudgetError{budgetTimeWait}

// isItemBudget reports the kind of limit an error is, "" for any other error.
func isItemBudget(err error) string {
	var be *itemBudgetError
	if errors.As(err, &be) {
		return be.kind
	}
	return ""
}

// registryCache holds the registry documents looked up for an item, by name
// and version, so that every run of the item looks each up once.
type registryCache struct {
	npm map[string]NpmDist
	py  map[string]PyPIRelease
}

// itemShared is what the runs of one item share when the item goes on to
// re-resolve the packages that hold a package back: the budget and the
// registry documents. An item that does not has none, and each of its runs
// keeps its own, as it always has.
type itemShared struct {
	budget *itemBudget
	cache  registryCache
	// started is when the item's work began, for the record of what it used.
	started time.Time
}

func newItemShared() *itemShared {
	return &itemShared{budget: newItemBudget(), cache: registryCache{npm: map[string]NpmDist{}, py: map[string]PyPIRelease{}}, started: time.Now()}
}

// usage is what the item has spent so far.
func (s *itemShared) usage() ChainUsage {
	return ChainUsage{Containers: s.budget.containers, Lookups: s.budget.lookups, Bytes: s.budget.bytes, ElapsedMS: time.Since(s.started).Milliseconds()}
}

// budgetFailure is the deferral of an item that ran into one of its limits.
func budgetFailure(err error) *updateFailure {
	return &updateFailure{category: CategoryDeferred, reason: ReasonChainItemBudget, detail: err.Error(),
		wait: &langWaitIntent{Kind: isItemBudget(err)}}
}
