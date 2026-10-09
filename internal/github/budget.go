package github

import "sync"

// Budget caps how many HTTP requests a client may send. The caller creates one
// per cycle and shares it; every request, redirects included, consumes one. A
// nil *Budget is unlimited.
type Budget struct {
	mu        sync.Mutex
	remaining int
	used      int
}

// NewBudget returns a budget of n requests.
func NewBudget(n int) *Budget {
	if n < 0 {
		n = 0
	}
	return &Budget{remaining: n}
}

// take consumes one request, or returns ErrBudgetExhausted.
func (b *Budget) take() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.remaining <= 0 {
		return ErrBudgetExhausted
	}
	b.remaining--
	b.used++
	return nil
}

// Used returns how many requests have been consumed.
func (b *Budget) Used() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// Remaining returns how many requests are left, or -1 for an unlimited budget.
func (b *Budget) Remaining() int {
	if b == nil {
		return -1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.remaining
}
