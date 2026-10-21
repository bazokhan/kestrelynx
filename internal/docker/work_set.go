package docker

import (
	"context"
	"errors"
	"fmt"
	"github.com/kitsunetrail/kestrelynx/internal/workexec"
	"sort"
	"sync"
)

// ErrImageUnavailable reports that the image a job needs could not be made
// ready: it could not be pulled, or the daemon's copy is not the pinned image
// for the platform. Nothing was run.
var ErrImageUnavailable = workexec.ErrImageUnavailable

// WorkSet is the work clients of the runtimes in use, one per official image,
// sharing one installation (instance id). A job names its runtime and runs on
// that client, whose image is pulled and checked the first time it is needed
// and again after a failure.
type WorkSet struct {
	mu      sync.Mutex
	clients map[string]*setClient
}

type setClient struct {
	client *WorkClient
	ready  bool
}

// NewWorkSet returns an empty set.
func NewWorkSet() *WorkSet { return &WorkSet{clients: map[string]*setClient{}} }

// Add registers the client for a runtime key. A key is added once.
func (s *WorkSet) Add(key string, c *WorkClient) error {
	if key == "" || c == nil {
		return errors.New("a work set entry needs a runtime key and a client")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.clients[key]; dup {
		return fmt.Errorf("runtime %q is added twice", key)
	}
	for _, o := range s.clients {
		if o.client.cfg.InstanceID != c.cfg.InstanceID {
			return errors.New("the clients of a work set share one instance id")
		}
	}
	s.clients[key] = &setClient{client: c}
	return nil
}

// Keys returns the runtime keys, in order.
func (s *WorkSet) Keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.clients))
	for k := range s.clients {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// CleanupStale removes the containers an earlier run of this installation
// left, whichever runtime they were made for. It is called once, before any
// job runs.
func (s *WorkSet) CleanupStale(ctx context.Context) (int, error) {
	keys := s.Keys()
	if len(keys) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	first := s.clients[keys[0]].client
	s.mu.Unlock()
	// The ownership conditions do not involve the image, so the containers of
	// every runtime of this installation are found through any one client.
	return first.CleanupStale(ctx)
}

// RunJob runs the job on the client of spec.Runtime.
func (s *WorkSet) RunJob(ctx context.Context, spec JobSpec) (JobResult, error) {
	s.mu.Lock()
	sc, ok := s.clients[spec.Runtime]
	s.mu.Unlock()
	if !ok {
		return JobResult{}, fmt.Errorf("no work client for runtime %q", spec.Runtime)
	}
	if err := s.ensure(ctx, sc); err != nil {
		return JobResult{}, fmt.Errorf("%w: %v", ErrImageUnavailable, err)
	}
	return sc.client.RunJob(ctx, spec)
}

func (s *WorkSet) ensure(ctx context.Context, sc *setClient) error {
	s.mu.Lock()
	ready := sc.ready
	s.mu.Unlock()
	if ready {
		return nil
	}
	if err := sc.client.EnsureImage(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	sc.ready = true
	s.mu.Unlock()
	return nil
}
