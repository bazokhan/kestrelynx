package kubernetes

import (
	"context"
	"net/http"
	"testing"
	"time"
)

const ownPodPath = "/api/v1/namespaces/kestrelynx/pods/kestrelynx-5b75c8dd58-tsc52"

// ownPodBody is a Pod with one container in the given state, shaped as the
// API server returns it.
func ownPodBody(state string) []byte {
	return []byte(`{"kind":"Pod","apiVersion":"v1",
"metadata":{"name":"kestrelynx-5b75c8dd58-tsc52","namespace":"kestrelynx"},
"spec":{"containers":[{"name":"kestrelynx","image":"ghcr.io/kitsunetrail/kestrelynx:latest"}]},
"status":{"phase":"Pending","containerStatuses":[{"name":"kestrelynx","image":"ghcr.io/kitsunetrail/kestrelynx:latest","imageID":"","state":` + state + `}]}}`)
}

var (
	ownPodWaiting = ownPodBody(`{"waiting":{"reason":"ContainerCreating"}}`)
	ownPodRunning = ownPodBody(`{"running":{"startedAt":"2026-10-27T08:22:53Z"}}`)
)

func TestWaitPodRunning_WaitsUntilRunning(t *testing.T) {
	f := newFakeServer(t)
	f.on(ownPodPath, ok(ownPodWaiting), ok(ownPodWaiting), ok(ownPodRunning))
	c := newTestClient(t, f.start(), nil)

	got, err := c.WaitPodRunning(context.Background(), "kestrelynx", "kestrelynx-5b75c8dd58-tsc52", 5*time.Second, time.Millisecond)
	if err != nil || !got {
		t.Fatalf("WaitPodRunning = %v, %v; want true, nil", got, err)
	}
	n := 0
	for _, r := range f.requests {
		if r == ownPodPath {
			n++
		}
	}
	if n != 3 {
		t.Errorf("requests for the Pod = %d, want 3", n)
	}
}

func TestWaitPodRunning_TimesOut(t *testing.T) {
	f := newFakeServer(t)
	f.onFunc(ownPodPath, func(w http.ResponseWriter, r *http.Request) {
		w.Write(ownPodWaiting)
	})
	c := newTestClient(t, f.start(), nil)

	got, err := c.WaitPodRunning(context.Background(), "kestrelynx", "kestrelynx-5b75c8dd58-tsc52", 50*time.Millisecond, 5*time.Millisecond)
	if err != nil || got {
		t.Fatalf("WaitPodRunning = %v, %v; want false, nil", got, err)
	}
}

// A Pod that cannot be read (another cluster, a hostname that is not the Pod
// name) ends the wait at once with the error.
func TestWaitPodRunning_NotFoundEndsWait(t *testing.T) {
	f := newFakeServer(t)
	f.on(ownPodPath, scriptedResponse{status: http.StatusNotFound, body: []byte(`{"kind":"Status","code":404}`)})
	c := newTestClient(t, f.start(), nil)

	start := time.Now()
	got, err := c.WaitPodRunning(context.Background(), "kestrelynx", "kestrelynx-5b75c8dd58-tsc52", 5*time.Second, time.Millisecond)
	if err == nil || got {
		t.Fatalf("WaitPodRunning = %v, %v; want false and an error", got, err)
	}
	if time.Since(start) > time.Second {
		t.Errorf("waited %v after a 404, want no wait", time.Since(start))
	}
}

func TestAllContainersRunning(t *testing.T) {
	running := containerState{Running: &struct{}{}}
	pod := func(spec []string, status map[string]containerState) podRaw {
		var p podRaw
		for _, n := range spec {
			p.Spec.Containers = append(p.Spec.Containers, specContainer{Name: n})
		}
		for n, st := range status {
			p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, containerStatus{Name: n, State: st})
		}
		return p
	}
	for _, tc := range []struct {
		name string
		pod  podRaw
		want bool
	}{
		{"all running", pod([]string{"a", "b"}, map[string]containerState{"a": running, "b": running}), true},
		{"one not running", pod([]string{"a", "b"}, map[string]containerState{"a": running, "b": {}}), false},
		{"no status yet", pod([]string{"a"}, nil), false},
		{"status for another name only", pod([]string{"a"}, map[string]containerState{"x": running}), false},
		{"no containers", pod(nil, nil), false},
	} {
		if got := allContainersRunning(tc.pod); got != tc.want {
			t.Errorf("%s: allContainersRunning = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A busy or failing server is not retried: the first failure ends the wait
// with its error, after one request, without honoring Retry-After.
func TestWaitPodRunning_FailureNotRetried(t *testing.T) {
	for _, tc := range []struct {
		name string
		resp scriptedResponse
	}{
		{"503", scriptedResponse{status: http.StatusServiceUnavailable, body: []byte("busy")}},
		{"429 with Retry-After", scriptedResponse{status: http.StatusTooManyRequests, header: http.Header{"Retry-After": {"30"}}}},
		{"401", scriptedResponse{status: http.StatusUnauthorized}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeServer(t)
			f.on(ownPodPath, tc.resp, ok(ownPodRunning))
			c := newTestClient(t, f.start(), nil)

			start := time.Now()
			got, err := c.WaitPodRunning(context.Background(), "kestrelynx", "kestrelynx-5b75c8dd58-tsc52", 5*time.Second, time.Millisecond)
			if err == nil || got {
				t.Fatalf("WaitPodRunning = %v, %v; want false and an error", got, err)
			}
			if time.Since(start) > time.Second {
				t.Errorf("waited %v, want no wait", time.Since(start))
			}
			if len(f.requests) != 1 {
				t.Errorf("requests = %d, want 1", len(f.requests))
			}
		})
	}
}

func TestWaitPodRunning_ConnectionErrorEndsWait(t *testing.T) {
	f := newFakeServer(t)
	srv := f.start()
	c := newTestClient(t, srv, nil)
	srv.Close()

	got, err := c.WaitPodRunning(context.Background(), "kestrelynx", "kestrelynx-5b75c8dd58-tsc52", 5*time.Second, time.Millisecond)
	if err == nil || got {
		t.Fatalf("WaitPodRunning = %v, %v; want false and an error", got, err)
	}
}

// An error status whose body never arrives still ends the wait at once.
func TestWaitPodRunning_StalledErrorBodyEndsWait(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f := newFakeServer(t)
	f.onFunc(ownPodPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	c := newTestClient(t, f.start(), nil)

	start := time.Now()
	got, err := c.WaitPodRunning(context.Background(), "kestrelynx", "kestrelynx-5b75c8dd58-tsc52", 5*time.Second, time.Millisecond)
	if err == nil || got {
		t.Fatalf("WaitPodRunning = %v, %v; want false and an error", got, err)
	}
	if time.Since(start) > time.Second {
		t.Errorf("waited %v on a stalled body, want no wait", time.Since(start))
	}
}
