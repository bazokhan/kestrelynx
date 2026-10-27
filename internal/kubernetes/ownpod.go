package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// WaitPodRunning polls one Pod until every container its spec names has a
// running status, and reports whether that happened before timeout. The
// kubelet writes a container's running state to the API a moment after the
// container starts, so a process that lists the cluster as soon as it starts
// may not yet see its own container running; a caller waits for its own Pod
// here before such a listing. Each poll is a single GET without the retries
// of the listing: any failure (the Pod is not found, the request is refused,
// the server is busy) ends the wait at once with that error, and the caller
// goes on without waiting.
func (c *Client) WaitPodRunning(ctx context.Context, namespace, name string, timeout, interval time.Duration) (bool, error) {
	hc := c.httpClient
	if hc == nil {
		built, err := c.buildHTTPClient()
		if err != nil {
			return false, fmt.Errorf("build http client: %w", err)
		}
		defer built.CloseIdleConnections()
		hc = built
	}
	token, err := c.readToken()
	if err != nil {
		return false, fmt.Errorf("read token: %w", err)
	}
	path := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/pods/" + url.PathEscape(name)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		body, err := c.getOnce(ctx, hc, token, path)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && ctx.Err() != nil {
				return false, nil
			}
			return false, err
		}
		var pod podRaw
		if err := json.Unmarshal(body, &pod); err != nil {
			return false, fmt.Errorf("decode pod: %w", err)
		}
		if allContainersRunning(pod) {
			return true, nil
		}
		select {
		case <-ctx.Done():
			return false, nil
		case <-time.After(interval):
		}
	}
}

// getOnce issues one GET and returns the body of a 200 response. Any other
// status is an error carrying only the status, never the body.
func (c *Client) getOnce(ctx context.Context, hc *http.Client, token, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// The body is not read: the wait ends here, and a server that stalls
		// mid-body must not hold it.
		return nil, fmt.Errorf("request %s: unexpected status %s", path, resp.Status)
	}
	body, err := readBodyLimited(resp.Body, maxPageBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("request %s: read response: %w", path, err)
	}
	return body, nil
}

// allContainersRunning reports whether every container of the Pod's spec has
// a status entry in the running state. A Pod whose spec names no container
// is not running anything this check could wait for.
func allContainersRunning(pod podRaw) bool {
	if len(pod.Spec.Containers) == 0 {
		return false
	}
	running := make(map[string]bool, len(pod.Status.ContainerStatuses))
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Running != nil {
			running[cs.Name] = true
		}
	}
	for _, sc := range pod.Spec.Containers {
		if !running[sc.Name] {
			return false
		}
	}
	return true
}
