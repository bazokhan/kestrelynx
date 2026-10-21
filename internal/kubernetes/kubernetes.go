// Package kubernetes lists running containers via the kube-apiserver REST API
// over a mounted ServiceAccount token and CA. It deliberately avoids
// client-go: the only capabilities this package needs are a handful of
// read-only LIST calls (paginated, retried, and re-authenticated on token
// rotation), which are cheaper to own directly than to pull in a typed
// clientset, informers, and their transitive dependency weight for.
package kubernetes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

// Default locations for the projected ServiceAccount token and the
// cluster CA, as mounted into every Pod by Kubernetes.
const (
	defaultTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// defaultBackoffBase is the starting delay for the exponential backoff used
// on retryable list failures (429, 5xx, transport errors). It doubles on
// each retry, capped at 3 retries.
const defaultBackoffBase = 500 * time.Millisecond

// Options configures a Client. Any field left at its zero value falls back
// to the in-cluster default for that field, so a Pod running under its own
// ServiceAccount needs only APIServer left empty to work.
type Options struct {
	// APIServer is the kube-apiserver base URL (e.g. "https://10.0.0.1:443").
	// Empty means build it from the KUBERNETES_SERVICE_HOST/PORT environment
	// variables Kubernetes injects into every Pod.
	APIServer string
	// TokenFile is the ServiceAccount token path. Empty means
	// defaultTokenFile. Read fresh on every call, since a projected token is
	// rotated by an atomic rename underneath this path.
	TokenFile string
	// CAFile is the cluster CA bundle path. Empty means defaultCAFile. Read
	// fresh on every call for the same reason as TokenFile.
	CAFile string
	// TLSServerName overrides the TLS ServerName used to validate the
	// apiserver's certificate. Empty leaves it unset, so crypto/tls
	// validates against whatever host or IP APIServer names — which is what
	// the apiserver's serving certificate actually carries as a SAN. This
	// must not default to "kubernetes.default.svc": an explicit APIServer
	// naming a different address would then fail against a perfectly valid
	// certificate.
	TLSServerName string
	// Namespaces restricts every namespaced LIST (Pods, ReplicaSets, Jobs)
	// to this set, issued one request per namespace. Nodes are always
	// listed cluster-scoped, since a Node isn't namespaced. Empty means
	// every namespace.
	Namespaces []string
	// Log, when set, receives diagnostics (an imageID that fails the
	// registry digest boundary check). Nil falls back to slog.Default.
	Log *slog.Logger
}

// Client talks to the kube-apiserver REST API. It only issues GET requests
// against LIST endpoints.
type Client struct {
	// httpClient is pre-set by the newClient test hook to point at an
	// httptest server; nil in production, where RunningContainers builds one
	// fresh every call from caFile (the CA is re-read every cycle, so a
	// rotated bundle takes effect on the next scan without a restart).
	httpClient    *http.Client
	baseURL       string
	tokenFile     string
	caFile        string
	tlsServerName string
	namespaces    []string
	backoffBase   time.Duration
	Log           *slog.Logger
}

func (c *Client) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.Default()
}

// New returns a Client configured from opts, resolving every empty field to
// its in-cluster default. It returns an error only when APIServer is empty
// and the in-cluster environment variables it would be derived from are not
// both present — every other field degrades to a default rather than
// failing here, since a wrong token or CA path only surfaces once a request
// is actually made.
func New(opts Options) (*Client, error) {
	apiServer := opts.APIServer
	if apiServer == "" {
		host := os.Getenv("KUBERNETES_SERVICE_HOST")
		port := os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return nil, fmt.Errorf("kubernetes: api_server not set and KUBERNETES_SERVICE_HOST/KUBERNETES_SERVICE_PORT are not both present")
		}
		apiServer = "https://" + net.JoinHostPort(host, port)
	}
	if !strings.HasPrefix(apiServer, "https://") {
		return nil, fmt.Errorf("kubernetes: api_server must use https, got %q", opts.APIServer)
	}

	tokenFile := opts.TokenFile
	if tokenFile == "" {
		tokenFile = defaultTokenFile
	}
	caFile := opts.CAFile
	if caFile == "" {
		caFile = defaultCAFile
	}

	return &Client{
		baseURL:       strings.TrimRight(apiServer, "/"),
		tokenFile:     tokenFile,
		caFile:        caFile,
		tlsServerName: opts.TLSServerName,
		namespaces:    append([]string(nil), opts.Namespaces...),
		backoffBase:   defaultBackoffBase,
		Log:           opts.Log,
	}, nil
}

// newClient is used by tests to point the client at an httptest server,
// bypassing the TLS/CA setup a real in-cluster connection needs (the test
// server speaks plain HTTP). backoffBase is set small so retry/backoff tests
// run fast.
func newClient(baseURL string, hc *http.Client, tokenFile string, namespaces []string) *Client {
	return &Client{
		baseURL:     baseURL,
		httpClient:  hc,
		tokenFile:   tokenFile,
		namespaces:  namespaces,
		backoffBase: time.Millisecond,
	}
}

// buildHTTPClient constructs an http.Client trusting caFile's CA bundle,
// read fresh so a rotated bundle is picked up without restarting the
// process. There is no insecure fallback: a CA that fails to load or parse
// is an error, not a reason to skip verification.
func (c *Client) buildHTTPClient() (*http.Client, error) {
	pem, err := os.ReadFile(c.caFile)
	if err != nil {
		return nil, fmt.Errorf("read ca file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("parse ca file %s: no certificates found", c.caFile)
	}
	tlsConfig := &tls.Config{RootCAs: pool}
	if c.tlsServerName != "" {
		tlsConfig.ServerName = c.tlsServerName
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   30 * time.Second,
		// There is no legitimate reason for a LIST against the apiserver to
		// redirect, and following one would replay the Authorization header
		// (bearing the SA token) at whatever the redirect names. Returning
		// the redirect response itself, rather than an error, lets it flow
		// into getWithRetry's normal status handling (a 3xx there falls
		// through to the "unexpected status" case) instead of being
		// misclassified as a transient transport error and retried.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// readToken reads the ServiceAccount token fresh from tokenFile. Called once
// per RunningContainers cycle, and again on a 401 mid-cycle, since a
// projected token is rotated by an atomic rename underneath this path.
func (c *Client) readToken() (string, error) {
	b, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// RunningContainers returns every running container as observed by
// Kubernetes, stripped down to the runtime-agnostic inventory.Container
// vocabulary. A container is "running" per containerSpec, in order:
// status.containerStatuses with state.running set, plus
// status.initContainerStatuses with state.running set whose corresponding
// spec.initContainers entry (matched by name) has restartPolicy "Always" (a
// native sidecar) — an ordinary init container has already exited by the
// time anything else is running and is not a running-container observation.
// Each Container.Workload is resolved by resolveWorkload from the Pod's
// owner-reference chain (relayed through the ReplicaSets and Jobs listed
// here); anything outside its allow-list is inventory.Workload{} (unknown),
// never guessed at. If any one of the LIST calls this needs ultimately fails
// (after its own retries), the whole cycle fails — a partial listing must
// never be mistaken for a complete one, since a container that silently
// dropped out of view is indistinguishable from one that stopped running.
func (c *Client) RunningContainers(ctx context.Context) ([]inventory.Container, error) {
	l, err := c.list(ctx, false)
	if err != nil {
		return nil, err
	}
	containers := c.mapContainers(l.pods, l.platformByNode, l.rsByKey, l.jobByKey)
	sortContainers(containers)
	return containers, nil
}

// Observe lists the cluster once and returns both what RunningContainers and
// what DeployBindings return from that one listing, so that a container and
// its management chain never come from two different moments. A failure of
// any LIST fails the whole observation, as it does for each of the two.
func (c *Client) Observe(ctx context.Context) ([]inventory.Container, []remediation.DeployBinding, error) {
	l, err := c.list(ctx, true)
	if err != nil {
		return nil, nil, err
	}
	containers := c.mapContainers(l.pods, l.platformByNode, l.rsByKey, l.jobByKey)
	sortContainers(containers)
	return containers, bindingsOf(l, time.Now().UTC()), nil
}

// listing is what one pass of LIST calls returned, indexed for the walks
// from a Pod to its owner. idx is filled only when the marker-checked kinds
// were listed.
type listing struct {
	pods           []podRaw
	platformByNode map[string]inventory.Platform
	rsByKey        map[string]replicaSetRaw
	jobByKey       map[string]jobRaw
	idx            markerIndexes
}

// list issues the LIST calls of one cycle: nodes, pods, ReplicaSets and Jobs,
// and with markers also the Deployments, StatefulSets, DaemonSets and
// CronJobs whose metadata carries the deployment-tool markers. ReplicaSets
// and Jobs are the relays resolveWorkload's owner-reference chain (Pod ->
// ReplicaSet -> Deployment, Pod -> Job -> CronJob) walks through. If any one
// LIST ultimately fails (after its own retries), the whole listing fails: a
// partial listing must never be mistaken for a complete one, since a
// container that silently dropped out of view is indistinguishable from one
// that stopped running.
func (c *Client) list(ctx context.Context, markers bool) (listing, error) {
	hc := c.httpClient
	if hc == nil {
		built, err := c.buildHTTPClient()
		if err != nil {
			return listing{}, fmt.Errorf("build http client: %w", err)
		}
		// This Transport is scoped to this one cycle (a fresh one is built
		// next cycle so a rotated CA takes effect promptly); without this,
		// its keep-alive connections and their goroutines would sit idle
		// until the peer closed them instead of being released once this
		// cycle is done with them.
		defer built.CloseIdleConnections()
		hc = built
	}

	token, err := c.readToken()
	if err != nil {
		return listing{}, fmt.Errorf("read token: %w", err)
	}

	nodes, err := fetchList[nodeRaw](ctx, c, hc, &token, "/api/v1/nodes")
	if err != nil {
		return listing{}, fmt.Errorf("list nodes: %w", err)
	}
	pods, err := listNamespaced[podRaw](ctx, c, hc, &token, "/api/v1", "pods")
	if err != nil {
		return listing{}, fmt.Errorf("list pods: %w", err)
	}
	replicaSets, err := listNamespaced[replicaSetRaw](ctx, c, hc, &token, "/apis/apps/v1", "replicasets")
	if err != nil {
		return listing{}, fmt.Errorf("list replicasets: %w", err)
	}
	jobs, err := listNamespaced[jobRaw](ctx, c, hc, &token, "/apis/batch/v1", "jobs")
	if err != nil {
		return listing{}, fmt.Errorf("list jobs: %w", err)
	}
	l := listing{
		pods:           pods,
		platformByNode: indexPlatforms(nodes),
		rsByKey:        indexReplicaSets(replicaSets),
		jobByKey:       indexJobs(jobs),
	}
	if !markers {
		return l, nil
	}
	for _, k := range []struct {
		group, resource string
		into            *map[string]markerMetadata
	}{
		{"/apis/apps/v1", "deployments", &l.idx.deployments},
		{"/apis/apps/v1", "statefulsets", &l.idx.statefulSets},
		{"/apis/apps/v1", "daemonsets", &l.idx.daemonSets},
		{"/apis/batch/v1", "cronjobs", &l.idx.cronJobs},
	} {
		objs, err := listNamespaced[markerObject](ctx, c, hc, &token, k.group, k.resource)
		if err != nil {
			return listing{}, fmt.Errorf("list %s: %w", k.resource, err)
		}
		*k.into = indexMarkerObjects(objs)
	}
	return l, nil
}

// sortContainers orders containers deterministically: (Image.Ref,
// Image.Config.Hex, Image.Registry.Digest.Hex, Image.Platform.OS,
// Image.Platform.Architecture, Image.Platform.Variant, Workload.Group,
// Workload.Name, Container.Name).
func sortContainers(containers []inventory.Container) {
	sort.Slice(containers, func(i, j int) bool {
		a, b := containers[i], containers[j]
		if a.Image.Ref != b.Image.Ref {
			return a.Image.Ref < b.Image.Ref
		}
		if a.Image.Config.Hex != b.Image.Config.Hex {
			return a.Image.Config.Hex < b.Image.Config.Hex
		}
		if a.Image.Registry.Digest.Hex != b.Image.Registry.Digest.Hex {
			return a.Image.Registry.Digest.Hex < b.Image.Registry.Digest.Hex
		}
		if a.Image.Platform.OS != b.Image.Platform.OS {
			return a.Image.Platform.OS < b.Image.Platform.OS
		}
		if a.Image.Platform.Architecture != b.Image.Platform.Architecture {
			return a.Image.Platform.Architecture < b.Image.Platform.Architecture
		}
		if a.Image.Platform.Variant != b.Image.Platform.Variant {
			return a.Image.Platform.Variant < b.Image.Platform.Variant
		}
		if a.Workload.Group != b.Workload.Group {
			return a.Workload.Group < b.Workload.Group
		}
		if a.Workload.Name != b.Workload.Name {
			return a.Workload.Name < b.Workload.Name
		}
		return a.Name < b.Name
	})
}
