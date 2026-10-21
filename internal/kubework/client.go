// Package kubework runs disposable work Pods in a dedicated namespace: the
// Kubernetes counterpart of the Docker work containers. Its client is a
// separate type from the read-only one that lists containers for scanning, and
// it can send only the requests of a fixed table (create a Pod, with or
// without dry run; get, list and delete Pods; read a Pod's log; attach to a
// Pod's init container), all within one namespace and all for Pods whose
// names have the work Pod shape. That is a coding discipline, not a privilege
// boundary: the privilege boundary is the Role the service account has and the
// admission policy of the namespace.
package kubework

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	// maxObjectBytes bounds a Pod or Status object read from the server.
	maxObjectBytes = 4 << 20
	// maxListBytes bounds a list of Pods.
	maxListBytes = 32 << 20
	listPageSize = 200
)

// Options configures a Client.
type Options struct {
	// APIServer is the API server's base URL; empty means the in-cluster
	// address from the environment.
	APIServer     string
	TokenFile     string
	CAFile        string
	TLSServerName string
	// Namespace is the only namespace the client touches.
	Namespace string
	Log       *slog.Logger
	// HTTPClient, when set, is used in place of one built from the CA (tests).
	HTTPClient *http.Client
}

// Client talks to the API server about work Pods.
type Client struct {
	base       *url.URL
	tokenFile  string
	caFile     string
	serverName string
	namespace  string
	hc         *http.Client
	log        *slog.Logger
}

var namespaceRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// New returns a Client for the namespace.
func New(o Options) (*Client, error) {
	if !namespaceRE.MatchString(o.Namespace) {
		return nil, fmt.Errorf("kubework: %q is not a namespace name", o.Namespace)
	}
	api := o.APIServer
	if api == "" {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return nil, errors.New("kubework: no API server address and not running in a cluster")
		}
		api = "https://" + net.JoinHostPort(host, port)
	}
	base, err := url.Parse(api)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return nil, fmt.Errorf("kubework: the API server address must be an https URL")
	}
	c := &Client{base: base, tokenFile: o.TokenFile, caFile: o.CAFile, serverName: o.TLSServerName, namespace: o.Namespace, hc: o.HTTPClient, log: o.Log}
	if c.tokenFile == "" {
		c.tokenFile = defaultTokenFile
	}
	if c.caFile == "" {
		c.caFile = defaultCAFile
	}
	return c, nil
}

func (c *Client) logger() *slog.Logger {
	if c.log != nil {
		return c.log
	}
	return slog.Default()
}

func (c *Client) token() (string, error) {
	b, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return "", fmt.Errorf("read the service account token: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// tlsConfig is built from the CA file each time it is needed, so a rotated
// bundle is used without a restart. There is no way around the check.
func (c *Client) tlsConfig() (*tls.Config, error) {
	pem, err := os.ReadFile(c.caFile)
	if err != nil {
		return nil, fmt.Errorf("read the CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("the CA bundle holds no certificate")
	}
	return &tls.Config{RootCAs: pool, ServerName: c.serverName, MinVersion: tls.VersionTLS12}, nil
}

// APIError is an error answer of the API server.
type APIError struct {
	Code    int
	Reason  string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("the API server answered %d %s: %s", e.Code, e.Reason, e.Message)
}

// IsNotFound and IsConflict classify an error.
func IsNotFound(err error) bool {
	var a *APIError
	return errors.As(err, &a) && a.Code == http.StatusNotFound
}
func IsConflict(err error) bool {
	var a *APIError
	return errors.As(err, &a) && a.Code == http.StatusConflict
}

// request is one request of the table.
type request struct {
	method string
	path   string
	query  url.Values
	body   []byte
}

func (c *Client) podsPath() string { return "/api/v1/namespaces/" + c.namespace + "/pods" }

func podPath(c *Client, name string) (string, error) {
	if !nameRE.MatchString(name) {
		return "", fmt.Errorf("%q is not the name of a work Pod", name)
	}
	return c.podsPath() + "/" + name, nil
}

func (c *Client) opCreate(pod map[string]any, dryRun bool) (request, error) {
	body, err := json.Marshal(pod)
	if err != nil {
		return request{}, err
	}
	q := url.Values{"fieldValidation": {"Strict"}}
	if dryRun {
		q.Set("dryRun", "All")
	}
	return request{method: http.MethodPost, path: c.podsPath(), query: q, body: body}, nil
}

func (c *Client) opGet(name string) (request, error) {
	p, err := podPath(c, name)
	return request{method: http.MethodGet, path: p}, err
}

func (c *Client) opList(selector, cont string) request {
	q := url.Values{"labelSelector": {selector}, "limit": {fmt.Sprint(listPageSize)}}
	if cont != "" {
		q.Set("continue", cont)
	}
	return request{method: http.MethodGet, path: c.podsPath(), query: q}
}

func (c *Client) opDelete(name, uid string) (request, error) {
	p, err := podPath(c, name)
	if err != nil {
		return request{}, err
	}
	if uid == "" {
		return request{}, errors.New("a Pod is deleted with its UID as a precondition")
	}
	body, _ := json.Marshal(map[string]any{
		"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": map[string]any{"uid": uid},
		"propagationPolicy": "Background",
	})
	return request{method: http.MethodDelete, path: p, body: body}, nil
}

func (c *Client) opLog(name, container string, limitBytes int64) (request, error) {
	p, err := podPath(c, name)
	if err != nil {
		return request{}, err
	}
	if container != WorkContainer && container != ReceiveContainer {
		return request{}, errors.New("not a container of a work Pod")
	}
	return request{method: http.MethodGet, path: p + "/log", query: url.Values{"container": {container}, "limitBytes": {fmt.Sprint(limitBytes)}}}, nil
}

func (c *Client) opVersion() request {
	return request{method: http.MethodGet, path: "/version"}
}

// opOwnPod reads the Pod KestreLynx itself runs in, to learn the image it
// runs; it is the one request that names a Pod outside the work Pods and is
// made on a client of KestreLynx's own namespace.
func (c *Client) opOwnPod(name string) (request, error) {
	if !ownPodNameRE.MatchString(name) {
		return request{}, fmt.Errorf("%q is not a Pod name", name)
	}
	return request{method: http.MethodGet, path: c.podsPath() + "/" + name}, nil
}

var ownPodNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

// do sends a request of the table and returns the response body, read up to
// max bytes (more is an error). A non-2xx answer is an *APIError.
func (c *Client) do(ctx context.Context, r request, max int64) ([]byte, error) {
	tok, err := c.token()
	if err != nil {
		return nil, err
	}
	hc := c.hc
	if hc == nil {
		cfg, err := c.tlsConfig()
		if err != nil {
			return nil, err
		}
		tr := &http.Transport{TLSClientConfig: cfg, ResponseHeaderTimeout: 60 * time.Second}
		defer tr.CloseIdleConnections()
		hc = &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	u := *c.base
	u.Path = r.path
	u.RawQuery = r.query.Encode()
	var body io.Reader
	if r.body != nil {
		body = bytes.NewReader(r.body)
	}
	req, err := http.NewRequestWithContext(ctx, r.method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	if r.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("the response is over %d bytes", max)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := &APIError{Code: resp.StatusCode}
		var st struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &st) == nil {
			ae.Reason, ae.Message = st.Reason, st.Message
		}
		if ae.Message == "" {
			ae.Message = clip(string(data), 200)
		}
		return nil, ae
	}
	return data, nil
}

// CreatePod creates a Pod, or checks that it could be created with dryRun,
// and returns the object the server answered with.
func (c *Client) CreatePod(ctx context.Context, pod map[string]any, dryRun bool) (map[string]any, error) {
	r, err := c.opCreate(pod, dryRun)
	if err != nil {
		return nil, err
	}
	data, err := c.do(ctx, r, maxObjectBytes)
	if err != nil {
		return nil, err
	}
	return decodeObject(data)
}

// GetPod reads a Pod.
func (c *Client) GetPod(ctx context.Context, name string) (map[string]any, error) {
	r, err := c.opGet(name)
	if err != nil {
		return nil, err
	}
	data, err := c.do(ctx, r, maxObjectBytes)
	if err != nil {
		return nil, err
	}
	return decodeObject(data)
}

// ServerVersion returns the major and minor version of the API server.
func (c *Client) ServerVersion(ctx context.Context) (major, minor int, err error) {
	data, err := c.do(ctx, c.opVersion(), 1<<16)
	if err != nil {
		return 0, 0, err
	}
	var v struct {
		Major string `json:"major"`
		Minor string `json:"minor"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return 0, 0, fmt.Errorf("the server version cannot be read: %w", err)
	}
	// Some distributions add a suffix to the minor version ("30+").
	minorDigits := strings.TrimRight(v.Minor, "+")
	major, err1 := strconv.Atoi(v.Major)
	minor, err2 := strconv.Atoi(minorDigits)
	if err1 != nil || err2 != nil {
		return 0, 0, fmt.Errorf("the server version %q.%q is not a number", v.Major, v.Minor)
	}
	return major, minor, nil
}

// OwnImageID returns the image ID (a reference pinned by digest) of the
// container of the named Pod that has the container name, as the kubelet
// reports it. The client is one of the namespace KestreLynx runs in.
func (c *Client) OwnImageID(ctx context.Context, pod, container string) (string, error) {
	r, err := c.opOwnPod(pod)
	if err != nil {
		return "", err
	}
	data, err := c.do(ctx, r, maxObjectBytes)
	if err != nil {
		return "", err
	}
	var p struct {
		Status struct {
			ContainerStatuses []struct {
				Name    string `json:"name"`
				ImageID string `json:"imageID"`
			} `json:"containerStatuses"`
		} `json:"status"`
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return "", fmt.Errorf("the Pod cannot be read: %w", err)
	}
	cs := p.Status.ContainerStatuses
	for _, s := range cs {
		if s.Name == container || (container == "" && len(cs) == 1) {
			return s.ImageID, nil
		}
	}
	return "", fmt.Errorf("the Pod has no container %q", container)
}

// ListPods reads every Pod with the label selector, page by page.
func (c *Client) ListPods(ctx context.Context, selector string) ([]map[string]any, error) {
	var out []map[string]any
	cont := ""
	for page := 0; page < 100; page++ {
		data, err := c.do(ctx, c.opList(selector, cont), maxListBytes)
		if err != nil {
			return nil, err
		}
		var l struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal(data, &l); err != nil {
			return nil, fmt.Errorf("the list of Pods cannot be read: %w", err)
		}
		out = append(out, l.Items...)
		if l.Metadata.Continue == "" {
			return out, nil
		}
		cont = l.Metadata.Continue
	}
	return nil, errors.New("the list of Pods has too many pages")
}

// DeletePod deletes the Pod, on the condition that its UID is the one given.
// A Pod that is not there is no error.
func (c *Client) DeletePod(ctx context.Context, name, uid string) error {
	r, err := c.opDelete(name, uid)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, r, maxObjectBytes)
	if IsNotFound(err) {
		return nil
	}
	return err
}

// PodLog reads at most limitBytes of the container's log.
func (c *Client) PodLog(ctx context.Context, name, container string, limitBytes int64) ([]byte, error) {
	r, err := c.opLog(name, container, limitBytes)
	if err != nil {
		return nil, err
	}
	return c.do(ctx, r, limitBytes)
}

// AttachInput sends data to the standard input of the receive container and
// closes it.
func (c *Client) AttachInput(ctx context.Context, name string, data []byte) error {
	if _, err := podPath(c, name); err != nil {
		return err
	}
	tok, err := c.token()
	if err != nil {
		return err
	}
	cfg, err := c.tlsConfig()
	if err != nil {
		return err
	}
	return attachStdin(ctx, c.base, tok, cfg, c.namespace, name, ReceiveContainer, data)
}

func decodeObject(data []byte) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("the response cannot be read: %w", err)
	}
	return m, nil
}
