package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/kitsunetrail/kestrelynx/internal/workexec"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WorkClient runs disposable work containers through the Docker Engine API.
// It is a separate type from Client (which only ever issues GET requests for
// discovery) and is constructed only when the feature that needs it is
// enabled. It knows nothing about what a job does: callers hand it an image
// reference, an entrypoint, input files, a deadline and resource values, and
// get back the files the job left under the fixed result directory plus its
// exit code.
//
// Every request is built by one of the *Op constructors below, which fix the
// method, path, query and body shape. do, the only function that sends a
// request, accepts nothing else. That is a coding discipline, not a privilege
// boundary: the mounted socket grants the full Engine API regardless.
type WorkClient struct {
	httpClient *http.Client
	baseURL    string
	cfg        WorkConfig
	repo       string // repository part of cfg.Image
	digest     string // "sha256:..." part of cfg.Image
	platform   string // "os/arch" the image is pulled, created and checked for
	log        *slog.Logger

	apiMu sync.Mutex
	// apiChecked is set once the Engine API version is known to be enough, and
	// apiErr once it is known not to be. A failure to ask is neither, and is
	// asked again next time.
	apiChecked bool
	apiErr     error

	mu    sync.Mutex
	owned map[string]*ownedContainer
}

// WorkConfig is the part of a work container that is fixed per client rather
// than per job.
type WorkConfig struct {
	// Image is the pinned work image reference, "repository@sha256:<64 hex>",
	// the digest being that of the image index. The repository may be written
	// in the familiar Docker Hub form ("node") or in full; a mirror is given
	// with its host and path. Only this repository and digest are ever pulled,
	// inspected or run.
	Image string
	// Platform is the "os/arch" the image is pulled and the container is
	// created for, for example "linux/amd64". The image the daemon holds must
	// report that operating system and architecture.
	Platform string
	// ExpectEnv are environment variables the image must carry with exactly
	// these values (the version of the language it holds).
	ExpectEnv map[string]string
	// Entrypoint is the fixed program the container runs. Job input never
	// reaches it.
	Entrypoint []string
	// Env is the complete environment of the container ("KEY=value"); the
	// host process environment is never inherited.
	Env []string
	// AllowedEnvKeys is the required closed set of names Env may use.
	// Whatever its value, names that look like credentials are refused.
	AllowedEnvKeys []string
	// InstanceID identifies this installation (see LoadOrCreateInstanceID).
	InstanceID string
	// Limits bound what a job may send and return.
	Limits TransferLimits
	// Log receives diagnostics; nil falls back to slog.Default.
	Log *slog.Logger

	// Per-operation deadlines; zero values use the defaults below. Streaming
	// calls (pull, wait) are bounded by the context, never by an HTTP client
	// timeout.
	OpTimeout       time.Duration
	PullTimeout     time.Duration
	TransferTimeout time.Duration
	CleanupTimeout  time.Duration
}

// TransferLimits bound the tar streams in both directions; Resources are the
// per-job resource values. Both are shared with the other executors.
type (
	TransferLimits = workexec.TransferLimits
	Resources      = workexec.Resources
)

const (
	defaultOpTimeout       = 30 * time.Second
	defaultPullTimeout     = 10 * time.Minute
	defaultTransferTimeout = 2 * time.Minute
	defaultCleanupTimeout  = 30 * time.Second
)

// Fixed container settings. They are constants on purpose: nothing a caller
// passes can change them.
const (
	workUID     = 10001
	workGID     = 10001
	workUser    = "10001:10001"
	workDir     = "/work"
	tmpMount    = "/tmp"
	homeMount   = "/home/worker"
	toolsMount  = "/opt/kestrelynx-tools"
	varTmpMount = "/var/tmp"
	lockMount   = "/run/lock"
	// coveredTmpfsBytes is the size of the tmpfs mounts that only cover a
	// directory of the image that anyone could write to.
	coveredTmpfsBytes = 1 << 20
	// minAPIMajor and minAPIMinor are the oldest Engine API this client
	// uses: the platform of a container is honoured from it on.
	minAPIMajor = 1
	minAPIMinor = 44
	workNamePfx = "kestrelynx-work-"

	labelWork     = "io.kestrelynx.work"
	labelInstance = "io.kestrelynx.work.instance"
	labelJob      = "io.kestrelynx.work.job"
	labelImage    = "io.kestrelynx.work.image"
)

var (
	imageRefRE   = regexp.MustCompile(`^([a-z0-9][a-z0-9._:/-]{0,254})@(sha256:[0-9a-f]{64})$`)
	instanceIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	digestRE     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	platformRE   = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9]+$`)
	jobIDRE      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)
)

var envKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// secretLikeNames are substrings that mark an environment variable as a
// likely credential; the work container never receives one.
var secretLikeNames = []string{"TOKEN", "SECRET", "PASSWORD", "KEY"}

func validateEnv(env, allowed []string) error {
	allow := map[string]bool{}
	for _, k := range allowed {
		allow[k] = true
	}
	seen := map[string]bool{}
	for _, e := range env {
		k, _, ok := strings.Cut(e, "=")
		if !ok || !envKeyRE.MatchString(k) {
			return fmt.Errorf("work env entry %q is not KEY=value with a plain name", e)
		}
		for _, bad := range secretLikeNames {
			if strings.Contains(strings.ToUpper(k), bad) {
				return fmt.Errorf("work env name %q looks like a credential", k)
			}
		}
		if !allow[k] {
			return fmt.Errorf("work env name %q is not in the allowed set", k)
		}
		if seen[k] {
			return fmt.Errorf("work env name %q is duplicated", k)
		}
		seen[k] = true
	}
	return nil
}

// NewWork returns a WorkClient that dials the Docker daemon over the given
// unix socket.
func NewWork(socketPath string, cfg WorkConfig) (*WorkClient, error) {
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}}
	return newWorkClient("http://docker", hc, cfg)
}

// newWorkClient is used by tests to point the client at an httptest server.
func newWorkClient(baseURL string, hc *http.Client, cfg WorkConfig) (*WorkClient, error) {
	m := imageRefRE.FindStringSubmatch(cfg.Image)
	if m == nil || strings.Contains(m[1], "//") || strings.Contains(m[1], "..") {
		return nil, fmt.Errorf("work image %q must be a pinned repository@sha256:<64 hex> reference", cfg.Image)
	}
	if !platformRE.MatchString(cfg.Platform) {
		return nil, fmt.Errorf("work platform %q must be os/arch, for example linux/amd64", cfg.Platform)
	}
	if l := cfg.Limits; l.MaxToolBytes < 0 || l.MaxProgramBytes < 0 {
		return nil, errors.New("work tool and program limits must not be negative")
	}
	if !instanceIDRE.MatchString(cfg.InstanceID) {
		return nil, fmt.Errorf("work instance id %q is malformed", cfg.InstanceID)
	}
	if len(cfg.Entrypoint) == 0 || cfg.Entrypoint[0] == "" {
		return nil, errors.New("work entrypoint is required")
	}
	l := cfg.Limits
	if l.MaxInputBytes <= 0 || l.MaxInputTarBytes <= 0 || l.MaxInputFiles <= 0 || l.MaxInputPathBytes <= 0 || l.LogMaxBytes <= 0 || l.MaxStdoutBytes < l.LogMaxBytes {
		return nil, errors.New("work transfer limits must be positive and MaxStdoutBytes at least LogMaxBytes")
	}
	if len(cfg.AllowedEnvKeys) == 0 {
		return nil, errors.New("work AllowedEnvKeys is required")
	}
	if err := validateEnv(cfg.Env, cfg.AllowedEnvKeys); err != nil {
		return nil, err
	}
	if cfg.OpTimeout <= 0 {
		cfg.OpTimeout = defaultOpTimeout
	}
	if cfg.PullTimeout <= 0 {
		cfg.PullTimeout = defaultPullTimeout
	}
	if cfg.TransferTimeout <= 0 {
		cfg.TransferTimeout = defaultTransferTimeout
	}
	if cfg.CleanupTimeout <= 0 {
		cfg.CleanupTimeout = defaultCleanupTimeout
	}
	c := &WorkClient{
		httpClient: hc, baseURL: baseURL, cfg: cfg,
		repo: m[1], digest: m[2], platform: cfg.Platform, log: cfg.Log,
		owned: map[string]*ownedContainer{},
	}
	if c.log == nil {
		c.log = slog.Default()
	}
	return c, nil
}

// workOp is one fully specified Engine API request.
type workOp struct {
	method      string
	path        string
	query       url.Values
	contentType string
	body        []byte
}

func (o workOp) String() string { return o.method + " " + o.path }

func containerPath(id, suffix string) string {
	return "/containers/" + url.PathEscape(id) + suffix
}

// imageInspectOp asks for an image. The platform parameter is honoured by
// Engine API 1.49 and later and silently ignored by older daemons, so the
// answer is always checked for the operating system and architecture it
// reports.
func imageInspectOp(ref, platform string) workOp {
	// ref is validated against imageRefRE by the constructor, so it is kept
	// unescaped: the daemon routes "/images/{name:.*}/json" on the raw path.
	op := workOp{method: http.MethodGet, path: "/images/" + ref + "/json"}
	if os, arch, ok := strings.Cut(platform, "/"); ok {
		pj, _ := json.Marshal(map[string]string{"os": os, "architecture": arch})
		op.query = url.Values{"platform": {string(pj)}}
	}
	return op
}

func imageCreateOp(repo, digest, platform string) workOp {
	return workOp{method: http.MethodPost, path: "/images/create",
		query: url.Values{"fromImage": {repo}, "tag": {digest}, "platform": {platform}}}
}

func containerCreateOp(name, platform string, body []byte) workOp {
	return workOp{method: http.MethodPost, path: "/containers/create",
		query: url.Values{"name": {name}, "platform": {platform}}, contentType: "application/json", body: body}
}

func versionOp() workOp {
	return workOp{method: http.MethodGet, path: "/version"}
}

func startOp(id string) workOp {
	return workOp{method: http.MethodPost, path: containerPath(id, "/start")}
}

func putArchiveOp(id string, tarBytes []byte) workOp {
	return workOp{method: http.MethodPut, path: containerPath(id, "/archive"),
		query: url.Values{"path": {"/"}}, contentType: "application/x-tar", body: tarBytes}
}

func waitOp(id string) workOp {
	return workOp{method: http.MethodPost, path: containerPath(id, "/wait"),
		query: url.Values{"condition": {"not-running"}}}
}

func logsOp(id string) workOp {
	return workOp{method: http.MethodGet, path: containerPath(id, "/logs"),
		query: url.Values{"stdout": {"1"}, "stderr": {"0"}}}
}

func killOp(id string) workOp {
	return workOp{method: http.MethodPost, path: containerPath(id, "/kill")}
}

func deleteOp(id string) workOp {
	return workOp{method: http.MethodDelete, path: containerPath(id, ""),
		query: url.Values{"force": {"true"}, "v": {"true"}}}
}

func containerInspectOp(id string) workOp {
	return workOp{method: http.MethodGet, path: containerPath(id, "/json")}
}

// containerInspectByNameOp reads a container by its deterministic name; name
// is always built by containerName from a validated job id.
func containerInspectByNameOp(name string) workOp {
	return workOp{method: http.MethodGet, path: containerPath(name, "/json")}
}

func listWorkOp(instanceID string) workOp {
	f, _ := json.Marshal(map[string][]string{"label": {labelWork + "=1", labelInstance + "=" + instanceID}})
	return workOp{method: http.MethodGet, path: "/containers/json",
		query: url.Values{"all": {"true"}, "filters": {string(f)}}}
}

// do sends op and returns the response; the caller closes the body. The
// status is not interpreted here.
func (c *WorkClient) do(ctx context.Context, op workOp) (*http.Response, error) {
	u := c.baseURL + op.path
	if len(op.query) > 0 {
		u += "?" + op.query.Encode()
	}
	var body io.Reader
	if op.body != nil {
		body = bytes.NewReader(op.body)
	}
	req, err := http.NewRequestWithContext(ctx, op.method, u, body)
	if err != nil {
		return nil, fmt.Errorf("build request %s: %w", op, err)
	}
	if op.contentType != "" {
		req.Header.Set("Content-Type", op.contentType)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return resp, nil
}

// statusError is returned for an unexpected HTTP status.
type statusError struct {
	op     workOp
	status int
	body   string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("%s: status %d: %s", e.op, e.status, e.body)
}

func hasStatus(err error, status int) bool {
	var se *statusError
	return errors.As(err, &se) && se.status == status
}

// call sends op, requires one of the wanted statuses, and decodes the JSON
// body into out when out is non-nil.
func (c *WorkClient) call(ctx context.Context, op workOp, out any, want ...int) error {
	resp, err := c.do(ctx, op)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	ok := false
	for _, w := range want {
		ok = ok || resp.StatusCode == w
	}
	if !ok {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &statusError{op: op, status: resp.StatusCode, body: strings.TrimSpace(string(b))}
	}
	if out == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out); err != nil {
		return fmt.Errorf("decode %s: %w", op, err)
	}
	return nil
}

func (c *WorkClient) withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, d)
}

// normalizeRef writes an image reference "repository@digest" in one full
// form so that two spellings of the same reference compare equal: the implicit
// Docker Hub host and the "library/" of an official image are added, and the
// aliases of the Hub's host are folded into docker.io. Any other host,
// including a mirror with a path, is kept whole, so a reference through one
// mirror is never taken for a reference through another or for the Hub's.
func normalizeRef(ref string) string {
	name, digest, hasDigest := strings.Cut(ref, "@")
	domain, rest := "docker.io", name
	if i := strings.IndexByte(name, '/'); i >= 0 {
		first := name[:i]
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			domain, rest = strings.ToLower(first), name[i+1:]
		}
	}
	switch domain {
	case "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com":
		domain = "docker.io"
	}
	if domain == "docker.io" && !strings.Contains(rest, "/") {
		rest = "library/" + rest
	}
	out := domain + "/" + rest
	if hasDigest {
		out += "@" + digest
	}
	return out
}

type imageInspect struct {
	ID           string   `json:"Id"`
	RepoDigests  []string `json:"RepoDigests"`
	Os           string   `json:"Os"`
	Architecture string   `json:"Architecture"`
	Config       struct {
		Volumes map[string]json.RawMessage `json:"Volumes"`
		Env     []string                   `json:"Env"`
	} `json:"Config"`
}

// errPlatformAbsent says the daemon holds no image for the platform; the
// image is pulled for it.
var errPlatformAbsent = errors.New("the image is not held for the platform")

// verifyImage checks what the daemon reports about the image against what is
// pinned: the operating system and architecture (an empty answer counts as
// different, which is what a daemon gives for a platform it does not hold),
// that its repository and digest are among the repo digests, that it declares
// no volumes, and the versions in its environment.
func (c *WorkClient) verifyImage(img imageInspect) error {
	os, arch, _ := strings.Cut(c.platform, "/")
	if img.Os != os || img.Architecture != arch {
		return fmt.Errorf("%w: it reports %q/%q, want %s", errPlatformAbsent, img.Os, img.Architecture, c.platform)
	}
	want := normalizeRef(c.cfg.Image)
	found := false
	for _, d := range img.RepoDigests {
		if normalizeRef(d) == want {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("work image %s is present but its repo digests %v do not include the pinned reference", c.cfg.Image, img.RepoDigests)
	}
	if len(img.Config.Volumes) != 0 {
		return fmt.Errorf("work image %s declares volumes, which would create anonymous volumes", c.cfg.Image)
	}
	for k, v := range c.cfg.ExpectEnv {
		if !slices.Contains(img.Config.Env, k+"="+v) {
			return fmt.Errorf("work image %s does not have %s=%s", c.cfg.Image, k, v)
		}
	}
	return nil
}

// checkImage reports whether the local image store holds the pinned image for
// the platform. A missing image, or one the daemon holds for another platform,
// is (false, nil). With the containerd image store Id is the index digest, so
// the repo digests decide.
func (c *WorkClient) checkImage(ctx context.Context) (bool, error) {
	ctx, cancel := c.withTimeout(ctx, c.cfg.OpTimeout)
	defer cancel()
	var img imageInspect
	if err := c.call(ctx, imageInspectOp(c.cfg.Image, c.platform), &img, http.StatusOK); err != nil {
		if hasStatus(err, http.StatusNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("inspect work image: %w", err)
	}
	if err := c.verifyImage(img); err != nil {
		if errors.Is(err, errPlatformAbsent) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// checkAPI requires an Engine API of at least the version this client needs.
// A version that is enough, or definitely too old, is remembered; a failure to
// read it (the daemon did not answer, the deadline passed) is not, so the next
// call asks again.
func (c *WorkClient) checkAPI(ctx context.Context) error {
	c.apiMu.Lock()
	defer c.apiMu.Unlock()
	if c.apiChecked {
		return c.apiErr
	}
	octx, cancel := c.withTimeout(ctx, c.cfg.OpTimeout)
	defer cancel()
	var v struct {
		APIVersion string `json:"ApiVersion"`
	}
	if err := c.call(octx, versionOp(), &v, http.StatusOK); err != nil {
		return fmt.Errorf("read the Docker Engine API version: %w", err)
	}
	maj, min, ok := parseAPIVersion(v.APIVersion)
	if !ok {
		return fmt.Errorf("the Docker Engine API version %q cannot be read", v.APIVersion)
	}
	if maj < minAPIMajor || maj == minAPIMajor && min < minAPIMinor {
		c.apiErr = fmt.Errorf("the Docker Engine API is %q; version %d.%d or later is required", v.APIVersion, minAPIMajor, minAPIMinor)
	}
	c.apiChecked = true
	return c.apiErr
}

func parseAPIVersion(s string) (major, minor int, ok bool) {
	a, b, found := strings.Cut(s, ".")
	if !found {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(a)
	minor, err2 := strconv.Atoi(b)
	return major, minor, err1 == nil && err2 == nil && major >= 0 && minor >= 0
}

// pullMessage is one JSON line of the /images/create progress stream.
type pullMessage struct {
	Error       string `json:"error"`
	ErrorDetail *struct {
		Message string `json:"message"`
	} `json:"errorDetail"`
}

func (c *WorkClient) pullImage(ctx context.Context) error {
	ctx, cancel := c.withTimeout(ctx, c.cfg.PullTimeout)
	defer cancel()
	op := imageCreateOp(c.repo, c.digest, c.platform)
	resp, err := c.do(ctx, op)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &statusError{op: op, status: resp.StatusCode, body: strings.TrimSpace(string(b))}
	}
	// The daemon answers 200 and reports a failure as a line in the stream.
	dec := json.NewDecoder(io.LimitReader(resp.Body, 64<<20))
	for {
		var m pullMessage
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read pull progress: %w", err)
		}
		if m.Error != "" || m.ErrorDetail != nil {
			msg := m.Error
			if msg == "" && m.ErrorDetail != nil {
				msg = m.ErrorDetail.Message
			}
			return fmt.Errorf("pull %s: %s", c.cfg.Image, msg)
		}
	}
}

// EnsureImage makes the pinned work image available locally, pulling it only
// when it is absent, and verifies it afterwards. A failed pull is an error;
// there is no fallback.
func (c *WorkClient) EnsureImage(ctx context.Context) error {
	if err := c.checkAPI(ctx); err != nil {
		return err
	}
	ok, err := c.checkImage(ctx)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	if err := c.pullImage(ctx); err != nil {
		return err
	}
	ok, err = c.checkImage(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("work image %s is still not available for %s after pull", c.cfg.Image, c.platform)
	}
	return nil
}
