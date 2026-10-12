// Package toolfetch fetches the package managers (npm, pnpm, uv) that update
// jobs run, checks them against the registry and the project's declaration,
// and keeps them in a content-addressed cache. It never unpacks an archive:
// the file it hands out is the registry's, unchanged.
package toolfetch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Defaults of the settings.
const (
	DefaultMinReleaseAge = 72 * time.Hour
	DefaultCacheMaxSize  = 1 << 30
	defaultHoldTTL       = 30 * time.Minute

	// A cycle may start this many fetches and spend this long fetching. A
	// failed fetch counts.
	cycleFetches = 4
	cycleTime    = 5 * time.Minute
)

// Request names one tool to provide.
type Request struct {
	Manager  Manager
	Version  string // exact version
	Platform string // PlatformAmd64 or PlatformArm64
	// NodeVersion is the exact Node.js version the job runs on; "" for uv.
	NodeVersion string
	// SpecHash is the hash the project declared with the version, written
	// "<algorithm>.<hex>", or "".
	SpecHash string
}

// Wrapper describes the second file fetched for pnpm 12, the package that a
// declared hash belongs to.
type Wrapper struct {
	Name           string
	Size           int64
	SHA256, SHA512 string
	RegistryDigest string
}

// Artifact is a verified tool file in the cache.
type Artifact struct {
	Manager Manager
	Version string
	Format  string // FormatNpmTgz or FormatWheel
	Path    string // absolute path of the cached file
	Size    int64
	SHA256  string // hex
	SHA512  string // hex
	// Entry is the executable inside the archive once extracted with the
	// leading package/ of an npm tarball removed.
	Entry       string
	RunWithNode bool
	PublishedAt time.Time
	// RegistryDigest is the registry's digest of the file, "<algo>-<hex>",
	// which the bytes matched.
	RegistryDigest string
	// SpecHashChecked is the declared hash the bytes matched, "" when the
	// project declared none. SpecHashOf says which file it was computed
	// over: "artifact", or "wrapper" for pnpm 12, whose declared hash is that
	// of the pnpm package while the file handed out is the executable
	// package, checked against the registry alone.
	SpecHashChecked string
	SpecHashOf      string
	Wrapper         *Wrapper
}

// Config sets up a Provider.
type Config struct {
	// StorageDir is remediation.storage_dir; the cache lives in its tools
	// directory.
	StorageDir string
	// MinReleaseAge is how long a version must have been published; zero
	// means DefaultMinReleaseAge.
	MinReleaseAge time.Duration
	// CacheMaxSize is the cache's capacity in bytes; zero means
	// DefaultCacheMaxSize.
	CacheMaxSize int64
	// Transport carries the requests; nil means the default transport.
	Transport http.RoundTripper
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Provider provides tools. It is safe for concurrent use.
type Provider struct {
	cache   *cache
	net     *fetcher
	minAge  time.Duration
	now     func() time.Time
	npmBase string
	pypi    string
	// reserve is the room kept for one file whose size is not known before
	// it is downloaded.
	reserve int64

	mu       sync.Mutex
	keyLocks map[string]*sync.Mutex
	// cycleTime is the time a cycle may spend fetching; it runs from the
	// cycle's first fetch.
	cycleTime time.Duration
	started   time.Time
	spent     int
}

// New opens the cache and returns a Provider.
func New(cfg Config) (*Provider, error) {
	if cfg.StorageDir == "" {
		return nil, errors.New("toolfetch: no storage directory")
	}
	if cfg.MinReleaseAge < 0 || cfg.CacheMaxSize < 0 {
		return nil, errors.New("toolfetch: negative setting")
	}
	if cfg.MinReleaseAge == 0 {
		cfg.MinReleaseAge = DefaultMinReleaseAge
	}
	if cfg.CacheMaxSize == 0 {
		cfg.CacheMaxSize = DefaultCacheMaxSize
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	c, err := openCache(filepath.Join(cfg.StorageDir, "tools"), cfg.CacheMaxSize, cfg.Now, defaultHoldTTL)
	if err != nil {
		return nil, fmt.Errorf("toolfetch: %w", err)
	}
	return &Provider{
		cache:     c,
		net:       newFetcher(cfg.Transport, defaultNetPolicy),
		minAge:    cfg.MinReleaseAge,
		now:       cfg.Now,
		npmBase:   "https://registry.npmjs.org",
		pypi:      "https://pypi.org",
		reserve:   maxArtifact,
		keyLocks:  map[string]*sync.Mutex{},
		cycleTime: cycleTime,
	}, nil
}

// NewCycle starts a new fetch budget: the count of fetches goes back to zero
// and the time allowed for fetching starts again with the next fetch. A
// budget is spent only by fetches, never by answers from the cache, and it is
// renewed only by this call; a caller that runs in cycles calls it at the
// start of each.
func (p *Provider) NewCycle() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.started, p.spent = time.Time{}, 0
}

// Release ends the hold a returned Artifact keeps on its file. A hold also
// ends by itself after a while.
func (p *Provider) Release(a Artifact) { p.cache.release(a.SHA256) }

// spend takes one fetch from the budget and returns the time left for
// fetching in the cycle.
func (p *Provider) spend() (time.Duration, *Error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if p.started.IsZero() {
		p.started = now
	}
	if p.spent >= cycleFetches {
		return 0, deferred(CodeFetchBudget, "%d tool fetches were already started in this cycle", cycleFetches)
	}
	left := p.cycleTime - now.Sub(p.started)
	if left <= 0 {
		return 0, deferred(CodeFetchBudget, "the %s a cycle may spend fetching tools are used up", p.cycleTime)
	}
	p.spent++
	return left, nil
}

func (p *Provider) lockFor(key string) *sync.Mutex {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := p.keyLocks[key]
	if m == nil {
		m = &sync.Mutex{}
		p.keyLocks[key] = m
	}
	return m
}

// Provide returns the tool for the request, from the cache when it is there
// and still allowed, and from the registry otherwise. A failure is an
// *Error.
func (p *Provider) Provide(ctx context.Context, req Request) (Artifact, error) {
	a, err := p.provide(ctx, req)
	if err != nil {
		return Artifact{}, err
	}
	return a, nil
}

func (p *Provider) provide(ctx context.Context, req Request) (Artifact, *Error) {
	t, e := resolve(req)
	if e != nil {
		return Artifact{}, e
	}
	algo, wantHex, e := parseSpecHash(req.SpecHash)
	if e != nil {
		return Artifact{}, e
	}
	if algo != "" && t.manager == ManagerUv {
		return Artifact{}, manual(CodeHashUnsupported, "uv takes no declared hash")
	}
	var node version
	if t.manager != ManagerUv {
		var ok bool
		if node, ok = parseExact(req.NodeVersion); !ok {
			return Artifact{}, manual(CodeVersionUnsupported, "the Node.js version %q is not an exact version", req.NodeVersion)
		}
	}
	in := input{t: t, node: node, algo: algo, wantHex: wantHex, platform: req.Platform}
	key := strings.Join([]string{string(t.manager), t.version, req.Platform}, "/")

	mu := p.lockFor(key)
	mu.Lock()
	defer mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Artifact{}, deferred(CodeFetchFailed, "%v", err)
	}
	var have *entry
	if cached, ok := p.cache.lookup(key); ok {
		art, st, e := p.fromCache(key, in, cached)
		switch {
		case e != nil:
			return Artifact{}, e
		case st == cacheHit:
			return art, nil
		case st == cachePartial:
			// The file is good and only a file that was not needed before is
			// missing: the rest is fetched, this stays.
			have = &cached
		}
	}
	return p.fetch(ctx, key, in, have)
}

// input is a request after checking.
type input struct {
	t        target
	node     version
	algo     string
	wantHex  string
	platform string
}
