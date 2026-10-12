package toolfetch

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

type cacheState int

const (
	cacheMiss cacheState = iota
	cacheHit
	// cachePartial: the main file is good, a file only a declared hash needs
	// is not there.
	cachePartial
)

// checkPolicy applies the rules every provided version must meet, whether it
// was fetched now or found in the cache: the versions of the files allow the
// job's Node.js, and they were published long enough ago.
func (p *Provider) checkPolicy(in input, published time.Time, engines []string) *Error {
	if in.t.manager != ManagerUv {
		for _, r := range engines {
			ok, valid := rangeAllows(r, in.node)
			switch {
			case !valid:
				return manual(CodeVersionUnsupported, "engines.node %q of %s %s cannot be read", clip(r), in.t.manager, in.t.version)
			case !ok:
				return manual(CodeVersionUnsupported, "%s %s requires Node.js %q, and the job runs on %s", in.t.manager, in.t.version, clip(r), in.node)
			}
		}
	}
	if published.IsZero() {
		return deferred(CodeTooNew, "the publication time of %s %s is not known", in.t.manager, in.t.version)
	}
	if age := p.now().Sub(published); age < p.minAge {
		return deferred(CodeTooNew, "%s %s was published %s ago; it can be used from %s",
			in.t.manager, in.t.version, age.Round(time.Minute), published.Add(p.minAge).UTC().Format(time.RFC3339))
	}
	return nil
}

func clip(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}

// specTarget says which file a declared hash is computed over.
func (in input) specTarget() string {
	if in.algo == "" {
		return ""
	}
	if in.t.wrapper != nil {
		return "wrapper"
	}
	return "artifact"
}

func (in input) mainAlgo() string {
	if in.specTarget() == "artifact" {
		return in.algo
	}
	return ""
}

func (in input) wrapperAlgo() string {
	if in.specTarget() == "wrapper" {
		return in.algo
	}
	return ""
}

// fromCache checks a cached entry against the request: the files are read
// again and hashed, then the policy is applied to what the registry said when
// they were fetched.
func (p *Provider) fromCache(key string, in input, e entry) (Artifact, cacheState, *Error) {
	if !consistent(e.Main) || (e.Wrapper != nil && !consistent(*e.Wrapper)) {
		p.cache.drop(key)
		return Artifact{}, cacheMiss, nil
	}
	specMain, err := p.cache.verify(e.Main, in.mainAlgo())
	if err != nil {
		p.cache.drop(key)
		return Artifact{}, cacheMiss, nil
	}
	var specWrap string
	if in.wrapperAlgo() != "" {
		if e.Wrapper == nil {
			return Artifact{}, cachePartial, nil
		}
		if specWrap, err = p.cache.verify(*e.Wrapper, in.wrapperAlgo()); err != nil {
			return Artifact{}, cachePartial, nil
		}
	}
	if e := p.checkPolicy(in, e.PublishedAt, e.Engines); e != nil {
		return Artifact{}, cacheMiss, e
	}
	if got := map[string]string{"artifact": specMain, "wrapper": specWrap}[in.specTarget()]; in.algo != "" && got != in.wantHex {
		return Artifact{}, cacheMiss, manual(CodeHashMismatch, "the cached %s %s does not match the declared hash", in.t.manager, in.t.version)
	}
	p.cache.touch(key)
	p.cache.hold(e.Main.SHA256)
	return p.artifact(in, e), cacheHit, nil
}

// consistent reports whether the registry digest a part was checked against
// agrees with the hashes recorded for it.
func consistent(pt part) bool {
	algo, sum, ok := strings.Cut(pt.Integrity, "-")
	if !ok {
		return false
	}
	switch algo {
	case "sha512":
		return sum == pt.SHA512
	case "sha256":
		return sum == pt.SHA256
	}
	return false
}

func (p *Provider) artifact(in input, e entry) Artifact {
	a := Artifact{
		Manager: in.t.manager, Version: in.t.version, Format: in.t.format,
		Path: p.cache.blobPath(e.Main.SHA256), Size: e.Main.Size,
		SHA256: e.Main.SHA256, SHA512: e.Main.SHA512,
		Entry: in.t.entry, RunWithNode: in.t.runNode,
		PublishedAt: e.PublishedAt, RegistryDigest: e.Main.Integrity,
	}
	if in.algo != "" {
		a.SpecHashChecked = in.algo + "." + in.wantHex
		a.SpecHashOf = in.specTarget()
	}
	if e.Wrapper != nil && in.specTarget() == "wrapper" {
		a.Wrapper = &Wrapper{Name: e.Wrapper.Name, Size: e.Wrapper.Size, SHA256: e.Wrapper.SHA256, SHA512: e.Wrapper.SHA512, RegistryDigest: e.Wrapper.Integrity}
	}
	return a
}

// meta is what a registry says about the file of one package version.
type meta struct {
	name      string
	url       string
	algo      string // "sha512" or "sha256"
	sum       string // hex
	published time.Time
	engines   string
	size      int64 // 0 when the registry does not say
}

// fetch gets the metadata, applies the policy, and downloads what is needed.
// have is a cached entry whose main file is good, or nil.
func (p *Provider) fetch(ctx context.Context, key string, in input, have *entry) (Artifact, *Error) {
	left, e := p.spend()
	if e != nil {
		return Artifact{}, e
	}
	// Every request and retry of the fetch runs within what is left of the
	// cycle's time.
	bctx, cancel := context.WithTimeout(ctx, left)
	defer cancel()
	art, e := p.fetchWithin(bctx, key, in, have)
	if e != nil && e.Class == ClassDeferred && e.Code == CodeFetchFailed && bctx.Err() != nil && ctx.Err() == nil {
		return Artifact{}, deferred(CodeFetchBudget, "the time a cycle may spend fetching tools ran out during the fetch of %s %s", in.t.manager, in.t.version)
	}
	return art, e
}

func (p *Provider) fetchWithin(ctx context.Context, key string, in input, have *entry) (Artifact, *Error) {
	t := in.t
	mainMeta, e := p.metadata(ctx, t.main, t.version)
	if e != nil {
		return Artifact{}, e
	}
	published, engines := mainMeta.published, nonEmpty(mainMeta.engines)
	var wrapMeta *meta
	if t.wrapper != nil {
		m, e := p.metadata(ctx, *t.wrapper, t.version)
		if e != nil {
			return Artifact{}, e
		}
		wrapMeta = &m
		if m.published.After(published) {
			published = m.published
		}
		engines = append(engines, nonEmpty(m.engines)...)
	}
	if e := p.checkPolicy(in, published, engines); e != nil {
		return Artifact{}, e
	}

	reuseMain := have != nil && have.Main.Integrity == mainMeta.algo+"-"+mainMeta.sum
	needWrapper := wrapMeta != nil && in.wrapperAlgo() != ""
	reuseWrap := needWrapper && have != nil && have.Wrapper != nil && have.Wrapper.Integrity == wrapMeta.algo+"-"+wrapMeta.sum

	var need int64
	keep := map[string]bool{}
	size := func(m meta) int64 {
		if m.size > 0 {
			return m.size
		}
		return p.reserve
	}
	if reuseMain {
		keep[have.Main.SHA256] = true
	} else {
		need += size(mainMeta)
	}
	if reuseWrap {
		keep[have.Wrapper.SHA256] = true
	} else if needWrapper {
		need += size(*wrapMeta)
	}
	if !p.cache.makeRoom(need, keep) {
		return Artifact{}, deferred(CodeCacheFull, "the tool cache (%d bytes) has no room for %d more bytes and nothing in it can be evicted", p.cache.max, need)
	}

	ent := entry{Manager: t.manager, Version: t.version, Platform: in.platform, PublishedAt: published, Engines: engines}
	if reuseMain {
		ent.Main = have.Main
	} else {
		pt, spec, e := p.acquire(ctx, mainMeta, in.mainAlgo(), t, true)
		if e != nil {
			return Artifact{}, e
		}
		if in.specTarget() == "artifact" && spec != in.wantHex {
			p.discard(pt)
			return Artifact{}, manual(CodeHashMismatch, "%s %s does not match the declared hash", t.manager, t.version)
		}
		ent.Main = pt
	}
	switch {
	case reuseWrap:
		ent.Wrapper = have.Wrapper
	case needWrapper:
		pt, spec, e := p.acquire(ctx, *wrapMeta, in.wrapperAlgo(), t, false)
		if e != nil {
			return Artifact{}, e
		}
		if spec != in.wantHex {
			p.discard(pt)
			return Artifact{}, manual(CodeHashMismatch, "the %s package %s does not match the declared hash", wrapMeta.name, t.version)
		}
		ent.Wrapper = &pt
	}
	if err := p.cache.store(key, ent); err != nil {
		return Artifact{}, deferred(CodeFetchFailed, "the tool cache could not be written: %v", err)
	}
	p.cache.hold(ent.Main.SHA256)
	return p.artifact(in, ent), nil
}

// discard removes a blob that was placed but whose entry is not kept, unless
// the index names it.
func (p *Provider) discard(pt part) {
	p.cache.mu.Lock()
	defer p.cache.mu.Unlock()
	for _, e := range p.cache.idx.Entries {
		if e.Main.SHA256 == pt.SHA256 || (e.Wrapper != nil && e.Wrapper.SHA256 == pt.SHA256) {
			return
		}
	}
	if !p.cache.heldLocked(pt.SHA256) {
		os.Remove(p.cache.blobPath(pt.SHA256))
	}
}

func nonEmpty(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return []string{s}
}

// acquire downloads one file, checks it against the registry's digest, lists
// the archive when it is the main file, and places it in the cache. It
// returns the digest under the declared hash's algorithm when specAlgo is
// given.
func (p *Provider) acquire(ctx context.Context, m meta, specAlgo string, t target, main bool) (part, string, *Error) {
	tmp, err := p.cache.newTmp()
	if err != nil {
		return part{}, "", deferred(CodeFetchFailed, "the tool cache could not be written: %v", err)
	}
	var d digests
	err = retry(ctx, func() error {
		os.Remove(tmp)
		var derr error
		d, derr = p.net.download(ctx, m.url, tmp, maxArtifact, specAlgo)
		return derr
	})
	if err != nil {
		os.Remove(tmp)
		return part{}, "", p.downloadError(err, m)
	}
	got := d.sha512
	if m.algo == "sha256" {
		got = d.sha256
	}
	if got != m.sum {
		os.Remove(tmp)
		return part{}, "", manual(CodeHashMismatch, "%s does not match the %s digest the registry lists", m.name, m.algo)
	}
	if main {
		inspect := inspectTgz
		if t.format == FormatWheel {
			inspect = inspectWheel
		}
		if _, err := inspect(tmp, t.entry); err != nil {
			os.Remove(tmp)
			return part{}, "", manual(CodeArtifactInvalid, "%s %s: %v", m.name, t.version, err)
		}
	}
	if err := p.cache.place(tmp, d.sha256); err != nil {
		os.Remove(tmp)
		return part{}, "", deferred(CodeFetchFailed, "the tool cache could not be written: %v", err)
	}
	return part{Name: m.name, Size: d.size, SHA256: d.sha256, SHA512: d.sha512, Integrity: m.algo + "-" + m.sum}, d.spec, nil
}

func (p *Provider) downloadError(err error, m meta) *Error {
	var se *httpStatusError
	switch {
	case errors.Is(err, errTooLarge):
		return manual(CodeArtifactInvalid, "%s is larger than %d bytes", m.name, int64(maxArtifact))
	case errors.As(err, &se) && se.status == 404:
		return manual(CodeVersionNotFound, "the file of %s is not at the address the registry lists", m.name)
	}
	return deferred(CodeFetchFailed, "downloading %s: %v", m.name, err)
}

// metadata reads the registry's document for the version and the time it was
// published.
func (p *Provider) metadata(ctx context.Context, src source, ver string) (meta, *Error) {
	if src.registry == "pypi" {
		return p.pypiMeta(ctx, src, ver)
	}
	return p.npmMeta(ctx, src, ver)
}

func (p *Provider) lookupError(err error, what string) *Error {
	var se *httpStatusError
	switch {
	case errors.As(err, &se) && se.status == 404:
		return manual(CodeVersionNotFound, "%s is not in the registry", what)
	case errors.Is(err, errTooLarge):
		return manual(CodeMetadataInvalid, "the registry's document for %s is over its size limit", what)
	}
	var syn *jsonError
	if errors.As(err, &syn) {
		return manual(CodeMetadataInvalid, "the registry's document for %s cannot be read", what)
	}
	return deferred(CodeFetchFailed, "reading the registry's document for %s: %v", what, err)
}

func (p *Provider) getJSON(ctx context.Context, rawURL string, limit int64, into any) error {
	return retry(ctx, func() error { return p.net.getJSON(ctx, rawURL, limit, into) })
}

func (p *Provider) npmMeta(ctx context.Context, src source, ver string) (meta, *Error) {
	what := src.name + "@" + ver
	esc := url.PathEscape(src.name)
	var doc struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Dist    struct {
			Tarball   string `json:"tarball"`
			Integrity string `json:"integrity"`
		} `json:"dist"`
		Engines map[string]any `json:"engines"`
	}
	if err := p.getJSON(ctx, p.npmBase+"/"+esc+"/"+url.PathEscape(ver), maxVersionDoc, &doc); err != nil {
		return meta{}, p.lookupError(err, what)
	}
	if doc.Name != src.name || doc.Version != ver {
		return meta{}, manual(CodeMetadataInvalid, "the registry's document for %s names %s@%s", what, doc.Name, doc.Version)
	}
	sum, ok := decodeIntegrity(doc.Dist.Integrity)
	if !ok {
		return meta{}, manual(CodeMetadataInvalid, "the registry lists no sha512 integrity for %s", what)
	}
	tb, err := url.Parse(doc.Dist.Tarball)
	if err != nil || p.net.policy.check(tb) != nil {
		return meta{}, manual(CodeMetadataInvalid, "the registry lists a file address for %s that is not allowed", what)
	}
	m := meta{name: src.name, url: doc.Dist.Tarball, algo: "sha512", sum: sum}
	if v, ok := doc.Engines["node"].(string); ok {
		m.engines = v
	}
	var pack struct {
		Time map[string]string `json:"time"`
	}
	if err := p.getJSON(ctx, p.npmBase+"/"+esc, maxPackument, &pack); err != nil {
		return meta{}, p.lookupError(err, src.name)
	}
	if ts, ok := pack.Time[ver]; ok {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			m.published = t
		}
	}
	return m, nil
}

func (p *Provider) pypiMeta(ctx context.Context, src source, ver string) (meta, *Error) {
	what := src.name + " " + ver
	var doc struct {
		Info struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"info"`
		URLs []struct {
			Filename    string `json:"filename"`
			URL         string `json:"url"`
			Size        int64  `json:"size"`
			Yanked      bool   `json:"yanked"`
			PackageType string `json:"packagetype"`
			UploadISO   string `json:"upload_time_iso_8601"`
			UploadTime  string `json:"upload_time"`
			Digests     struct {
				SHA256 string `json:"sha256"`
			} `json:"digests"`
		} `json:"urls"`
	}
	if err := p.getJSON(ctx, p.pypi+"/pypi/"+url.PathEscape(src.name)+"/"+url.PathEscape(ver)+"/json", maxVersionDoc, &doc); err != nil {
		return meta{}, p.lookupError(err, what)
	}
	if doc.Info.Version != ver {
		return meta{}, manual(CodeMetadataInvalid, "the registry's document for %s names version %s", what, doc.Info.Version)
	}
	want := wheelName(src.name, ver, src.platform)
	var found []int
	for i, f := range doc.URLs {
		if f.PackageType == "bdist_wheel" && wheelMatches(f.Filename, want) {
			found = append(found, i)
		}
	}
	if len(found) != 1 {
		return meta{}, manual(CodeVersionNotFound, "%s has %d wheels for %s, not one", what, len(found), src.platform)
	}
	f := doc.URLs[found[0]]
	if f.Yanked {
		return meta{}, manual(CodeVersionUnsupported, "%s is yanked", what)
	}
	if len(f.Digests.SHA256) != 64 {
		return meta{}, manual(CodeMetadataInvalid, "the registry lists no sha256 for %s", f.Filename)
	}
	if _, err := hex.DecodeString(f.Digests.SHA256); err != nil {
		return meta{}, manual(CodeMetadataInvalid, "the registry lists no sha256 for %s", f.Filename)
	}
	fu, err := url.Parse(f.URL)
	if err != nil || p.net.policy.check(fu) != nil {
		return meta{}, manual(CodeMetadataInvalid, "the registry lists a file address for %s that is not allowed", f.Filename)
	}
	if f.Size > maxArtifact {
		return meta{}, manual(CodeArtifactInvalid, "%s is %d bytes, over %d", f.Filename, f.Size, int64(maxArtifact))
	}
	m := meta{name: f.Filename, url: f.URL, algo: "sha256", sum: strings.ToLower(f.Digests.SHA256), size: f.Size}
	if f.UploadISO != "" {
		if t, err := time.Parse(time.RFC3339, f.UploadISO); err == nil {
			m.published = t
		}
	}
	if m.published.IsZero() && f.UploadTime != "" {
		if t, err := time.Parse("2006-01-02T15:04:05", f.UploadTime); err == nil {
			m.published = t.UTC()
		}
	}
	return m, nil
}

// wheelName is the platform tag set the wheel for a platform must have.
func wheelName(name, ver, platform string) string {
	tag := "manylinux_2_17_x86_64"
	if platform == PlatformArm64 {
		tag = "manylinux_2_28_aarch64"
	}
	return fmt.Sprintf("%s-%s-py3-none-%s", name, ver, tag)
}

// wheelMatches reports whether a file name is the wheel wanted: the same
// name, version and tags up to the platform, where the platform tags (joined
// by dots) include the one wanted and no musl tag.
func wheelMatches(file, want string) bool {
	base, ok := strings.CutSuffix(file, ".whl")
	if !ok {
		return false
	}
	i := strings.LastIndex(want, "-")
	prefix, tag := want[:i+1], want[i+1:]
	rest, ok := strings.CutPrefix(base, prefix)
	if !ok {
		return false
	}
	has := false
	for _, t := range strings.Split(rest, ".") {
		if strings.HasPrefix(t, "musllinux") {
			return false
		}
		has = has || t == tag
	}
	return has
}
