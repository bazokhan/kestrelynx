package toolfetch

import (
	"context"
	"crypto/sha1" //nolint:gosec // a declared hash may be written with any of the algorithms package managers accept
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Limits on what is read from and fetched from the registries.
const (
	maxVersionDoc  = 2 << 20  // a version's document, after decompression
	maxPackument   = 32 << 20 // a full packument, after decompression
	maxArtifact    = 64 << 20 // a file as downloaded
	maxExpanded    = 160 << 20
	maxArchiveFile = 5000
	maxRedirects   = 5

	metadataTimeout = 30 * time.Second
	downloadTimeout = 3 * time.Minute
)

// allowedHosts are the only hosts a request or a redirect may go to.
var allowedHosts = map[string]bool{
	"registry.npmjs.org":     true,
	"pypi.org":               true,
	"files.pythonhosted.org": true,
}

// netPolicy decides which addresses may be requested. Tests widen it to reach
// a local server; the zero value is not used.
type netPolicy struct {
	hosts map[string]bool
	port  string // the only port allowed
}

var defaultNetPolicy = netPolicy{hosts: allowedHosts, port: "443"}

// check refuses an address that is not HTTPS on the allowed port of an
// allowed host, or that carries credentials.
func (p netPolicy) check(u *url.URL) error {
	if u.Scheme != "https" {
		return refuse("%s is not HTTPS", redact(u))
	}
	if u.User != nil {
		return refuse("%s carries credentials", redact(u))
	}
	if port := u.Port(); port != "" && port != p.port {
		return refuse("%s uses port %s", redact(u), port)
	}
	if port := u.Port(); port == "" && p.port != "443" {
		return refuse("%s uses port 443", redact(u))
	}
	host := strings.ToLower(u.Hostname())
	if !p.hosts[host] {
		return refuse("host %s is not allowed", host)
	}
	return nil
}

// refusedError is an address the policy does not allow; it is never retried.
type refusedError struct{ msg string }

func (e *refusedError) Error() string { return e.msg }

func refuse(format string, args ...any) error { return &refusedError{fmt.Sprintf(format, args...)} }

func redact(u *url.URL) string {
	c := *u
	c.User = nil
	c.RawQuery = ""
	return c.String()
}

// fetcher makes the HTTP requests, within the address policy.
type fetcher struct {
	client *http.Client
	policy netPolicy
}

func newFetcher(rt http.RoundTripper, p netPolicy) *fetcher {
	if rt == nil {
		rt = http.DefaultTransport
	}
	f := &fetcher{policy: p}
	f.client = &http.Client{
		Transport: rt,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return refuse("more than %d redirects", maxRedirects)
			}
			return f.policy.check(req.URL)
		},
	}
	return f
}

// httpStatusError is a response other than 200.
type httpStatusError struct {
	status int
	url    string
}

func (e *httpStatusError) Error() string { return fmt.Sprintf("%s answered %d", e.url, e.status) }

// errTooLarge means a body went over its limit.
var errTooLarge = errors.New("body over its size limit")

// open starts a GET. The caller closes the body and cancels the context's
// timeout through the returned cancel.
func (f *fetcher) open(ctx context.Context, rawURL string, timeout time.Duration, identity bool) (*http.Response, context.CancelFunc, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, err
	}
	if err := f.policy.check(u); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "kestrelynx-toolfetch")
	if identity {
		// The bytes are hashed as served, so no transfer decoding is wanted.
		req.Header.Set("Accept-Encoding", "identity")
	} else {
		req.Header.Set("Accept", "application/json")
	}
	resp, err := f.client.Do(req)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		return nil, nil, &httpStatusError{status: resp.StatusCode, url: redact(u)}
	}
	return resp, cancel, nil
}

// getJSON reads a JSON document of at most limit bytes after decompression.
func (f *fetcher) getJSON(ctx context.Context, rawURL string, limit int64, into any) error {
	resp, cancel, err := f.open(ctx, rawURL, metadataTimeout, false)
	if err != nil {
		return err
	}
	defer cancel()
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return errTooLarge
	}
	if err := json.Unmarshal(data, into); err != nil {
		return &jsonError{err}
	}
	return nil
}

// jsonError is a document that is not the JSON that was expected.
type jsonError struct{ error }

// digests are the hashes computed over a downloaded file.
type digests struct {
	size   int64
	sha256 string
	sha512 string
	spec   string // hex under the declared hash's algorithm, "" when none
}

// download writes the body to dst (created exclusively, mode 0600) and hashes
// it. It stops at limit bytes.
func (f *fetcher) download(ctx context.Context, rawURL, dst string, limit int64, specAlgo string) (digests, error) {
	var d digests
	resp, cancel, err := f.open(ctx, rawURL, downloadTimeout, true)
	if err != nil {
		return d, err
	}
	defer cancel()
	defer resp.Body.Close()
	if resp.ContentLength > limit {
		return d, errTooLarge
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return d, err
	}
	h256, h512 := sha256.New(), sha512.New()
	hs := []io.Writer{out, h256, h512}
	var hSpec hash.Hash
	if specAlgo != "" {
		hSpec = newHash(specAlgo)
		hs = append(hs, hSpec)
	}
	n, err := io.Copy(io.MultiWriter(hs...), io.LimitReader(resp.Body, limit+1))
	cerr := out.Close()
	switch {
	case err != nil:
		os.Remove(dst)
		return d, err
	case cerr != nil:
		os.Remove(dst)
		return d, cerr
	case n > limit:
		os.Remove(dst)
		return d, errTooLarge
	}
	d.size, d.sha256, d.sha512 = n, hex.EncodeToString(h256.Sum(nil)), hex.EncodeToString(h512.Sum(nil))
	if hSpec != nil {
		d.spec = hex.EncodeToString(hSpec.Sum(nil))
	}
	return d, nil
}

// specAlgos are the algorithms a declared hash may use, with the length of
// their hex digests.
var specAlgos = map[string]int{"sha1": 40, "sha224": 56, "sha256": 64, "sha384": 96, "sha512": 128}

func newHash(algo string) hash.Hash {
	switch algo {
	case "sha1":
		return sha1.New() //nolint:gosec
	case "sha224":
		return sha256.New224()
	case "sha256":
		return sha256.New()
	case "sha384":
		return sha512.New384()
	}
	return sha512.New()
}

// parseSpecHash reads "<algo>.<hex>". algo is "" for no hash.
func parseSpecHash(s string) (algo, hexsum string, err *Error) {
	if s == "" {
		return "", "", nil
	}
	algo, hexsum, ok := strings.Cut(s, ".")
	n, known := specAlgos[algo]
	if !ok || !known || len(hexsum) != n {
		return "", "", manual(CodeHashUnsupported, "the declared hash is not written as <algorithm>.<hex> with sha1, sha224, sha256, sha384 or sha512")
	}
	hexsum = strings.ToLower(hexsum)
	if _, e := hex.DecodeString(hexsum); e != nil {
		return "", "", manual(CodeHashUnsupported, "the declared hash is not hexadecimal")
	}
	return algo, hexsum, nil
}

// decodeIntegrity reads an npm "sha512-<base64>" integrity into hex.
func decodeIntegrity(s string) (string, bool) {
	rest, ok := strings.CutPrefix(s, "sha512-")
	if !ok {
		return "", false
	}
	b, err := base64.StdEncoding.DecodeString(rest)
	if err != nil || len(b) != sha512.Size {
		return "", false
	}
	return hex.EncodeToString(b), true
}

// transient reports a failure that is the registry's or the network's and
// may pass: it is retried once and, if it persists, deferred.
func transient(err error) bool {
	var rf *refusedError
	if errors.As(err, &rf) {
		return false
	}
	var se *httpStatusError
	if errors.As(err, &se) {
		return se.status >= 500 || se.status == http.StatusTooManyRequests || se.status == http.StatusRequestTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	return errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, context.DeadlineExceeded)
}

// retry runs op, and once more when it failed in a way that may pass.
func retry(ctx context.Context, op func() error) error {
	err := op()
	if err != nil && transient(err) && ctx.Err() == nil {
		select {
		case <-time.After(500 * time.Millisecond):
		case <-ctx.Done():
			return err
		}
		return op()
	}
	return err
}
