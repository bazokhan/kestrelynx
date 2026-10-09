package remediation

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func hex64(c byte) string { return strings.Repeat(string(c), 64) }

func configKey(c byte) inventory.EntityKey {
	d, _ := inventory.ParseDigest(inventory.DigestConfig, "sha256:"+hex64(c))
	return inventory.EntityKey{Digest: d}
}

var linuxAmd64 = inventory.Platform{OS: "linux", Architecture: "amd64"}

func testConds(db string) scanner.ScanConditions {
	t := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	return scanner.ScanConditions{
		TrivyVersion:       "0.71.2",
		VulnerabilityDB:    scanner.DBInfo{Version: 2, UpdatedAt: t},
		JavaDB:             scanner.DBInfo{Version: 1, UpdatedAt: t},
		Severities:         []string{"CRITICAL", "HIGH"},
		AnalysisSettings:   "image;test",
		VulnerabilityDBSHA: db,
		JavaDBSHA:          "j",
		TrivySHA:           "t",
	}
}

func finding(vuln, pkg, ver, fixed string, sev scanner.Severity) scanner.Finding {
	st := scanner.StatusFixed
	if fixed == "" {
		st = scanner.StatusAffected
	}
	return scanner.Finding{
		Class: inventory.ClassOS, Type: "debian", Target: "img (debian 12)",
		Package: pkg, InstalledVer: ver, FixedVer: fixed, Status: st, Severity: sev, VulnID: vuln,
	}
}

func pkgs(pairs ...string) []scanner.ResultPackages {
	rp := scanner.ResultPackages{Target: "img (debian 12)", Class: inventory.ClassOS, Type: "debian"}
	for i := 0; i+1 < len(pairs); i += 2 {
		rp.Packages = append(rp.Packages, scanner.Package{Name: pairs[i], Version: pairs[i+1]})
	}
	return []scanner.ResultPackages{rp}
}

// configScan is a successful, pinned baseline scan of a local image.
func configScan(ref string, h byte, fs []scanner.Finding, pk []scanner.ResultPackages) scanner.ImageScan {
	key := configKey(h)
	return scanner.ImageScan{
		Image: ref, OSFamily: "debian", Findings: fs, Packages: pk, Platform: linuxAmd64, Pinned: true, Source: scanner.SourceLocal,
		Subject:    inventory.ImageSubject{Ref: ref, Key: key, Resolved: true},
		ScannedKey: key,
	}
}

// remoteScan is the successful result of scanning target.
func remoteScan(target scanner.ScanTarget, fs []scanner.Finding, pk []scanner.ResultPackages) scanner.ImageScan {
	return scanner.ImageScan{
		Image: target.Subject.Ref, OSFamily: "debian", Findings: fs, Packages: pk, Platform: target.Subject.Key.Platform, Pinned: true,
		Source: scanner.SourceRemote, Subject: target.Subject, ScannedKey: target.Subject.Key,
	}
}

type fakeRegistry struct {
	mu         sync.Mutex
	tags       map[string]registry.TagList
	tagErr     map[string]error
	res        map[string]registry.Resolution // key "repo:tag"
	resErr     map[string]error
	listCalls  int
	allowances []int
	errPages   map[string]int // pages consumed before a listing error
	resolveCnt map[string]int
}

func newFakeRegistry() *fakeRegistry {
	return &fakeRegistry{
		tags: map[string]registry.TagList{}, tagErr: map[string]error{}, errPages: map[string]int{},
		res: map[string]registry.Resolution{}, resErr: map[string]error{}, resolveCnt: map[string]int{},
	}
}

// ListTagsUpTo serves the configured list, cut to the allowance the way the
// real client does.
func (f *fakeRegistry) ListTagsUpTo(_ context.Context, repo string, maxPages int) (registry.TagList, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	f.allowances = append(f.allowances, maxPages)
	if err := f.tagErr[repo]; err != nil {
		return registry.TagList{Pages: f.errPages[repo]}, err
	}
	l := f.tags[repo]
	if l.Pages > maxPages {
		l.Tags, l.Truncated, l.Pages = nil, true, maxPages
	}
	return l, nil
}

func (f *fakeRegistry) Resolve(_ context.Context, repo, ref string, _ inventory.Platform) (registry.Resolution, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := repo + ":" + ref
	f.resolveCnt[k]++
	if err := f.resErr[k]; err != nil {
		return registry.Resolution{}, err
	}
	r, ok := f.res[k]
	if !ok {
		return registry.Resolution{}, registry.ErrNotFound
	}
	return r, nil
}

func resolution(manifest, config byte) registry.Resolution {
	return registry.Resolution{
		TopDigest: "sha256:" + hex64('0'), TopMediaType: "application/vnd.oci.image.index.v1+json",
		ManifestDigest: "sha256:" + hex64(manifest), ConfigDigest: "sha256:" + hex64(config), PlatformVerified: true,
	}
}

type fakeScanner struct {
	mu       sync.Mutex
	scans    map[string]func(scanner.ScanTarget) scanner.ImageScan // by Subject.Ref
	calls    []string
	verifyOK bool
	verifyEr error
}

func newFakeScanner() *fakeScanner {
	return &fakeScanner{scans: map[string]func(scanner.ScanTarget) scanner.ImageScan{}, verifyOK: true}
}

func (f *fakeScanner) Scan(_ context.Context, t scanner.ScanTarget) scanner.ImageScan {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, t.Subject.Ref)
	fn, ok := f.scans[t.Subject.Ref]
	if !ok {
		return scanner.ImageScan{Image: t.Subject.Ref, Subject: t.Subject, Err: context.Canceled}
	}
	return fn(t)
}

func (f *fakeScanner) VerifyDB(context.Context, scanner.ScanConditions) (bool, error) {
	return f.verifyOK, f.verifyEr
}
