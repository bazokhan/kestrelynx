package remediation

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/registry"
)

// sortedPager serves ListTagsAfter over a fixed tag set the way a registry
// that lists in ascending order does: the tags after last, at most n.
type sortedPager struct {
	mu       sync.Mutex
	tags     []string // sorted
	calls    []string // the last arguments of each request
	pageSize int      // the page size the registry caps n at, 0 for n
	// dropsFirst makes the registry behave like docker.elastic.co: when last
	// is not itself a tag, the first tag after it is left out of the answer.
	dropsFirst bool
	// misbehave, when set, replaces the answer.
	misbehave func(last string, n int) []string
	err       error
	errAfter  int // requests answered before err
}

func newSortedPager(tags []string) *sortedPager {
	s := append([]string(nil), tags...)
	sort.Strings(s)
	return &sortedPager{tags: s}
}

func (p *sortedPager) ListTagsAfter(_ context.Context, _ string, last string, n int) (registry.TagsAfter, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil && len(p.calls) >= p.errAfter {
		p.calls = append(p.calls, last)
		return registry.TagsAfter{Sent: true}, p.err
	}
	p.calls = append(p.calls, last)
	if p.misbehave != nil {
		t := p.misbehave(last, n)
		return registry.TagsAfter{Tags: t, More: len(t) >= n, Sent: true}, nil
	}
	if p.pageSize > 0 && n > p.pageSize {
		n = p.pageSize
	}
	i := sort.SearchStrings(p.tags, last)
	if i < len(p.tags) && p.tags[i] == last {
		i++ // last is a tag: the answer starts after it
	} else if p.dropsFirst && last != "" && i < len(p.tags) {
		i++
	}
	rest := p.tags[i:]
	more := len(rest) > n
	if len(rest) > n {
		rest = rest[:n]
	}
	return registry.TagsAfter{Tags: append([]string(nil), rest...), More: more, Sent: true}, nil
}

func (p *sortedPager) requests() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

func tv(t *testing.T, tag string) TagVersion {
	t.Helper()
	v, ok := ParseTagVersion(tag)
	if !ok {
		t.Fatalf("%q is not a pinned tag", tag)
	}
	return v
}

func TestTagBefore(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"8.19.0", "8.19./~"},
		{"8.19.160", "8.19.16/~"},
		{"1.25.3-alpine", "1.25.3-alpind~"},
	} {
		if got := tagBefore(c.in); got != c.want {
			t.Errorf("tagBefore(%q) = %q, want %q", c.in, got, c.want)
		}
		if !(tagBefore(c.in) < c.in) {
			t.Errorf("tagBefore(%q) = %q does not sort before it", c.in, tagBefore(c.in))
		}
	}
	// Everything valid below x sorts at or below tagBefore(x).
	for _, below := range []string{"8.19.", "8.19.-", "8.19.0", "8.19.0-x", "8.18.9", "8.19"} {
		if !(below < tagBefore("8.19.1")) {
			t.Errorf("%q should sort before %q", below, tagBefore("8.19.1"))
		}
	}
}

// elasticLike has, for each patch of 8.19, the release tag and a few hundred
// build tags that sort right after it, as docker.elastic.co does.
func elasticLike() []string {
	var tags []string
	for p := 0; p <= 17; p++ {
		if p <= 16 {
			tags = append(tags, fmt.Sprintf("8.19.%d", p))
		}
		for i := 0; i < 300; i++ {
			tags = append(tags, fmt.Sprintf("8.19.%d-%08x-SNAPSHOT", p, i*7919+p))
		}
	}
	for p := 0; p <= 12; p++ {
		tags = append(tags, fmt.Sprintf("8.18.%d", p), fmt.Sprintf("8.18.%d-aaaa-SNAPSHOT", p), fmt.Sprintf("8.20.%d-bbbb-SNAPSHOT", p))
	}
	tags = append(tags, "7.17.29", "9.0.0", "latest", "8.19", "8.19-SNAPSHOT", "8.190.1", "8.2.0")
	return tags
}

// registryKinds are the two ways a registry answers "after last" when last is
// not a tag: correctly, and the way docker.elastic.co does, which leaves out
// the first tag that follows.
var registryKinds = map[string]bool{"exact": false, "drops the first tag after a position": true}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func TestWalkSeriesReadsOnlyTheNeighbourhood(t *testing.T) {
	for kind, drops := range registryKinds {
		pager := newSortedPager(elasticLike())
		pager.dropsFirst = drops
		w, err := walkSeries(context.Background(), pager, "r", tv(t, "8.19.16"), 40)
		if err != nil {
			t.Fatal(err)
		}
		if !w.complete || w.unreliable {
			t.Fatalf("%s: walk = %+v, want complete", kind, w)
		}
		var want []string
		for p := 0; p <= 16; p++ {
			want = append(want, fmt.Sprintf("8.19.%d", p))
		}
		if !reflect.DeepEqual(sortedStrings(w.tags), sortedStrings(want)) {
			t.Errorf("%s: tags = %v, want %v", kind, sortedStrings(w.tags), sortedStrings(want))
		}
		// About 5.4 thousand series tags and a few others: 6 pages, not the
		// 6 pages of every earlier version as well.
		if w.requests > 7 {
			t.Errorf("%s: %d requests", kind, w.requests)
		}
		if sel := SelectPinned(tv(t, "8.19.16"), registry.TagList{Tags: w.tags}); sel.Outcome != SelectionNone {
			t.Errorf("%s: selection = %+v, want none (8.19.17 exists only as snapshots)", kind, sel)
		}
	}
}

func TestWalkSeriesFindsNewerPatchAmongSnapshots(t *testing.T) {
	tags := append(elasticLike(), "8.19.17", "8.19.23")
	for kind, drops := range registryKinds {
		pager := newSortedPager(tags)
		pager.dropsFirst = drops
		w, err := walkSeries(context.Background(), pager, "r", tv(t, "8.19.16"), 40)
		if err != nil || !w.complete {
			t.Fatalf("%s: walk = %+v, %v", kind, w, err)
		}
		if sel := SelectPinned(tv(t, "8.19.16"), registry.TagList{Tags: w.tags}); sel.Outcome != SelectionFound || sel.Tag != "8.19.23" {
			t.Errorf("%s: selection = %+v, want 8.19.23", kind, sel)
		}
	}
}

func TestWalkSeriesDigitCounts(t *testing.T) {
	tags := []string{"8.19.1", "8.19.2", "8.19.20", "8.19.200", "8.19.3", "8.19.30", "8.19.9", "8.19.10", "8.19.100",
		"8.19.2-x", "8.19.20-x", "8.19.200-x-SNAPSHOT", "8.18.99", "8.20.0"}
	for kind, drops := range registryKinds {
		pager := newSortedPager(tags)
		pager.dropsFirst = drops
		w, err := walkSeries(context.Background(), pager, "r", tv(t, "8.19.2"), 40)
		if err != nil || !w.complete {
			t.Fatalf("%s: walk = %+v, %v", kind, w, err)
		}
		sel := SelectPinned(tv(t, "8.19.2"), registry.TagList{Tags: w.tags})
		if sel.Outcome != SelectionFound || sel.Tag != "8.19.200" {
			t.Errorf("%s: selection = %+v, want 8.19.200 (numeric, not lexical)", kind, sel)
		}
		want := []string{"8.19.1", "8.19.10", "8.19.100", "8.19.2", "8.19.20", "8.19.200", "8.19.3", "8.19.30", "8.19.9"}
		if !reflect.DeepEqual(sortedStrings(w.tags), want) {
			t.Errorf("%s: tags = %v, want %v", kind, sortedStrings(w.tags), want)
		}
	}
}

func TestWalkSeriesSuffixAndPrefix(t *testing.T) {
	tags := []string{"1.25.2-alpine", "1.25.3", "1.25.3-alpine", "1.25.3-alpine-perl", "1.25.3-alpine3.18", "1.25.3-bookworm",
		"1.25.4", "1.25.4-alpine", "1.25.4-alpine-slim", "1.25.40-alpine", "1.25.5-aaa", "1.25.5-alpine", "1.25.6-bookworm", "1.26.0-alpine",
		"v2.4.1", "v2.4.2", "w2.4.9"}
	for kind, drops := range registryKinds {
		pager := newSortedPager(tags)
		pager.dropsFirst = drops
		w, err := walkSeries(context.Background(), pager, "r", tv(t, "1.25.3-alpine"), 40)
		if err != nil || !w.complete {
			t.Fatalf("%s: walk = %+v, %v", kind, w, err)
		}
		want := []string{"1.25.2-alpine", "1.25.3-alpine", "1.25.4-alpine", "1.25.40-alpine", "1.25.5-alpine"}
		if !reflect.DeepEqual(w.tags, want) {
			t.Errorf("%s: tags = %v, want %v", kind, w.tags, want)
		}
		pager = newSortedPager(tags)
		pager.dropsFirst = drops
		w, err = walkSeries(context.Background(), pager, "r", tv(t, "v2.4.1"), 40)
		if err != nil || !w.complete || !reflect.DeepEqual(w.tags, []string{"v2.4.1", "v2.4.2"}) {
			t.Errorf("%s: prefixed walk = %+v, %v", kind, w, err)
		}
	}
}

// TestWalkSeriesKeepsTheFirstTagOfTheSeries is the case a registry that drops
// a tag after a position would break: the series starts with a release tag,
// and there is nothing of an earlier version to absorb the loss.
func TestWalkSeriesKeepsTheFirstTagOfTheSeries(t *testing.T) {
	for name, tags := range map[string][]string{
		"only the series":              {"8.19.1", "8.19.2", "8.19.3"},
		"only a later version beside":  {"8.19.1", "8.19.2", "9.0.0"},
		"the one tag of the series":    {"8.19.1"},
		"earlier minor far away":       {"8.3.0", "8.19.10", "8.19.2", "8.20.1"},
		"previous minor has one tag":   {"8.18.1", "8.19.10", "8.19.2", "8.20.1"},
		"older minors are all missing": {"7.17.9", "8.19.10", "8.19.2"},
	} {
		pager := newSortedPager(tags)
		pager.dropsFirst = true
		w, err := walkSeries(context.Background(), pager, "r", tv(t, "8.19.1"), 40)
		if err != nil || !w.complete {
			t.Fatalf("%s: walk = %+v, %v", name, w, err)
		}
		var want []string
		for _, tg := range tags {
			if inSeries(tg, tv(t, "8.19.1")) {
				want = append(want, tg)
			}
		}
		if !reflect.DeepEqual(sortedStrings(w.tags), sortedStrings(want)) {
			t.Errorf("%s: tags = %v, want %v (calls %v)", name, sortedStrings(w.tags), sortedStrings(want), pager.calls)
		}
	}
}

// TestWalkSeriesAgainstFullListing checks the walk against reading
// everything, over many random listings full of near misses, for both kinds
// of registry and for registries that cap the page size.
func TestWalkSeriesAgainstFullListing(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	tails := []string{"", "", "-x", "-alpine", "-alpine3", "-alpine-perl", "-aaa", "-zzz", ".1", ".10", "rc1", "a", "_x", "-SNAPSHOT", "-0abc-SNAPSHOT", "A"}
	digits := []string{"0", "1", "2", "9", "10", "16", "17", "19", "20", "99", "100", "109", "190", "200", "1000", "016", ""}
	for iter := 0; iter < 600; iter++ {
		suffix := []string{"", "-alpine"}[rng.Intn(2)]
		prefix := []string{"", "v"}[rng.Intn(2)]
		minor := rng.Intn(25)
		cur := TagVersion{Prefix: prefix, Major: 8, Minor: minor, Patch: rng.Intn(30), Suffix: suffix}
		var tags []string
		for i := 0; i < 20+rng.Intn(200); i++ {
			m := minor
			switch rng.Intn(5) {
			case 0:
				m = minor - 1 - rng.Intn(4)
			case 1:
				m = minor + 1 + rng.Intn(3)
			}
			if m < 0 {
				m = minor
			}
			switch rng.Intn(8) {
			case 0:
				tags = append(tags, fmt.Sprintf("%s8.%d%s", prefix, m, tails[rng.Intn(len(tails))]))
			case 1:
				tags = append(tags, fmt.Sprintf("%d.0.%s", 7+rng.Intn(3), digits[rng.Intn(len(digits))]))
			default:
				tags = append(tags, fmt.Sprintf("%s8.%d.%s%s", prefix, m, digits[rng.Intn(len(digits))], tails[rng.Intn(len(tails))]))
				if rng.Intn(3) == 0 {
					tags = append(tags, fmt.Sprintf("%s8.%d.%s%s", prefix, m, digits[rng.Intn(len(digits))], suffix))
				}
			}
		}
		seen := map[string]bool{}
		uniq := tags[:0]
		for _, tg := range tags {
			if !seen[tg] {
				seen[tg] = true
				uniq = append(uniq, tg)
			}
		}
		var want []string
		for _, tg := range uniq {
			if inSeries(tg, cur) {
				want = append(want, tg)
			}
		}
		want = sortedStrings(want)
		for kind, drops := range registryKinds {
			pager := newSortedPager(uniq)
			pager.dropsFirst = drops
			pager.pageSize = []int{0, 1, 3, 7, 50}[rng.Intn(5)]
			w, err := walkSeries(context.Background(), pager, "r", cur, 100000)
			if err != nil || !w.complete || w.unreliable {
				t.Fatalf("iter %d (%s): walk = %+v, %v", iter, kind, w, err)
			}
			got := sortedStrings(w.tags)
			if !reflect.DeepEqual(got, want) && !(len(got) == 0 && len(want) == 0) {
				t.Fatalf("iter %d (%s): cur=%v\nwalk found   %v\nlisting has %v\ntags=%v\ncalls=%q", iter, kind, cur, got, want, uniq, pager.calls)
			}
		}
	}
}

func TestWalkSeriesLimitLeavesItIncomplete(t *testing.T) {
	w, err := walkSeries(context.Background(), newSortedPager(elasticLike()), "r", tv(t, "8.19.16"), 2)
	if err != nil {
		t.Fatal(err)
	}
	if w.complete || w.requests != 2 {
		t.Errorf("walk = %+v, want 2 requests and not complete", w)
	}
	list, err := listPinnedSeries(context.Background(), seriesRegistry{newFakeRegistry(), newSortedPager(elasticLike())}, "r", tv(t, "8.19.16"), 2)
	if err != nil || !list.Truncated || list.Pages != 2 {
		t.Errorf("list = %+v, %v; want truncated after 2 requests", list, err)
	}
	if SelectPinned(tv(t, "8.19.16"), list).Outcome != SelectionIncomplete {
		t.Error("a walk cut short must not read as no candidate")
	}
}

func TestWalkSeriesOrderBreaks(t *testing.T) {
	for name, mis := range map[string]func(last string, n int) []string{
		"list ignores last":    func(string, int) []string { return []string{"1.0.0", "8.19.1", "8.19.2"} },
		"descending":           func(string, int) []string { return []string{"8.18.5", "8.18.4"} },
		"repeats the last tag": func(last string, _ int) []string { return []string{last} },
		"descends later":       func(string, int) []string { return []string{"8.18.4", "8.19.5", "8.19.4"} },
	} {
		w, err := walkSeries(context.Background(), &sortedPager{misbehave: mis}, "r", tv(t, "8.19.2"), 10)
		if err != nil || !w.unreliable || w.complete {
			t.Errorf("%s: walk = %+v, %v; want unreliable", name, w, err)
		}
	}
}

// seriesRegistry is a Registry that can also page.
type seriesRegistry struct {
	*fakeRegistry
	TagPager
}

func (s seriesRegistry) ListTagsUpTo(ctx context.Context, repo string, n int) (registry.TagList, error) {
	return s.fakeRegistry.ListTagsUpTo(ctx, repo, n)
}

func TestListPinnedSeriesFallsBackToFullListing(t *testing.T) {
	fake := newFakeRegistry()
	fake.tags["r"] = registry.TagList{Tags: []string{"8.19.1", "8.19.3"}, Pages: 2}
	reg := seriesRegistry{fake, &sortedPager{misbehave: func(string, int) []string { return []string{"8.18.5", "8.18.4"} }}}
	list, err := listPinnedSeries(context.Background(), reg, "r", tv(t, "8.19.1"), 10)
	if err != nil {
		t.Fatal(err)
	}
	if list.Truncated || !reflect.DeepEqual(list.Tags, []string{"8.19.1", "8.19.3"}) {
		t.Errorf("list = %+v", list)
	}
	if list.Pages != 3 {
		t.Errorf("pages = %d, want the 1 skipping request plus the 2 pages of the listing", list.Pages)
	}
	if len(fake.allowances) != 1 || fake.allowances[0] != 9 {
		t.Errorf("full listing allowance = %v, want what the skipping request left (9)", fake.allowances)
	}
	// With no allowance left the fallback is not started and the list is
	// incomplete.
	fake.allowances = nil
	list, err = listPinnedSeries(context.Background(), reg, "r", tv(t, "8.19.1"), 1)
	if err != nil || !list.Truncated || len(fake.allowances) != 0 {
		t.Errorf("list = %+v, %v, allowances %v; want truncated and no full listing", list, err, fake.allowances)
	}
}

func TestListPinnedSeriesErrorKeepsRequestCount(t *testing.T) {
	boom := errors.New("boom")
	pager := newSortedPager(elasticLike())
	pager.err, pager.errAfter = boom, 2
	list, err := listPinnedSeries(context.Background(), seriesRegistry{newFakeRegistry(), pager}, "r", tv(t, "8.19.16"), 40)
	if !errors.Is(err, boom) || list.Pages != 3 || len(list.Tags) != 0 {
		t.Errorf("list = %+v, err = %v; want the error and 3 requests counted", list, err)
	}
}

func TestListPinnedSeriesWithoutPagerReadsTheListing(t *testing.T) {
	fake := newFakeRegistry()
	fake.tags["r"] = registry.TagList{Tags: []string{"8.19.1"}, Pages: 1}
	list, err := listPinnedSeries(context.Background(), fake, "r", tv(t, "8.19.1"), 5)
	if err != nil || !reflect.DeepEqual(list.Tags, []string{"8.19.1"}) || fake.listCalls != 1 {
		t.Errorf("list = %+v, %v, calls %d", list, err, fake.listCalls)
	}
}

func TestSeriesKeyIsPerSeries(t *testing.T) {
	a, b, c := seriesKey(tv(t, "1.25.3")), seriesKey(tv(t, "1.25.3-alpine")), seriesKey(tv(t, "1.26.3"))
	if a == b || a == c || b == c {
		t.Errorf("keys = %q %q %q; different series must differ", a, b, c)
	}
	if seriesKey(tv(t, "1.25.3")) != seriesKey(tv(t, "1.25.9")) {
		t.Error("patches of one series must share a key")
	}
}

// scriptedPager answers with fixed pages in turn.
type scriptedPager struct {
	pages []registry.TagsAfter
	calls int
}

func (p *scriptedPager) ListTagsAfter(context.Context, string, string, int) (registry.TagsAfter, error) {
	if p.calls >= len(p.pages) {
		return registry.TagsAfter{Sent: true}, nil
	}
	pg := p.pages[p.calls]
	p.calls++
	pg.Sent = true
	return pg, nil
}

// TestWalkSeriesChecksTheWholePageBeforeEndingTheSeries: the tag after the
// series (8.20.0) must not end the walk before the out-of-place 8.19.23
// behind it has been seen.
func TestWalkSeriesChecksTheWholePageBeforeEndingTheSeries(t *testing.T) {
	p := &scriptedPager{pages: []registry.TagsAfter{{Tags: []string{"8.18.9", "8.19.16", "8.20.0", "8.19.23"}}}}
	w, err := walkSeries(context.Background(), p, "r", tv(t, "8.19.16"), 10)
	if err != nil || !w.unreliable || w.complete {
		t.Fatalf("walk = %+v, %v; want unreliable and not complete", w, err)
	}
	// Through listPinnedSeries the whole listing is read instead, and the
	// out-of-place tag is found there.
	fake := newFakeRegistry()
	fake.tags["r"] = registry.TagList{Tags: []string{"8.19.16", "8.19.23"}, Pages: 1}
	list, err := listPinnedSeries(context.Background(), seriesRegistry{fake, &sortedPager{misbehave: func(string, int) []string { return []string{"8.18.9", "8.19.16", "8.20.0", "8.19.23"} }}}, "r", tv(t, "8.19.16"), 10)
	if err != nil || list.Truncated || SelectPinned(tv(t, "8.19.16"), list).Tag != "8.19.23" {
		t.Errorf("list = %+v, %v", list, err)
	}
}

func TestWalkSeriesEmptyPageWithMoreIsNotTheEnd(t *testing.T) {
	// Every start gets an empty page that says more follow.
	p := &scriptedPager{pages: []registry.TagsAfter{{More: true}, {More: true}, {More: true}, {More: true}, {More: true}, {More: true}}}
	w, err := walkSeries(context.Background(), p, "r", tv(t, "8.19.16"), 20)
	if err != nil || !w.unreliable || w.complete {
		t.Fatalf("walk = %+v, %v", w, err)
	}
	// After a good page, an empty one with More is just as unreliable.
	p = &scriptedPager{pages: []registry.TagsAfter{{Tags: []string{"8.18.1", "8.19.1"}, More: true}, {More: true}}}
	w, err = walkSeries(context.Background(), p, "r", tv(t, "8.19.16"), 20)
	if err != nil || !w.unreliable || w.complete {
		t.Fatalf("walk = %+v, %v", w, err)
	}
	// With the whole listing unreadable within the allowance, no candidate
	// is ruled out.
	fake := newFakeRegistry()
	fake.tags["r"] = registry.TagList{Tags: []string{"8.19.16"}, Pages: 5, Truncated: true}
	list, err := listPinnedSeries(context.Background(), seriesRegistry{fake, &scriptedPager{pages: []registry.TagsAfter{{Tags: []string{"8.18.1", "8.19.1"}, More: true}, {More: true}}}}, "r", tv(t, "8.19.16"), 6)
	if err != nil || SelectPinned(tv(t, "8.19.16"), list).Outcome != SelectionIncomplete {
		t.Errorf("list = %+v, %v; want an incomplete selection", list, err)
	}
	// A genuinely empty last page ends it.
	p = &scriptedPager{pages: []registry.TagsAfter{{Tags: []string{"8.18.1", "8.19.1"}, More: true}, {}}}
	if w, _ = walkSeries(context.Background(), p, "r", tv(t, "8.19.16"), 20); !w.complete {
		t.Errorf("walk = %+v", w)
	}
}
