package remediation

import (
	"context"
	"fmt"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/registry"
)

// TagPager reads a tag listing from a given position, one request at a time.
// A registry client that offers it lets the planner read only the part of a
// repository's tag list around one series instead of the whole listing.
type TagPager interface {
	ListTagsAfter(ctx context.Context, repo, last string, n int) (registry.TagsAfter, error)
}

var _ TagPager = (*registry.Client)(nil)

// seriesPageSize is how many tags one request of a series walk asks for.
// Large public registries answer a tag listing request in about the same time
// whatever n is, so the walk asks for the page size the client already uses
// for whole listings.
const seriesPageSize = 1000

// maxStartMinors is how many earlier minor versions the walk tries as the
// place to start reading before it widens the start.
const maxStartMinors = 3

// seriesBase is the text every tag of cur's series starts with, the prefix
// and the first two numbers of the version and the dot after them.
func seriesBase(cur TagVersion) string {
	return fmt.Sprintf("%s%d.%d.", cur.Prefix, cur.Major, cur.Minor)
}

// seriesKey identifies the listing a series walk produces: it depends on the
// series and not on the patch, so images of one series share it.
func seriesKey(cur TagVersion) string {
	return seriesBase(cur) + cur.Suffix
}

// inSeries reports whether tag is a pinned tag of cur's series: the same
// prefix, suffix, major and minor, any patch.
func inSeries(tag string, cur TagVersion) bool {
	v, ok := ParseTagVersion(tag)
	return ok && v.Prefix == cur.Prefix && v.Suffix == cur.Suffix && v.Major == cur.Major && v.Minor == cur.Minor
}

// tagBefore returns a position that sorts after every valid tag below x and
// before x itself, so that a listing "after" it starts at the first tag that
// is x or greater. Tags use the characters A-Z a-z 0-9 "_" "." "-", all
// below "~", which is why a "~" can stand for "everything with this
// beginning". x must not be empty.
func tagBefore(x string) string {
	return x[:len(x)-1] + string(x[len(x)-1]-1) + "~"
}

// seriesStarts lists the positions the walk may start reading from, in the
// order it tries them. All but the last are positions at which no tag need
// exist: the registry is asked for the tags after them. A registry may drop
// the first tag after a position that is not itself a tag, and the walk must
// not lose a tag of the series that way. Each of these positions therefore
// lies in front of a stretch of tags of an earlier version, so that the tag
// that may be dropped is one of those and not one of the series; walkFrom
// checks that this held. The last position is the start of the listing, which
// has no such problem.
func seriesStarts(cur TagVersion) []string {
	var out []string
	for k := cur.Minor - 1; k >= 0 && k >= cur.Minor-maxStartMinors; k-- {
		out = append(out, tagBefore(fmt.Sprintf("%s%d.%d.", cur.Prefix, cur.Major, k)))
	}
	out = append(out, tagBefore(fmt.Sprintf("%s%d.", cur.Prefix, cur.Major)), "")
	return out
}

// seriesWalk is the outcome of a walk over a series.
type seriesWalk struct {
	tags     []string // the series tags found, in listing order
	complete bool     // the walk reached the end of the series
	// unreliable says reading from a position cannot be trusted: the registry
	// did not return tags in ascending order, or gave an empty page while
	// saying more follow. The caller reads the whole listing instead.
	unreliable bool
	requests   int
}

// walkSeries reads the tags of cur's series from a registry that lists tags
// in ascending order and accepts a starting position. It starts a little
// before the series, which skips the thousands of tags of other versions in
// front of it, reads page after page from the last tag of the previous one,
// and stops at the first tag after the series. Versions with more digits
// (8.19.2, 8.19.20, 8.19.200) lie inside the range and are read in order.
//
// Every page is checked for order in full before anything in it is used: a
// tag that does not sort after the one before it ends the walk with
// unreliable set. The walk is complete only when
// it reached the end of the series or of the listing; a request limit or an
// error leaves it incomplete.
func walkSeries(ctx context.Context, pager TagPager, repo string, cur TagVersion, maxRequests int) (seriesWalk, error) {
	var w seriesWalk
	for _, start := range seriesStarts(cur) {
		done, err := walkFrom(ctx, pager, repo, cur, start, maxRequests, &w)
		if err != nil || done {
			return w, err
		}
	}
	return w, nil
}

// walkFrom reads from start, adding its requests to w.requests. It returns
// done=false, with nothing else recorded, when the first page does not show
// that start was safe, and the walk then tries the next start; in every other
// case w holds the outcome.
//
// A start other than "" is safe when the first tag the registry returns still
// sorts before the series: a registry that dropped the first tag after start
// dropped something earlier than that, which is not a tag of the series. An
// empty first page is not taken as safe, since the one tag there was may be
// the one dropped.
func walkFrom(ctx context.Context, pager TagPager, repo string, cur TagVersion, start string, maxRequests int, w *seriesWalk) (done bool, err error) {
	base := seriesBase(cur)
	w.tags, w.complete, w.unreliable = nil, false, false
	last := start
	first := true
	for {
		if w.requests >= maxRequests {
			return true, nil
		}
		page, err := pager.ListTagsAfter(ctx, repo, last, seriesPageSize)
		if page.Sent {
			w.requests++
		}
		if err != nil {
			return true, err
		}
		if first && start != "" && (len(page.Tags) == 0 || page.Tags[0] >= base) {
			return false, nil
		}
		first = false
		if len(page.Tags) == 0 {
			// An empty page that says more follow gives nothing to continue
			// from; the end of the listing is not shown.
			if page.More {
				w.unreliable = true
			} else {
				w.complete = true
			}
			return true, nil
		}
		// The order of the whole page is settled before the end of the series
		// is: a tag after the series must not end the walk while a tag out of
		// place is still to come behind it.
		prev := last
		for _, tag := range page.Tags {
			if tag <= prev {
				w.unreliable = true
				return true, nil
			}
			prev = tag
		}
		for _, tag := range page.Tags {
			switch {
			case strings.HasPrefix(tag, base):
				if inSeries(tag, cur) {
					w.tags = append(w.tags, tag)
				}
			case tag > base:
				w.complete = true
				return true, nil
			}
		}
		if !page.More {
			w.complete = true
			return true, nil
		}
		last = prev
	}
}

// listPinnedSeries lists the tags that matter for a pinned image: those of
// its series. With a registry that can read from a position it walks the
// series; if the registry does not list in order it reads the whole listing
// as before, with what is left of the allowance. Without such a registry it
// reads the whole listing. The allowance counts every request of either
// kind. A walk the allowance or an error stops is reported like a listing
// that was cut short: Truncated, or the error with the requests made so far
// in Pages.
func listPinnedSeries(ctx context.Context, reg Registry, repo string, cur TagVersion, allowance int) (registry.TagList, error) {
	pager, ok := reg.(TagPager)
	if !ok {
		return reg.ListTagsUpTo(ctx, repo, allowance)
	}
	w, err := walkSeries(ctx, pager, repo, cur, allowance)
	if err != nil {
		return registry.TagList{Pages: w.requests}, err
	}
	if w.unreliable {
		rest := allowance - w.requests
		if rest <= 0 {
			return registry.TagList{Pages: w.requests, Truncated: true}, nil
		}
		l, err := reg.ListTagsUpTo(ctx, repo, rest)
		l.Pages += w.requests
		return l, err
	}
	return registry.TagList{Tags: w.tags, Truncated: !w.complete, Pages: w.requests}, nil
}
