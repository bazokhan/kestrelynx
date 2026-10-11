package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
)

// TagList is the result of ListTags.
type TagList struct {
	Tags []string
	// Truncated is true when the registry had more pages than the client is
	// willing to follow. Tags is then only a prefix of the repository's tags
	// and must not be treated as complete.
	Truncated bool
	// Pages is how many pages were fetched.
	Pages int
}

var linkNextRE = regexp.MustCompile(`<([^>]*)>\s*;[^,]*\brel="?next"?`)

// ListTags lists the tags of repo, following the Link header between pages up
// to the configured page limit. When the limit is hit with pages remaining
// the partial list is returned with Truncated set and no error. Any error
// discards the partial tags but still reports in Pages how many page requests
// were made.
func (c *Client) ListTags(ctx context.Context, repo string) (TagList, error) {
	return c.ListTagsUpTo(ctx, repo, 0)
}

// ListTagsUpTo is ListTags with a per-call page allowance: it follows at most
// maxPages pages, or the configured limit when that is smaller. A maxPages of
// zero or less means the configured limit alone.
func (c *Client) ListTagsUpTo(ctx context.Context, repo string, maxPages int) (TagList, error) {
	t, err := newTarget(repo)
	if err != nil {
		return TagList{}, err
	}
	limit := c.opts.MaxTagPages
	if maxPages > 0 && maxPages < limit {
		limit = maxPages
	}
	next := t.base() + "/tags/list?n=" + strconv.Itoa(c.opts.TagPageSize)
	var out TagList
	for next != "" {
		if out.Pages >= limit {
			out.Truncated = true
			return out, nil
		}
		r, sent, err := c.getSent(ctx, t, next, "application/json", c.opts.MaxTagPageBytes)
		if err != nil {
			pages := out.Pages
			if sent {
				pages++
			}
			return TagList{Pages: pages}, err
		}
		out.Pages++
		var page struct {
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(r.body, &page); err != nil {
			return TagList{Pages: out.Pages}, fmt.Errorf("%w: tag list from %s is not JSON", ErrBadResponse, t.host)
		}
		out.Tags = append(out.Tags, page.Tags...)

		next = ""
		for _, h := range r.header.Values("Link") {
			if m := linkNextRE.FindStringSubmatch(h); m != nil {
				base, _ := url.Parse(t.base() + "/tags/list")
				ref, err := url.Parse(m[1])
				if err != nil {
					return TagList{Pages: out.Pages}, fmt.Errorf("%w: unusable Link header from %s", ErrBadResponse, t.host)
				}
				u := base.ResolveReference(ref)
				if u.Scheme != "https" || u.Host != t.host {
					return TagList{Pages: out.Pages}, fmt.Errorf("%w: %s paginates to another location", ErrBadResponse, t.host)
				}
				next = u.String()
				break
			}
		}
	}
	return out, nil
}

// TagsAfter is the result of ListTagsAfter: one request's worth of tags.
type TagsAfter struct {
	// Tags are the tags the registry returned, in the order it returned
	// them. They are not checked here.
	Tags []string
	// More is true when the registry may hold tags after these: the page was
	// full, or the response carried a Link to a next page.
	More bool
	// Sent says a tag listing request went out, even if it then failed.
	Sent bool
}

// maxLastBytes bounds the position argument of ListTagsAfter.
const maxLastBytes = 512

// ListTagsAfter makes one tag listing request for at most n tags that sort
// after last in the registry's order (the n and last query parameters of the
// tag listing). last may be any string, not only an existing tag; empty means
// from the start. It is the building block for reading a part of a very long
// tag list without following every page. It sends one request (plus a token
// request when challenged) and does not follow Link headers.
func (c *Client) ListTagsAfter(ctx context.Context, repo, last string, n int) (TagsAfter, error) {
	t, err := newTarget(repo)
	if err != nil {
		return TagsAfter{}, err
	}
	if n <= 0 || n > 10000 {
		return TagsAfter{}, fmt.Errorf("%w: tag page size %d", ErrInvalidInput, n)
	}
	if len(last) > maxLastBytes {
		return TagsAfter{}, fmt.Errorf("%w: tag listing position is too long", ErrInvalidInput)
	}
	q := url.Values{"n": {strconv.Itoa(n)}}
	if last != "" {
		q.Set("last", last)
	}
	r, sent, err := c.getSent(ctx, t, t.base()+"/tags/list?"+q.Encode(), "application/json", c.opts.MaxTagPageBytes)
	if err != nil {
		return TagsAfter{Sent: sent}, err
	}
	var page struct {
		Tags []string `json:"tags"`
	}
	if err := json.Unmarshal(r.body, &page); err != nil {
		return TagsAfter{Sent: true}, fmt.Errorf("%w: tag list from %s is not JSON", ErrBadResponse, t.host)
	}
	out := TagsAfter{Tags: page.Tags, Sent: true, More: len(page.Tags) >= n}
	for _, h := range r.header.Values("Link") {
		if linkNextRE.MatchString(h) {
			out.More = true
		}
	}
	return out, nil
}
