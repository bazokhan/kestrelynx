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
