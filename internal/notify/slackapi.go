// Slack Web API delivery. An incoming
// webhook cannot thread: it never returns the posted message's ts and cannot
// reply to one. The bot-token path can — posting returns ts, replies target
// it as thread_ts, and chat.getPermalink turns it into the "everything open
// as of the last report" link shown on the days the thread is skipped. Both
// paths post Block Kit messages: the fallback text plus the blocks.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/state"
)

const (
	slackAPIBase = "https://slack.com/api"
	// apiAttempts retries transient API failures: a thread that ultimately
	// fails leaves the stored ref untouched, so the previous permalink keeps
	// working and the next cycle re-posts in full.
	apiAttempts = 3
	retryDelay  = 2 * time.Second
	// threadPostGap paces consecutive posts to one channel. chat.postMessage
	// has a special per-channel limit of about one message per second, so one
	// second between posts keeps a burst of messages inside it.
	threadPostGap = time.Second
	// maxRetryAfter caps how long a 429's Retry-After is honored.
	maxRetryAfter = 30 * time.Second
)

// retryAfter reads a 429 response's Retry-After header (seconds): one second
// when absent or unreadable, never more than maxRetryAfter.
func retryAfter(resp *http.Response) time.Duration {
	d := time.Second
	if secs, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && secs >= 0 {
		d = time.Duration(secs) * time.Second
	}
	if d > maxRetryAfter {
		d = maxRetryAfter
	}
	return d
}

// SlackAPINotifier posts the channel message to a channel via
// chat.postMessage and, when the message asks for it, the full open-findings
// report as replies in the thread of the first channel message (channel = the
// diff, thread = the state). Requires a bot token with chat:write;
// reply_broadcast is never used, so the thread stays out of the channel
// timeline.
type SlackAPINotifier struct {
	Token   string
	Channel string              // channel ID (recommended) or name the bot can resolve
	Client  *http.Client        // nil = defaultClient
	BaseURL string              // test override; empty = https://slack.com/api
	Sleep   func(time.Duration) // test override; nil = time.Sleep
	// Limits are the sizes messages are packed against; the zero value is the
	// defaults. It exists for tests that need small messages.
	Limits RenderLimits
	// Language selects the wording dictionary the channel message and
	// thread report render from. The zero value is LanguageEN.
	Language Language
}

func (n SlackAPINotifier) Send(ctx context.Context, m Message) error {
	postThread := m.Thread
	// Diff mode with no usable link — first run, a pre-thread state file, or
	// the destination channel changed — forces a fresh full report even on a
	// no-changes day, so a link can be offered again.
	if m.Diff != nil && !m.LastReport.ValidFor(n.Channel) {
		postThread = true
	}
	if m.SkipReport {
		postThread = false
	}
	lim := limitsOrDefault(n.Limits)
	msg := messagesFor(n.Language)
	var thread []SlackMessage
	if postThread {
		thread = buildThreadBlockMessages(m.Report, Ages{Finding: m.FirstSeen, EOL: m.EOLFirstSeen}, msg, lim)
	}

	footer := ChannelFooter{}
	switch {
	case len(thread) > 0:
		footer.Kind = FooterThreadNotice
	case m.LastReport.ValidFor(n.Channel):
		footer = ChannelFooter{Kind: FooterLastReport, Permalink: m.LastReport.Permalink}
	}
	var channel []SlackMessage
	if !m.SkipReport {
		channel = buildChannelMessages(m, footer, msg, lim)
	}
	// The fix plan follows the vulnerability message in the channel, as a
	// top-level message of its own.
	plan := buildPlanMessages(m, msg, lim)

	// The first channel message is the thread's parent; the rest are plain
	// top-level messages. The vulnerability message with its thread and the
	// fix plan are delivered on their own: a failure of one does not keep the
	// other from being sent or recorded.
	ts := ""
	posted := 0
	pace := func() {
		if posted > 0 {
			n.sleep(threadPostGap)
		}
		posted++
	}
	var errs []error
	reportOK := true
	for i, cm := range channel {
		pace()
		got, err := n.postMessage(ctx, cm, "")
		if err != nil {
			errs = append(errs, fmt.Errorf("post summary %d/%d: %w", i+1, len(channel), err))
			reportOK = false
			break
		}
		if i == 0 {
			ts = got
		}
	}
	if len(plan) > 0 {
		var planErr error
		for i, pm := range plan {
			pace()
			if _, err := n.postMessage(ctx, pm, ""); err != nil {
				planErr = fmt.Errorf("post fix plan %d/%d: %w", i+1, len(plan), err)
				break
			}
		}
		if planErr != nil {
			errs = append(errs, planErr)
		}
		m.PlanDelivery.record(planErr == nil)
	}
	if !reportOK || len(thread) == 0 {
		return errors.Join(errs...)
	}
	for i, reply := range thread {
		pace()
		if _, err := n.postMessage(ctx, reply, ts); err != nil {
			errs = append(errs, fmt.Errorf("post thread reply %d/%d: %w", i+1, len(thread), err))
			return errors.Join(errs...)
		}
	}
	link, err := n.permalink(ctx, ts)
	if err != nil {
		errs = append(errs, fmt.Errorf("get permalink: %w", err))
		return errors.Join(errs...)
	}
	if m.Result != nil {
		m.Result.Ref = state.ReportRef{Channel: n.Channel, TS: ts, Permalink: link}
	}
	return errors.Join(errs...)
}

// limitsOrDefault resolves the zero RenderLimits to the defaults.
func limitsOrDefault(l RenderLimits) RenderLimits {
	if l == (RenderLimits{}) {
		return defaultRenderLimits
	}
	return l
}

// postMessage posts one message to the channel (threaded under threadTS when
// set) and returns the new message's ts.
func (n SlackAPINotifier) postMessage(ctx context.Context, sm SlackMessage, threadTS string) (string, error) {
	blocks := sm.Blocks
	if blocks == nil {
		blocks = []Block{}
	}
	body := map[string]any{"channel": n.Channel, "text": sm.Text, "blocks": blocks, "unfurl_links": false}
	if threadTS != "" {
		body["thread_ts"] = threadTS
	}
	data, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	var out struct {
		TS string `json:"ts"`
	}
	err = n.call(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.base()+"/chat.postMessage", bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		return req, nil
	}, &out)
	return out.TS, err
}

// permalink resolves a message ts to its shareable URL.
func (n SlackAPINotifier) permalink(ctx context.Context, ts string) (string, error) {
	q := url.Values{"channel": {n.Channel}, "message_ts": {ts}}
	var out struct {
		Permalink string `json:"permalink"`
	}
	err := n.call(ctx, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, n.base()+"/chat.getPermalink?"+q.Encode(), nil)
	}, &out)
	return out.Permalink, err
}

// call performs one Web API request with retries, decoding the response into
// out once the {"ok": true} envelope checks out.
func (n SlackAPINotifier) call(ctx context.Context, build func() (*http.Request, error), out any) error {
	c := client(n.Client)
	var lastErr error
	wait := retryDelay
	for attempt := 0; attempt < apiAttempts; attempt++ {
		if attempt > 0 {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			n.sleep(wait)
			wait = retryDelay
		}
		req, err := build()
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+n.Token)

		resp, err := c.Do(req)
		if err != nil {
			lastErr = redact(err)
			continue
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("read response: %w", err)
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			wait = retryAfter(resp)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("slack api: unexpected status %d", resp.StatusCode)
			continue
		}
		var env struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(data, &env); err != nil {
			lastErr = fmt.Errorf("slack api: parse response: %w", err)
			continue
		}
		if !env.OK {
			lastErr = fmt.Errorf("slack api: %s", env.Error)
			continue
		}
		if out != nil {
			if err := json.Unmarshal(data, out); err != nil {
				lastErr = fmt.Errorf("slack api: parse response: %w", err)
				continue
			}
		}
		return nil
	}
	return lastErr
}

func (n SlackAPINotifier) base() string {
	if n.BaseURL != "" {
		return n.BaseURL
	}
	return slackAPIBase
}

func (n SlackAPINotifier) sleep(d time.Duration) {
	if n.Sleep != nil {
		n.Sleep(d)
		return
	}
	time.Sleep(d)
}
