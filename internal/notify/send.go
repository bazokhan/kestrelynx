package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// Message is one notification: the full report, plus the diff against the
// previous scan when diff mode is on (nil Diff = full mode, render everything).
// FullReport asks diff mode to append the complete open-findings view (the
// weekly digest day).
//
// The thread-report fields are consumed by SlackAPINotifier only; webhook
// notifiers ignore them. Thread asks for the full open-findings report to be
// posted as replies under the summary message.
// FirstSeen looks up a finding's first-seen time for the "open N day(s)"
// lines, and EOLFirstSeen the time an end-of-life package was first seen
// end-of-life, for the same lines of end-of-life groups. LastReport is the most recent successfully posted thread (nil when
// none). Result, when non-nil, receives the ref of a thread posted by this
// send, so the caller can persist it only after delivery succeeded.
//
// Holding is diff mode's "we are silently carrying over unconfirmed findings"
// signal: true when at least one reference this cycle failed to pin
// (Report.UnconfirmedRefs) still has a finding on record from the previous
// state. The runner computes it (it alone loads the previous state) and
// passes it through here so the pure formatting layer never needs its own
// copy of state; it only ever affects diff-mode "open now" rendering.
type Message struct {
	Report     analyze.Report
	Diff       *state.Diff
	FullReport bool
	Holding    bool

	Thread       bool
	FirstSeen    func(image, pkg string) (time.Time, bool)
	EOLFirstSeen func(image, pkg string) (time.Time, bool)
	LastReport   *state.ReportRef
	Result       *ThreadResult

	// Plan is the read-only fix plan of this cycle: nil when the plan is not
	// enabled, in which case nothing about it is rendered or sent. Slack gets
	// it as a message of its own after the vulnerability message, when it
	// changed and on the weekly day; the generic webhook carries every item
	// together with the report.
	Plan *PlanInfo

	// SkipReport says the vulnerability message (and the thread report) is not
	// due in this cycle: only the fix plan is sent to Slack. The generic
	// webhook still gets the report with the plan.
	SkipReport bool

	// PlanDelivery, when set, receives whether the Slack fix plan message was
	// delivered, so the caller can record it although something else in the
	// same send failed.
	PlanDelivery *PlanDelivery

	// EmailDelivery, when set, receives whether the email fix plan was
	// delivered, so the caller can record it although something else in the
	// same send failed.
	EmailDelivery *PlanDelivery
}

// PlanDelivery is the out-slot for the delivery of the Slack fix plan message.
// Both fields are false when none was sent.
type PlanDelivery struct {
	Posted bool // every message of the fix plan was posted
	Failed bool // posting the fix plan failed
}

// record notes the outcome of posting the fix plan; a nil slot ignores it.
func (d *PlanDelivery) record(ok bool) {
	if d != nil {
		d.Posted, d.Failed = ok, !ok
	}
}

// ThreadResult is the out-slot for a thread post: a zero Ref means no thread
// was posted (or it failed before completing).
type ThreadResult struct {
	Ref state.ReportRef
}

// Notifier delivers a message to a destination.
type Notifier interface {
	Send(ctx context.Context, m Message) error
}

// defaultClient is used when a notifier has no client configured.
var defaultClient = &http.Client{Timeout: 15 * time.Second}

// SlackNotifier posts the channel message to a Slack Incoming Webhook as
// Block Kit messages (fallback text plus blocks), one POST per message in
// order. A webhook cannot thread, so the messages carry no thread notice or
// last-report link.
type SlackNotifier struct {
	WebhookURL string
	Client     *http.Client
	// Language selects the wording dictionary the message body renders
	// from. The zero value is LanguageEN.
	Language Language
	// Sleep paces the posts; nil = time.Sleep. A test override.
	Sleep func(time.Duration)
	// Limits are the sizes messages are packed against; the zero value is the
	// defaults. It exists for tests that need small messages.
	Limits RenderLimits
}

func (n SlackNotifier) Send(ctx context.Context, m Message) error {
	msg, lim := messagesFor(n.Language), limitsOrDefault(n.Limits)
	var report []SlackMessage
	if !m.SkipReport {
		report = buildChannelMessages(m, ChannelFooter{}, msg, lim)
	}
	plan := buildPlanMessages(m, msg, lim)
	sleep := n.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	total := len(report) + len(plan)
	posted := 0
	// The vulnerability messages and the plan are sent on their own: a failure
	// of one stops the rest of that one, not the other.
	post := func(msgs []SlackMessage, first int) error {
		for i, sm := range msgs {
			if posted > 0 {
				sleep(threadPostGap)
			}
			posted++
			if err := postSlackWebhook(ctx, client(n.Client), n.WebhookURL, sm, sleep); err != nil {
				return fmt.Errorf("post message %d/%d: %w", first+i+1, total, err)
			}
		}
		return nil
	}
	var errs []error
	if err := post(report, 0); err != nil {
		errs = append(errs, err)
	}
	if len(plan) > 0 {
		err := post(plan, len(report))
		if err != nil {
			errs = append(errs, err)
		}
		m.PlanDelivery.record(err == nil)
	}
	return errors.Join(errs...)
}

// postSlackWebhook posts one message, waiting out a 429's Retry-After and
// retrying up to apiAttempts times in all.
func postSlackWebhook(ctx context.Context, c *http.Client, endpoint string, sm SlackMessage, sleep func(time.Duration)) error {
	const dest = "slack webhook"
	data, err := json.Marshal(sm)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	var lastErr error
	for attempt := 0; attempt < apiAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("build request for %s: %w", dest, redact(err))
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			return fmt.Errorf("post to %s: %w", dest, redact(err))
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return nil
		case resp.StatusCode == http.StatusTooManyRequests:
			// Only the numeric code reaches the error: the reason phrase is
			// server-chosen text.
			lastErr = fmt.Errorf("post to %s: unexpected status %d", dest, resp.StatusCode)
			if attempt < apiAttempts-1 {
				sleep(retryAfter(resp))
			}
		default:
			return fmt.Errorf("post to %s: unexpected status %d", dest, resp.StatusCode)
		}
	}
	return lastErr
}

// WebhookNotifier posts the structured JSON payload to a generic endpoint. It
// always carries the full data regardless of mode: Slack is the summary, the
// webhook is the record.
type WebhookNotifier struct {
	URL    string
	Client *http.Client
}

func (n WebhookNotifier) Send(ctx context.Context, m Message) error {
	return postJSON(ctx, client(n.Client), "generic webhook", n.URL, BuildWebhookPayloadWithPlan(m.Report, m.Diff, m.Plan))
}

// MultiNotifier fans a message out to several notifiers, attempting all even if
// some fail, and joining their errors.
type MultiNotifier []Notifier

// Multi builds a MultiNotifier from the given notifiers.
func Multi(notifiers ...Notifier) MultiNotifier { return MultiNotifier(notifiers) }

func (m MultiNotifier) Send(ctx context.Context, msg Message) error {
	var errs []error
	for _, n := range m {
		if err := n.Send(ctx, msg); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func client(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return defaultClient
}

// postJSON posts body to endpoint. Errors name the destination only by dest
// (e.g. "slack webhook"): webhook URLs are credentials — a Slack Incoming
// Webhook URL is the whole secret — so they must never reach logs.
func postJSON(ctx context.Context, c *http.Client, dest, endpoint string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request for %s: %w", dest, redact(err))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("post to %s: %w", dest, redact(err))
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// resp.Status carries the server's reason phrase verbatim; report
		// only the numeric code so no server-chosen text reaches logs.
		return fmt.Errorf("post to %s: unexpected status %d", dest, resp.StatusCode)
	}
	return nil
}

// redactedError hides the original error text — which may embed the webhook
// URL — behind a scrubbed message, while Unwrap keeps the original chain
// reachable for errors.Is / errors.As (context.DeadlineExceeded etc.).
type redactedError struct {
	msg string
	err error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.err }

// redact discards err's text entirely and substitutes a classification:
// transport errors can embed the webhook URL (url.Error wrappers carry the
// full URL) or server-reflected fragments of it (redirect Location parse
// errors, malformed headers), so no message derived from the original error
// is safe to log. Scrubbing by substring cannot cover partial reflections, so
// the text is fixed; the original chain stays inspectable through Unwrap.
func redact(err error) error {
	msg := "request failed"
	var nerr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		msg = "timeout"
	case errors.Is(err, context.Canceled):
		msg = "canceled"
	case errors.As(err, &nerr) && nerr.Timeout():
		msg = "timeout"
	}
	return &redactedError{msg: msg, err: err}
}
