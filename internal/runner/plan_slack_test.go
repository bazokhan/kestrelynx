package runner

import (
	"context"
	"errors"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/notify"
)

// slackDelivered is a delivered-plan record that also keeps what the Slack
// and email fix plan messages showed.
type slackDelivered struct {
	fakeDelivered
	slack      string
	slackSaves []string
	email      string
	emailSaves []string
}

func (f *slackDelivered) LoadSlack() (string, error) { return f.slack, nil }
func (f *slackDelivered) SaveSlack(fp string) error {
	f.slackSaves = append(f.slackSaves, fp)
	f.slack = fp
	return nil
}
func (f *slackDelivered) LoadEmail() (string, error) { return f.email, nil }
func (f *slackDelivered) SaveEmail(fp string) error {
	f.emailSaves = append(f.emailSaves, fp)
	f.email = fp
	return nil
}

func newSlackPlanHarness(withFindings bool) (*planHarness, *slackDelivered) {
	var h *planHarness
	if withFindings {
		h = newPlanHarness(osFinding("CVE-1"))
	} else {
		h = newPlanHarness()
	}
	d := &slackDelivered{}
	h.delivered = &d.fakeDelivered
	h.r.Plan.Delivered = d
	return h, d
}

// The Slack message is due when what it shows changed, and its record is kept
// only after the notification was sent.
func TestPlanSlack_DueWhenWhatItShowsChanged(t *testing.T) {
	h, d := newSlackPlanHarness(true)
	h.notif.err = errors.New("slack down")
	if err := h.r.RunOnce(t.Context()); err == nil {
		t.Fatal("expected the send error")
	}
	if len(d.slackSaves) != 0 {
		t.Errorf("recorded %v after a failed send", d.slackSaves)
	}

	h.notif.err = nil
	h.run(t)
	p := h.notif.msg.Plan
	if p == nil || !p.SlackChanged || !p.SlackDue() || h.notif.msg.SkipReport {
		t.Fatalf("first plan: %+v skip=%v", p, h.notif.msg.SkipReport)
	}
	if want := p.SlackFingerprint(); want == "" || len(d.slackSaves) != 1 || d.slackSaves[0] != want {
		t.Errorf("slack saves = %v, want the fingerprint of the message", d.slackSaves)
	}

	// The same plan again: the heartbeat goes out and the plan does not.
	h.store.st = *h.store.saved
	h.notif.called = false
	h.run(t)
	p = h.notif.msg.Plan
	if !h.notif.called || p == nil || p.SlackChanged || p.SlackDue() || h.notif.msg.SkipReport {
		t.Errorf("unchanged plan: called=%v plan=%+v", h.notif.called, p)
	}
	if len(d.slackSaves) != 1 {
		t.Errorf("slack saves = %v after an unchanged plan", d.slackSaves)
	}
}

// A plan that changed is sent although there is nothing to say about the
// vulnerabilities, and then it is quiet.
func TestPlanSlack_PlanAloneWhenTheReportIsNotDue(t *testing.T) {
	for _, mode := range []string{"diff", "full"} {
		t.Run(mode, func(t *testing.T) {
			h, d := newSlackPlanHarness(false)
			if mode == "full" {
				h.r.Store = nil
			}
			d.slack = "what-slack-showed-before"
			h.run(t)
			if !h.notif.called {
				t.Fatal("a plan that became empty is not sent")
			}
			m := h.notif.msg
			if !m.SkipReport || m.Plan == nil || !m.Plan.SlackDue() {
				t.Errorf("skip=%v plan=%+v", m.SkipReport, m.Plan)
			}
			if len(d.slackSaves) != 1 || d.slackSaves[0] != "" {
				t.Errorf("slack saves = %v, want the empty fingerprint", d.slackSaves)
			}
			h.notif.called = false
			h.run(t)
			if h.notif.called {
				t.Error("an unchanged, empty plan sent a notification")
			}
		})
	}
}

// The generic webhook still gets a change that the Slack message does not
// show, with the vulnerability message and the plan message left alone.
func TestPlanSlack_WebhookChangeAloneSkipsSlack(t *testing.T) {
	h, d := newSlackPlanHarness(false)
	h.delivered.fp = "previous-plan"
	h.run(t)
	if !h.notif.called {
		t.Fatal("the webhook missed the change")
	}
	m := h.notif.msg
	if !m.SkipReport || m.Plan == nil || !m.Plan.Changed || m.Plan.SlackChanged || m.Plan.SlackDue() {
		t.Errorf("skip=%v plan=%+v", m.SkipReport, m.Plan)
	}
	if len(h.delivered.saves) != 1 || len(d.slackSaves) != 0 {
		t.Errorf("saves = %v, slack saves = %v", h.delivered.saves, d.slackSaves)
	}
}

// On the weekly day the plan is sent whether or not it changed.
func TestPlanSlack_WeeklyDaySendsAnUnchangedPlan(t *testing.T) {
	h, d := newSlackPlanHarness(true)
	h.r.FullReportDay = clock().Weekday()
	h.run(t)
	h.store.st = *h.store.saved
	h.notif.called = false
	h.run(t)
	p := h.notif.msg.Plan
	if !h.notif.called || p == nil || p.SlackChanged || !p.Weekly || !p.SlackDue() {
		t.Fatalf("weekly day: called=%v plan=%+v", h.notif.called, p)
	}
	if len(d.slackSaves) != 1 {
		t.Errorf("slack saves = %v, want only the first", d.slackSaves)
	}

	// Another day of the week: not due.
	h.r.FullReportDay = (clock().Weekday() + 1) % 7
	h.notif.called = false
	h.run(t)
	if p := h.notif.msg.Plan; !h.notif.called || p.Weekly || p.SlackDue() {
		t.Errorf("other day: plan=%+v", p)
	}
}

// deliveryNotifier fails after telling how the Slack and email plans went.
type deliveryNotifier struct {
	posted, failed           bool
	emailPosted, emailFailed bool
	setEmail                 bool
}

func (n deliveryNotifier) Send(_ context.Context, m notify.Message) error {
	m.PlanDelivery.Posted, m.PlanDelivery.Failed = n.posted, n.failed
	if n.setEmail {
		m.EmailDelivery.Posted, m.EmailDelivery.Failed = n.emailPosted, n.emailFailed
	}
	return errors.New("the thread failed")
}

// The plan that was posted is recorded although the rest of the send failed;
// a plan that was not posted is not.
func TestPlanSlack_PostedPlanIsRecordedAfterAFailedSend(t *testing.T) {
	for name, tc := range map[string]struct {
		n    deliveryNotifier
		want int
	}{
		"posted":     {deliveryNotifier{posted: true}, 1},
		"not posted": {deliveryNotifier{failed: true}, 0},
		"no plan":    {deliveryNotifier{}, 0},
	} {
		h, d := newSlackPlanHarness(true)
		h.r.Notifier = tc.n
		if err := h.r.RunOnce(context.Background()); err == nil {
			t.Fatalf("%s: the send error was swallowed", name)
		}
		if len(d.slackSaves) != tc.want {
			t.Errorf("%s: slack saves = %v, want %d", name, d.slackSaves, tc.want)
		}
		if len(h.delivered.saves) != 0 {
			t.Errorf("%s: the plan as a whole was recorded after a failed send: %v", name, h.delivered.saves)
		}
	}
}

// postedEmailNotifier records a successful email plan and keeps the message
// the runner built.
type postedEmailNotifier struct {
	msg notify.Message
}

func (n *postedEmailNotifier) Send(_ context.Context, m notify.Message) error {
	n.msg = m
	if m.Plan.EmailDue() {
		m.EmailDelivery.Posted = true
	}
	return nil
}

// Slack success and email failure keep separate records: the next cycle can
// still send the plan by email.
func TestPlanEmail_StaysDueWhenOnlySlackWasRecorded(t *testing.T) {
	h, d := newSlackPlanHarness(true)
	h.r.EmailConfigured = true
	h.r.Notifier = deliveryNotifier{posted: true, setEmail: true, emailFailed: true}
	if err := h.r.RunOnce(context.Background()); err == nil {
		t.Fatal("expected the send error")
	}
	if len(d.slackSaves) != 1 {
		t.Fatalf("slack saves = %v, want the posted plan", d.slackSaves)
	}
	if len(d.emailSaves) != 0 {
		t.Fatalf("email saves = %v after a failed email", d.emailSaves)
	}

	ok := &postedEmailNotifier{}
	h.r.Notifier = ok
	if err := h.r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	p := ok.msg.Plan
	if p == nil || p.SlackChanged || !p.EmailChanged || !p.EmailDue() {
		t.Fatalf("after Slack-only record: plan=%+v", p)
	}
	if len(d.emailSaves) != 1 || d.emailSaves[0] != p.SlackFingerprint() {
		t.Errorf("email saves = %v, want the display fingerprint", d.emailSaves)
	}
}

// Without email configured, a successful Slack send does not store an email
// fingerprint, and the plan is not treated as waiting on email.
func TestPlanEmail_IgnoredWhenEmailIsNotConfigured(t *testing.T) {
	h, d := newSlackPlanHarness(true)
	h.run(t)
	p := h.notif.msg.Plan
	if p == nil || p.EmailChanged || p.EmailDue() {
		t.Fatalf("email plan due without email: %+v", p)
	}
	if len(d.emailSaves) != 0 {
		t.Fatalf("email saves = %v without email configured", d.emailSaves)
	}
}
