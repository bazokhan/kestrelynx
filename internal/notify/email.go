// Email delivery over SMTP. TLS is required: either STARTTLS after a plain
// connect, or implicit TLS on the connection. The body reuses the Slack
// channel, thread, and fix-plan messages, converted from mrkdwn to plain text.
package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
	"unicode/utf8"
)

// emailSendTimeout is the default limit for one SMTP send, from dial through
// QUIT. A silent server must not stall the scan loop.
const emailSendTimeout = 30 * time.Second

// emailRenderLimits are large enough that the Slack packer keeps each
// channel, thread, and plan section in one message, so continuation markers
// never appear in the email body.
var emailRenderLimits = RenderLimits{
	MaxBlocks:        1 << 30,
	MaxTextUnits:     1 << 30,
	MaxMessageUnits:  1 << 30,
	MaxFallbackUnits: 1 << 30,
}

// EmailNotifier delivers one plain-text message per cycle to the configured
// SMTP destination. It does not write Message.Result or Message.PlanDelivery;
// those belong to the Slack bot path. It does write Message.EmailDelivery when
// this message carried the fix plan.
type EmailNotifier struct {
	Host     string
	Port     int
	TLS      string // "starttls" or "tls"
	Username string
	Password string
	From     string
	To       []string
	// Language selects the wording dictionary. The zero value is LanguageEN.
	Language Language
	// Timeout bounds one send from dial through QUIT. Zero means 30s.
	Timeout time.Duration

	// DialContext opens the TCP connection; nil uses a net.Dialer.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// TLSConfig is used for STARTTLS and implicit TLS; nil sets ServerName to Host.
	TLSConfig *tls.Config
}

func (n EmailNotifier) Send(ctx context.Context, m Message) error {
	msgs := buildEmailMessages(m, n.Language)
	if len(msgs) == 0 {
		return nil
	}
	subject := emailSubject(msgs)
	body := emailBody(msgs)
	timeout := n.Timeout
	if timeout <= 0 {
		timeout = emailSendTimeout
	}
	sendCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err := n.deliver(sendCtx, subject, body)
	if m.Plan != nil && m.Plan.EmailDue() {
		m.EmailDelivery.record(err == nil)
	}
	return err
}

// buildEmailMessages collects the Slack messages that make up one email.
func buildEmailMessages(m Message, lang Language) []SlackMessage {
	msg, lim := messagesFor(lang), emailRenderLimits
	var out []SlackMessage
	if !m.SkipReport {
		out = append(out, buildChannelMessages(m, ChannelFooter{}, msg, lim)...)
		if m.Thread {
			out = append(out, buildThreadBlockMessagesWithPlan(m.Report, Ages{Finding: m.FirstSeen, EOL: m.EOLFirstSeen}, m.Plan, msg, lim)...)
		}
	}
	out = append(out, buildEmailPlanMessages(m, msg, lim)...)
	return out
}

// buildEmailPlanMessages is the fix-plan body for email: due when EmailDue is
// set, and shown whole when EmailChanged is set.
func buildEmailPlanMessages(m Message, msg messages, lim RenderLimits) []SlackMessage {
	p := m.Plan
	if !p.EmailDue() {
		return nil
	}
	lim = lim.normalized()
	v := buildPlanView(p, msg, planOpts{openOnly: !p.EmailChanged})
	if m.Report.GenericWebhookConfigured && len(v.groups) > 0 {
		v.notes = append(v.notes, trimNL(msg.DetailsInWebhook))
	}

	head := []string{trimNL(msg.PlanHeading)}
	plain := v.summary
	switch {
	case v.unavailable != "":
		head = append(head, v.unavailable)
		plain = strings.Trim(v.unavailable, "_")
	case v.summary != "":
		head = append(head, v.summary)
	case len(v.groups) == 0 && len(v.notes) == 0:
		head = append(head, trimNL(msg.PlanNothing))
		plain = trimNL(msg.PlanNothing)
	}
	var l layout
	l.section(lim, head, false)
	for _, g := range v.groups {
		l.group()
		lines := append(append([]string(nil), g.headings...), g.lines...)
		l.emit(unit{blocks: sectionBlocks(lines, lim.MaxTextUnits), contTitle: g.headings[0]}, false)
	}
	if len(v.notes) > 0 {
		l.group()
		l.section(lim, v.notes, false)
	}

	date := (&chView{r: m.Report}).dateText()
	return splitUnits(l.units, splitSpec{
		lim: lim,
		lead: func(n, total int) string {
			return trimNL(msg.PlanHeading) + fmt.Sprintf(msg.ChannelContinued, n, total)
		},
		cont: msg.ThreadContinued,
		fallback: func(info msgInfo) string {
			if info.n > 1 {
				return fmt.Sprintf(msg.PlanFallbackCont, date, info.n, info.total)
			}
			return fmt.Sprintf(msg.PlanFallback, date, plain)
		},
	})
}

func emailSubject(msgs []SlackMessage) string {
	s := "KestreLynx"
	if len(msgs) > 0 && msgs[0].Text != "" {
		s = msgs[0].Text
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(mrkdwnToPlain(s))
	s = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, s)
	if s == "" {
		s = "KestreLynx"
	}
	if utf8.RuneCountInString(s) > 200 {
		s = string([]rune(s)[:200])
	}
	return s
}

func emailBody(msgs []SlackMessage) string {
	var parts []string
	for _, sm := range msgs {
		var lines []string
		for _, b := range sm.Blocks {
			switch b.Kind {
			case BlockDivider:
				lines = append(lines, "---")
			case BlockSection, BlockContext:
				if t := strings.TrimSpace(mrkdwnToPlain(b.Text)); t != "" {
					lines = append(lines, t)
				}
			}
		}
		if len(lines) > 0 {
			parts = append(parts, strings.Join(lines, "\n"))
		}
	}
	return strings.Join(parts, "\n\n")
}

func encodeSubject(s string) string {
	for _, r := range s {
		if r > 127 {
			return mime.QEncoding.Encode("utf-8", s)
		}
	}
	return s
}

func (n EmailNotifier) deliver(ctx context.Context, subject, body string) error {
	from, err := mail.ParseAddress(n.From)
	if err != nil {
		return fmt.Errorf("email from: invalid address")
	}
	toAddrs := make([]string, 0, len(n.To))
	toHeaders := make([]string, 0, len(n.To))
	for i, raw := range n.To {
		a, err := mail.ParseAddress(raw)
		if err != nil {
			return fmt.Errorf("email to[%d]: invalid address", i)
		}
		toAddrs = append(toAddrs, a.Address)
		toHeaders = append(toHeaders, formatMailbox(a))
	}
	msg, err := buildMIME(formatMailbox(from), toHeaders, encodeSubject(subject), body)
	if err != nil {
		return fmt.Errorf("email: build message: %w", err)
	}
	addr := net.JoinHostPort(n.Host, fmt.Sprintf("%d", n.Port))
	if err := n.smtpSend(ctx, addr, from.Address, toAddrs, msg); err != nil {
		return fmt.Errorf("email: %w", redactEmailErr(err, n.Password))
	}
	return nil
}

func formatMailbox(a *mail.Address) string {
	if a.Name == "" {
		return a.Address
	}
	return a.String()
}

func buildMIME(from string, to []string, subject, body string) ([]byte, error) {
	var encoded bytes.Buffer
	w := quotedprintable.NewWriter(&encoded)
	if _, err := w.Write([]byte(body)); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("From: ")
	b.WriteString(from)
	b.WriteString("\r\n")
	b.WriteString("To: ")
	b.WriteString(strings.Join(to, ", "))
	b.WriteString("\r\n")
	b.WriteString("Subject: ")
	b.WriteString(subject)
	b.WriteString("\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	b.WriteString("\r\n")
	b.Write(encoded.Bytes())
	return []byte(b.String()), nil
}

func (n EmailNotifier) smtpSend(ctx context.Context, addr, from string, to []string, msg []byte) error {
	tlsCfg := n.tlsConfig()
	var conn net.Conn
	var err error
	switch n.TLS {
	case "tls":
		conn, err = n.dialTLS(ctx, addr, tlsCfg)
	case "starttls":
		conn, err = n.dial(ctx, addr)
	default:
		return fmt.Errorf("unsupported tls mode %q", n.TLS)
	}
	if err != nil {
		return err
	}
	// Cancel closes the connection. SMTP itself has no context.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	client, err := smtp.NewClient(conn, n.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer client.Close()

	if n.TLS == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("server does not offer STARTTLS")
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			return err
		}
	}
	if n.Username != "" {
		if ok, _ := client.Extension("AUTH"); !ok {
			return errors.New("server does not offer AUTH")
		}
		if err := client.Auth(smtp.PlainAuth("", n.Username, n.Password, n.Host)); err != nil {
			return err
		}
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	// DATA already succeeded. A later QUIT failure must not make the runner
	// send the same report again.
	_ = client.Quit()
	return nil
}

func (n EmailNotifier) dial(ctx context.Context, addr string) (net.Conn, error) {
	if n.DialContext != nil {
		return n.DialContext(ctx, "tcp", addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

func (n EmailNotifier) dialTLS(ctx context.Context, addr string, cfg *tls.Config) (net.Conn, error) {
	raw, err := n.dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	c := tls.Client(raw, cfg)
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	if err := c.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	return c, nil
}

func (n EmailNotifier) tlsConfig() *tls.Config {
	if n.TLSConfig != nil {
		return n.TLSConfig.Clone()
	}
	name := n.Host
	if ip := net.ParseIP(strings.Trim(n.Host, "[]")); ip != nil {
		name = ip.String()
	}
	return &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12}
}

// redactEmailErr hides transport details that may include the password and
// classifies common context failures the way webhook delivery does.
func redactEmailErr(err error, password string) error {
	if err == nil {
		return nil
	}
	msg := "request failed"
	var nerr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		msg = "timeout"
	case errors.Is(err, context.Canceled):
		msg = "canceled"
	case errors.As(err, &nerr) && nerr.Timeout():
		msg = "timeout"
	default:
		text := err.Error()
		if password != "" && strings.Contains(text, password) {
			text = strings.ReplaceAll(text, password, "[redacted]")
		}
		// Keep a short classification without raw server chatter when possible.
		lower := strings.ToLower(text)
		switch {
		case strings.Contains(lower, "starttls"):
			msg = "tls required"
		case strings.Contains(lower, "auth"):
			msg = "authentication failed"
		case strings.Contains(lower, "certificate") || strings.Contains(lower, "tls"):
			msg = "tls failed"
		default:
			msg = "delivery failed"
		}
	}
	return &redactedError{msg: msg, err: err}
}
