// Escaping for the Block Kit rendering. Every value that comes from outside
// the dictionary — a title, a package name, a version, an image reference, an
// environment name, a vulnerability id, a reference label, an error text — is
// escaped exactly once, where the card renderers and view builders put it
// into mrkdwn: Slack's own control syntax (<!channel>, <@user>, <url|label>)
// is introduced by "<", so "&", "<" and ">" are replaced with their entities.
// A link is built from a validated URL and an escaped label, never by
// escaping a finished link. The plain-text renderers keep their historical
// output and do not use this file.
package notify

import (
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

var mrkdwnEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// escMrkdwn escapes s for Slack mrkdwn. Apply it to a raw value once.
func escMrkdwn(s string) string { return mrkdwnEscaper.Replace(s) }

// validLinkURL reports whether raw may be placed inside a Slack link: an
// http or https URL with a host and none of the characters that end or split
// a link (whitespace, "|", "<", ">") or open a code span.
func validLinkURL(raw string) bool {
	if raw == "" {
		return false
	}
	for _, r := range raw {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == '|' || r == '<' || r == '>' || r == '`' {
			return false
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

// mrkdwnLink renders <url|label> from a raw URL and a raw label. A URL that
// cannot be a link target is shown as escaped plain text instead.
func mrkdwnLink(rawURL, label string) string {
	if !validLinkURL(rawURL) {
		if label == "" || label == rawURL {
			return escMrkdwn(rawURL)
		}
		return escMrkdwn(label) + " (" + escMrkdwn(rawURL) + ")"
	}
	if label == "" {
		label = rawURL
	}
	return "<" + strings.ReplaceAll(rawURL, "&", "&amp;") + "|" + escMrkdwn(label) + ">"
}

var safeCVEID = regexp.MustCompile(`^CVE-[0-9A-Za-z-]+$`)

// cardIDLink is vulnIDLink for the Block Kit rendering: a CVE id of the
// ordinary shape links to its NVD page, anything else is escaped text.
func cardIDLink(id string) string {
	if safeCVEID.MatchString(id) {
		return "<https://nvd.nist.gov/vuln/detail/" + id + "|" + id + ">"
	}
	return escMrkdwn(id)
}

// refLinksSafe renders refs as Slack links with escaped labels and validated
// URLs.
func refLinksSafe(refs []cardRef, msg messages) []string {
	parts := make([]string, 0, len(refs))
	for _, ref := range refs {
		switch ref.Kind {
		case "advisory":
			parts = append(parts, mrkdwnLink(ref.URL, msg.AdvisoryLinkLabel))
		case "vendor":
			parts = append(parts, mrkdwnLink(ref.URL, msg.VendorAdvisoryLinkLabel))
		case "discussion":
			parts = append(parts, mrkdwnLink(ref.URL, "💬 "+ref.Label))
		default:
			parts = append(parts, mrkdwnLink(ref.URL, ref.Label))
		}
	}
	return parts
}

// literalNeedsCode matches a value that Slack would read as formatting: a
// backtick, a star or a tilde anywhere, or an underscore at the edge of a
// word.
var literalNeedsCode = regexp.MustCompile("[`*~]|(^|[^A-Za-z0-9])_|_([^A-Za-z0-9]|$)")

// litMrkdwn shows an external value (an image reference, a path, a package
// name, a version, a code) as the literal text it is. It is escaped like
// escMrkdwn; a value with characters that would format the text around it is
// put in an inline code span, in which a backtick is shown as an apostrophe.
func litMrkdwn(s string) string {
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	e := escMrkdwn(s)
	if !literalNeedsCode.MatchString(s) {
		return e
	}
	return "`" + strings.ReplaceAll(e, "`", "'") + "`"
}

// refMrkdwn shows an image reference. One that starts with a registry host
// (ghcr.io/org/app:tag) is put in an inline code span: Slack turns such a
// name into a link, and the link would take the closing mark of a bold line
// with it.
func refMrkdwn(ref string) string {
	if i := strings.IndexByte(ref, '/'); i > 0 && strings.ContainsAny(ref[:i], ".:") {
		return "`" + strings.ReplaceAll(escMrkdwn(strings.NewReplacer("\r", " ", "\n", " ").Replace(ref)), "`", "'") + "`"
	}
	return litMrkdwn(ref)
}
