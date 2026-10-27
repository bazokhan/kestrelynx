// Escaping for the Block Kit rendering. Every value that comes from outside
// the dictionary — a title, a package name, a version, an image reference, an
// environment name, a vulnerability id, a reference label, an error text — is
// escaped exactly once, where the card renderers and view builders put it
// into mrkdwn: Slack's own control syntax (<!channel>, <@user>, <url|label>)
// is introduced by "<", so "&", "<" and ">" are replaced with their entities.
// A link is built from a validated URL and an escaped label, never by
// escaping a finished link. The saved plain-text goldens do not use this
// file. Email does: mrkdwnToPlain turns a finished message into text.
package notify

import (
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

var mrkdwnEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
var mrkdwnUnescaper = strings.NewReplacer("&lt;", "<", "&gt;", ">", "&amp;", "&")

// escMrkdwn escapes s for Slack mrkdwn. Apply it to a raw value once.
func escMrkdwn(s string) string { return mrkdwnEscaper.Replace(s) }

// unescapeMrkdwn undoes escMrkdwn.
func unescapeMrkdwn(s string) string { return mrkdwnUnescaper.Replace(s) }

var (
	mrkdwnLinkLabel = regexp.MustCompile(`<([^<>|]+)\|([^<>]+)>`)
	mrkdwnLinkBare  = regexp.MustCompile(`<([^<>|]+)>`)
	mrkdwnBold      = regexp.MustCompile(`\*(.+?)\*`)
)

// mrkdwnToPlain turns Slack mrkdwn into readable plain text for email.
func mrkdwnToPlain(s string) string {
	s = mrkdwnLinkLabel.ReplaceAllStringFunc(s, func(m string) string {
		sub := mrkdwnLinkLabel.FindStringSubmatch(m)
		u := unescapeMrkdwn(sub[1])
		label := unescapeMrkdwn(sub[2])
		if label == u {
			return u
		}
		return label + " (" + u + ")"
	})
	s = mrkdwnLinkBare.ReplaceAllStringFunc(s, func(m string) string {
		return unescapeMrkdwn(mrkdwnLinkBare.FindStringSubmatch(m)[1])
	})
	s = mrkdwnBold.ReplaceAllString(s, "$1")
	s = strings.ReplaceAll(s, "`", "")
	s = unescapeMrkdwn(s)
	return stripWholeLineItalic(s)
}

// stripWholeLineItalic removes Slack italics that wrap an entire line
// (_like this_). Underscores inside a line stay, so versions and package
// names are unchanged.
func stripWholeLineItalic(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if len(trim) < 2 || !strings.HasPrefix(trim, "_") || !strings.HasSuffix(trim, "_") {
			continue
		}
		inner := trim[1 : len(trim)-1]
		if strings.Contains(inner, "_") {
			continue
		}
		lines[i] = strings.Replace(line, trim, inner, 1)
	}
	return strings.Join(lines, "\n")
}

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

// hostPath reports whether s starts with a host name and a path
// (ghcr.io/org/app:tag, github.com/org/module). Slack turns such a name into
// a link, and in a bold line the link would take the closing mark with it.
// A scoped npm name (@scope.v1/pkg) starts with "@" and is not a host.
func hostPath(s string) bool {
	i := strings.IndexByte(s, '/')
	return i > 0 && s[0] != '@' && strings.ContainsAny(s[:i], ".:") && !strings.ContainsAny(s[:i], " \t")
}

// codeSpan puts s in an inline code span on one line, a backtick shown as an
// apostrophe.
func codeSpan(s string) string {
	return "`" + strings.ReplaceAll(escMrkdwn(strings.NewReplacer("\r", " ", "\n", " ").Replace(s)), "`", "'") + "`"
}

// refMrkdwn shows an image reference. One that starts with a registry host
// is put in an inline code span (see hostPath).
func refMrkdwn(ref string) string {
	if hostPath(ref) {
		return codeSpan(ref)
	}
	return litMrkdwn(ref)
}

// boldLine makes the bold line prefix+value from a value already rendered
// for mrkdwn. Slack drops the bold marks of a line whose text starts or ends
// with a code span, so when value starts or ends with one (see boldMrkdwn,
// refMrkdwn, litMrkdwn) only the prefix is bold and the value follows it:
// "*Image:* `ghcr.io/org/app`".
func boldLine(prefix, value string) string {
	if strings.HasPrefix(value, "`") || strings.HasSuffix(value, "`") {
		return "*" + strings.TrimRight(prefix, " ") + "* " + value
	}
	return "*" + prefix + value + "*"
}

// boldMrkdwn escapes a name shown in a bold line. When its first word starts
// with a host and a path (see hostPath), that word is put in an inline code
// span and the rest is escaped as usual.
func boldMrkdwn(s string) string {
	head, rest := s, ""
	if i := strings.IndexByte(s, ' '); i > 0 {
		head, rest = s[:i], s[i:]
	}
	if !hostPath(head) {
		return escMrkdwn(s)
	}
	return codeSpan(head) + escMrkdwn(rest)
}

// boldMrkdwnCapped is boldMrkdwn shortened to max units. A name that starts
// with a host and a path is put in a code span whole, so the cut cannot leave
// the span open.
func boldMrkdwnCapped(s string, max int) string {
	if !hostPath(s) {
		return capEscaped(escMrkdwn(s), max)
	}
	e := strings.ReplaceAll(escMrkdwn(strings.NewReplacer("\r", " ", "\n", " ").Replace(s)), "`", "'")
	return "`" + capEscaped(e, max) + "`"
}
