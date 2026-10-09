package github

import (
	"fmt"
	"io"
	"log/slog"
)

const redacted = "[redacted]"

// Token is a GitHub credential that prints as a placeholder under every fmt
// verb, in slog and when marshalled, so a struct holding one cannot leak it by
// being printed. Use Value to read it.
type Token string

// Value returns the credential itself.
func (t Token) Value() string { return string(t) }

func (t Token) text() string {
	if t == "" {
		return ""
	}
	return redacted
}

func (t Token) String() string   { return t.text() }
func (t Token) GoString() string { return `"` + t.text() + `"` }

// Format implements fmt.Formatter, covering every verb.
func (t Token) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, t.text()) }

func (t Token) LogValue() slog.Value         { return slog.StringValue(t.text()) }
func (t Token) MarshalText() ([]byte, error) { return []byte(t.text()), nil }
func (t Token) MarshalJSON() ([]byte, error) { return []byte(`"` + t.text() + `"`), nil }

// bearer returns the Authorization header value for a token, or "" for none.
// The client keeps it as a func: fmt prints unexported fields without calling
// their methods (a bad verb even prints a pointer's target), but it prints a
// func only as an address, so the value stays out of any printed Client.
func bearer(t Token) func() string {
	v := ""
	if t != "" {
		v = "Bearer " + t.Value()
	}
	return func() string { return v }
}
