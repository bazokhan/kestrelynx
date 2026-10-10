//go:build unix

package runner

import (
	"bytes"
	"strings"
	"unicode"
)

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	max       int
	buf       []byte
	truncated bool
	// marker, when set, is looked for in everything written, not only in the
	// kept tail; found records that it appeared.
	marker string
	found  bool
	carry  []byte
}

func newTailBuffer(max int) *tailBuffer { return &tailBuffer{max: max} }

// newMarkedTailBuffer is a tailBuffer that also notes whether marker was
// written anywhere in the stream.
func newMarkedTailBuffer(max int, marker string) *tailBuffer {
	return &tailBuffer{max: max, marker: marker}
}

func (t *tailBuffer) scan(p []byte) {
	if t.marker == "" || t.found {
		return
	}
	window := append(t.carry, p...)
	if bytes.Contains(window, []byte(t.marker)) {
		t.found = true
		t.carry = nil
		return
	}
	if keep := len(t.marker) - 1; len(window) > keep {
		window = window[len(window)-keep:]
	}
	t.carry = append([]byte(nil), window...)
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.scan(p)
	n := len(p)
	if n >= t.max {
		if n > t.max || len(t.buf) > 0 {
			t.truncated = true
		}
		t.buf = append(t.buf[:0], p[n-t.max:]...)
		return n, nil
	}
	if over := len(t.buf) + n - t.max; over > 0 {
		t.truncated = true
		t.buf = append(t.buf[:0], t.buf[over:]...)
	}
	t.buf = append(t.buf, p...)
	return n, nil
}

// String returns the kept tail as text with invalid UTF-8 and control
// characters removed (newline and tab stay), so it is safe to store and show.
func (t *tailBuffer) String() string { return sanitize(string(t.buf)) }

func sanitize(s string) string {
	s = strings.ToValidUTF8(s, "")
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || r == 0x2028 || r == 0x2029 {
			return -1
		}
		return r
	}, s)
}
