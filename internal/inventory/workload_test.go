package inventory

import (
	"strings"
	"testing"
)

func TestValidComposeName(t *testing.T) {
	for _, v := range []string{"web", "my-project_1", "プロジェクト", strings.Repeat("a", 253)} {
		if !ValidComposeName(v) {
			t.Errorf("%q rejected", v)
		}
	}
	for _, v := range []string{"", strings.Repeat("a", 254), "a\tb", "a\nb", "a\x7fb", "a\u0085b"} {
		if ValidComposeName(v) {
			t.Errorf("%q accepted", v)
		}
	}
}
