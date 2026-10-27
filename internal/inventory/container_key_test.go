package inventory

import (
	"strings"
	"testing"
)

func TestParseContainerKey(t *testing.T) {
	for _, v := range []string{"web", "Ab", "shop_api-1.x", "0day", strings.Repeat("a", 253)} {
		name, err := ParseContainerKey("container/" + v)
		if err != nil || name != v {
			t.Errorf("%q: name %q, err %v", v, name, err)
		}
	}
	for _, key := range []string{
		"", "container", "container/", "container/a", "container/-web", "container/_web", "container/.web",
		"container/a/b", "container/a b", "container/a\tb", "container/a\nb", "container/a\x07b", "container/wéb",
		"container/" + strings.Repeat("a", 254), "compose/p/s", "Container/web",
	} {
		if _, err := ParseContainerKey(key); err == nil {
			t.Errorf("%q accepted", key)
		}
	}
}
