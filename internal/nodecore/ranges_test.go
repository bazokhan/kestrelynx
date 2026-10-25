package nodecore

import "testing"

func mustVersion(t *testing.T, s string) version {
	t.Helper()
	v, ok := parseVersion(s)
	if !ok {
		t.Fatalf("bad test version %q", s)
	}
	return v
}

func TestParseRange(t *testing.T) {
	tests := []struct {
		name    string
		rng     string
		patched bool
		in      []string
		out     []string
	}{
		{"exact", "8.5.0", false, []string{"8.5.0"}, []string{"8.5.1", "8.4.9"}},
		{"x major", "8.x", false, []string{"8.0.0", "8.99.1"}, []string{"7.9.9", "9.0.0"}},
		{"x minor", "9.7.x", false, []string{"9.7.0", "9.7.5"}, []string{"9.6.9", "9.8.0"}},
		{"partial major", "10", false, []string{"10.4.4"}, []string{"11.0.0"}},
		{"partial minor", "10.2", false, []string{"10.2.9"}, []string{"10.3.0", "10.1.9"}},
		{"caret", "^4.8.2", false, []string{"4.8.2", "4.9.0"}, []string{"4.8.1", "5.0.0"}},
		{"caret zero minor", "^0.10.48", false, []string{"0.10.48", "0.10.99"}, []string{"0.11.0", "0.10.47"}},
		{"caret zero zero", "^0.0.3", false, []string{"0.0.3"}, []string{"0.0.4"}},
		{"gte spaced", ">= 10.9.0", false, []string{"10.9.0", "22.1.0"}, []string{"10.8.9"}},
		{"gt", ">10.0.0", false, []string{"10.0.1"}, []string{"10.0.0"}},
		{"lte partial spaced", "<= 10", false, []string{"0.10.1", "10.99.9"}, []string{"11.0.0"}},
		{"lt", "<6.2.0", false, []string{"6.1.9"}, []string{"6.2.0"}},
		{"eq", "=8.5.0", false, []string{"8.5.0"}, []string{"8.5.1"}},
		{"and", ">=6.0.0 <6.2.0", false, []string{"6.0.0", "6.1.9"}, []string{"5.9.9", "6.2.0"}},
		{"and spaced operators", ">= 6.0.0   <  6.2.0", false, []string{"6.1.0"}, []string{"6.2.0"}},
		{"or", ">=6.0.0 <6.2.0 || 5.x || 4.x", false, []string{"6.1.0", "5.1.1", "4.0.0"}, []string{"7.0.0", "6.2.0"}},
		{"or extra spaces", " 4.x  ||  6.x ", false, []string{"4.1.1", "6.1.1"}, []string{"5.1.1"}},
		{"patched bare exact", "^12.19.1 || ^14.15.1 || 15.2.1", true, []string{"15.2.1", "15.9.0", "12.19.1"}, []string{"15.2.0", "16.0.0"}},
		{"vulnerable bare exact stays exact", "15.2.1", false, []string{"15.2.1"}, []string{"15.2.2"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := parseRange(tc.rng, tc.patched)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range tc.in {
				if !r.contains(mustVersion(t, v)) {
					t.Errorf("%q should contain %s", tc.rng, v)
				}
			}
			for _, v := range tc.out {
				if r.contains(mustVersion(t, v)) {
					t.Errorf("%q should not contain %s", tc.rng, v)
				}
			}
		})
	}
}

func TestParseRangeErrors(t *testing.T) {
	for _, s := range []string{"", "1.2.3 - 2.0.0", "~1.2.3", "a.b.c", "1.2.3.4", "1.x.3", "4.x ||", ">", "01.2.3", "latest"} {
		if _, err := parseRange(s, false); err == nil {
			t.Errorf("parseRange(%q) should fail", s)
		}
	}
}

func TestRangeTouchesMajor(t *testing.T) {
	r, err := parseRange("^22.23.0 || >= 10.9.0 <12.0.0 || 4.x", false)
	if err != nil {
		t.Fatal(err)
	}
	for m, want := range map[int]bool{4: true, 5: false, 10: true, 11: true, 12: false, 22: true, 23: false} {
		if got := r.touchesMajor(m); got != want {
			t.Errorf("touchesMajor(%d) = %v, want %v", m, got, want)
		}
	}
}

func TestParseVersion(t *testing.T) {
	for _, s := range []string{"22.23.3", "0.10.48", "7.0.0"} {
		if _, ok := parseVersion(s); !ok {
			t.Errorf("parseVersion(%q) should succeed", s)
		}
	}
	for _, s := range []string{"v22.1.0", "22.1", "22.01.0", "22.1.0-rc.1", "22.1.0 ", "", "1.2.3.4", "9999999999.0.0"} {
		if _, ok := parseVersion(s); ok {
			t.Errorf("parseVersion(%q) should fail", s)
		}
	}
}
