package remediation

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func did(c string) string { return "sha256:" + strings.Repeat(c, 64) }

func TestMatchBaseLayers(t *testing.T) {
	a, b, c, d := did("a"), did("b"), did("c"), did("d")
	tests := []struct {
		name   string
		image  []string
		typ    string
		base   []string
		status BaseLayerStatus
		count  int
	}{
		{"prefix", []string{a, b, c, d}, "layers", []string{a, b, c}, BaseLayersConfirmed, 3},
		{"one layer prefix", []string{a, b}, "layers", []string{a}, BaseLayersConfirmed, 1},
		{"identical lists", []string{a, b}, "layers", []string{a, b}, BaseLayersConfirmed, 2},
		{"repeated layer inside the prefix", []string{a, a, b}, "layers", []string{a, a}, BaseLayersConfirmed, 2},
		{"base is not at the start", []string{a, b, c}, "layers", []string{b, c}, BaseLayersMismatch, 0},
		{"first layer differs", []string{d, b, c}, "layers", []string{a, b}, BaseLayersMismatch, 0},
		{"last base layer differs", []string{a, b, c}, "layers", []string{a, d}, BaseLayersMismatch, 0},
		{"base longer than the image", []string{a}, "layers", []string{a, b}, BaseLayersMismatch, 0},
		{"order matters", []string{a, b}, "layers", []string{b, a}, BaseLayersMismatch, 0},
		{"base rootfs type missing", []string{a, b}, "", []string{a}, BaseLayersUnusable, 0},
		{"base rootfs type other", []string{a, b}, "other", []string{a}, BaseLayersUnusable, 0},
		{"base rootfs type case", []string{a, b}, "Layers", []string{a}, BaseLayersUnusable, 0},
		{"base diff_ids empty", []string{a, b}, "layers", nil, BaseLayersUnusable, 0},
		{"image layers empty", nil, "layers", []string{a}, BaseLayersUnusable, 0},
		{"base id malformed", []string{a, b}, "layers", []string{"sha256:xyz"}, BaseLayersUnusable, 0},
		{"base id upper case", []string{a, b}, "layers", []string{"sha256:" + strings.Repeat("A", 64)}, BaseLayersUnusable, 0},
		{"base id wrong algorithm", []string{a, b}, "layers", []string{"sha512:" + strings.Repeat("a", 64)}, BaseLayersUnusable, 0},
		{"image id malformed", []string{a, "bogus"}, "layers", []string{a}, BaseLayersUnusable, 0},
		{"both empty", nil, "layers", nil, BaseLayersUnusable, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchBaseLayers(tc.image, tc.typ, tc.base)
			if got.Status != tc.status || got.Count != tc.count {
				t.Errorf("got %+v, want %s/%d", got, tc.status, tc.count)
			}
			if got.Status != BaseLayersConfirmed && got.Detail == "" {
				t.Error("no detail for a result that is not confirmed")
			}
		})
	}
}

func TestClassifyFindingsByLayer(t *testing.T) {
	a, b, c, d, e := did("a"), did("b"), did("c"), did("d"), did("e")
	f := func(pkg, layer string) scanner.Finding {
		return scanner.Finding{Package: pkg, VulnID: "CVE-1", LayerDiffID: layer}
	}
	names := func(fs []scanner.Finding) []string {
		var out []string
		for _, x := range fs {
			out = append(out, x.Package)
		}
		return out
	}
	findings := []scanner.Finding{
		f("p0", a), f("p1", b), f("p2", c), f("p3", d), f("none", ""), f("foreign", e), f("p4", b), f("p5", d),
	}
	got := ClassifyFindingsByLayer([]string{a, b, c, d}, 3, findings)
	if want := []string{"p0", "p1", "p2", "p4"}; !reflect.DeepEqual(names(got.Base), want) {
		t.Errorf("base = %v, want %v", names(got.Base), want)
	}
	if want := []string{"p3", "p5"}; !reflect.DeepEqual(names(got.Upper), want) {
		t.Errorf("upper = %v, want %v", names(got.Upper), want)
	}
	if want := []string{"none", "foreign"}; !reflect.DeepEqual(names(got.Unknown), want) {
		t.Errorf("unknown = %v, want %v", names(got.Unknown), want)
	}

	// A layer that occurs on both sides of the boundary cannot be placed.
	got = ClassifyFindingsByLayer([]string{a, b, a}, 2, []scanner.Finding{f("dup", a), f("b", b)})
	if !reflect.DeepEqual(names(got.Unknown), []string{"dup"}) || !reflect.DeepEqual(names(got.Base), []string{"b"}) || len(got.Upper) != 0 {
		t.Errorf("repeated layer: %+v", got)
	}

	// A base that is the whole image leaves nothing above it.
	got = ClassifyFindingsByLayer([]string{a, b}, 2, []scanner.Finding{f("x", b)})
	if len(got.Base) != 1 || len(got.Upper) != 0 || len(got.Unknown) != 0 {
		t.Errorf("whole image: %+v", got)
	}

	// Without a usable prefix length nothing is placed.
	for _, n := range []int{-1, 0, 5} {
		got = ClassifyFindingsByLayer([]string{a, b}, n, []scanner.Finding{f("x", a), f("y", b)})
		if len(got.Unknown) != 2 || len(got.Base) != 0 || len(got.Upper) != 0 {
			t.Errorf("baseLayers %d: %+v", n, got)
		}
	}
	if got := ClassifyFindingsByLayer(nil, 1, nil); len(got.Base)+len(got.Upper)+len(got.Unknown) != 0 {
		t.Errorf("empty input: %+v", got)
	}
}

// A real Trivy report of an image built FROM python:3.12.3-slim plus one
// RUN: the base's five layers come first, the build's own layer last.
func TestClassifyFindingsByLayer_RealReport(t *testing.T) {
	data, err := os.ReadFile("../scanner/testdata/real_python_3.12.3-slim_layers.json")
	if err != nil {
		t.Fatal(err)
	}
	scan, err := scanner.ParseReport(data)
	if err != nil {
		t.Fatal(err)
	}
	// The five diff_ids of the base's registry config for linux/amd64.
	base := scan.DiffIDs[:5]
	m := MatchBaseLayers(scan.DiffIDs, "layers", base)
	if m.Status != BaseLayersConfirmed || m.Count != 5 {
		t.Fatalf("match = %+v", m)
	}
	got := ClassifyFindingsByLayer(scan.DiffIDs, m.Count, scan.Findings)
	if len(got.Unknown) != 0 || len(got.Upper) != 2 || len(got.Base) != len(scan.Findings)-2 {
		t.Fatalf("base %d upper %d unknown %d of %d", len(got.Base), len(got.Upper), len(got.Unknown), len(scan.Findings))
	}
	for _, f := range got.Upper {
		if f.Package != "requests" {
			t.Errorf("upper finding %s", f.Package)
		}
	}
	for _, f := range got.Base {
		if f.Package == "requests" {
			t.Errorf("requests placed in the base")
		}
	}
	// With a different base the same image does not match.
	other := append([]string{did("f")}, base[1:]...)
	if MatchBaseLayers(scan.DiffIDs, "layers", other).Status != BaseLayersMismatch {
		t.Error("a base with another first layer matched")
	}
}
