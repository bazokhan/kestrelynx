package scanner

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseReport_LayersFromRealReport(t *testing.T) {
	scan, err := ParseReport(loadFixture(t, "real_python_3.12.3-slim_layers.json"))
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	// The image has the base's five layers and one layer of its own.
	if len(scan.DiffIDs) != 6 {
		t.Fatalf("DiffIDs = %d entries, want 6", len(scan.DiffIDs))
	}
	for i, d := range scan.DiffIDs {
		if !strings.HasPrefix(d, "sha256:") || len(d) != len("sha256:")+64 {
			t.Errorf("DiffIDs[%d] = %q", i, d)
		}
	}

	index := map[string]int{}
	for i, d := range scan.DiffIDs {
		index[d] = i
	}
	byPkg := map[string][]int{}
	for _, f := range scan.Findings {
		if !strings.HasPrefix(f.LayerDigest, "sha256:") {
			t.Errorf("%s %s: LayerDigest = %q", f.Package, f.VulnID, f.LayerDigest)
		}
		i, ok := index[f.LayerDiffID]
		if !ok {
			t.Fatalf("%s %s: LayerDiffID %q is not one of the image's DiffIDs", f.Package, f.VulnID, f.LayerDiffID)
		}
		byPkg[f.Package] = append(byPkg[f.Package], i)
	}
	// OS packages sit in base layers; pip came with the base image and
	// requests was installed by the build's own layer.
	want := map[string][]int{
		"apt": {0, 0}, "bash": {0}, "ca-certificates": {1}, "libssl3": {1}, "libexpat1": {2, 2},
		"pip": {4, 4}, "requests": {5, 5},
	}
	for pkg, layers := range want {
		got := byPkg[pkg]
		if len(got) == 0 {
			t.Errorf("no finding for %s", pkg)
			continue
		}
		for _, l := range got {
			if l != layers[0] {
				t.Errorf("%s attributed to layer %d, want %d", pkg, l, layers[0])
			}
		}
	}
}

func TestParseReport_NoLayerInformation(t *testing.T) {
	scan, err := ParseReport(loadFixture(t, "sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) == 0 {
		t.Fatal("fixture has no findings")
	}
	if scan.DiffIDs != nil {
		t.Errorf("DiffIDs = %v, want nil when the report has none", scan.DiffIDs)
	}
	for _, f := range scan.Findings {
		if f.LayerDiffID != "" || f.LayerDigest != "" {
			t.Errorf("%s: layer = %q/%q, want empty", f.VulnID, f.LayerDiffID, f.LayerDigest)
		}
	}
}

func TestParseReport_DiffIDsAreCopied(t *testing.T) {
	data := []byte(`{"ArtifactName":"x","Metadata":{"DiffIDs":["sha256:a","sha256:b"]},"Results":[{"Class":"os-pkgs","Type":"debian","Target":"t","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"p","InstalledVersion":"1","Severity":"HIGH","Layer":{"DiffID":"sha256:b","Digest":"sha256:c"}}]}]}`)
	scan, err := ParseReport(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(scan.DiffIDs, []string{"sha256:a", "sha256:b"}) {
		t.Errorf("DiffIDs = %v", scan.DiffIDs)
	}
	f := scan.Findings[0]
	if f.LayerDiffID != "sha256:b" || f.LayerDigest != "sha256:c" {
		t.Errorf("layer = %q/%q", f.LayerDiffID, f.LayerDigest)
	}
}
