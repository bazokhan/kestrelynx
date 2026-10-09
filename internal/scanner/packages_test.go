package scanner

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestParseReport_PackagesAndVersion(t *testing.T) {
	data, err := os.ReadFile("testdata/real_packages_debian_python.json")
	if err != nil {
		t.Fatal(err)
	}
	scan, err := ParseReport(data)
	if err != nil {
		t.Fatal(err)
	}
	if scan.TrivyVersion != "0.71.2" {
		t.Errorf("TrivyVersion = %q", scan.TrivyVersion)
	}
	if scan.PackagesTruncated {
		t.Error("small report must not be truncated")
	}
	if len(scan.Packages) != 2 {
		t.Fatalf("Packages results = %d", len(scan.Packages))
	}
	os0, lang := scan.Packages[0], scan.Packages[1]
	if os0.Class != ClassOS || os0.Type != "debian" || !strings.Contains(os0.Target, "debian") {
		t.Errorf("os result = %+v", os0)
	}
	versions := map[string]string{}
	for _, p := range os0.Packages {
		versions[p.Name] = p.Version
		if p.PkgPath != "" {
			t.Errorf("OS package %s has PkgPath %q", p.Name, p.PkgPath)
		}
	}
	// Epoch and release are folded in the way Trivy writes InstalledVersion.
	for name, want := range map[string]string{"adduser": "3.134", "bash": "5.2.15-2+b13", "bsdutils": "1:2.38.1-5+deb12u3", "coreutils": "9.1-1"} {
		if versions[name] != want {
			t.Errorf("%s version = %q, want %q", name, versions[name], want)
		}
	}
	if lang.Class != ClassLang || lang.Type != "python-pkg" || len(lang.Packages) != 1 {
		t.Fatalf("lang result = %+v", lang)
	}
	if p := lang.Packages[0]; p.Name != "pip" || p.Version != "25.0.1" ||
		p.PkgPath != "usr/local/lib/python3.12/site-packages/pip-25.0.1.dist-info/METADATA" {
		t.Errorf("lang package = %+v", p)
	}
}

func TestParseReport_PackagePathLeadingSlashTrimmed(t *testing.T) {
	scan, err := ParseReport([]byte(`{"Results":[{"Class":"lang-pkgs","Type":"jar","Target":"/app/x.jar","Packages":[{"Name":"a","Version":"1","FilePath":"/app/x.jar"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	r := scan.Packages[0]
	if r.Target != "app/x.jar" || r.Packages[0].PkgPath != "app/x.jar" {
		t.Errorf("%+v", r)
	}
}

func TestParseReport_ExistingFixturesUnaffected(t *testing.T) {
	data, err := os.ReadFile("testdata/real_alpine_3.19.json")
	if err != nil {
		t.Fatal(err)
	}
	scan, err := ParseReport(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Packages) != 0 || scan.PackagesTruncated {
		t.Errorf("a report without Packages must yield none: %+v", scan.Packages)
	}
	if scan.TrivyVersion != "0.71.2" || len(scan.Findings) == 0 {
		t.Errorf("version=%q findings=%d", scan.TrivyVersion, len(scan.Findings))
	}
}

func TestParseReport_PackageCapTruncates(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"Results":[{"Class":"lang-pkgs","Type":"npm","Target":"t","Packages":[`)
	for i := 0; i < maxRetainedPackages+5; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"Name":"p%d","Version":"1"}`, i)
	}
	b.WriteString(`]},{"Class":"lang-pkgs","Type":"pip","Target":"u","Packages":[{"Name":"late","Version":"1"}]}]}`)
	scan, err := ParseReport([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if !scan.PackagesTruncated {
		t.Error("over-cap report must be marked truncated")
	}
	total := 0
	for _, r := range scan.Packages {
		total += len(r.Packages)
	}
	if total != maxRetainedPackages {
		t.Errorf("retained %d, want %d", total, maxRetainedPackages)
	}
}

func TestParseReport_ExactlyAtCapNotTruncated(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"Results":[{"Class":"lang-pkgs","Type":"npm","Target":"t","Packages":[`)
	for i := 0; i < maxRetainedPackages; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"Name":"p","Version":"1"}`)
	}
	b.WriteString(`]}]}`)
	scan, err := ParseReport([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if scan.PackagesTruncated {
		t.Error("exactly the cap must not be marked truncated")
	}
}
