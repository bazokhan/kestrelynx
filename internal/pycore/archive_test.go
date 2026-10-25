package pycore

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

func okAdvisory(id string) tarEntry {
	return tarEntry{name: psfFile(id), body: advisoryJSON(id, false, "CVE-2026-1000")}
}

func TestParseArchiveRealData(t *testing.T) {
	advs, err := parseArchive(readTestdata(t, "psf-advisory-database.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 197 {
		t.Errorf("advisories = %d, want 197", len(advs))
	}
	cves := 0
	for _, a := range advs {
		cves += len(a.cves)
		if a.withdrawn {
			t.Errorf("%s withdrawn", a.id)
		}
	}
	if cves != 182 {
		t.Errorf("CVE aliases = %d, want 182", cves)
	}
}

func TestParseArchiveSkipsOtherEntries(t *testing.T) {
	data := makeArchive(t, []tarEntry{
		{name: "advisory-database-main/", typ: '5'},
		okAdvisory("PSF-2026-1"),
		// Links, even to a valid-looking target, are not read.
		{name: psfFile("PSF-2026-2"), typ: '2', link: "../../../etc/passwd"},
		{name: psfFile("PSF-2026-3"), typ: '1', link: psfFile("PSF-2026-1")},
		// Traversal and stray paths are skipped.
		{name: "../advisories/python/PSF-2026-4.json", body: advisoryJSON("PSF-2026-4", false)},
		{name: "advisory-database-main/../../advisories/python/PSF-2026-5.json", body: advisoryJSON("PSF-2026-5", false)},
		{name: "advisory-database-main/advisories/pypi/PSF-2026-6.json", body: advisoryJSON("PSF-2026-6", false)},
		{name: "advisory-database-main/advisories/python/sub/PSF-2026-7.json", body: advisoryJSON("PSF-2026-7", false)},
		{name: "advisory-database-main/advisories/python/README.md", body: "x"},
		{name: "advisory-database-main/advisories/python/PSF-2026-8.json.bak", body: "x"},
		{name: "advisory-database-main/advisories/python/psf-2026-9.json", body: "x"},
		{name: "advisory-database-main/tools/PSF-2026-10.json", body: "not json"},
		{name: psfFile("PSF-2026-12"), typ: '3'},
		{name: "/abs/advisories/python/PSF-2026-11.json", body: advisoryJSON("PSF-2026-11", false)},
	})
	advs, err := parseArchive(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 || advs[0].id != "PSF-2026-1" {
		t.Errorf("advisories = %+v, want only PSF-2026-1", advs)
	}
}

func TestParseArchiveRejects(t *testing.T) {
	big := okAdvisory("PSF-2026-1")
	big.body = `{"id":"PSF-2026-1","details":"` + strings.Repeat("x", maxAdvisoryBytes) + `"}`

	many := []tarEntry{okAdvisory("PSF-2026-1")}
	for i := 0; i < maxArchiveEntries; i++ {
		many = append(many, tarEntry{name: fmt.Sprintf("advisory-database-main/other/f%d", i)})
	}

	var tooMany []tarEntry
	for i := 1; i <= maxAdvisories+1; i++ {
		tooMany = append(tooMany, okAdvisory(fmt.Sprintf("PSF-2026-%d", i)))
	}

	aliases := make([]string, maxAliases+1)
	for i := range aliases {
		aliases[i] = fmt.Sprintf("CVE-2026-%d", 1000+i)
	}

	tests := []struct {
		name    string
		entries []tarEntry
	}{
		{"oversized file", []tarEntry{big}},
		{"too many entries", many},
		{"too many advisories", tooMany},
		{"too many aliases", []tarEntry{{name: psfFile("PSF-2026-1"), body: advisoryJSON("PSF-2026-1", false, aliases...)}}},
		{"id differs from the file name", []tarEntry{{name: psfFile("PSF-2026-1"), body: advisoryJSON("PSF-2026-2", false)}}},
		{"id not in the PSF format", []tarEntry{{name: psfFile("PSF-2026-1"), body: `{"id":"PSF-26-1"}`}}},
		{"invalid json", []tarEntry{{name: psfFile("PSF-2026-1"), body: `{`}}},
		{"duplicate", []tarEntry{okAdvisory("PSF-2026-1"), okAdvisory("PSF-2026-1")}},
		{"two roots", []tarEntry{okAdvisory("PSF-2026-1"), {name: "other-root/advisories/python/PSF-2026-2.json", body: advisoryJSON("PSF-2026-2", false)}}},
		{"no advisories", []tarEntry{{name: "advisory-database-main/README.md", body: "x"}}},
	}
	for _, tc := range tests {
		if _, err := parseArchive(makeArchive(t, tc.entries)); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}

	if _, err := parseArchive([]byte("not gzip")); err == nil {
		t.Error("non-gzip accepted")
	}
}

func TestParseArchiveAtTheLimits(t *testing.T) {
	// Exactly at the per-file, alias and entry limits is still fine.
	aliases := make([]string, maxAliases)
	for i := range aliases {
		aliases[i] = fmt.Sprintf("CVE-2026-%d", 1000+i)
	}
	entries := []tarEntry{{name: psfFile("PSF-2026-1"), body: advisoryJSON("PSF-2026-1", false, aliases...)}}
	for i := 0; i < maxArchiveEntries-1; i++ {
		entries = append(entries, tarEntry{name: fmt.Sprintf("advisory-database-main/other/f%d", i)})
	}
	advs, err := parseArchive(makeArchive(t, entries))
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 || len(advs[0].cves) != maxAliases {
		t.Errorf("advisories = %+v", advs)
	}
}

func TestParseArchiveUncompressedLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a large archive")
	}
	// A few KB compressed, 65 MiB once unpacked, in entries that are skipped.
	data := makeArchive(t, []tarEntry{
		okAdvisory("PSF-2026-1"),
		{name: "advisory-database-main/blob", body: strings.Repeat("\x00", maxArchiveTotalBytes+1)},
	})
	if len(data) > 1<<20 {
		t.Fatalf("test archive is %d bytes", len(data))
	}
	if _, err := parseArchive(data); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("err = %v, want the uncompressed limit", err)
	}
}

func TestParseArchiveCompressedLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a large archive")
	}
	// Incompressible content so the gzip stream passes 16 MiB.
	blob := make([]byte, maxArchiveBytes+1<<20)
	rand.New(rand.NewSource(1)).Read(blob)
	data := makeArchive(t, []tarEntry{okAdvisory("PSF-2026-1"), {name: "advisory-database-main/blob", body: string(blob)}})
	if len(data) <= maxArchiveBytes {
		t.Fatalf("test archive is only %d bytes", len(data))
	}
	if _, err := parseArchive(data); err == nil {
		t.Error("archive over the compressed limit accepted")
	}
}

func TestParseAdvisoryAliases(t *testing.T) {
	a, err := parseAdvisory("PSF-2026-1", []byte(`{"id":"PSF-2026-1","aliases":["GHSA-xxxx-yyyy-zzzz","CVE-2026-1234","CVE-2026-1234","CVE-26-1","CVE-2026-123456789","cve-2026-1234"],"details":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.cves) != 1 || a.cves[0] != "CVE-2026-1234" {
		t.Errorf("cves = %v, want only the valid CVE once", a.cves)
	}
	w, err := parseAdvisory("PSF-2026-1", []byte(`{"id":"PSF-2026-1","withdrawn":"2026-01-01T00:00:00Z"}`))
	if err != nil || !w.withdrawn {
		t.Errorf("withdrawn = %+v, %v", w, err)
	}
}
