package state

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func uncheckedScan(image string, finds ...scanner.Finding) scanner.ImageScan {
	s := scanOf(image, finds...)
	s.RuntimeUnchecked = true
	return s
}

func resolvedPackages(d Diff) []string {
	var out []string
	for _, r := range d.Resolved {
		out = append(out, r.Image+" "+r.Package)
	}
	return out
}

func TestCompute_UncheckedNodeRuntimeIsHeld(t *testing.T) {
	const img = "node:22"
	node := finding(img, inventory.NodeRuntimePackage, "CVE-N", scanner.StatusFixed)
	other := finding(img, "left-pad", "CVE-L", scanner.StatusFixed)

	_, st1 := Compute(empty(), report(day1, scanOf(img, node, other)))
	st1.Muted[img+"\t"+inventory.NodeRuntimePackage] = true

	// Cycle 2: the runtime was not checked, so Node.js findings are absent
	// while the other package is judged as usual (and is gone).
	d2, st2 := Compute(st1, report(day2, uncheckedScan(img)))
	if _, ok := st2.Findings[img+"\t"+inventory.NodeRuntimePackage]; !ok {
		t.Fatal("the Node.js entry was dropped for an unchecked runtime")
	}
	if !st2.Muted[img+"\t"+inventory.NodeRuntimePackage] {
		t.Error("the muted flag of the held entry was not carried over")
	}
	if got := resolvedPackages(d2); len(got) != 1 || got[0] != img+" left-pad" {
		t.Errorf("Resolved = %v, want only the other package", got)
	}
	if !st2.Findings[img+"\t"+inventory.NodeRuntimePackage].FirstSeen.Equal(day1) {
		t.Error("FirstSeen of the held entry changed")
	}

	// Cycle 3: the runtime is checked again and the finding is gone.
	d3, st3 := Compute(st2, report(day2.AddDate(0, 0, 1), scanOf(img)))
	if _, ok := st3.Findings[img+"\t"+inventory.NodeRuntimePackage]; ok {
		t.Error("the Node.js entry survived a checked cycle without findings")
	}
	if got := resolvedPackages(d3); len(got) != 1 || got[0] != img+" "+inventory.NodeRuntimePackage {
		t.Errorf("Resolved = %v, want the Node.js package", got)
	}
}

func TestCompute_NodeRuntimeResolvesWhenNotUnchecked(t *testing.T) {
	const img = "node:22"
	node := finding(img, inventory.NodeRuntimePackage, "CVE-N", scanner.StatusFixed)
	_, st1 := Compute(empty(), report(day1, scanOf(img, node)))
	d2, st2 := Compute(st1, report(day2, scanOf(img)))
	if len(st2.Findings) != 0 {
		t.Errorf("Findings = %v, want none", st2.Findings)
	}
	if got := resolvedPackages(d2); len(got) != 1 {
		t.Errorf("Resolved = %v, want the Node.js package", got)
	}
}

func TestCompute_UncheckedOtherRefDoesNotHoldNodeRuntime(t *testing.T) {
	node := finding("node:22", inventory.NodeRuntimePackage, "CVE-N", scanner.StatusFixed)
	_, st1 := Compute(empty(), report(day1, scanOf("node:22", node), scanOf("other:1")))
	d2, _ := Compute(st1, report(day2, scanOf("node:22"), uncheckedScan("other:1")))
	if got := resolvedPackages(d2); len(got) != 1 || got[0] != "node:22 "+inventory.NodeRuntimePackage {
		t.Errorf("Resolved = %v, want the Node.js package of node:22", got)
	}
}

func TestCompute_UncheckedNodeRuntimeEOLIsHeld(t *testing.T) {
	const img = "node:18"
	eol := eolFinding(img, inventory.NodeRuntimePackage, "CVE-E")
	k := img + "\t" + inventory.NodeRuntimePackage

	_, st1 := Compute(empty(), report(day1, scanOf(img, eol)))
	if _, ok := st1.EOLPackages[k]; !ok {
		t.Fatal("cycle 1 recorded no end-of-life Node.js entry")
	}
	st1.Muted[k] = true

	d2, st2 := Compute(st1, report(day2, uncheckedScan(img)))
	if _, ok := st2.EOLPackages[k]; !ok {
		t.Error("the end-of-life Node.js entry was dropped for an unchecked runtime")
	}
	if len(d2.ResolvedEOLPackages) != 0 {
		t.Errorf("ResolvedEOLPackages = %v, want none", d2.ResolvedEOLPackages)
	}
	if !st2.Muted[k] {
		t.Error("the muted flag of the held end-of-life entry was not carried over")
	}

	// Checked again, and no longer end-of-life: resolved.
	d3, st3 := Compute(st2, report(day2.AddDate(0, 0, 1), scanOf(img)))
	if _, ok := st3.EOLPackages[k]; ok {
		t.Error("the end-of-life entry survived a checked cycle without it")
	}
	if len(d3.ResolvedEOLPackages) != 1 {
		t.Errorf("ResolvedEOLPackages = %v, want one", d3.ResolvedEOLPackages)
	}
}
