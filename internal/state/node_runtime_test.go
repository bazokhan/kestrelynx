package state

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func uncheckedScan(image string, finds ...scanner.Finding) scanner.ImageScan {
	s := scanOf(image, finds...)
	s.RuntimeUnchecked = []string{inventory.NodeRuntimePackage}
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

func TestCompute_OnlyTheUncheckedRuntimeIsHeld(t *testing.T) {
	const img = "app:1"
	node := finding(img, inventory.NodeRuntimePackage, "CVE-N", scanner.StatusFixed)
	py := finding(img, inventory.PythonRuntimePackage, "CVE-P", scanner.StatusFixed)
	nodeKey := img + "\t" + inventory.NodeRuntimePackage
	pyKey := img + "\t" + inventory.PythonRuntimePackage

	_, st1 := Compute(empty(), report(day1, scanOf(img, node, py)))
	if len(st1.Findings) != 2 {
		t.Fatalf("cycle 1 Findings = %v, want both runtimes", st1.Findings)
	}

	// Only the Python runtime data was unavailable: its record is held, the
	// Node.js record is judged as usual and, being absent, resolved.
	s := scanOf(img)
	s.RuntimeUnchecked = []string{inventory.PythonRuntimePackage}
	d2, st2 := Compute(st1, report(day2, s))
	if _, ok := st2.Findings[pyKey]; !ok {
		t.Error("the Python runtime entry was dropped although it was unchecked")
	}
	if _, ok := st2.Findings[nodeKey]; ok {
		t.Error("the Node.js entry was held although only the Python runtime was unchecked")
	}
	if got := resolvedPackages(d2); len(got) != 1 || got[0] != img+" "+inventory.NodeRuntimePackage {
		t.Errorf("Resolved = %v, want only the Node.js package", got)
	}

	// Both unchecked: both held.
	s = scanOf(img)
	s.RuntimeUnchecked = []string{inventory.NodeRuntimePackage, inventory.PythonRuntimePackage}
	d3, st3 := Compute(st1, report(day2, s))
	if len(st3.Findings) != 2 || len(d3.Resolved) != 0 {
		t.Errorf("Findings = %v, Resolved = %v, want both held and none resolved", st3.Findings, d3.Resolved)
	}
}

func TestCompute_OnlyTheUncheckedRuntimeEOLIsHeld(t *testing.T) {
	const img = "app:1"
	nodeKey := img + "\t" + inventory.NodeRuntimePackage
	pyKey := img + "\t" + inventory.PythonRuntimePackage

	_, st1 := Compute(empty(), report(day1, scanOf(img,
		eolFinding(img, inventory.NodeRuntimePackage, "CVE-E1"),
		eolFinding(img, inventory.PythonRuntimePackage, "CVE-E2"))))
	if len(st1.EOLPackages) != 2 {
		t.Fatalf("cycle 1 EOLPackages = %v, want both runtimes", st1.EOLPackages)
	}

	s := scanOf(img)
	s.RuntimeUnchecked = []string{inventory.NodeRuntimePackage}
	d2, st2 := Compute(st1, report(day2, s))
	if _, ok := st2.EOLPackages[nodeKey]; !ok {
		t.Error("the Node.js end-of-life entry was dropped although it was unchecked")
	}
	if _, ok := st2.EOLPackages[pyKey]; ok {
		t.Error("the Python runtime end-of-life entry was held although only Node.js was unchecked")
	}
	if len(d2.ResolvedEOLPackages) != 1 || d2.ResolvedEOLPackages[0].Package != inventory.PythonRuntimePackage {
		t.Errorf("ResolvedEOLPackages = %v, want only the Python runtime", d2.ResolvedEOLPackages)
	}
}
