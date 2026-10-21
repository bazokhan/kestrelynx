package state

import (
	"sort"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// RefChange is one workload that moved to another reference of the same
// repository (a tag or digest change on update) and whose recorded history
// Compute carried over to the new reference instead of reporting the old
// reference's findings resolved and the new one's new.
type RefChange struct {
	Repository  string   // repository as written in the new reference, without tag or digest
	PreviousRef string   // the reference that stopped running
	Ref         string   // the reference now running in its place
	Workloads   []string // workload keys that ran PreviousRef and now run Ref, sorted
}

// WorkloadKey identifies the workload a container belongs to, for matching a
// reference's runners across cycles. "" means no usable key.
//
//   - Compose: compose/<project>/<service>
//   - Kubernetes: <kind>/<namespace>/<name>/<container>, the container being
//     the last element of the adapter's namespace/pod/container name, so a
//     sidecar is told apart from the main container of the same Pod
//   - a container with no known workload: container/<name>
func WorkloadKey(c inventory.Container) string { return c.WorkloadKey() }

// workloadKeys returns the sorted, de-duplicated workload keys of containers.
func workloadKeys(containers []inventory.Container) []string {
	set := map[string]bool{}
	for _, c := range containers {
		if k := WorkloadKey(c); k != "" {
			set[k] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return sortedIDs(set)
}

// entityConfirmed reports whether this cycle's observation of a reference
// settles what is running under it: the scan succeeded in full, nothing is
// unconfirmed, and every container resolves to the same single image entity.
// Resolution is judged per container with inventory.EntityKeyOf (the same
// rule scan pinning uses) rather than IdentityResolved, which only recognises
// config digests.
func entityConfirmed(o analyze.ImageObservation) bool {
	if o.ScanFailed || o.PartialFailure || o.Unconfirmed || o.Ambiguous || len(o.Containers) == 0 {
		return false
	}
	var first inventory.EntityKey
	for i, c := range o.Containers {
		key, ok := inventory.EntityKeyOf(c.Image)
		if !ok {
			return false
		}
		if i == 0 {
			first = key
		} else if key != first {
			return false
		}
	}
	return true
}

// pairRefChanges finds the references that a workload replaced by another
// reference of the same repository. A pair (O, N) needs all of:
//   - O was recorded last cycle and is not observed at all this cycle, N is
//     observed this cycle and was not recorded last cycle (every observed
//     reference counts, failed or clean)
//   - both are well-formed references of the same repository
//   - O's recorded workloads and N's current workloads share a key
//   - the match is one to one: for each shared workload key, O is the only
//     vanished and N the only appeared reference carrying it, and neither O
//     nor N takes part in any other candidate pair
//   - N's entity is confirmed this cycle and N has no history of its own;
//     this is judged last, so a candidate that fails it still counts
//     against the uniqueness of the others
func pairRefChanges(prev State, obs []analyze.ImageObservation) []RefChange {
	observed := map[string]bool{}
	for _, o := range obs {
		observed[o.Ref] = true
	}
	var gone []string
	for ref := range prev.Images {
		if !observed[ref] {
			gone = append(gone, ref)
		}
	}
	sort.Strings(gone)
	type appearedRef struct {
		o         analyze.ImageObservation
		workloads []string
	}
	var appeared []appearedRef
	for _, o := range obs {
		if _, known := prev.Images[o.Ref]; !known {
			appeared = append(appeared, appearedRef{o, workloadKeys(o.Containers)})
		}
	}
	if len(gone) == 0 || len(appeared) == 0 {
		return nil
	}

	goneBy := map[string][]string{} // workload key -> vanished refs carrying it
	for _, ref := range gone {
		for _, w := range prev.Images[ref].Workloads {
			goneBy[w] = append(goneBy[w], ref)
		}
	}
	appearedBy := map[string][]string{}
	for _, a := range appeared {
		for _, w := range a.workloads {
			appearedBy[w] = append(appearedBy[w], a.o.Ref)
		}
	}

	byRef := map[string]analyze.ImageObservation{}
	for _, a := range appeared {
		byRef[a.o.Ref] = a.o
	}

	var cands []RefChange
	for _, oldRef := range gone {
		oldRepo, ok := inventory.RepositoryKey(oldRef)
		if !ok {
			continue
		}
		for _, a := range appeared {
			newRepo, ok := inventory.RepositoryKey(a.o.Ref)
			if !ok || newRepo != oldRepo {
				continue
			}
			shared := intersectSorted(prev.Images[oldRef].Workloads, a.workloads)
			if len(shared) == 0 {
				continue
			}
			repo, _ := inventory.RepositoryOf(a.o.Ref)
			cands = append(cands, RefChange{Repository: repo, PreviousRef: oldRef, Ref: a.o.Ref, Workloads: shared})
		}
	}

	oldUses, newUses := map[string]int{}, map[string]int{}
	for _, c := range cands {
		oldUses[c.PreviousRef]++
		newUses[c.Ref]++
	}
	var out []RefChange
	for _, c := range cands {
		// Uniqueness is counted over every candidate before any is dropped,
		// both per reference and per shared workload: a workload that moved
		// to two references, or a reference that two others vanished into,
		// leaves the move ambiguous for every pair it touches.
		if oldUses[c.PreviousRef] != 1 || newUses[c.Ref] != 1 {
			continue
		}
		unique := true
		for _, w := range c.Workloads {
			if len(goneBy[w]) != 1 || len(appearedBy[w]) != 1 {
				unique = false
				break
			}
		}
		if !unique {
			continue
		}
		// Eligibility is judged only after uniqueness, on the full candidate
		// set: a sibling that failed to scan still makes the match ambiguous.
		if !entityConfirmed(byRef[c.Ref]) || hasHistory(prev, c.Ref) {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ref != out[j].Ref {
			return out[i].Ref < out[j].Ref
		}
		return out[i].PreviousRef < out[j].PreviousRef
	})
	return out
}

// hasHistory reports whether prev holds any record under ref.
func hasHistory(prev State, ref string) bool {
	if _, ok := prev.EOSL[ref]; ok {
		return true
	}
	if prev.HasFindingsFor(ref) {
		return true
	}
	for k := range prev.Muted {
		if keyImage(k) == ref {
			return true
		}
	}
	return false
}

// intersectSorted returns the members common to two sorted lists.
func intersectSorted(a, b []string) []string {
	var out []string
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			out = append(out, a[i])
			i++
			j++
		case a[i] < b[j]:
			i++
		default:
			j++
		}
	}
	return out
}

// carryOverRefChanges returns prev with each paired reference's history moved
// to the new reference, and the pairs. prev itself is never modified; when
// there are no pairs it is returned as is.
//
// What moves: findings, end-of-life packages, the muted record and the
// base-OS end-of-life date. The content ID of a finding does not (the
// new reference's own ID comes from this cycle's observation), and the old
// reference's image record is dropped rather than presented as the new
// reference's.
func carryOverRefChanges(prev State, obs []analyze.ImageObservation) (State, []RefChange) {
	changes := pairRefChanges(prev, obs)
	if len(changes) == 0 {
		return prev, nil
	}
	moved := map[string]string{}
	for _, c := range changes {
		moved[c.PreviousRef] = c.Ref
	}
	rekey := func(k string) string {
		if n, ok := moved[keyImage(k)]; ok {
			return key(n, keyPackage(k))
		}
		return k
	}

	out := prev
	out.Findings = make(map[string]Entry, len(prev.Findings))
	for k, e := range prev.Findings {
		if _, ok := moved[keyImage(k)]; ok {
			e.ContentID = ""
		}
		out.Findings[rekey(k)] = e
	}
	out.EOLPackages = make(map[string]EOLEntry, len(prev.EOLPackages))
	for k, e := range prev.EOLPackages {
		out.EOLPackages[rekey(k)] = e
	}
	out.Muted = make(map[string]bool, len(prev.Muted))
	for k, v := range prev.Muted {
		out.Muted[rekey(k)] = v
	}
	out.EOSL = make(map[string]time.Time, len(prev.EOSL))
	for img, t := range prev.EOSL {
		if n, ok := moved[img]; ok {
			img = n
		}
		out.EOSL[img] = t
	}
	out.Images = make(map[string]ImageMeta, len(prev.Images))
	for ref, m := range prev.Images {
		if _, ok := moved[ref]; ok {
			continue
		}
		out.Images[ref] = m
	}
	return out, changes
}
