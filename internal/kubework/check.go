package kubework

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

// CheckPod compares a Pod the API server returned with the one that was asked
// for. A mutating admission step, a default the server adds or a change by
// anyone else shows up here: the Pod must equal the request in every field,
// except that the server may add the fields listed as defaults below, each with
// the value it is allowed to have. afterScheduling says the Pod may have been
// placed on a node; a Pod just created has not been, and one placed must stay
// on the node it was placed on (prev is that node, "" when not yet seen).
//
// The comparison is on the whole object, so a field neither side names is a
// difference too: an annotation, a sidecar, a volume, a probe, a changed
// command all fail it.
func CheckPod(requested, got map[string]any, afterScheduling bool, prevNode string) (node string, err error) {
	want := normalized(requested).(map[string]any)
	// The class's preemption policy is set by the server from the priority
	// class; it must be Never.
	spec := want["spec"].(map[string]any)
	spec["preemptionPolicy"] = "Never"

	obs, ok := normalized(got).(map[string]any)
	if !ok {
		return "", errors.New("the Pod is not an object")
	}
	delete(obs, "status")
	if k, _ := obs["kind"].(string); k != "Pod" {
		return "", errors.New("the object is not a Pod")
	}
	if err := (&checker{root: want}).diff("", want, obs); err != nil {
		return "", err
	}
	ospec := obs["spec"].(map[string]any)
	n, _ := ospec["nodeName"].(string)
	switch {
	case !afterScheduling && n != "":
		return "", fmt.Errorf("the new Pod already names a node")
	case prevNode != "" && n != prevNode:
		return "", fmt.Errorf("the Pod's node changed")
	}
	return n, nil
}

var indexRE = regexp.MustCompile(`\[\d+\]`)

// defaultTolerations are the two tolerations the server adds to every Pod.
var defaultTolerations = []any{
	map[string]any{"key": "node.kubernetes.io/not-ready", "operator": "Exists", "effect": "NoExecute", "tolerationSeconds": float64(300)},
	map[string]any{"key": "node.kubernetes.io/unreachable", "operator": "Exists", "effect": "NoExecute", "tolerationSeconds": float64(300)},
}

// defaultResizePolicy is what servers that support in-place resizing add to a
// container that has resources.
var defaultResizePolicy = []any{
	map[string]any{"resourceName": "cpu", "restartPolicy": "NotRequired"},
	map[string]any{"resourceName": "memory", "restartPolicy": "NotRequired"},
}

// allowedExtra says whether the server may add the field at path with the value.
func (c *checker) allowedExtra(path string, v any) bool {
	generic := indexRE.ReplaceAllString(path, "[]")
	switch generic {
	case "metadata.uid", "metadata.resourceVersion", "metadata.creationTimestamp":
		_, isString := v.(string)
		return isString
	case "metadata.managedFields":
		return true
	case "metadata.generation":
		// Kubernetes 1.34 and newer set the generation of a Pod to 1 when it is
		// created; older servers leave it out.
		f, ok := v.(float64)
		return ok && f >= 1 && f == math.Trunc(f)
	case "metadata.annotations":
		m, ok := v.(map[string]any)
		return ok && len(m) == 0
	case "spec.nodeName":
		s, ok := v.(string)
		return ok && s != ""
	case "spec.priority":
		_, ok := v.(float64)
		return ok
	case "spec.schedulerName":
		return v == "default-scheduler"
	case "spec.serviceAccount":
		return v == c.root["spec"].(map[string]any)["serviceAccountName"]
	case "spec.tolerations":
		return sameSet(v, defaultTolerations)
	case "spec.initContainers[].imagePullPolicy", "spec.containers[].imagePullPolicy":
		return v == "IfNotPresent"
	case "spec.initContainers[].resizePolicy", "spec.containers[].resizePolicy":
		return reflect.DeepEqual(v, defaultResizePolicy)
	}
	return false
}

// sameSet reports whether list holds exactly the wanted objects, in any order.
func sameSet(list any, want []any) bool {
	l, ok := list.([]any)
	if !ok || len(l) != len(want) {
		return false
	}
	keys := func(items []any) []string {
		var out []string
		for _, it := range items {
			b, _ := json.Marshal(it)
			out = append(out, string(b))
		}
		sort.Strings(out)
		return out
	}
	return reflect.DeepEqual(keys(l), keys(want))
}

// checker holds the whole requested object, which a few of the rules refer to.
type checker struct{ root map[string]any }

// diff walks the requested and observed values together.
func (c *checker) diff(path string, want, got any) error {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return fmt.Errorf("%s is not an object", pathName(path))
		}
		for k := range w {
			gv, present := g[k]
			if !present {
				return fmt.Errorf("%s is missing", join(path, k))
			}
			if err := c.diff(join(path, k), w[k], gv); err != nil {
				return err
			}
		}
		for k, gv := range g {
			if _, wanted := w[k]; wanted {
				continue
			}
			if !c.allowedExtra(join(path, k), gv) {
				return fmt.Errorf("%s was added", join(path, k))
			}
		}
		return nil
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return fmt.Errorf("%s differs in length", pathName(path))
		}
		for i := range w {
			if err := c.diff(fmt.Sprintf("%s[%d]", path, i), w[i], g[i]); err != nil {
				return err
			}
		}
		return nil
	}
	if reflect.DeepEqual(want, got) {
		return nil
	}
	// The server writes a quantity in its canonical form ("1000m" as "1",
	// "536870912" as "512Mi"); two spellings of one amount are the same.
	if ws, ok := want.(string); ok && isQuantityPath(path) {
		if gs, ok := got.(string); ok && quantityEqual(ws, gs) {
			return nil
		}
	}
	return fmt.Errorf("%s differs", pathName(path))
}

var quantityPathRE = regexp.MustCompile(`\.resources\.(requests|limits)\.[a-z-]+$|\.emptyDir\.sizeLimit$`)

func isQuantityPath(p string) bool { return quantityPathRE.MatchString(p) }

var quantitySuffixes = map[string]*big.Rat{
	"m": big.NewRat(1, 1000), "": big.NewRat(1, 1),
	"k": big.NewRat(1000, 1), "M": big.NewRat(1000000, 1), "G": big.NewRat(1000000000, 1),
	"T": big.NewRat(1000000000000, 1), "P": big.NewRat(1000000000000000, 1), "E": big.NewRat(1000000000000000000, 1),
	"Ki": big.NewRat(1<<10, 1), "Mi": big.NewRat(1<<20, 1), "Gi": big.NewRat(1<<30, 1),
	"Ti": big.NewRat(1<<40, 1), "Pi": big.NewRat(1<<50, 1), "Ei": big.NewRat(1<<60, 1),
}

var quantityRE = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)(m|k|M|G|T|P|E|Ki|Mi|Gi|Ti|Pi|Ei)?$`)

func parseQuantity(s string) (*big.Rat, bool) {
	m := quantityRE.FindStringSubmatch(s)
	if m == nil {
		return nil, false
	}
	n, ok := new(big.Rat).SetString(m[1])
	if !ok {
		return nil, false
	}
	return n.Mul(n, quantitySuffixes[m[2]]), true
}

func quantityEqual(a, b string) bool {
	x, ok1 := parseQuantity(a)
	y, ok2 := parseQuantity(b)
	return ok1 && ok2 && x.Cmp(y) == 0
}

func join(path, k string) string {
	if path == "" {
		return k
	}
	return path + "." + k
}

func pathName(p string) string {
	if p == "" {
		return "the object"
	}
	return strings.TrimPrefix(p, ".")
}
