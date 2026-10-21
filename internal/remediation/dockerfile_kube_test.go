package remediation

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

const kubeApp = "deployment/shop/app/web"

func kubeDFMapping() []DockerfileMapping {
	return []DockerfileMapping{{Workload: kubeApp, Repository: "ex/app", BaseBranch: "main", Path: "Dockerfile"}}
}

// kubeDFInput is a scanned image of a Kubernetes container built on the
// layers, as a registry-digest scan reports them.
func kubeDFInput(layers []byte, declared string, fs ...scanner.Finding) ImageInput {
	in := dfInput("docker.io/example/myapp:1", 'a', "unused", layers, fs...)
	in.Services = []ServiceRef{{Workload: kubeApp}}
	in.Declared = []DeclaredInstance{{Workload: kubeApp, Ref: declared, PullPolicy: "IfNotPresent"}}
	return in
}

// The Dockerfile route works for a Kubernetes workload as it does for Compose
// when the scan reports the layers of the running image, and stops when it does
// not.
func TestDockerfileKubernetesWorkload(t *testing.T) {
	e := newDFEnv()
	e.standard()
	plan := e.plan(t, bigLimits, kubeDFMapping(), nil, kubeDFInput(appLayers, "example/myapp:1", standardFindings()...))
	it := onlyDockerfile(t, plan)
	if it.Category != CategoryPRCandidate || len(it.Workloads) != 1 || it.Workloads[0] != kubeApp || it.Entities[0].Layers.Status != "confirmed" {
		t.Fatalf("item = %s/%s workloads %v (%s)", it.Category, it.Reason, it.Workloads, it.Detail)
	}

	// No layer IDs in the scan: the layers cannot be compared, nothing is claimed.
	e = newDFEnv()
	e.standard()
	plan = e.plan(t, bigLimits, kubeDFMapping(), nil, kubeDFInput(nil, "example/myapp:1", standardFindings()...))
	it = onlyDockerfile(t, plan)
	if it.Category != CategoryNotComparable || it.Reason != ReasonBaseLayersUnusable || it.Candidate != nil || len(plan.Scans) != 0 {
		t.Errorf("without layer IDs: %s/%s candidate %v scans %d", it.Category, it.Reason, it.Candidate, len(plan.Scans))
	}

	// A base that is not the start of the image's layers: a mismatch, nothing claimed.
	e = newDFEnv()
	e.standard()
	e.reg.res["python:3.12.3-slim"] = baseResolution('1', '2', 'a', '9')
	plan = e.plan(t, bigLimits, kubeDFMapping(), nil, kubeDFInput(appLayers, "example/myapp:1", standardFindings()...))
	if it = onlyDockerfile(t, plan); it.Category != CategoryNotComparable || it.Reason != ReasonBaseLayersMismatch {
		t.Errorf("with a base that is not the image's start: %s/%s", it.Category, it.Reason)
	}
}

func TestDockerfileKubernetesDeclaredProblemStopsTheEntity(t *testing.T) {
	for name, tc := range map[string]struct {
		declared string
		reason   Reason
	}{
		"other image declared": {"example/other:1", ReasonDeclaredRefMismatch},
		"declaration unread":   {"", ReasonDeclaredRefUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			e := newDFEnv()
			e.standard()
			plan := e.plan(t, bigLimits, kubeDFMapping(), nil, kubeDFInput(appLayers, tc.declared, standardFindings()...))
			it := onlyDockerfile(t, plan)
			if it.Category == CategoryPRCandidate {
				t.Fatalf("item adopted although the declaration is wrong")
			}
			if len(it.Entities) != 1 || it.Entities[0].Reason != tc.reason || it.Entities[0].Category != CategoryNotComparable {
				t.Errorf("entity = %s/%s (%s)", it.Entities[0].Category, it.Entities[0].Reason, it.Entities[0].Detail)
			}
			if plan.Usage.CandidateScans != 0 {
				t.Error("a candidate was scanned")
			}
		})
	}
}
