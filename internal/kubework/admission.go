package kubework

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/workexec"
)

// The admission policy of the work namespace is what keeps a compromised
// KestreLynx from creating a different Pod than the one it should. Before the
// first job of every cycle the Runner proves, with dry-run creations, that the
// policy is in force: the right Pod is accepted, and each of a list of
// otherwise right Pods with one thing wrong is refused, by the rule that is
// meant to refuse it. A rule that has been removed, a binding pointed at
// another namespace, a missing parameter object, or a policy that matches by
// labels a Pod can change each shows up as a probe that is not refused as
// expected.
const (
	// PolicyName and BindingName are the names of the policy and its binding in
	// deploy/kubernetes/work. A refusal names both.
	PolicyName  = "kestrelynx-work"
	BindingName = "kestrelynx-work"
)

// refusalPrefix is how a refusal by the policy begins.
func refusalPrefix() string {
	return "ValidatingAdmissionPolicy '" + PolicyName + "' with binding '" + BindingName + "' denied request: "
}

// RuleMessage is the fixed text a rule of the policy refuses with.
func RuleMessage(id string) string { return "KRW-" + id }

// podSecurityMark is what a refusal by Pod Security contains.
const podSecurityMark = `violates PodSecurity "restricted:`

type expectKind int

const (
	expectRule    expectKind = iota // refused by the policy's rule
	expectAnyRule                   // refused by the policy, by any rule
	expectPodSec                    // refused by Pod Security
)

// probe is a right Pod with one thing wrong.
type probe struct {
	// id names the probe; for expectRule it is also the rule's id.
	id     string
	expect expectKind
	mutate func(pod map[string]any)
}

type pm = map[string]any

func specOf(p pm) pm      { return p["spec"].(pm) }
func workOf(p pm) pm      { return specOf(p)["containers"].([]any)[0].(pm) }
func receiveOf(p pm) pm   { return specOf(p)["initContainers"].([]any)[0].(pm) }
func labelsOf(p pm) pm    { return p["metadata"].(pm)["labels"].(pm) }
func secOf(c pm) pm       { return c["securityContext"].(pm) }
func resourcesOf(c pm) pm { return c["resources"].(pm) }

func deepCopy(m pm) pm { return normalized(m).(pm) }

// probes is the list of wrong Pods. Every rule of the policy that can be tried
// by creating a Pod has one; the rules about changing a placed Pod and about
// ephemeral containers need a running Pod and are checked in the real cluster
// by the tests, and the rule about the runtime class cannot be tried without a
// RuntimeClass that exists. The comparison of every Pod the server returns
// (CheckPod) covers what the policy does not.
func probes() []probe {
	return []probe{
		{"name", expectRule, func(p pm) { p["metadata"].(pm)["name"] = "kestrelynx-work-other" }},
		{"labels", expectRule, func(p pm) { labelsOf(p)["extra"] = "x" }},
		{"metadata", expectRule, func(p pm) { p["metadata"].(pm)["annotations"] = pm{"a": "b"} }},
		{"serviceaccount", expectRule, func(p pm) { specOf(p)["serviceAccountName"] = "default" }},
		{"pullsecrets", expectRule, func(p pm) { specOf(p)["imagePullSecrets"] = []any{pm{"name": "x"}} }},
		{"dns", expectRule, func(p pm) { specOf(p)["dnsPolicy"] = "Default" }},
		{"placement", expectRule, func(p pm) { specOf(p)["nodeSelector"].(pm)["extra"] = "x" }},
		{"placement", expectRule, func(p pm) { specOf(p)["schedulerName"] = "other-scheduler" }},
		{"placement", expectRule, func(p pm) {
			// A toleration that lasts for hours instead of the default five minutes;
			// the server adds the other default.
			specOf(p)["tolerations"] = []any{pm{"key": "node.kubernetes.io/not-ready", "operator": "Exists", "effect": "NoExecute", "tolerationSeconds": int64(3600)}}
		}},
		{"placement", expectRule, func(p pm) { specOf(p)["tolerations"] = []any{pm{"operator": "Exists"}} }},
		{"resources", expectRule, func(p pm) { resourcesOf(workOf(p))["requests"].(pm)["memory"] = "0" }},
		{"resources", expectRule, func(p pm) {
			r := resourcesOf(receiveOf(p))
			r["requests"].(pm)["cpu"], r["limits"].(pm)["cpu"] = "0", "0"
		}},
		{"resources", expectRule, func(p pm) {
			r := resourcesOf(workOf(p))
			r["requests"].(pm)["ephemeral-storage"], r["limits"].(pm)["ephemeral-storage"] = "0", "0"
		}},
		{"volumes", expectRule, func(p pm) { specOf(p)["volumes"].([]any)[1].(pm)["emptyDir"].(pm)["sizeLimit"] = "0" }},
		{"priority", expectRule, func(p pm) { specOf(p)["priorityClassName"] = "system-cluster-critical" }},
		{"lifetime", expectRule, func(p pm) { specOf(p)["restartPolicy"] = "OnFailure" }},
		{"host", expectRule, func(p pm) { specOf(p)["shareProcessNamespace"] = true }},
		{"podsecurity", expectRule, func(p pm) { specOf(p)["securityContext"].(pm)["fsGroup"] = int64(1000) }},
		{"containers", expectRule, func(p pm) {
			extra := deepCopy(workOf(p))
			extra["name"] = "extra"
			s := specOf(p)
			s["containers"] = append(s["containers"].([]any), extra)
		}},
		{"images", expectRule, func(p pm) { workOf(p)["image"] = "docker.io/library/busybox@sha256:" + strings.Repeat("0", 64) }},
		{"commands", expectRule, func(p pm) { workOf(p)["command"] = []any{"sh"} }},
		{"execpaths", expectRule, func(p pm) { workOf(p)["livenessProbe"] = pm{"exec": pm{"command": []any{"true"}}} }},
		{"io", expectRule, func(p pm) { workOf(p)["stdin"] = true }},
		{"env", expectRule, func(p pm) { w := workOf(p); w["env"] = append(w["env"].([]any), pm{"name": "X", "value": "1"}) }},
		{"secctx", expectRule, func(p pm) { secOf(workOf(p))["runAsUser"] = int64(10005) }},
		{"termination", expectRule, func(p pm) { workOf(p)["terminationMessagePath"] = "/dev/termination-log" }},
		{"volumes", expectRule, func(p pm) {
			s := specOf(p)
			s["volumes"] = append(s["volumes"].([]any), pm{"name": "extra", "emptyDir": pm{"medium": "Memory", "sizeLimit": "1Mi"}})
		}},
		{"mounts", expectRule, func(p pm) { workOf(p)["volumeMounts"].([]any)[0].(pm)["readOnly"] = false }},
		{"resources", expectRule, func(p pm) { delete(resourcesOf(workOf(p))["limits"].(pm), "ephemeral-storage") }},
		{"workdir", expectRule, func(p pm) { workOf(p)["workingDir"] = "/tmp" }},

		// What Pod Security refuses, which must be Pod Security's refusal.
		{"escalation", expectPodSec, func(p pm) { secOf(workOf(p))["allowPrivilegeEscalation"] = true }},
		{"hostnetwork", expectPodSec, func(p pm) { specOf(p)["hostNetwork"] = true }},
		{"root", expectPodSec, func(p pm) { s := secOf(workOf(p)); s["runAsUser"] = int64(0); s["runAsNonRoot"] = false }},
		{"hostpath", expectPodSec, func(p pm) {
			s := specOf(p)
			s["volumes"].([]any)[1] = pm{"name": "tmp", "hostPath": pm{"path": "/"}}
		}},

		// A Pod whose labels have been taken off, with something else wrong,
		// is still refused: the policy is chosen by namespace, not by labels.
		{"nolabels", expectAnyRule, func(p pm) {
			delete(p["metadata"].(pm), "labels")
			specOf(p)["securityContext"].(pm)["fsGroup"] = int64(1000)
		}},
		{"otherlabels", expectAnyRule, func(p pm) {
			p["metadata"].(pm)["labels"] = pm{"app": "x"}
			specOf(p)["securityContext"].(pm)["fsGroup"] = int64(1000)
		}},
	}
}

// ProbeIDs are the ids of the probes, for tests that compare them with the
// policy.
func ProbeIDs() []string {
	var ids []string
	for _, p := range probes() {
		if p.expect == expectRule {
			ids = append(ids, p.id)
		}
	}
	sort.Strings(ids)
	return ids
}

// VerifyAdmission runs the checks and records the outcome: jobs run only if
// the policy is in force. It returns the reason jobs will not run, nil when
// they will. A check that could not be made counts as a failure; the next
// cycle makes it again.
func (r *Runner) VerifyAdmission(ctx context.Context) *workexec.Unavailable {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	problem := r.probeAdmission(ctx)
	r.mu.Lock()
	r.admission = admissionState{checked: true, problem: problem, at: time.Now()}
	r.mu.Unlock()
	if problem != nil {
		r.log().Warn("language package updates cannot run", "reason", problem.Reason, "detail", problem.Detail)
	}
	return problem
}

// MinMinorVersion is the lowest Kubernetes 1.x minor version the admission
// policy of the work namespace is written for.
const MinMinorVersion = 30

func (r *Runner) probeAdmission(ctx context.Context) *workexec.Unavailable {
	major, minor, err := r.cfg.API.ServerVersion(ctx)
	if err != nil {
		return unavailable(false, ReasonAdmissionUnverified, "the version of the cluster could not be read: %v", clip(err.Error(), 200))
	}
	if major < 1 || (major == 1 && minor < MinMinorVersion) {
		return unavailable(true, ReasonClusterTooOld, "the cluster is version %d.%d; the work Pod policy needs 1.%d or newer", major, minor, MinMinorVersion)
	}
	image := ""
	for _, img := range r.cfg.Images {
		image = img
		break
	}
	params := r.params(workexec.JobSpec{JobID: "admission-check", Timeout: time.Minute, Resources: probeResources()}, image)
	good := BuildPod(params)

	got, err := r.cfg.API.CreatePod(ctx, good, true)
	if err != nil {
		var ae *APIError
		switch {
		case errors.As(err, &ae) && ae.Code == 403 && strings.Contains(ae.Message, "exceeded quota"):
			return unavailable(false, ReasonPodLimit, "the quota of the work namespace is used up: %s", clip(ae.Message, 200))
		case errors.As(err, &ae) && strings.Contains(ae.Message, "no PriorityClass with name"):
			return unavailable(true, ReasonPriorityClass, "the priority class %q does not exist", r.cfg.PriorityClass)
		case errors.As(err, &ae) && strings.Contains(ae.Message, RuleMessage("priority")):
			return unavailable(true, ReasonPriorityClass, "the priority class %q is not one that never preempts, or is not the one the policy expects", r.cfg.PriorityClass)
		}
		return unavailable(true, ReasonAdmissionUnverified, "the right Pod was not accepted in a dry run: %s", clip(err.Error(), 300))
	}
	if _, err := CheckPod(good, got, false, ""); err != nil {
		return unavailable(true, ReasonAdmissionUnverified, "the server changes Pods in a way not allowed for: %v", err)
	}
	for _, pr := range probes() {
		pod := deepCopy(good)
		pr.mutate(pod)
		_, err := r.cfg.API.CreatePod(ctx, pod, true)
		var ae *APIError
		if !errors.As(err, &ae) {
			if err == nil {
				return unavailable(true, ReasonAdmissionUnverified, "a Pod that breaks the rule %q was accepted: the policy is not in force", pr.id)
			}
			return unavailable(true, ReasonAdmissionUnverified, "the check of the rule %q could not be made: %s", pr.id, clip(err.Error(), 200))
		}
		ok := false
		switch pr.expect {
		case expectRule:
			ok = strings.Contains(ae.Message, refusalPrefix()+RuleMessage(pr.id))
		case expectAnyRule:
			ok = strings.Contains(ae.Message, refusalPrefix())
		case expectPodSec:
			ok = strings.Contains(ae.Message, podSecurityMark)
		}
		if !ok {
			return unavailable(true, ReasonAdmissionUnverified, "a Pod that breaks the rule %q was refused for another reason: %s", pr.id, clip(ae.Message, 200))
		}
	}
	return nil
}

func probeResources() workexec.Resources {
	return workexec.Resources{MemoryBytes: 1 << 30, NanoCPUs: 1_000_000_000, TmpSizeBytes: 64 << 20, HomeSizeBytes: 64 << 20, ToolsSizeBytes: 64 << 20, ShmSizeBytes: 16 << 20}
}

// String lets an admission result be logged.
func (a admissionState) String() string {
	if a.problem == nil {
		return "in force"
	}
	return fmt.Sprint(a.problem)
}
