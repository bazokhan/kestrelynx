package inventory

import (
	"fmt"
	"regexp"
	"strings"
)

// KubernetesWorkload is a parsed <kind>/<namespace>/<name>/<container> key.
type KubernetesWorkload struct {
	Kind      WorkloadKind
	Namespace string
	Name      string
	Container string
}

var (
	dns1123LabelRE     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	dns1123SubdomainRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
)

// kubernetesWorkloadKinds are the kinds the Kubernetes adapter reports.
var kubernetesWorkloadKinds = map[string]WorkloadKind{
	"deployment":  WorkloadDeployment,
	"statefulset": WorkloadStatefulSet,
	"daemonset":   WorkloadDaemonSet,
	"job":         WorkloadJob,
	"cronjob":     WorkloadCronJob,
	"pod":         WorkloadPod,
}

// ParseKubernetesWorkloadKey splits a <kind>/<namespace>/<name>/<container>
// workload key, the form notifications and the webhook show for a Kubernetes
// container. The container is part of the key: one Pod's containers can come
// from different images and different sources. Names follow the Kubernetes
// rules (a DNS-1123 label for namespace and container, a DNS-1123 subdomain
// of at most 253 bytes for the workload name).
func ParseKubernetesWorkloadKey(key string) (KubernetesWorkload, error) {
	parts := strings.Split(key, "/")
	if len(parts) != 4 {
		return KubernetesWorkload{}, fmt.Errorf("must be <kind>/<namespace>/<name>/<container>")
	}
	kind, ok := kubernetesWorkloadKinds[parts[0]]
	if !ok {
		return KubernetesWorkload{}, fmt.Errorf("has an unknown kind %q (allowed: deployment, statefulset, daemonset, job, cronjob, pod)", parts[0])
	}
	if !dns1123LabelRE.MatchString(parts[1]) {
		return KubernetesWorkload{}, fmt.Errorf("has an invalid namespace")
	}
	if len(parts[2]) > 253 || !dns1123SubdomainRE.MatchString(parts[2]) {
		return KubernetesWorkload{}, fmt.Errorf("has an invalid workload name")
	}
	if !dns1123LabelRE.MatchString(parts[3]) {
		return KubernetesWorkload{}, fmt.Errorf("has an invalid container name")
	}
	return KubernetesWorkload{Kind: kind, Namespace: parts[1], Name: parts[2], Container: parts[3]}, nil
}

// ValidDNS1123Subdomain reports whether s is a DNS-1123 subdomain of at most
// 253 bytes, the rule for the names of Kubernetes objects.
func ValidDNS1123Subdomain(s string) bool {
	return len(s) <= 253 && dns1123SubdomainRE.MatchString(s)
}
