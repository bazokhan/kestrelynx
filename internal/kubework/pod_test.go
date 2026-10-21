package kubework

import (
	"strings"
	"testing"
	"time"
)

func testParams() Params {
	f := newFake()
	r := testRunnerNoT(f)
	return r.params(testSpec("job-1"), testNodeImg)
}

func TestBuildPodShape(t *testing.T) {
	p := BuildPod(testParams())
	spec := specOf(p)
	if p["metadata"].(pm)["namespace"] != "kestrelynx-work" || len(labelsOf(p)) != 4 {
		t.Errorf("metadata %+v", p["metadata"])
	}
	if spec["automountServiceAccountToken"] != false || spec["hostNetwork"] != nil && spec["hostNetwork"] != false {
		t.Errorf("token or host network: %+v", spec)
	}
	if spec["restartPolicy"] != "Never" || spec["priorityClassName"] != "kestrelynx-work" {
		t.Errorf("restart or priority: %v %v", spec["restartPolicy"], spec["priorityClassName"])
	}
	recv, work := receiveOf(p), workOf(p)
	if recv["stdin"] != true || recv["stdinOnce"] != true || work["stdin"] == true {
		t.Errorf("stdin: receive %v/%v work %v", recv["stdin"], recv["stdinOnce"], work["stdin"])
	}
	for _, c := range []pm{recv, work} {
		sc := secOf(c)
		if sc["allowPrivilegeEscalation"] != false || sc["readOnlyRootFilesystem"] != true || sc["runAsNonRoot"] != true {
			t.Errorf("%v security context: %+v", c["name"], sc)
		}
		if !strings.HasPrefix(c["terminationMessagePath"].(string), "/root/.kestrelynx-termination/") {
			t.Errorf("%v termination path %v", c["name"], c["terminationMessagePath"])
		}
	}
	if secOf(recv)["runAsUser"] != int64(10002) || secOf(work)["runAsUser"] != int64(10001) {
		t.Errorf("users: %v %v", secOf(recv)["runAsUser"], secOf(work)["runAsUser"])
	}
	// /work is read-only for the job.
	foundRO := false
	for _, m := range work["volumeMounts"].([]any) {
		if m.(pm)["mountPath"] == "/work" && m.(pm)["readOnly"] == true {
			foundRO = true
		}
	}
	if !foundRO {
		t.Error("/work is not mounted read-only into the work container")
	}
	if strings.Contains(strings.ToLower(mustJSON(p)), "hostpath") {
		t.Error("a hostPath volume")
	}
}

func TestParamsValidate(t *testing.T) {
	bad := map[string]func(p *Params){
		"no namespace":      func(p *Params) { p.Namespace = "" },
		"tag image":         func(p *Params) { p.WorkImage = "node:24" },
		"bad instance":      func(p *Params) { p.Instance = "xyz" },
		"bad session":       func(p *Params) { p.Session = "" },
		"no command":        func(p *Params) { p.Entrypoint = nil },
		"deadline too long": func(p *Params) { p.ActiveDeadlineSeconds = MaxActiveDeadlineSeconds + 1 },
		"no memory":         func(p *Params) { p.Resources.MemoryBytes = 0 },
	}
	for name, mutate := range bad {
		p := testParams()
		mutate(&p)
		if p.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := testParams().Validate(); err != nil {
		t.Errorf("good params: %v", err)
	}
}

func TestCheckPodAllowsOnlyTheListedServerAdditions(t *testing.T) {
	req := BuildPod(testParams())
	server := func(mutate func(p pm)) pm {
		p := deepCopy(req)
		meta := p["metadata"].(pm)
		meta["uid"], meta["resourceVersion"], meta["creationTimestamp"] = testUID(1), "7", "2026-10-21T00:00:00Z"
		specOf(p)["preemptionPolicy"] = "Never"
		specOf(p)["priority"] = float64(-100)
		specOf(p)["schedulerName"] = "default-scheduler"
		specOf(p)["serviceAccount"] = specOf(p)["serviceAccountName"]
		specOf(p)["tolerations"] = deepCopyList(defaultTolerations)
		for _, c := range append(specOf(p)["containers"].([]any), specOf(p)["initContainers"].([]any)...) {
			c.(pm)["imagePullPolicy"] = "IfNotPresent"
		}
		if mutate != nil {
			mutate(p)
		}
		return p
	}
	if _, err := CheckPod(req, server(nil), false, ""); err != nil {
		t.Fatalf("a Pod with the usual defaults: %v", err)
	}
	// Quantities in their canonical spelling.
	canon := server(func(p pm) {
		l := resourcesOf(workOf(p))["limits"].(pm)
		l["cpu"] = "1"
	})
	if _, err := CheckPod(req, canon, false, ""); err != nil {
		t.Errorf("canonical quantity: %v", err)
	}
	wrong := map[string]func(p pm){
		"other quantity": func(p pm) { resourcesOf(workOf(p))["limits"].(pm)["cpu"] = "4" },
		"toleration": func(p pm) {
			specOf(p)["tolerations"] = append(specOf(p)["tolerations"].([]any), pm{"operator": "Exists"})
		},
		"host alias":    func(p pm) { specOf(p)["hostAliases"] = []any{pm{"ip": "1.2.3.4"}} },
		"initContainer": func(p pm) { specOf(p)["initContainers"] = append(specOf(p)["initContainers"].([]any), pm{"name": "x"}) },
		"owner":         func(p pm) { p["metadata"].(pm)["ownerReferences"] = []any{pm{"name": "x"}} },
		"finalizer":     func(p pm) { p["metadata"].(pm)["finalizers"] = []any{"x"} },
		"label":         func(p pm) { labelsOf(p)["x"] = "y" },
		"pull policy":   func(p pm) { workOf(p)["imagePullPolicy"] = "Always" },
		"preemption":    func(p pm) { specOf(p)["preemptionPolicy"] = "PreemptLowerPriority" },
		"not a Pod":     func(p pm) { p["kind"] = "Secret" },
	}
	for name, mutate := range wrong {
		if _, err := CheckPod(req, server(mutate), false, ""); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A node name before scheduling is refused, and after it must stay.
	placed := server(func(p pm) { specOf(p)["nodeName"] = "n1" })
	if _, err := CheckPod(req, placed, false, ""); err == nil {
		t.Error("a new Pod that names a node was accepted")
	}
	if n, err := CheckPod(req, placed, true, ""); err != nil || n != "n1" {
		t.Errorf("placed Pod: %q %v", n, err)
	}
	if _, err := CheckPod(req, placed, true, "n2"); err == nil {
		t.Error("a Pod that moved nodes was accepted")
	}
}

func TestCollect(t *testing.T) {
	f := newFake()
	r := testRunner(t, f)
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	pod := func(name, instance, session, job string, age time.Duration, uid string) map[string]any {
		return pm{"metadata": pm{
			"name": name, "uid": uid, "creationTimestamp": now.Add(-age).Format(time.RFC3339),
			"labels": pm{LabelWork: LabelWorkValue, LabelInstance: instance, LabelSession: session, LabelJob: job},
		}}
	}
	nm := func(job string) string { return PodNamePrefix + testInstance + "-" + job }
	j := func(c string) string { return strings.Repeat(c, 16) }
	f.listExtra = []map[string]any{
		pod(nm(j("1")), testInstance, "ffffffffffffffff", j("1"), time.Minute, "uid-old-session"),
		pod(nm(j("2")), testInstance, testSession, j("2"), time.Minute, "uid-young"),
		pod(nm(j("3")), testInstance, testSession, j("3"), 3*time.Hour, "uid-aged"),
		// Not ours: the name does not follow from the labels, the labels carry
		// a different instance, an extra label, or are not those of a work Pod.
		pod("kestrelynx-work-other", testInstance, "ffffffffffffffff", j("4"), 9*time.Hour, "uid-badname"),
		pod(PodNamePrefix+strings.Repeat("e", 32)+"-"+j("5"), strings.Repeat("e", 32), "ffffffffffffffff", j("5"), 9*time.Hour, "uid-otherinstance"),
		pod(nm(j("6")), testInstance, "ffffffffffffffff", j("7"), 9*time.Hour, "uid-namemismatch"),
	}
	extra := pod(nm(j("8")), testInstance, "ffffffffffffffff", j("8"), 9*time.Hour, "uid-extralabel")
	extra["metadata"].(pm)["labels"].(pm)["more"] = "x"
	f.listExtra = append(f.listExtra, extra)

	n, err := r.Collect(t.Context(), now)
	if err != nil || n != 2 {
		t.Fatalf("collected %d, %v", n, err)
	}
	got := strings.Join(f.deleteUID, ",")
	if got != "uid-old-session,uid-aged" && got != "uid-aged,uid-old-session" {
		t.Errorf("deleted with UIDs %q", got)
	}
}

func TestCollectKeepsWhatItCannotRead(t *testing.T) {
	f := newFake()
	r := testRunner(t, f)
	f.listExtra = []map[string]any{
		{"metadata": pm{"name": PodNamePrefix + testInstance + "-" + strings.Repeat("1", 16), "labels": pm{}}},
		{"metadata": pm{"uid": "x"}},
		{},
	}
	if n, err := r.Collect(t.Context(), time.Now()); err != nil || n != 0 || len(f.deleted) != 0 {
		t.Fatalf("%d %v %v", n, err, f.deleted)
	}
}
