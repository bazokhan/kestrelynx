package remediation

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

const deployDoc = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: shop
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25.3 # keep
        - name: log
          image: busybox:1.36.1
`

func webTarget() ManifestTarget {
	return ManifestTarget{Kind: inventory.WorkloadDeployment, Namespace: "shop", Name: "web", Container: "app"}
}

func manifestReq(content string, targets ...ManifestTarget) ManifestEditRequest {
	if len(targets) == 0 {
		targets = []ManifestTarget{webTarget()}
	}
	return ManifestEditRequest{
		Content: []byte(content), Targets: targets,
		Current: "docker.io/library/nginx:1.25.3", Declared: "nginx:1.25.3", NewTag: "1.25.5",
	}
}

// wantManifestProblem edits and expects the reason.
func wantManifestProblem(t *testing.T, req ManifestEditRequest, reason Reason) {
	t.Helper()
	edit, prob := EditManifestImageTag(req)
	if prob == nil {
		t.Fatalf("edited; want %s:\n%s", reason, edit.Content)
	}
	if prob.Reason != reason {
		t.Fatalf("problem = %s, want %s", prob.Error(), reason)
	}
	if edit.Content != nil {
		t.Error("a problem came with content")
	}
}

func TestEditManifest_ChangesOnlyTheTag(t *testing.T) {
	edit, prob := EditManifestImageTag(manifestReq(deployDoc))
	if prob != nil {
		t.Fatalf("problem: %v", prob)
	}
	want := strings.Replace(deployDoc, "nginx:1.25.3 # keep", "nginx:1.25.5 # keep", 1)
	if string(edit.Content) != want {
		t.Errorf("content:\n%s\nwant:\n%s", edit.Content, want)
	}
	if len(edit.Changes) != 1 {
		t.Fatalf("changes = %+v", edit.Changes)
	}
	c := edit.Changes[0]
	if c.Old != "nginx:1.25.3" || c.New != "nginx:1.25.5" || c.Location != "Deployment/shop/web/containers/app" || c.Workload != "deployment/shop/web/app" {
		t.Errorf("change = %+v", c)
	}
}

func TestEditManifest_FormattingIsKept(t *testing.T) {
	for name, tc := range map[string]struct{ in, old, new string }{
		"double quoted": {strings.Replace(deployDoc, "nginx:1.25.3", `"nginx:1.25.3"`, 1), `"nginx:1.25.3"`, `"nginx:1.25.5"`},
		"single quoted": {strings.Replace(deployDoc, "nginx:1.25.3", `'nginx:1.25.3'`, 1), `'nginx:1.25.3'`, `'nginx:1.25.5'`},
		"crlf":          {strings.ReplaceAll(deployDoc, "\n", "\r\n"), "nginx:1.25.3", "nginx:1.25.5"},
		"flow style": {`apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec: {template: {spec: {containers: [{name: app, image: "nginx:1.25.3"}]}}}
`, "nginx:1.25.3", "nginx:1.25.5"},
		"bom": {"\ufeff" + deployDoc, "nginx:1.25.3", "nginx:1.25.5"},
	} {
		t.Run(name, func(t *testing.T) {
			edit, prob := EditManifestImageTag(manifestReq(tc.in))
			if prob != nil {
				t.Fatalf("problem: %v", prob)
			}
			if want := strings.Replace(tc.in, tc.old, tc.new, 1); string(edit.Content) != want {
				t.Errorf("content:\n%q\nwant:\n%q", edit.Content, want)
			}
		})
	}
}

const multiDoc = `# leading comment
apiVersion: v1
kind: ConfigMap
metadata:
  name: web
---
---
# only a comment
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25.3
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25.3
`

func TestEditManifest_MultiDocumentSelectsByKindAndName(t *testing.T) {
	// The ConfigMap and the StatefulSet are called web too; only the Deployment is edited.
	edit, prob := EditManifestImageTag(manifestReq(multiDoc))
	if prob != nil {
		t.Fatalf("problem: %v", prob)
	}
	idx := strings.LastIndex(multiDoc, "nginx:1.25.3")
	want := multiDoc[:idx] + "nginx:1.25.5" + multiDoc[idx+len("nginx:1.25.3"):]
	if string(edit.Content) != want {
		t.Errorf("content:\n%s", edit.Content)
	}
	if edit.Changes[0].Location != "Deployment//web/containers/app" {
		t.Errorf("location = %q, want the namespace left empty as the file has it", edit.Changes[0].Location)
	}
	// The StatefulSet is selected by its own kind.
	st := ManifestTarget{Kind: inventory.WorkloadStatefulSet, Namespace: "shop", Name: "web", Container: "app"}
	edit, prob = EditManifestImageTag(manifestReq(multiDoc, st))
	if prob != nil {
		t.Fatalf("problem: %v", prob)
	}
	first := strings.Index(multiDoc, "nginx:1.25.3")
	if want := multiDoc[:first] + "nginx:1.25.5" + multiDoc[first+len("nginx:1.25.3"):]; string(edit.Content) != want {
		t.Errorf("statefulset content:\n%s", edit.Content)
	}
}

func TestEditManifest_BothContainersOfOneFileTogether(t *testing.T) {
	two := strings.Replace(deployDoc, "busybox:1.36.1", "nginx:1.25.3", 1)
	log := webTarget()
	log.Container = "log"
	// Both containers use the image, so the pair is edited when both are mapped...
	edit, prob := EditManifestImageTag(manifestReq(two, webTarget(), log))
	if prob != nil {
		t.Fatalf("problem: %v", prob)
	}
	if strings.Count(string(edit.Content), "nginx:1.25.5") != 2 || strings.Contains(string(edit.Content), "nginx:1.25.3") {
		t.Errorf("content:\n%s", edit.Content)
	}
	// ...and with only one mapped, the other keeps its tag and is reported.
	edit, prob = EditManifestImageTag(manifestReq(two))
	if prob != nil {
		t.Fatalf("one mapped: %v", prob)
	}
	if want := strings.Replace(two, "nginx:1.25.3 # keep", "nginx:1.25.5 # keep", 1); string(edit.Content) != want {
		t.Errorf("content:\n%s", edit.Content)
	}
	if len(edit.Unchanged) != 1 || edit.Unchanged[0] != "Deployment/shop/web/containers/log" {
		t.Errorf("unchanged = %v", edit.Unchanged)
	}
}

func TestEditManifest_SharedImageWithInitContainer(t *testing.T) {
	doc := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      initContainers:
        - name: migrate
          image: nginx:1.25.3
      containers:
        - name: app
          image: nginx:1.25.3
        - name: env
          image: other:1
          env:
            - name: IMG
              value: nginx:1.25.3
`
	// The init container is left as it is and reported; an env value that
	// happens to hold the image is not an image field.
	edit, prob := EditManifestImageTag(manifestReq(doc))
	if prob != nil {
		t.Fatalf("problem: %v", prob)
	}
	if want := strings.Replace(doc, "      containers:\n        - name: app\n          image: nginx:1.25.3", "      containers:\n        - name: app\n          image: nginx:1.25.5", 1); string(edit.Content) != want {
		t.Errorf("content:\n%s", edit.Content)
	}
	if len(edit.Unchanged) != 1 || edit.Unchanged[0] != "Deployment//web/initContainers/migrate" {
		t.Errorf("unchanged = %v", edit.Unchanged)
	}
	// A different tag is not shared.
	other := strings.Replace(doc, "image: nginx:1.25.3\n      containers", "image: nginx:1.24.0\n      containers", 1)
	if edit, prob := EditManifestImageTag(manifestReq(other)); prob != nil || len(edit.Unchanged) != 0 {
		t.Errorf("another tag: %v / %v", prob, edit.Unchanged)
	}
}

func TestEditManifest_TemplateAnywhereIsRefused(t *testing.T) {
	// In a comment, in another field and in another document: the file is not a plain manifest.
	for name, doc := range map[string]string{
		"comment":          deployDoc + "# {{ .Values.x }}\n",
		"another field":    strings.Replace(deployDoc, "namespace: shop", "namespace: shop\n  labels:\n    a: '{{ .Release.Name }}'", 1),
		"another document": deployDoc + "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\ndata:\n  k: \"{{ x }}\"\n",
	} {
		t.Run(name, func(t *testing.T) { wantManifestProblem(t, manifestReq(doc), ReasonManifestTemplate) })
	}
}

func TestEditManifest_IdentityMustBeReadableFromTheText(t *testing.T) {
	// The merge puts the document in namespace prod; read as written, it has none.
	merged := strings.Replace(deployDoc, "  name: web\n  namespace: shop\n", "  name: web\n  <<: {namespace: prod}\n", 1)
	wantManifestProblem(t, manifestReq(merged), ReasonManifestMergeKey)
	rootMerge := "<<: {kind: Deployment}\n" + strings.Replace(deployDoc, "kind: Deployment\n", "", 1)
	wantManifestProblem(t, manifestReq(rootMerge), ReasonManifestMergeKey)
	// A merge key in a document that is not the target still hides what that document is.
	wantManifestProblem(t, manifestReq(deployDoc+"---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n  <<: {name: web}\n"), ReasonManifestMergeKey)
	for name, doc := range map[string]string{
		"aliased name":      "x: &n web\n" + strings.Replace(deployDoc, "name: web\n", "name: *n\n", 1),
		"anchored metadata": strings.Replace(deployDoc, "metadata:\n", "metadata: &m\n", 1),
		"aliased namespace": "x: &ns shop\n" + strings.Replace(deployDoc, "namespace: shop", "namespace: *ns", 1),
		"anchored kind":     strings.Replace(deployDoc, "kind: Deployment", "kind: &k Deployment", 1),
	} {
		t.Run(name, func(t *testing.T) { wantManifestProblem(t, manifestReq(doc), ReasonManifestAnchorAlias) })
	}
}

func TestEditManifest_ObjectSelection(t *testing.T) {
	// No such object.
	wantManifestProblem(t, manifestReq(strings.Replace(deployDoc, "name: web", "name: other", 1)), ReasonSourceObjectMissing)
	// Another namespace in the file.
	wantManifestProblem(t, manifestReq(strings.Replace(deployDoc, "namespace: shop", "namespace: prod", 1)), ReasonSourceObjectMissing)
	// Another kind or apiVersion.
	wantManifestProblem(t, manifestReq(strings.Replace(deployDoc, "kind: Deployment", "kind: StatefulSet", 1)), ReasonSourceObjectMissing)
	wantManifestProblem(t, manifestReq(strings.Replace(deployDoc, "apps/v1", "apps/v1beta1", 1)), ReasonSourceObjectMissing)
	// Two documents for the same object.
	wantManifestProblem(t, manifestReq(deployDoc+"---\n"+deployDoc), ReasonSourceObjectAmbiguous)
	// Objects in a List are not read.
	list := "apiVersion: v1\nkind: List\nitems:\n  - " + strings.ReplaceAll(strings.TrimSuffix(deployDoc, "\n"), "\n", "\n    ") + "\n"
	edit, prob := EditManifestImageTag(manifestReq(list))
	if prob == nil || prob.Reason != ReasonSourceObjectMissing || !strings.Contains(prob.Detail, "List") {
		t.Errorf("list: %v / %q", prob, edit.Content)
	}
	// The object may be named otherwise in the file.
	tg := webTarget()
	tg.ObjectName = "prod-web"
	edit, prob = EditManifestImageTag(manifestReq(strings.Replace(deployDoc, "name: web", "name: prod-web", 1), tg))
	if prob != nil || !strings.Contains(string(edit.Content), "nginx:1.25.5") {
		t.Errorf("renamed object: %v", prob)
	}
	tg.ObjectKind = "StatefulSet"
	wantManifestProblem(t, manifestReq(deployDoc, tg), ReasonManifestInvalid)
}

func TestEditManifest_ContainerSelection(t *testing.T) {
	// Container not in the object.
	tg := webTarget()
	tg.Container = "missing"
	wantManifestProblem(t, manifestReq(deployDoc, tg), ReasonSourceContainerMissing)
	// An ordinary init container is not edited.
	ord := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      initContainers:
        - name: wait
          image: nginx:1.25.3
      containers:
        - name: app
          image: busybox:1
`
	tg.Container = "wait"
	wantManifestProblem(t, manifestReq(ord, tg), ReasonSourceContainerMissing)
	// A native sidecar is.
	side := strings.Replace(ord, "image: nginx:1.25.3\n", "image: nginx:1.25.3\n          restartPolicy: Always\n", 1)
	edit, prob := EditManifestImageTag(manifestReq(side, tg))
	if prob != nil {
		t.Fatalf("native sidecar: %v", prob)
	}
	if edit.Changes[0].Location != "Deployment//web/initContainers/wait" || !strings.Contains(string(edit.Content), "image: nginx:1.25.5\n          restartPolicy: Always") {
		t.Errorf("sidecar edit: %+v\n%s", edit.Changes, edit.Content)
	}
	// Two containers of one name.
	dup := strings.Replace(deployDoc, "name: log", "name: app", 1)
	wantManifestProblem(t, manifestReq(dup), ReasonManifestInvalid)
}

func TestEditManifest_PodTemplatePaths(t *testing.T) {
	for kind, doc := range map[inventory.WorkloadKind]string{
		inventory.WorkloadCronJob:   "apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: web\nspec:\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          containers:\n            - name: app\n              image: nginx:1.25.3\n",
		inventory.WorkloadJob:       "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: nginx:1.25.3\n",
		inventory.WorkloadPod:       "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n  containers:\n    - name: app\n      image: nginx:1.25.3\n",
		inventory.WorkloadDaemonSet: "apiVersion: apps/v1\nkind: DaemonSet\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: nginx:1.25.3\n",
	} {
		tg := ManifestTarget{Kind: kind, Namespace: "shop", Name: "web", Container: "app"}
		edit, prob := EditManifestImageTag(manifestReq(doc, tg))
		if prob != nil {
			t.Errorf("%s: %v", kind, prob)
			continue
		}
		if !strings.Contains(string(edit.Content), "nginx:1.25.5") || strings.Contains(string(edit.Content), "1.25.3") {
			t.Errorf("%s: content\n%s", kind, edit.Content)
		}
	}
	// A CronJob template is not where a Deployment's is.
	cron := "apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: nginx:1.25.3\n"
	wantManifestProblem(t, manifestReq(cron, ManifestTarget{Kind: inventory.WorkloadCronJob, Namespace: "shop", Name: "web", Container: "app"}), ReasonSourceContainerMissing)
}

func TestEditManifest_ImageValueRefusals(t *testing.T) {
	swap := func(image string) string { return strings.Replace(deployDoc, "nginx:1.25.3 # keep", image, 1) }
	d := "sha256:" + hex64('a')
	for name, tc := range map[string]struct {
		doc    string
		reason Reason
	}{
		"digest":                {swap("nginx@" + d), ReasonManifestDigest},
		"tag and digest":        {swap("nginx:1.25.3@" + d), ReasonManifestDigest},
		"no tag":                {swap("nginx"), ReasonManifestTagMissing},
		"variable":              {swap("nginx:${TAG}"), ReasonManifestVariable},
		"template":              {swap("'{{ .Values.image }}'"), ReasonManifestTemplate},
		"block scalar":          {strings.Replace(deployDoc, "image: nginx:1.25.3 # keep", "image: |-\n            nginx:1.25.3", 1), ReasonManifestBlockScalar},
		"other tag":             {swap("nginx:1.25.4"), ReasonSourceMismatch},
		"other repository":      {swap("ghcr.io/x/nginx:1.25.3"), ReasonSourceMismatch},
		"flux image automation": {swap(`nginx:1.25.3 # {"$imagepolicy": "flux-system:web:tag"}`), ReasonManifestImageAutomation},
		"explicit tag":          {swap("!!str nginx:1.25.3"), ReasonManifestNotString},
		"not a string":          {swap("1.25"), ReasonManifestNotString},
		"anchor":                {swap("&img nginx:1.25.3"), ReasonManifestAnchorAlias},
		"alias":                 {strings.Replace(swap("nginx:1.25.3"), "image: busybox:1.36.1", "image: *img", 1), ReasonManifestInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			_, prob := EditManifestImageTag(manifestReq(tc.doc))
			if prob == nil {
				t.Fatal("edited")
			}
			if prob.Reason != tc.reason {
				// An unknown alias fails to parse, which is the same refusal.
				t.Errorf("problem = %s, want %s", prob.Error(), tc.reason)
			}
		})
	}
}

func TestEditManifest_AnchorsAndMergeKeysOnThePath(t *testing.T) {
	anchored := strings.Replace(deployDoc, "      containers:", "      containers: &c", 1)
	_, prob := EditManifestImageTag(manifestReq(anchored))
	if prob == nil {
		t.Fatal("an anchored container list was edited")
	}
	merged := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      <<: {serviceAccountName: x}
      containers:
        - name: app
          image: nginx:1.25.3
`
	wantManifestProblem(t, manifestReq(merged), ReasonManifestMergeKey)
	aliasContainer := strings.Replace(deployDoc, "        - name: app\n          image: nginx:1.25.3 # keep\n", "        - &app\n          name: app\n          image: nginx:1.25.3\n", 1)
	wantManifestProblem(t, manifestReq(aliasContainer), ReasonManifestAnchorAlias)
}

func TestEditManifest_DuplicateKeysBeforeAndAfter(t *testing.T) {
	// A repeated key anywhere in any document refuses the file, edited or not.
	dupImage := strings.Replace(deployDoc, "          image: nginx:1.25.3 # keep\n", "          image: nginx:1.25.3\n          image: nginx:1.20.0\n", 1)
	wantManifestProblem(t, manifestReq(dupImage), ReasonManifestInvalid)
	other := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cfg\ndata:\n  a: 1\n  a: 2\n"
	wantManifestProblem(t, manifestReq(deployDoc+"---\n"+other), ReasonManifestInvalid)
	wantManifestProblem(t, manifestReq(other+"---\n"+deployDoc), ReasonManifestInvalid)
	// The check after the edit is the same function over the result.
	edited := strings.Replace(deployDoc, "nginx:1.25.3", "nginx:1.25.5", 1)
	if _, prob := parseManifestDocuments([]byte(edited)); prob != nil {
		t.Errorf("a clean result is refused: %v", prob)
	}
	if _, prob := parseManifestDocuments([]byte(edited + "  extra: 1\n  extra: 2\n")); prob == nil {
		t.Error("a result with a repeated key is accepted")
	}
}

func TestEditManifest_RequestChecks(t *testing.T) {
	req := manifestReq(deployDoc)
	for name, mut := range map[string]func(*ManifestEditRequest){
		"no targets":         func(r *ManifestEditRequest) { r.Targets = nil },
		"bad tag":            func(r *ManifestEditRequest) { r.NewTag = "1.25.5/x" },
		"same tag":           func(r *ManifestEditRequest) { r.NewTag = "1.25.3" },
		"running has digest": func(r *ManifestEditRequest) { r.Current = "nginx@sha256:" + hex64('a') },
		"running no tag":     func(r *ManifestEditRequest) { r.Current = "nginx" },
		"declared differs":   func(r *ManifestEditRequest) { r.Declared = "nginx:1.25.4" },
		"utf-16":             func(r *ManifestEditRequest) { r.Content = []byte{0xFF, 0xFE, 'a', 0} },
		"empty":              func(r *ManifestEditRequest) { r.Content = nil },
		"not yaml":           func(r *ManifestEditRequest) { r.Content = []byte("a: [") },
	} {
		r := req
		mut(&r)
		if edit, prob := EditManifestImageTag(r); prob == nil {
			t.Errorf("%s: edited:\n%s", name, edit.Content)
		}
	}
}

// Documents are located by the parser's positions over the whole stream: a
// document after others, after separators with CRLF line ends, is edited at
// its own bytes and no other.
func TestEditManifest_PositionsAcrossDocuments(t *testing.T) {
	docs := strings.ReplaceAll(multiDoc, "\n", "\r\n")
	edit, prob := EditManifestImageTag(manifestReq(docs))
	if prob != nil {
		t.Fatalf("problem: %v", prob)
	}
	idx := strings.LastIndex(docs, "nginx:1.25.3")
	want := docs[:idx] + "nginx:1.25.5" + docs[idx+len("nginx:1.25.3"):]
	if !bytes.Equal(edit.Content, []byte(want)) {
		t.Errorf("content differs from the expected single edit:\n%q", edit.Content)
	}
	// Non-ASCII text before the image does not move the position.
	wide := strings.Replace(multiDoc, "# leading comment", "# コメント 日本語 ✓", 1)
	edit, prob = EditManifestImageTag(manifestReq(wide))
	if prob != nil {
		t.Fatalf("wide: %v", prob)
	}
	idx = strings.LastIndex(wide, "nginx:1.25.3")
	if want := wide[:idx] + "nginx:1.25.5" + wide[idx+len("nginx:1.25.3"):]; string(edit.Content) != want {
		t.Errorf("wide content:\n%s", edit.Content)
	}
}
