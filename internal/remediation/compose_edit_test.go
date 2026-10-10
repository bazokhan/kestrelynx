package remediation

import (
	"bytes"
	"strings"
	"testing"
)

func composeReq(content string, current, newTag string, services ...string) ComposeEditRequest {
	return ComposeEditRequest{Content: []byte(content), Services: services, Current: current, NewTag: newTag}
}

func TestEditComposeImageTagSuccess(t *testing.T) {
	const bom = "\xef\xbb\xbf"
	tests := []struct {
		name     string
		in       string
		current  string
		services []string
		newTag   string // "1.25.5" when empty
		want     string
		changes  []ComposeChange
	}{
		{
			name:     "plain",
			in:       "services:\n  web:\n    image: nginx:1.25.3\n",
			current:  "nginx:1.25.3",
			services: []string{"web"},
			want:     "services:\n  web:\n    image: nginx:1.25.5\n",
			changes:  []ComposeChange{{"web", "services.web.image", "nginx:1.25.3", "nginx:1.25.5"}},
		},
		{
			name:     "single quoted",
			in:       "services:\n  web:\n    image: 'nginx:1.25.3'\n",
			current:  "nginx:1.25.3",
			services: []string{"web"},
			want:     "services:\n  web:\n    image: 'nginx:1.25.5'\n",
			changes:  []ComposeChange{{"web", "services.web.image", "nginx:1.25.3", "nginx:1.25.5"}},
		},
		{
			name:     "double quoted",
			in:       "services:\n  web:\n    image: \"nginx:1.25.3\"\n",
			current:  "nginx:1.25.3",
			services: []string{"web"},
			want:     "services:\n  web:\n    image: \"nginx:1.25.5\"\n",
			changes:  []ComposeChange{{"web", "services.web.image", "nginx:1.25.3", "nginx:1.25.5"}},
		},
		{
			name:     "comments above and on the same line",
			in:       "# top\nservices:\n  web:\n    # pinned\n    image: nginx:1.25.3 # keep this\n    ports: [\"80:80\"]\n",
			current:  "nginx:1.25.3",
			services: []string{"web"},
			want:     "# top\nservices:\n  web:\n    # pinned\n    image: nginx:1.25.5 # keep this\n    ports: [\"80:80\"]\n",
			changes:  []ComposeChange{{"web", "services.web.image", "nginx:1.25.3", "nginx:1.25.5"}},
		},
		{
			name:     "CRLF",
			in:       "services:\r\n  web:\r\n    image: nginx:1.25.3\r\n  db:\r\n    image: \"nginx:1.25.3\"\r\n",
			current:  "nginx:1.25.3",
			services: []string{"db"},
			want:     "services:\r\n  web:\r\n    image: nginx:1.25.3\r\n  db:\r\n    image: \"nginx:1.25.5\"\r\n",
			changes:  []ComposeChange{{"db", "services.db.image", "nginx:1.25.3", "nginx:1.25.5"}},
		},
		{
			name:     "lone CR line breaks",
			in:       "services:\r  web:\r    image: nginx:1.25.3\r",
			current:  "nginx:1.25.3",
			services: []string{"web"},
			want:     "services:\r  web:\r    image: nginx:1.25.5\r",
			changes:  []ComposeChange{{"web", "services.web.image", "nginx:1.25.3", "nginx:1.25.5"}},
		},
		{
			name:     "BOM",
			in:       bom + "services:\n  web:\n    image: nginx:1.25.3\n",
			current:  "nginx:1.25.3",
			services: []string{"web"},
			want:     bom + "services:\n  web:\n    image: nginx:1.25.5\n",
			changes:  []ComposeChange{{"web", "services.web.image", "nginx:1.25.3", "nginx:1.25.5"}},
		},
		{
			name:     "BOM with the image on the first line (flow)",
			in:       bom + "{services: {web: {image: nginx:1.25.3}}}\n",
			current:  "nginx:1.25.3",
			services: []string{"web"},
			want:     bom + "{services: {web: {image: nginx:1.25.5}}}\n",
			changes:  []ComposeChange{{"web", "services.web.image", "nginx:1.25.3", "nginx:1.25.5"}},
		},
		{
			name:     "multibyte text before the value on the same line",
			in:       "services:\n  ウェブ: {x-メモ: \"日本語\", image: \"nginx:1.25.3\"}\n",
			current:  "nginx:1.25.3",
			services: []string{"ウェブ"},
			want:     "services:\n  ウェブ: {x-メモ: \"日本語\", image: \"nginx:1.25.5\"}\n",
			changes:  []ComposeChange{{"ウェブ", "services.ウェブ.image", "nginx:1.25.3", "nginx:1.25.5"}},
		},
		{
			name:     "Japanese comment above",
			in:       "# 日本語のコメント\nservices:\n  web:\n    image: nginx:1.25.3 # 固定\n",
			current:  "nginx:1.25.3",
			services: []string{"web"},
			want:     "# 日本語のコメント\nservices:\n  web:\n    image: nginx:1.25.5 # 固定\n",
			changes:  []ComposeChange{{"web", "services.web.image", "nginx:1.25.3", "nginx:1.25.5"}},
		},
		{
			name:     "two targets with one image, order irrelevant and duplicates ignored",
			in:       "services:\n  web:\n    image: nginx:1.25.3\n  api:\n    image: 'nginx:1.25.3'\n",
			current:  "nginx:1.25.3",
			services: []string{"web", "api", "web"},
			want:     "services:\n  web:\n    image: nginx:1.25.5\n  api:\n    image: 'nginx:1.25.5'\n",
			changes: []ComposeChange{
				{"api", "services.api.image", "nginx:1.25.3", "nginx:1.25.5"},
				{"web", "services.web.image", "nginx:1.25.3", "nginx:1.25.5"},
			},
		},
		{
			name:     "non-target service with the same image stays",
			in:       "services:\n  web:\n    image: nginx:1.25.3\n  other:\n    image: nginx:1.25.3\n",
			current:  "nginx:1.25.3",
			services: []string{"web"},
			want:     "services:\n  web:\n    image: nginx:1.25.5\n  other:\n    image: nginx:1.25.3\n",
			changes:  []ComposeChange{{"web", "services.web.image", "nginx:1.25.3", "nginx:1.25.5"}},
		},
		{
			name:     "repository written in full keeps its spelling",
			in:       "services:\n  web:\n    image: docker.io/library/nginx:1.25.3\n",
			current:  "nginx:1.25.3",
			services: []string{"web"},
			want:     "services:\n  web:\n    image: docker.io/library/nginx:1.25.5\n",
			changes:  []ComposeChange{{"web", "services.web.image", "docker.io/library/nginx:1.25.3", "docker.io/library/nginx:1.25.5"}},
		},
		{
			name:     "file short form, running image in full",
			in:       "services:\n  web:\n    image: nginx:1.25.3\n",
			current:  "docker.io/library/nginx:1.25.3",
			services: []string{"web"},
			want:     "services:\n  web:\n    image: nginx:1.25.5\n",
			changes:  []ComposeChange{{"web", "services.web.image", "nginx:1.25.3", "nginx:1.25.5"}},
		},
		{
			name:     "namespaced repository and registry with port",
			in:       "services:\n  web:\n    image: registry.local:5000/team/app:v1.2.3-alpine\n",
			current:  "registry.local:5000/team/app:v1.2.3-alpine",
			services: []string{"web"},
			newTag:   "v1.2.5-alpine",
			want:     "services:\n  web:\n    image: registry.local:5000/team/app:v1.2.5-alpine\n",
			changes:  []ComposeChange{{"web", "services.web.image", "registry.local:5000/team/app:v1.2.3-alpine", "registry.local:5000/team/app:v1.2.5-alpine"}},
		},
		{
			name:     "flow mapping service",
			in:       "services:\n  web: {image: \"nginx:1.25.3\", ports: [\"80:80\"]}\n",
			current:  "nginx:1.25.3",
			services: []string{"web"},
			want:     "services:\n  web: {image: \"nginx:1.25.5\", ports: [\"80:80\"]}\n",
			changes:  []ComposeChange{{"web", "services.web.image", "nginx:1.25.3", "nginx:1.25.5"}},
		},
		{
			name:     "plain scalar in a flow mapping",
			in:       "services:\n  web: {image: nginx:1.25.3}\n  db: {image: nginx:1.25.3, x: 1}\n",
			current:  "nginx:1.25.3",
			services: []string{"web", "db"},
			want:     "services:\n  web: {image: nginx:1.25.5}\n  db: {image: nginx:1.25.5, x: 1}\n",
			changes: []ComposeChange{
				{"db", "services.db.image", "nginx:1.25.3", "nginx:1.25.5"},
				{"web", "services.web.image", "nginx:1.25.3", "nginx:1.25.5"},
			},
		},
		{
			name:     "quoted key and tab-free odd spacing",
			in:       "services:\n  \"web\":\n      \"image\"  :   'nginx:1.25.3'   \n",
			current:  "nginx:1.25.3",
			services: []string{"web"},
			want:     "services:\n  \"web\":\n      \"image\"  :   'nginx:1.25.5'   \n",
			changes:  []ComposeChange{{"web", "services.web.image", "nginx:1.25.3", "nginx:1.25.5"}},
		},
		{
			name:     "no trailing newline",
			in:       "services:\n  web:\n    image: nginx:1.25.3",
			current:  "nginx:1.25.3",
			services: []string{"web"},
			want:     "services:\n  web:\n    image: nginx:1.25.5",
			changes:  []ComposeChange{{"web", "services.web.image", "nginx:1.25.3", "nginx:1.25.5"}},
		},
		{
			name:     "other node anchored elsewhere is untouched",
			in:       "x-env: &env\n  A: b\nservices:\n  web:\n    image: nginx:1.25.3\n    environment: *env\n",
			current:  "nginx:1.25.3",
			services: []string{"web"},
			want:     "x-env: &env\n  A: b\nservices:\n  web:\n    image: nginx:1.25.5\n    environment: *env\n",
			changes:  []ComposeChange{{"web", "services.web.image", "nginx:1.25.3", "nginx:1.25.5"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			newTag := "1.25.5"
			if tc.newTag != "" {
				newTag = tc.newTag
			}
			got, prob := EditComposeImageTag(composeReq(tc.in, tc.current, newTag, tc.services...))
			if prob != nil {
				t.Fatalf("problem: %v", prob)
			}
			if string(got.Content) != tc.want {
				t.Errorf("content:\n got %q\nwant %q", got.Content, tc.want)
			}
			if len(got.Changes) != len(tc.changes) {
				t.Fatalf("changes = %+v, want %+v", got.Changes, tc.changes)
			}
			for i := range tc.changes {
				if got.Changes[i] != tc.changes[i] {
					t.Errorf("change %d = %+v, want %+v", i, got.Changes[i], tc.changes[i])
				}
			}
		})
	}
}

func TestEditComposeImageTagRefusals(t *testing.T) {
	const img = "    image: nginx:1.25.3\n"
	tests := []struct {
		name     string
		in       string
		current  string
		newTag   string
		services []string
		reason   Reason
	}{
		{"build", "services:\n  web:\n    build: .\n" + img, "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeBuild},
		{"braced variable", "services:\n  web:\n    image: nginx:${TAG}\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeVariable},
		{"bare variable", "services:\n  web:\n    image: \"nginx:$TAG\"\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeVariable},
		{"anchor on image", "services:\n  web:\n    image: &i nginx:1.25.3\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeAnchorAlias},
		{"alias image", "x: &i nginx:1.25.3\nservices:\n  web:\n    image: *i\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeAnchorAlias},
		{"anchor on service", "services:\n  web: &w\n" + img + "  b: *w\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeAnchorAlias},
		{"service is an alias", "x: &w\n  image: nginx:1.25.3\nservices:\n  web: *w\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeAnchorAlias},
		{"anchor on services", "services: &s\n  web:\n" + img, "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeAnchorAlias},
		{"merge key in service", "x-base: &base\n  restart: always\nservices:\n  web:\n    <<: *base\n" + img, "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeMergeKey},
		{"merge key in services", "x-base: &base\n  web:\n" + img + "services:\n  <<: *base\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeMergeKey},
		{"merge key at root", "x-base: &base\n  services: {}\n<<: *base\nservices:\n  web:\n" + img, "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeMergeKey},
		{"include", "include:\n  - other.yml\nservices:\n  web:\n" + img, "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeIncludeExtends},
		{"extends", "services:\n  web:\n    extends:\n      file: base.yml\n      service: x\n" + img, "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeIncludeExtends},
		{"digest only", "services:\n  web:\n    image: nginx@sha256:" + strings.Repeat("a", 64) + "\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeDigest},
		{"tag and digest", "services:\n  web:\n    image: nginx:1.25.3@sha256:" + strings.Repeat("a", 64) + "\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeDigest},
		{"repository mismatch", "services:\n  web:\n    image: apache:1.25.3\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeSourceMismatch},
		{"registry mismatch", "services:\n  web:\n    image: ghcr.io/nginx:1.25.3\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeSourceMismatch},
		{"tag mismatch", "services:\n  web:\n    image: nginx:1.25.4\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeSourceMismatch},
		{"no tag in file", "services:\n  web:\n    image: nginx\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeSourceMismatch},
		{"missing service", "services:\n  web:\n" + img, "nginx:1.25.3", "1.25.5", []string{"nope"}, ReasonComposeServiceMissing},
		{"missing image", "services:\n  web:\n    command: x\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeServiceMissing},
		{"no services key", "name: x\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeServiceMissing},
		{"one missing refuses the whole set", "services:\n  web:\n" + img, "nginx:1.25.3", "1.25.5", []string{"web", "nope"}, ReasonComposeServiceMissing},
		{"one mismatch refuses the whole set", "services:\n  web:\n" + img + "  db:\n    image: nginx:9.9.9\n", "nginx:1.25.3", "1.25.5", []string{"web", "db"}, ReasonComposeSourceMismatch},
		{"duplicate keys", "services:\n  web:\n" + img + "  web:\n" + img, "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeInvalid},
		{"duplicate image keys", "services:\n  web:\n" + img + img, "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeInvalid},
		{"block scalar literal", "services:\n  web:\n    image: |\n      nginx:1.25.3\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeBlockScalar},
		{"block scalar folded", "services:\n  web:\n    image: >-\n      nginx:1.25.3\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeBlockScalar},
		{"explicit str tag", "services:\n  web:\n    image: !!str nginx:1.25.3\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeNotString},
		{"non-string", "services:\n  web:\n    image: 123\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeNotString},
		{"null image", "services:\n  web:\n    image:\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeNotString},
		{"mapping image", "services:\n  web:\n    image: {a: b}\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeNotString},
		{"escape in double quotes", "services:\n  web:\n    image: \"nginx:1.25.\\x33\"\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeInvalid},
		{"folded double quotes", "services:\n  web:\n    image: \"nginx:\n      1.25.3\"\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeInvalid},
		{"multiple documents", "services:\n  web:\n" + img + "---\nservices:\n  web:\n" + img, "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeInvalid},
		{"trailing empty document", "services:\n  web:\n" + img + "---\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeInvalid},
		{"parse error", "services: [\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeInvalid},
		{"empty file", "", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeInvalid},
		{"top level sequence", "- a\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeInvalid},
		{"services not a mapping", "services: []\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeInvalid},
		{"service not a mapping", "services:\n  web: nginx\n", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeInvalid},
		{"UTF-16", "\xff\xfes\x00", "nginx:1.25.3", "1.25.5", []string{"web"}, ReasonComposeInvalid},
		{"bad new tag", "services:\n  web:\n" + img, "nginx:1.25.3", "1.25.5/x", []string{"web"}, ReasonComposeInvalid},
		{"empty new tag", "services:\n  web:\n" + img, "nginx:1.25.3", "", []string{"web"}, ReasonComposeInvalid},
		{"new tag starting with dot", "services:\n  web:\n" + img, "nginx:1.25.3", ".1", []string{"web"}, ReasonComposeInvalid},
		{"new tag too long", "services:\n  web:\n" + img, "nginx:1.25.3", strings.Repeat("a", 129), []string{"web"}, ReasonComposeInvalid},
		{"no services requested", "services:\n  web:\n" + img, "nginx:1.25.3", "1.25.5", nil, ReasonComposeInvalid},
		{"empty service name", "services:\n  web:\n" + img, "nginx:1.25.3", "1.25.5", []string{""}, ReasonComposeInvalid},
		{"current without tag", "services:\n  web:\n" + img, "nginx", "1.25.5", []string{"web"}, ReasonComposeInvalid},
		{"current malformed", "services:\n  web:\n" + img, "NGINX:1", "1.25.5", []string{"web"}, ReasonComposeInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, prob := EditComposeImageTag(composeReq(tc.in, tc.current, tc.newTag, tc.services...))
			if prob == nil {
				t.Fatalf("edit succeeded: %q", got.Content)
			}
			if prob.Reason != tc.reason {
				t.Errorf("reason = %s (%s), want %s", prob.Reason, prob.Detail, tc.reason)
			}
			if got.Content != nil || got.Changes != nil {
				t.Errorf("a refusal returned a partial edit: %+v", got)
			}
		})
	}
}

func TestEditComposeImageTagDoesNotMutateInput(t *testing.T) {
	in := []byte("services:\n  web:\n    image: nginx:1.25.3\n")
	orig := bytes.Clone(in)
	if _, prob := EditComposeImageTag(ComposeEditRequest{Content: in, Services: []string{"web"}, Current: "nginx:1.25.3", NewTag: "1.25.5"}); prob != nil {
		t.Fatal(prob)
	}
	if !bytes.Equal(in, orig) {
		t.Errorf("input changed: %q", in)
	}
}

func TestEditComposeImageTagSameTagIsRefused(t *testing.T) {
	in := "services:\n  web:\n    image: nginx:1.25.3\n"
	_, prob := EditComposeImageTag(composeReq(in, "nginx:1.25.3", "1.25.3", "web"))
	if prob == nil || prob.Reason != ReasonComposeInvalid {
		t.Fatalf("problem = %v", prob)
	}
}

// checkComposeEditInvariants asserts the guarantees of a successful edit
// without using the code under test's own verification.
func checkComposeEditInvariants(t *testing.T, req ComposeEditRequest, got ComposeEdit) {
	t.Helper()
	if len(got.Changes) == 0 {
		t.Fatal("success without changes")
	}
	want := dedupeSorted(req.Services)
	if len(got.Changes) != len(want) {
		t.Fatalf("changes %v for services %v", got.Changes, want)
	}
	for i, c := range got.Changes {
		if c.Service != want[i] || c.Location != "services."+want[i]+".image" {
			t.Fatalf("change %d = %+v", i, c)
		}
		if !strings.HasSuffix(c.New, ":"+req.NewTag) || strings.Contains(c.Old+c.New, "\n") {
			t.Fatalf("change %d = %+v", i, c)
		}
	}
	oldLines := bytes.Split(req.Content, []byte("\n"))
	newLines := bytes.Split(got.Content, []byte("\n"))
	if len(oldLines) != len(newLines) {
		t.Fatalf("line count changed: %d -> %d", len(oldLines), len(newLines))
	}
	differing := 0
	for i := range oldLines {
		if !bytes.Equal(oldLines[i], newLines[i]) {
			differing++
		}
	}
	if differing > len(got.Changes) {
		t.Fatalf("%d lines differ for %d changes", differing, len(got.Changes))
	}
	root0, p := parseComposeDocument(req.Content)
	if p != nil {
		t.Fatalf("original does not parse: %v", p)
	}
	root1, p := parseComposeDocument(got.Content)
	if p != nil {
		t.Fatalf("result does not parse: %v", p)
	}
	var diffs []string
	diffComposeNodes(root0, root1, "", &diffs)
	if len(diffs) != len(got.Changes) {
		t.Fatalf("diffs %v for changes %v", diffs, got.Changes)
	}
	for _, c := range got.Changes {
		img := mapValue(mapValue(mapValue(root1, "services"), c.Service), "image")
		if img == nil || img.Value != c.New {
			t.Fatalf("%s does not hold %q", c.Location, c.New)
		}
		found := false
		for _, d := range diffs {
			found = found || d == c.Location
		}
		if !found {
			t.Fatalf("no diff at %s: %v", c.Location, diffs)
		}
	}
}

func FuzzEditComposeImageTag(f *testing.F) {
	seeds := []string{
		"services:\n  web:\n    image: nginx:1.25.3\n",
		"services:\n  web:\n    image: 'nginx:1.25.3'\n  db:\n    image: \"nginx:1.25.3\" # c\n",
		"\xef\xbb\xbfservices:\r\n  web:\r\n    image: nginx:1.25.3\r\n",
		"services:\n  ウェブ: {x: \"日本\", image: nginx:1.25.3}\n  web: {image: nginx:1.25.3}\n",
		"services:\n  web: &w\n    image: nginx:1.25.3\n  db: *w\n",
		"x: &base\n  restart: always\nservices:\n  web:\n    <<: *base\n    image: nginx:1.25.3\n",
		"services:\n  web:\n    image: \"nginx:\n      1.25.3\"\n",
		"services:\n  web:\n    image: nginx:1.25.3\n---\nservices: {}\n",
		"services:\r  web:\r    image: docker.io/library/nginx:1.25.3\r",
		"services:\n  web:\n    image: !!str nginx:1.25.3\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s), "web", "nginx:1.25.3", "1.25.5")
		f.Add([]byte(s), "ウェブ", "nginx:1.25.3", "v2")
	}
	f.Fuzz(func(t *testing.T, content []byte, service, current, newTag string) {
		req := ComposeEditRequest{Content: content, Services: []string{service, "web"}, Current: current, NewTag: newTag}
		before := bytes.Clone(content)
		got, prob := EditComposeImageTag(req)
		if !bytes.Equal(before, content) {
			t.Fatal("input was modified")
		}
		if prob != nil {
			if got.Content != nil || got.Changes != nil || prob.Reason == "" {
				t.Fatalf("refusal with a partial result: %+v %+v", got, prob)
			}
			return
		}
		checkComposeEditInvariants(t, req, got)
	})
}
