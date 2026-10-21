package remediation

import (
	"strings"
	"testing"
)

func hreq(content, key, current string) HelmValuesEditRequest {
	return HelmValuesEditRequest{Content: []byte(content), Key: key, Current: current, Declared: current, NewTag: "1.27.0"}
}

func TestEditHelmValuesTag(t *testing.T) {
	const cur = "docker.io/library/nginx:1.26.2"
	cases := map[string]struct{ in, key, current, want, location string }{
		"repository and tag": {
			in:  "replicaCount: 2\nimage:\n  repository: nginx\n  tag: 1.26.2\n  pullPolicy: IfNotPresent\n",
			key: "image", current: cur, location: "image.tag",
			want: "replicaCount: 2\nimage:\n  repository: nginx\n  tag: 1.27.0\n  pullPolicy: IfNotPresent\n",
		},
		"double quoted tag with a comment": {
			in:  "image:\n  repository: nginx\n  tag: \"1.26.2\" # pinned\n",
			key: "image", current: cur, location: "image.tag",
			want: "image:\n  repository: nginx\n  tag: \"1.27.0\" # pinned\n",
		},
		"single quoted tag, tag before repository": {
			in:  "image:\n  tag: '1.26.2'\n  repository: docker.io/library/nginx\n",
			key: "image", current: cur, location: "image.tag",
			want: "image:\n  tag: '1.27.0'\n  repository: docker.io/library/nginx\n",
		},
		"registry and repository": {
			in:  "primary:\n  image:\n    registry: ghcr.io\n    repository: example/db\n    tag: v1\n",
			key: "primary.image", current: "ghcr.io/example/db:v1", location: "primary.image.tag",
			want: "primary:\n  image:\n    registry: ghcr.io\n    repository: example/db\n    tag: 1.27.0\n",
		},
		"registry with a trailing slash": {
			in:  "image:\n  registry: ghcr.io/\n  repository: example/db\n  tag: v1\n",
			key: "image", current: "ghcr.io/example/db:v1", location: "image.tag",
			want: "image:\n  registry: ghcr.io/\n  repository: example/db\n  tag: 1.27.0\n",
		},
		"an empty digest and an empty registry": {
			in:  "image:\n  registry: \"\"\n  repository: nginx\n  tag: 1.26.2\n  digest: \"\"\n",
			key: "image", current: cur, location: "image.tag",
			want: "image:\n  registry: \"\"\n  repository: nginx\n  tag: 1.27.0\n  digest: \"\"\n",
		},
		"a repository:tag string": {
			in:  "app:\n  image: \"nginx:1.26.2\" # web\n",
			key: "app.image", current: cur, location: "app.image",
			want: "app:\n  image: \"nginx:1.27.0\" # web\n",
		},
		"a plain repository:tag string": {
			in:  "image: ghcr.io/example/api:v1\nother: x\n",
			key: "image", current: "ghcr.io/example/api:v1", location: "image",
			want: "image: ghcr.io/example/api:1.27.0\nother: x\n",
		},
		"flow mapping": {
			in:  "image: {repository: nginx, tag: \"1.26.2\"}\n",
			key: "image", current: cur, location: "image.tag",
			want: "image: {repository: nginx, tag: \"1.27.0\"}\n",
		},
		"CRLF and a BOM": {
			in:  "\xEF\xBB\xBFimage:\r\n  repository: nginx\r\n  tag: 1.26.2\r\n",
			key: "image", current: cur, location: "image.tag",
			want: "\xEF\xBB\xBFimage:\r\n  repository: nginx\r\n  tag: 1.27.0\r\n",
		},
		"non-ASCII comments": {
			in:  "# 設定\nimage:\n  repository: nginx # 本体\n  tag: 1.26.2\n",
			key: "image", current: cur, location: "image.tag",
			want: "# 設定\nimage:\n  repository: nginx # 本体\n  tag: 1.27.0\n",
		},
		"a deep key among others": {
			in:  "a:\n  b:\n    c:\n      image:\n        repository: nginx\n        tag: 1.26.2\n    d:\n      image:\n        repository: nginx\n        tag: 1.26.2\n",
			key: "a.b.c.image", current: cur, location: "a.b.c.image.tag",
			want: "a:\n  b:\n    c:\n      image:\n        repository: nginx\n        tag: 1.27.0\n    d:\n      image:\n        repository: nginx\n        tag: 1.26.2\n",
		},
	}
	cases["a new tag that stays a string is not quoted"] = struct{ in, key, current, want, location string }{
		in: "image:\n  repository: nginx\n  tag: 1.26.2\n", key: "image", current: cur, location: "image.tag",
		want: "image:\n  repository: nginx\n  tag: 1.27.0\n",
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			edit, prob := EditHelmValuesTag(hreq(tc.in, tc.key, tc.current))
			if prob != nil {
				t.Fatalf("problem: %v", prob)
			}
			if string(edit.Content) != tc.want {
				t.Errorf("content =\n%q\nwant\n%q", edit.Content, tc.want)
			}
			if edit.Change.Location != tc.location || edit.Change.New != "1.27.0" || edit.Change.Old == "" {
				t.Errorf("change = %+v, want location %s", edit.Change, tc.location)
			}
		})
	}
}

func TestEditHelmValuesTagRefuses(t *testing.T) {
	const cur = "docker.io/library/nginx:1.26.2"
	img := func(body string) string { return "image:\n  repository: nginx\n" + body }
	cases := map[string]struct {
		in     string
		reason Reason
		mod    func(*HelmValuesEditRequest)
	}{
		"key missing":                   {"other: 1\n", ReasonHelmKeyMissing, nil},
		"key missing deeper":            {"image:\n  repo: x\n", ReasonHelmKeyMissing, func(r *HelmValuesEditRequest) { r.Key = "image.a.b" }},
		"a list":                        {"image: [a, b]\n", ReasonHelmValuesShape, nil},
		"a number":                      {"image: 5\n", ReasonHelmNotString, nil},
		"a string that is no image":     {"image: \"not an image ref\"\n", ReasonHelmValuesShape, nil},
		"string without a tag":          {"image: nginx\n", ReasonHelmTagFromChart, nil},
		"string with a digest":          {"image: nginx@sha256:" + strings.Repeat("a", 64) + "\n", ReasonHelmDigest, nil},
		"string with a tag and digest":  {"image: nginx:1.26.2@sha256:" + strings.Repeat("a", 64) + "\n", ReasonHelmDigest, nil},
		"no tag":                        {img(""), ReasonHelmTagFromChart, nil},
		"empty tag":                     {img("  tag: \"\"\n"), ReasonHelmTagFromChart, nil},
		"null tag":                      {img("  tag:\n"), ReasonHelmNotString, nil},
		"no repository":                 {"image:\n  tag: 1.26.2\n", ReasonHelmValuesShape, nil},
		"name instead":                  {"image:\n  name: nginx\n  tag: 1.26.2\n", ReasonHelmValuesShape, nil},
		"an image key beside":           {img("  tag: 1.26.2\n  image: x\n"), ReasonHelmValuesShape, nil},
		"digest":                        {img("  tag: 1.26.2\n  digest: sha256:" + strings.Repeat("a", 64) + "\n"), ReasonHelmDigest, nil},
		"repository with a tag":         {"image:\n  repository: nginx:1.26.2\n  tag: 1.26.2\n", ReasonHelmValuesShape, nil},
		"repository with a digest":      {"image:\n  repository: nginx@sha256:" + strings.Repeat("a", 64) + "\n  tag: 1.26.2\n", ReasonHelmValuesShape, nil},
		"numeric tag":                   {img("  tag: 1.26\n"), ReasonHelmNotString, func(r *HelmValuesEditRequest) { r.Current, r.Declared = "nginx:1.26", "nginx:1.26" }},
		"integer tag":                   {img("  tag: 1\n"), ReasonHelmNotString, func(r *HelmValuesEditRequest) { r.Current, r.Declared = "nginx:1", "nginx:1" }},
		"block scalar tag":              {img("  tag: |\n    1.26.2\n"), ReasonHelmBlockScalar, nil},
		"variable":                      {img("  tag: ${TAG}\n"), ReasonHelmVariable, nil},
		"variable in repository":        {"image:\n  repository: $(REG)/nginx\n  tag: 1.26.2\n", ReasonHelmVariable, nil},
		"explicit tag":                  {img("  tag: !!str 1.26.2\n"), ReasonHelmNotString, nil},
		"anchored tag":                  {img("  tag: &t 1.26.2\n"), ReasonHelmAnchorAlias, nil},
		"aliased tag":                   {"x: &t 1.26.2\nimage:\n  repository: nginx\n  tag: *t\n", ReasonHelmAnchorAlias, nil},
		"aliased image":                 {"base: &i\n  repository: nginx\n  tag: 1.26.2\nimage: *i\n", ReasonHelmAnchorAlias, nil},
		"anchored image":                {"image: &i\n  repository: nginx\n  tag: 1.26.2\n", ReasonHelmAnchorAlias, nil},
		"anchored parent":               {"app: &a\n  image:\n    repository: nginx\n    tag: 1.26.2\n", ReasonHelmAnchorAlias, func(r *HelmValuesEditRequest) { r.Key = "app.image" }},
		"merge key in the image":        {"base: &b\n  tag: 1.26.2\nimage:\n  repository: nginx\n  <<: *b\n", ReasonHelmMergeKey, nil},
		"merge key above the image":     {"base: &b\n  other: 1\napp:\n  <<: *b\n  image:\n    repository: nginx\n    tag: 1.26.2\n", ReasonHelmMergeKey, func(r *HelmValuesEditRequest) { r.Key = "app.image" }},
		"merge key at the root":         {"base: &b\n  other: 1\n<<: *b\n" + img("  tag: 1.26.2\n"), ReasonHelmMergeKey, nil},
		"template":                      {img("  tag: 1.26.2\n") + "name: {{ .Release.Name }}\n", ReasonHelmTemplate, nil},
		"Flux image automation":         {img("  tag: 1.26.2 # {\"$imagepolicy\": \"flux:nginx:tag\"}\n"), ReasonHelmImageAutomation, nil},
		"Flux marker on the repository": {"image:\n  repository: nginx # {\"$imagepolicy\": \"flux:nginx:name\"}\n  tag: 1.26.2\n", ReasonHelmImageAutomation, nil},
		"Flux marker on a string":       {"image: nginx:1.26.2 # {\"$imagepolicy\": \"flux:nginx\"}\n", ReasonHelmImageAutomation, nil},
		"two documents":                 {img("  tag: 1.26.2\n") + "---\nimage: {}\n", ReasonHelmInvalid, nil},
		"duplicate tag":                 {img("  tag: 1.26.2\n  tag: 1.25.0\n"), ReasonHelmInvalid, nil},
		"duplicate image":               {img("  tag: 1.26.2\n") + "image:\n  repository: nginx\n  tag: 1.26.2\n", ReasonHelmInvalid, nil},
		"duplicate elsewhere":           {img("  tag: 1.26.2\n") + "x: 1\nx: 2\n", ReasonHelmInvalid, nil},
		"empty file":                    {"", ReasonHelmInvalid, nil},
		"not a mapping":                 {"- a\n", ReasonHelmInvalid, nil},
		"UTF-16":                        {"\xFF\xFEi", ReasonHelmInvalid, nil},
		"other tag":                     {img("  tag: 1.25.0\n"), ReasonSourceMismatch, nil},
		"other repository":              {"image:\n  repository: busybox\n  tag: 1.26.2\n", ReasonSourceMismatch, nil},
		"other registry":                {"image:\n  registry: ghcr.io\n  repository: nginx\n  tag: 1.26.2\n", ReasonSourceMismatch, nil},
		"declared differs":              {img("  tag: 1.26.2\n"), ReasonSourceMismatch, func(r *HelmValuesEditRequest) { r.Declared = "docker.io/library/nginx:1.25.0" }},
		"running has no tag":            {img("  tag: 1.26.2\n"), ReasonHelmInvalid, func(r *HelmValuesEditRequest) { r.Current, r.Declared = "nginx", "nginx" }},
		"new tag is the current":        {img("  tag: 1.26.2\n"), ReasonHelmInvalid, func(r *HelmValuesEditRequest) { r.NewTag = "1.26.2" }},
		"new tag is not a tag":          {img("  tag: 1.26.2\n"), ReasonHelmInvalid, func(r *HelmValuesEditRequest) { r.NewTag = "a b" }},
		"no key":                        {img("  tag: 1.26.2\n"), ReasonHelmInvalid, func(r *HelmValuesEditRequest) { r.Key = "" }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := hreq(tc.in, "image", cur)
			if tc.mod != nil {
				tc.mod(&req)
			}
			edit, prob := EditHelmValuesTag(req)
			if prob == nil {
				t.Fatalf("accepted:\n%s", edit.Content)
			}
			if prob.Reason != tc.reason {
				t.Errorf("reason = %s (%s), want %s", prob.Reason, prob.Detail, tc.reason)
			}
			if edit.Content != nil {
				t.Error("content returned with a problem")
			}
		})
	}
}

// Helm reads the file as YAML 1.1: an unquoted tag that is a number or a
// boolean there is not a string. An unquoted new tag of that kind is written in
// double quotes; one that was quoted keeps its style; an unquoted old tag of
// that kind is refused.
func TestEditHelmValuesTagKeepsTheTagAString(t *testing.T) {
	const cur = "docker.io/library/nginx:1.26.2"
	for _, tag := range []string{"1.10", "1.1", "on", "On", "off", "yes", "no", "y", "n", "true", "False", "null", "~", "1e3", "0x1F", "010", "0b101", "1_000", "12", "+5", ".5", ".inf", "2026-10-21", "1e-3"} {
		req := hreq("image:\n  repository: nginx\n  tag: 1.26.2\n", "image", cur)
		req.NewTag = tag
		edit, prob := EditHelmValuesTag(req)
		if !composeTagRE.MatchString(tag) {
			continue
		}
		if prob != nil {
			t.Errorf("%s: %v", tag, prob)
			continue
		}
		if want := "image:\n  repository: nginx\n  tag: \"" + tag + "\"\n"; string(edit.Content) != want || !edit.Change.Quoted {
			t.Errorf("%s: content %q quoted %v, want %q", tag, edit.Content, edit.Change.Quoted, want)
		}
		// Quoted before: the style stays, and nothing is announced.
		for _, q := range []string{`"`, `'`} {
			req := hreq("image:\n  repository: nginx\n  tag: "+q+"1.26.2"+q+"\n", "image", cur)
			req.NewTag = tag
			edit, prob := EditHelmValuesTag(req)
			if prob != nil || string(edit.Content) != "image:\n  repository: nginx\n  tag: "+q+tag+q+"\n" || edit.Change.Quoted {
				t.Errorf("%s with %s: %v %q quoted %v", tag, q, prob, edit.Content, edit.Change.Quoted)
			}
		}
	}
	// Strings that are fine plain.
	for _, tag := range []string{"1.27.0", "v1.2", "1.27.0-alpine", "latest", "stable-perl", "1.2.3.4"} {
		req := hreq("image:\n  repository: nginx\n  tag: 1.26.2\n", "image", cur)
		req.NewTag = tag
		edit, prob := EditHelmValuesTag(req)
		if prob != nil || edit.Change.Quoted || !strings.Contains(string(edit.Content), "tag: "+tag+"\n") {
			t.Errorf("%s: %v %q", tag, prob, edit.Content)
		}
	}
	// An unquoted old tag that is not a string for Helm: refused.
	for _, old := range []string{"1.10", "on", "1e3", "0x1F"} {
		req := hreq("image:\n  repository: nginx\n  tag: "+old+"\n", "image", "nginx:"+old)
		if _, prob := EditHelmValuesTag(req); prob == nil || prob.Reason != ReasonHelmNotString {
			t.Errorf("old %s: %v", old, prob)
		}
	}
	// The string form is one string scalar and is not affected.
	req := hreq("app:\n  image: nginx:1.26.2\n", "app.image", cur)
	req.NewTag = "1.10"
	if edit, prob := EditHelmValuesTag(req); prob != nil || string(edit.Content) != "app:\n  image: nginx:1.10\n" {
		t.Errorf("string form: %v %q", prob, edit.Content)
	}
}

// Mapping keys that are aliases or not plain strings are not read past: an
// aliased key resolves to a name that could shadow or repeat the tag key.
func TestEditHelmValuesTagRefusesAliasedAndOddKeys(t *testing.T) {
	const cur = "docker.io/library/nginx:1.26.2"
	for name, tc := range map[string]struct {
		in     string
		key    string
		reason Reason
	}{
		"the reviewer's aliased tag key":                     {"tagKey: &tagKey tag\nimage:\n  repository: nginx\n  tag: 1.26.2\n  *tagKey: 1.26.2\n", "image", ReasonHelmAnchorAlias},
		"an aliased repository key":                          {"k: &k repository\nimage:\n  *k: nginx\n  tag: 1.26.2\n", "image", ReasonHelmAnchorAlias},
		"an aliased key at the root":                         {"k: &k image\n*k:\n  repository: busybox\n  tag: 1.26.2\nimage:\n  repository: nginx\n  tag: 1.26.2\n", "image", ReasonHelmAnchorAlias},
		"an aliased key far from the path":                   {"k: &k x\nother:\n  deep:\n    *k: 1\nimage:\n  repository: nginx\n  tag: 1.26.2\n", "image", ReasonHelmAnchorAlias},
		"an aliased key on the path":                         {"k: &k app\n*k:\n  image:\n    repository: nginx\n    tag: 1.26.2\n", "app.image", ReasonHelmAnchorAlias},
		"an anchored key in the image":                       {"image:\n  repository: nginx\n  &t tag: 1.26.2\n", "image", ReasonHelmInvalid},
		"a number as a key in the image":                     {"image:\n  repository: nginx\n  tag: 1.26.2\n  1: x\n", "image", ReasonHelmInvalid},
		"a boolean as a key on the path":                     {"app:\n  true: x\n  image:\n    repository: nginx\n    tag: 1.26.2\n", "app.image", ReasonHelmInvalid},
		"a null key in the image":                            {"image:\n  repository: nginx\n  tag: 1.26.2\n  ~: x\n", "image", ReasonHelmInvalid},
		"a list as a key":                                    {"? [a]\n: b\nimage:\n  repository: nginx\n  tag: 1.26.2\n", "image", ReasonHelmInvalid},
		"the reviewer's collision: a quoted \"true\" and on": {"image:\n  repository: nginx\n  tag: 1.26.2\n  \"true\": a\n  on: b\n", "image", ReasonHelmInvalid},
		"on and then a quoted \"true\"":                      {"image:\n  repository: nginx\n  tag: 1.26.2\n  on: b\n  \"true\": a\n", "image", ReasonHelmInvalid},
		"yes and no keys in the image":                       {"image:\n  repository: nginx\n  tag: 1.26.2\n  yes: a\n", "image", ReasonHelmInvalid},
		"an unquoted ~ and a quoted \"null\"":                {"image:\n  repository: nginx\n  tag: 1.26.2\n  \"null\": a\n  ~: b\n", "image", ReasonHelmInvalid},
		"an unquoted number key in the image":                {"image:\n  repository: nginx\n  tag: 1.26.2\n  1.10: a\n", "image", ReasonHelmInvalid},
		"an unquoted on on the path":                         {"app:\n  on: x\n  image:\n    repository: nginx\n    tag: 1.26.2\n", "app.image", ReasonHelmInvalid},
		"an unquoted y at the root":                          {"y: 1\nimage:\n  repository: nginx\n  tag: 1.26.2\n", "image", ReasonHelmInvalid},
		"an explicit tag on a key":                           {"image:\n  repository: nginx\n  !!str tag: 1.26.2\n", "image", ReasonHelmInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			edit, prob := EditHelmValuesTag(hreq(tc.in, tc.key, cur))
			if prob == nil {
				t.Fatalf("accepted:\n%s", edit.Content)
			}
			if prob.Reason != tc.reason {
				t.Errorf("reason = %s (%s), want %s", prob.Reason, prob.Detail, tc.reason)
			}
		})
	}
	// Quoted keys that look like booleans are strings for Helm too: allowed.
	quoted := "image:\n  repository: nginx\n  tag: 1.26.2\n  \"on\": a\n  'yes': b\n  \"true\": c\n\"y\": d\n"
	if edit, prob := EditHelmValuesTag(hreq(quoted, "image", cur)); prob != nil || !strings.Contains(string(edit.Content), "tag: 1.27.0") {
		t.Errorf("quoted boolean-looking keys: %v", prob)
	}
	// Plain scalar keys that are not strings, in a mapping off the path, are fine.
	ok := "other:\n  1: one\n  true: yes\nimage:\n  repository: nginx\n  tag: 1.26.2\n"
	if _, prob := EditHelmValuesTag(hreq(ok, "image", cur)); prob != nil {
		t.Errorf("plain numeric and boolean keys off the path: %v", prob)
	}
}

// The same content is read by each route as that route reads it: a values
// file with two documents is refused where a manifest file takes them, and the
// kind and name selection of a manifest is not applied to a values file.
func TestHelmValuesFileIsNotReadLikeAManifest(t *testing.T) {
	two := "image:\n  repository: nginx\n  tag: 1.26.2\n---\nkind: Deployment\nmetadata:\n  name: web\n"
	if _, prob := EditHelmValuesTag(hreq(two, "image", "docker.io/library/nginx:1.26.2")); prob == nil || prob.Reason != ReasonHelmInvalid {
		t.Errorf("two documents: %v", prob)
	}
	withKind := "apiVersion: v1\nkind: Deployment\nmetadata:\n  name: web\nimage:\n  repository: nginx\n  tag: 1.26.2\n"
	if _, prob := EditHelmValuesTag(hreq(withKind, "image", "docker.io/library/nginx:1.26.2")); prob != nil {
		t.Errorf("a values file with kind and metadata keys: %v", prob)
	}
}
