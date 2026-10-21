package remediation

import (
	"strings"
	"testing"
)

func kreq(content, image, current string) KustomizeEditRequest {
	return KustomizeEditRequest{Content: []byte(content), Image: image, Current: current, Declared: current, NewTag: "1.27.0"}
}

func TestEditKustomizeNewTag(t *testing.T) {
	const cur = "docker.io/library/nginx:1.26.2"
	cases := map[string]struct{ in, image, current, want string }{
		"plain": {
			in:    "resources:\n  - ../base\nimages:\n  - name: nginx\n    newTag: 1.26.2\n",
			image: "nginx", current: cur,
			want: "resources:\n  - ../base\nimages:\n  - name: nginx\n    newTag: 1.27.0\n",
		},
		"double quoted with a comment": {
			in:    "images:\n  - name: nginx\n    newTag: \"1.26.2\" # pinned\n",
			image: "nginx", current: cur,
			want: "images:\n  - name: nginx\n    newTag: \"1.27.0\" # pinned\n",
		},
		"single quoted": {
			in:    "images:\n  - name: nginx\n    newTag: '1.26.2'\n",
			image: "nginx", current: cur,
			want: "images:\n  - name: nginx\n    newTag: '1.27.0'\n",
		},
		"CRLF": {
			in:    "images:\r\n  - name: nginx\r\n    newTag: 1.26.2\r\n",
			image: "nginx", current: cur,
			want: "images:\r\n  - name: nginx\r\n    newTag: 1.27.0\r\n",
		},
		"flow entry": {
			in:    "images:\n  - {name: nginx, newTag: \"1.26.2\"}\n",
			image: "nginx", current: cur,
			want: "images:\n  - {name: nginx, newTag: \"1.27.0\"}\n",
		},
		"key order and other entries untouched": {
			in:    "images:\n  - newTag: v2\n    name: other\n  - newTag: 1.26.2\n    name: nginx\n  - name: third\n    newTag: 1.26.2\n",
			image: "nginx", current: cur,
			want: "images:\n  - newTag: v2\n    name: other\n  - newTag: 1.27.0\n    name: nginx\n  - name: third\n    newTag: 1.26.2\n",
		},
		"newName renames the repository": {
			// The entry for busybox turns it into nginx: the entry is chosen by its
			// name, and its result is what is compared.
			in:    "images:\n  - name: busybox\n    newName: nginx\n    newTag: \"1.26.2\"\n",
			image: "busybox", current: cur,
			want: "images:\n  - name: busybox\n    newName: nginx\n    newTag: \"1.27.0\"\n",
		},
		"registry name": {
			in:    "images:\n  - name: ghcr.io/example/api\n    newTag: v1\n",
			image: "ghcr.io/example/api", current: "ghcr.io/example/api:v1",
			want: "images:\n  - name: ghcr.io/example/api\n    newTag: 1.27.0\n",
		},
		"local resources and other features that do not matter": {
			in:    "namespace: shop\nnamePrefix: prod-\nresources:\n  - ../base\n  - deploy.yaml\n  - ./extra\nlabels:\n  - pairs: {a: b}\nimages:\n  - name: nginx\n    newTag: 1.26.2\n",
			image: "nginx", current: cur,
			want: "namespace: shop\nnamePrefix: prod-\nresources:\n  - ../base\n  - deploy.yaml\n  - ./extra\nlabels:\n  - pairs: {a: b}\nimages:\n  - name: nginx\n    newTag: 1.27.0\n",
		},
		"non-ASCII before the value": {
			in:    "# 日本語のコメント\nimages:\n  - name: nginx\n    newTag: 1.26.2\n",
			image: "nginx", current: cur,
			want: "# 日本語のコメント\nimages:\n  - name: nginx\n    newTag: 1.27.0\n",
		},
		"with apiVersion and kind, which are not used to choose anything": {
			in:    "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nmetadata:\n  name: prod\nimages:\n  - name: nginx\n    newTag: 1.26.2\n",
			image: "nginx", current: cur,
			want: "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nmetadata:\n  name: prod\nimages:\n  - name: nginx\n    newTag: 1.27.0\n",
		},
		"metacharacters in other names that do not match": {
			in:    "images:\n  - name: nginx\n    newTag: 1.26.2\n  - name: ghcr.io/example/web\n    newTag: 1\n  - name: a+b\n    newTag: 1\n  - name: \"[ab]c\"\n    newTag: 1\n  - name: nginx-proxy\n    newTag: v2\n",
			image: "nginx", current: cur,
			want: "images:\n  - name: nginx\n    newTag: 1.27.0\n  - name: ghcr.io/example/web\n    newTag: 1\n  - name: a+b\n    newTag: 1\n  - name: \"[ab]c\"\n    newTag: 1\n  - name: nginx-proxy\n    newTag: v2\n",
		},
		"dots in the target's own name that match nothing else": {
			in:    "images:\n  - name: ghcr.io/example/api\n    newTag: v1\n  - name: ghcr.io/example/worker\n    newTag: v1\n",
			image: "ghcr.io/example/api", current: "ghcr.io/example/api:v1",
			want: "images:\n  - name: ghcr.io/example/api\n    newTag: 1.27.0\n  - name: ghcr.io/example/worker\n    newTag: v1\n",
		},
		"BOM": {
			in:    "\xEF\xBB\xBFimages:\n  - name: nginx\n    newTag: 1.26.2\n",
			image: "nginx", current: cur,
			want: "\xEF\xBB\xBFimages:\n  - name: nginx\n    newTag: 1.27.0\n",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			edit, prob := EditKustomizeNewTag(kreq(tc.in, tc.image, tc.current))
			if prob != nil {
				t.Fatalf("problem: %v", prob)
			}
			if string(edit.Content) != tc.want {
				t.Errorf("content =\n%q\nwant\n%q", edit.Content, tc.want)
			}
			if edit.Change.Location != "images["+tc.image+"].newTag" || edit.Change.New != "1.27.0" || edit.Change.Old == "" {
				t.Errorf("change = %+v", edit.Change)
			}
		})
	}
}

func TestEditKustomizeNewTagRefuses(t *testing.T) {
	const cur = "docker.io/library/nginx:1.26.2"
	img := func(entry string) string { return "images:\n  - name: nginx\n" + entry }
	cases := map[string]struct {
		in     string
		reason Reason
		mod    func(*KustomizeEditRequest)
	}{
		"no images list":        {"resources: [../base]\n", ReasonKustomizeImageMissing, nil},
		"images not a list":     {"images:\n  nginx: 1.26.2\n", ReasonKustomizeInvalid, nil},
		"entry of another name": {"images:\n  - name: other\n    newTag: 1.26.2\n", ReasonKustomizeImageMissing, nil},
		"the name of the result, not of the entry": {
			// An entry that renames busybox to nginx is not the entry named nginx.
			"images:\n  - name: busybox\n    newName: nginx\n    newTag: 1.26.2\n", ReasonKustomizeImageMissing, nil},
		"two entries of one name":  {"images:\n  - name: nginx\n    newTag: 1.26.2\n  - name: nginx\n    newTag: 1.26.2\n", ReasonKustomizeImageAmbiguous, nil},
		"no newTag":                {img("    newName: nginx\n"), ReasonKustomizeTagNotSet, nil},
		"empty newTag":             {img("    newTag: \"\"\n"), ReasonKustomizeTagNotSet, nil},
		"digest":                   {img("    newTag: 1.26.2\n    digest: sha256:" + strings.Repeat("a", 64) + "\n"), ReasonKustomizeDigest, nil},
		"digest in newName":        {img("    newName: nginx@sha256:" + strings.Repeat("a", 64) + "\n    newTag: 1.26.2\n"), ReasonKustomizeDigest, nil},
		"tag in newName":           {img("    newName: nginx:1.26.2\n    newTag: 1.26.2\n"), ReasonKustomizeInvalid, nil},
		"numeric newTag":           {img("    newTag: 1.26\n"), ReasonKustomizeNotString, func(r *KustomizeEditRequest) { r.Current, r.Declared = "nginx:1.26", "nginx:1.26" }},
		"integer newTag":           {img("    newTag: 1\n"), ReasonKustomizeNotString, func(r *KustomizeEditRequest) { r.Current, r.Declared = "nginx:1", "nginx:1" }},
		"boolean-like newTag":      {img("    newTag: true\n"), ReasonKustomizeNotString, nil},
		"explicit tag":             {img("    newTag: !!str 1.26.2\n"), ReasonKustomizeNotString, nil},
		"block scalar":             {img("    newTag: |\n      1.26.2\n"), ReasonKustomizeBlockScalar, nil},
		"variable":                 {img("    newTag: ${TAG}\n"), ReasonKustomizeVariable, nil},
		"variable in newName":      {img("    newName: $(REG)/nginx\n    newTag: 1.26.2\n"), ReasonKustomizeVariable, nil},
		"alias newTag":             {"x: &t 1.26.2\nimages:\n  - name: nginx\n    newTag: *t\n", ReasonKustomizeAnchorAlias, nil},
		"anchored newTag":          {img("    newTag: &t 1.26.2\n"), ReasonKustomizeAnchorAlias, nil},
		"anchored entry":           {"images:\n  - &e\n    name: nginx\n    newTag: 1.26.2\n", ReasonKustomizeAnchorAlias, nil},
		"alias entry":              {"base: &e\n  name: nginx\n  newTag: 1.26.2\nimages:\n  - *e\n", ReasonKustomizeAnchorAlias, nil},
		"merge key":                {"base: &e\n  newTag: 1.26.2\nimages:\n  - name: nginx\n    <<: *e\n", ReasonKustomizeMergeKey, nil},
		"anchored images":          {"images: &i\n  - name: nginx\n    newTag: 1.26.2\n", ReasonKustomizeAnchorAlias, nil},
		"template":                 {img("    newTag: 1.26.2\n# {{ .Values.x }}\n"), ReasonKustomizeTemplate, nil},
		"Flux image automation":    {img("    newTag: 1.26.2 # {\"$imagepolicy\": \"flux:nginx:tag\"}\n"), ReasonKustomizeImageAutomation, nil},
		"two documents":            {img("    newTag: 1.26.2\n") + "---\nimages: []\n", ReasonKustomizeInvalid, nil},
		"duplicate key":            {"images:\n  - name: nginx\n    newTag: 1.26.2\n    newTag: 1.25.0\n", ReasonKustomizeInvalid, nil},
		"duplicate images key":     {"images:\n  - name: nginx\n    newTag: 1.26.2\nimages: []\n", ReasonKustomizeInvalid, nil},
		"empty file":               {"", ReasonKustomizeInvalid, nil},
		"not a mapping":            {"- a\n", ReasonKustomizeInvalid, nil},
		"broken yaml":              {"images: [\n", ReasonKustomizeInvalid, nil},
		"UTF-16":                   {"\xFF\xFEi", ReasonKustomizeInvalid, nil},
		"source: other tag":        {img("    newTag: 1.25.0\n"), ReasonSourceMismatch, nil},
		"source: other repository": {"images:\n  - name: nginx\n    newName: busybox\n    newTag: 1.26.2\n", ReasonSourceMismatch, nil},
		"declared differs":         {img("    newTag: 1.26.2\n"), ReasonSourceMismatch, func(r *KustomizeEditRequest) { r.Declared = "docker.io/library/nginx:1.25.0" }},
		"running has no tag":       {img("    newTag: 1.26.2\n"), ReasonKustomizeInvalid, func(r *KustomizeEditRequest) { r.Current, r.Declared = "nginx", "nginx" }},
		"new tag is the current":   {img("    newTag: 1.26.2\n"), ReasonKustomizeInvalid, func(r *KustomizeEditRequest) { r.NewTag = "1.26.2" }},
		"new tag is not a tag":     {img("    newTag: 1.26.2\n"), ReasonKustomizeInvalid, func(r *KustomizeEditRequest) { r.NewTag = "a b" }},
	}
	// Other images entries that act on this one's name or result.
	chain := func(in, image string, reason Reason) {
		cases["chained: "+strings.ReplaceAll(in, "\n", " ")+" @"+image] = struct {
			in     string
			reason Reason
			mod    func(*KustomizeEditRequest)
		}{in, reason, func(r *KustomizeEditRequest) { r.Image = image }}
	}
	// busybox is turned into nginx and nginx then gets its own tag: the second
	// entry has the last word over the first.
	both := "images:\n  - name: busybox\n    newName: nginx\n    newTag: 1.26.2\n  - name: nginx\n    newTag: 1.26.2\n"
	chain(both, "busybox", ReasonKustomizeImageChained)
	chain(both, "nginx", ReasonKustomizeImageChained)
	// An entry that renames something to the name of this one.
	chain("images:\n  - name: nginx\n    newTag: 1.26.2\n  - name: busybox\n    newName: nginx\n", "nginx", ReasonKustomizeImageChained)
	// An entry that matches the name this entry's result has.
	chain("images:\n  - name: busybox\n    newName: nginx\n    newTag: 1.26.2\n  - name: docker.io/library/nginx\n    newTag: 1.20.0\n", "busybox", ReasonKustomizeImageChained)
	// Two entries that rename to the same result.
	chain("images:\n  - name: busybox\n    newName: nginx\n    newTag: 1.26.2\n  - name: alpine\n    newName: nginx\n    newTag: 1.26.2\n", "busybox", ReasonKustomizeImageChained)
	// Kustomize puts a name into a regular expression unescaped: the dot of
	// acme/api.v1 matches the dash of acme/api-v1, so the later entry sets the
	// tag the earlier one sets.
	regexChain := "images:\n  - name: acme/api-v1\n    newTag: 1.26.2\n  - name: acme/api.v1\n    newTag: 1.26.2\n"
	chain(regexChain, "acme/api-v1", ReasonKustomizeImageChained)
	chain(regexChain, "acme/api.v1", ReasonKustomizeImageChained)
	chain("images:\n  - name: nginx\n    newTag: 1.26.2\n  - name: ngin.\n    newTag: 1.20.0\n", "nginx", ReasonKustomizeImageChained)
	chain("images:\n  - name: nginx\n    newTag: 1.26.2\n  - name: nginx.*\n    newTag: 1.20.0\n", "nginx", ReasonKustomizeImageChained)
	chain("images:\n  - name: nginx\n    newTag: 1.26.2\n  - name: (nginx|redis)\n    newTag: 1.20.0\n", "nginx", ReasonKustomizeImageChained)
	for _, bad := range []string{"api(", "[a-", "a**", `\`} {
		cases["a name that is not a regular expression: "+bad] = struct {
			in     string
			reason Reason
			mod    func(*KustomizeEditRequest)
		}{"images:\n  - name: nginx\n    newTag: 1.26.2\n  - name: '" + bad + "'\n    newTag: 1\n", ReasonKustomizeInvalid, nil}
	}
	cases["imageTags"] = struct {
		in     string
		reason Reason
		mod    func(*KustomizeEditRequest)
	}{"imageTags:\n  - name: nginx\n    newTag: 1.20.0\n" + img("    newTag: 1.26.2\n"), ReasonKustomizeUnsupported, nil}
	// Names that cannot be read are not skipped.
	cases["alias duplicate name"] = struct {
		in     string
		reason Reason
		mod    func(*KustomizeEditRequest)
	}{"images:\n  - name: &n nginx\n    newTag: 1.26.2\n  - name: *n\n    newTag: 1.26.2\n", ReasonKustomizeAnchorAlias, nil}
	for name, in := range map[string]string{
		"an anchored name":         "images:\n  - name: &n nginx\n    newTag: 1.26.2\n",
		"a number as a name":       "images:\n  - name: nginx\n    newTag: 1.26.2\n  - name: 5\n    newTag: 1.1\n",
		"a list as a name":         "images:\n  - name: nginx\n    newTag: 1.26.2\n  - name: [a]\n",
		"a block scalar name":      "images:\n  - name: nginx\n    newTag: 1.26.2\n  - name: |\n      other\n",
		"a tagged name":            "images:\n  - name: nginx\n    newTag: 1.26.2\n  - name: !!str other\n",
		"no name":                  "images:\n  - name: nginx\n    newTag: 1.26.2\n  - newTag: 1.1\n",
		"a variable name":          "images:\n  - name: nginx\n    newTag: 1.26.2\n  - name: $(X)\n",
		"a newName that is a list": "images:\n  - name: nginx\n    newTag: 1.26.2\n  - name: other\n    newName: [a]\n",
	} {
		cases[name] = struct {
			in     string
			reason Reason
			mod    func(*KustomizeEditRequest)
		}{in, "", nil}
	}
	// Spellings Kustomize reads without regard to case.
	for name, in := range map[string]string{
		"newtag beside newTag":   img("    newTag: 1.26.2\n    newtag: 1.20.0\n"),
		"only Newtag":            img("    Newtag: 1.26.2\n"),
		"NEWTAG upper-case":      img("    NEWTAG: 1.26.2\n    newTag: 1.26.2\n"),
		"newname beside newName": img("    newName: nginx\n    newname: busybox\n    newTag: 1.26.2\n"),
		"Digest":                 img("    newTag: 1.26.2\n    Digest: sha256:" + strings.Repeat("a", 64) + "\n"),
		"Name":                   "images:\n  - Name: nginx\n    newTag: 1.26.2\n",
		"Replacements":           "Replacements: []\n" + img("    newTag: 1.26.2\n"),
		"PATCHES":                "PATCHES: []\n" + img("    newTag: 1.26.2\n"),
		"Images beside images":   "Images:\n  - name: nginx\n    newTag: 1.20.0\n" + img("    newTag: 1.26.2\n"),
		"imagetags":              "imagetags:\n  - name: nginx\n" + img("    newTag: 1.26.2\n"),
		"Resources":              "Resources: [../base]\n" + img("    newTag: 1.26.2\n"),
		"a non-string key":       "? [a]\n: b\n" + img("    newTag: 1.26.2\n"),
	} {
		cases["spelling: "+name] = struct {
			in     string
			reason Reason
			mod    func(*KustomizeEditRequest)
		}{in, ReasonKustomizeInvalid, nil}
	}
	for _, f := range []string{"replacements", "patches", "patchesStrategicMerge", "patchesJson6902", "components", "helmCharts", "generators", "transformers", "vars"} {
		cases["feature "+f] = struct {
			in     string
			reason Reason
			mod    func(*KustomizeEditRequest)
		}{f + ":\n  - x\n" + img("    newTag: 1.26.2\n"), ReasonKustomizeUnsupported, nil}
	}
	for _, r := range []string{"https://github.com/org/repo//base?ref=v1", "git@github.com:org/repo.git", "github.com/org/repo/base", "ssh://git@host/x", "../base/?ref=main", "kustomize-base.git/x"} {
		cases["remote resource "+r] = struct {
			in     string
			reason Reason
			mod    func(*KustomizeEditRequest)
		}{"resources:\n  - " + r + "\n" + img("    newTag: 1.26.2\n"), ReasonKustomizeUnsupported, nil}
	}
	cases["remote base"] = struct {
		in     string
		reason Reason
		mod    func(*KustomizeEditRequest)
	}{"bases:\n  - https://example.com/base\n" + img("    newTag: 1.26.2\n"), ReasonKustomizeUnsupported, nil}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := kreq(tc.in, "nginx", cur)
			if tc.mod != nil {
				tc.mod(&req)
			}
			edit, prob := EditKustomizeNewTag(req)
			if prob == nil {
				t.Fatalf("accepted:\n%s", edit.Content)
			}
			if tc.reason != "" && prob.Reason != tc.reason {
				t.Errorf("reason = %s (%s), want %s", prob.Reason, prob.Detail, tc.reason)
			}
			if edit.Content != nil {
				t.Error("content returned with a problem")
			}
		})
	}
}

// Only the images entry of the requested name is looked at: a second entry
// that is broken in a way that matters for itself does not matter here, but a
// feature that changes the whole file does.
func TestEditKustomizeNewTagIgnoresOtherEntries(t *testing.T) {
	in := "images:\n  - name: other\n    newTag: 1.5\n    digest: sha256:" + strings.Repeat("b", 64) + "\n  - name: nginx\n    newTag: 1.26.2\n"
	edit, prob := EditKustomizeNewTag(kreq(in, "nginx", "docker.io/library/nginx:1.26.2"))
	if prob != nil {
		t.Fatalf("problem: %v", prob)
	}
	if !strings.Contains(string(edit.Content), "newTag: 1.27.0") || !strings.Contains(string(edit.Content), "newTag: 1.5") {
		t.Errorf("content = %q", edit.Content)
	}
}
