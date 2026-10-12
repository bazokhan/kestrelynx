package docker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeRef(t *testing.T) {
	d := "@" + testDigest
	same := [][]string{
		{"node" + d, "library/node" + d, "docker.io/node" + d, "docker.io/library/node" + d, "index.docker.io/library/node" + d, "index.docker.io/node" + d, "registry-1.docker.io/library/node" + d},
		{"registry.example.com:5000/dockerhub/library/node" + d},
		{"user/app" + d, "docker.io/user/app" + d},
	}
	for _, g := range same {
		want := normalizeRef(g[0])
		for _, r := range g {
			if got := normalizeRef(r); got != want {
				t.Errorf("%s = %s, want %s", r, got, want)
			}
		}
	}
	// Different repositories, hosts and mirror paths stay different.
	diff := [][2]string{
		{"node" + d, "python" + d},
		{"node" + d, "user/node" + d},
		{"node" + d, "registry.example.com/library/node" + d},
		{"registry.example.com/a/node" + d, "registry.example.com/b/node" + d},
		{"registry.example.com/node" + d, "other.example.com/node" + d},
		{"node" + d, "node@sha256:" + strings.Repeat("b", 64)},
		{"localhost/node" + d, "node" + d},
	}
	for _, p := range diff {
		if normalizeRef(p[0]) == normalizeRef(p[1]) {
			t.Errorf("%s and %s compare equal", p[0], p[1])
		}
	}
	if got := normalizeRef("node" + d); got != "docker.io/library/node"+d {
		t.Errorf("node = %s", got)
	}
}

func goodInspect() imageInspect {
	var i imageInspect
	i.Os, i.Architecture = "linux", "amd64"
	i.RepoDigests = []string{"index.docker.io/library/work@" + testDigest}
	i.Config.Env = []string{"PATH=/bin", "WORK_VERSION=1.2.3"}
	return i
}

func newVerifyClient(t *testing.T, image string) *WorkClient {
	t.Helper()
	c, err := newWorkClient("x", nil, WorkConfig{
		Image: image, Platform: "linux/amd64", ExpectEnv: map[string]string{"WORK_VERSION": "1.2.3"},
		Entrypoint: []string{"/w"}, AllowedEnvKeys: []string{"HOME"}, InstanceID: testInstance, Limits: testLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestVerifyImage(t *testing.T) {
	c := newVerifyClient(t, "work@"+testDigest)
	if err := c.verifyImage(goodInspect()); err != nil {
		t.Fatalf("good image: %v", err)
	}
	// A reference through the full Docker Hub form on the pinned side matches
	// the familiar form on the daemon side too.
	c2 := newVerifyClient(t, "docker.io/library/work@"+testDigest)
	i := goodInspect()
	i.RepoDigests = []string{"work@" + testDigest}
	if err := c2.verifyImage(i); err != nil {
		t.Errorf("full vs familiar: %v", err)
	}
	cases := map[string]func(*imageInspect){
		"empty os":            func(i *imageInspect) { i.Os = "" },
		"empty architecture":  func(i *imageInspect) { i.Architecture = "" },
		"other architecture":  func(i *imageInspect) { i.Architecture = "arm64" },
		"other os":            func(i *imageInspect) { i.Os = "windows" },
		"other repository":    func(i *imageInspect) { i.RepoDigests = []string{"other@" + testDigest} },
		"other digest":        func(i *imageInspect) { i.RepoDigests = []string{"work@sha256:" + strings.Repeat("b", 64)} },
		"no repo digests":     func(i *imageInspect) { i.RepoDigests = nil },
		"volumes":             func(i *imageInspect) { i.Config.Volumes = map[string]json.RawMessage{"/data": nil} },
		"missing version":     func(i *imageInspect) { i.Config.Env = []string{"PATH=/bin"} },
		"other version":       func(i *imageInspect) { i.Config.Env = []string{"WORK_VERSION=1.2.4"} },
		"version as a prefix": func(i *imageInspect) { i.Config.Env = []string{"WORK_VERSION=1.2.30"} },
	}
	for name, mod := range cases {
		i := goodInspect()
		mod(&i)
		if err := c.verifyImage(i); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A mirror's reference needs the mirror's repo digest.
	m := newVerifyClient(t, "mirror.example.com:5000/hub/library/work@"+testDigest)
	i = goodInspect()
	if err := m.verifyImage(i); err == nil {
		t.Error("a Docker Hub repo digest satisfied a mirror reference")
	}
	i.RepoDigests = []string{"mirror.example.com:5000/hub/library/work@" + testDigest}
	if err := m.verifyImage(i); err != nil {
		t.Errorf("mirror: %v", err)
	}
}

func TestCheckImagePlatformAbsentIsPulled(t *testing.T) {
	var pulled bool
	var pullQuery, inspectQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/version":
			json.NewEncoder(w).Encode(map[string]any{"ApiVersion": "1.52"})
		case r.Method == "POST" && r.URL.Path == "/images/create":
			pulled, pullQuery = true, r.URL.RawQuery
		case strings.HasPrefix(r.URL.Path, "/images/"):
			inspectQuery = r.URL.Query().Get("platform")
			if !pulled { // the daemon answers 200 with empty fields for a platform it lacks
				json.NewEncoder(w).Encode(map[string]any{"RepoDigests": []string{testImage}})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"RepoDigests": []string{testImage}, "Os": "linux", "Architecture": "amd64"})
		default:
			t.Errorf("unexpected %s", r.URL)
		}
	}))
	defer srv.Close()
	c, _ := newWorkClient(srv.URL, srv.Client(), WorkConfig{Image: testImage, Platform: "linux/amd64", Entrypoint: []string{"/w"}, AllowedEnvKeys: []string{"HOME"}, InstanceID: testInstance, Limits: testLimits()})
	if err := c.EnsureImage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !pulled || !strings.Contains(pullQuery, "platform=linux%2Famd64") {
		t.Errorf("pulled=%v query=%q", pulled, pullQuery)
	}
	if inspectQuery != `{"architecture":"amd64","os":"linux"}` {
		t.Errorf("inspect platform = %q", inspectQuery)
	}
}

func TestEnsureImageStillWrongAfterPullFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			json.NewEncoder(w).Encode(map[string]any{"ApiVersion": "1.52"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"RepoDigests": []string{testImage}, "Os": "linux", "Architecture": "arm64"})
	}))
	defer srv.Close()
	c, _ := newWorkClient(srv.URL, srv.Client(), WorkConfig{Image: testImage, Platform: "linux/amd64", Entrypoint: []string{"/w"}, AllowedEnvKeys: []string{"HOME"}, InstanceID: testInstance, Limits: testLimits()})
	if err := c.EnsureImage(context.Background()); err == nil || !strings.Contains(err.Error(), "linux/amd64") {
		t.Fatalf("err = %v", err)
	}
}

func TestEngineAPIVersion(t *testing.T) {
	for v, ok := range map[string]bool{"1.52": true, "1.44": true, "1.43": false, "1.9": false, "2.0": true, "": false, "x.y": false} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"ApiVersion": v})
		}))
		c, _ := newWorkClient(srv.URL, srv.Client(), WorkConfig{Image: testImage, Platform: "linux/amd64", Entrypoint: []string{"/w"}, AllowedEnvKeys: []string{"HOME"}, InstanceID: testInstance, Limits: testLimits()})
		if err := c.checkAPI(context.Background()); (err == nil) != ok {
			t.Errorf("API %q: err = %v, want ok=%v", v, err, ok)
		}
		srv.Close()
	}
}

func TestCreateUsesThePlatformAndRefusesMountsAndHealthChecks(t *testing.T) {
	f, c := newFake(t)
	f.logsBody = frames(1, "x")
	if _, err := c.RunJob(context.Background(), spec()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	var q string
	for i, r := range f.reqs {
		if r == "POST /containers/create" {
			q = f.queries[i]
		}
	}
	f.mu.Unlock()
	if !strings.Contains(q, "platform=linux%2Famd64") {
		t.Errorf("create query = %q", q)
	}
	for name, mut := range map[string]func(m map[string]any){
		"mounts": func(m map[string]any) { m["Mounts"] = []any{map[string]any{"Type": "volume", "Destination": "/data"}} },
		"volumes": func(m map[string]any) {
			m["Config"].(map[string]any)["Volumes"] = map[string]any{"/data": map[string]any{}}
		},
		"no health check": func(m map[string]any) { delete(m["Config"].(map[string]any), "Healthcheck") },
		"other health check": func(m map[string]any) {
			m["Config"].(map[string]any)["Healthcheck"] = map[string]any{"Test": []string{"CMD", "true"}}
		},
		"tools may not execute": func(m map[string]any) {
			m["HostConfig"].(map[string]any)["Tmpfs"] = map[string]string{"/tmp": "rw", "/home/worker": "rw", "/opt/kestrelynx-tools": "rw"}
		},
	} {
		f, c := newFake(t)
		f.mutate = mut
		if _, err := c.RunJob(context.Background(), spec()); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if f.has("POST /containers/" + testCID + "/start") {
			t.Errorf("%s: started", name)
		}
	}
}

func TestBuildInputTarKinds(t *testing.T) {
	lim := testLimits()
	lim.MaxToolBytes, lim.MaxProgramBytes = 100, 50
	ok := []InputFile{
		{Path: "job.json", Content: []byte("{}")},
		{Path: "bin/prog", Content: make([]byte, 40), Kind: KindProgram, Executable: true},
		{Path: "tools/npm-1.0.0.tgz", Content: make([]byte, 90), Kind: KindTool},
	}
	data, err := buildInputTar(ok, lim)
	if err != nil {
		t.Fatal(err)
	}
	modes := tarModes(t, data)
	if modes["work/bin/prog"] != 0o755 || modes["work/tools/npm-1.0.0.tgz"] != 0o644 || modes["work/bin/"] != 0o755 {
		t.Errorf("modes = %v", modes)
	}
	bad := map[string][]InputFile{
		"tool over its limit":    {{Path: "t/a", Content: make([]byte, 101), Kind: KindTool}},
		"program over its limit": {{Path: "b/p", Content: make([]byte, 51), Kind: KindProgram}},
		"two programs":           {{Path: "a", Kind: KindProgram}, {Path: "b", Kind: KindProgram}},
		"three tools":            {{Path: "a", Kind: KindTool}, {Path: "b", Kind: KindTool}, {Path: "c", Kind: KindTool}},
		"executable input":       {{Path: "a", Executable: true}},
		"executable tool":        {{Path: "a", Kind: KindTool, Executable: true}},
		"unknown kind":           {{Path: "a", Kind: 7}},
	}
	for name, in := range bad {
		if _, err := buildInputTar(in, lim); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Tool and program bytes do not take from the input files' room.
	lim.MaxInputBytes = 12
	if _, err := buildInputTar(append(ok, InputFile{Path: "src/a", Content: make([]byte, 10)}), lim); err != nil {
		t.Errorf("tool and program counted against the inputs: %v", err)
	}
	if _, err := buildInputTar(append(ok, InputFile{Path: "src/a", Content: make([]byte, 11)}), lim); err == nil {
		t.Error("inputs over their limit accepted")
	}
}

func TestWorkSet(t *testing.T) {
	f, c := newFake(t)
	f.logsBody = frames(1, "ok")
	set := NewWorkSet()
	if err := set.Add("rt", c); err != nil {
		t.Fatal(err)
	}
	if err := set.Add("rt", c); err == nil {
		t.Error("added twice")
	}
	if err := set.Add("", c); err == nil {
		t.Error("empty key")
	}
	s := spec()
	s.Runtime = "rt"
	res, err := set.RunJob(context.Background(), s)
	if err != nil || string(res.Stdout) != "ok" {
		t.Fatalf("%v %v", res, err)
	}
	if !f.has("GET /version") {
		t.Error("the Engine API version was not read")
	}
	s.Runtime = "other"
	if _, err := set.RunJob(context.Background(), s); err == nil {
		t.Error("unknown runtime ran")
	}
	if got := set.Keys(); len(got) != 1 || got[0] != "rt" {
		t.Errorf("keys = %v", got)
	}
}

func TestWorkSetImageProblemsAreErrImageUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
	}))
	defer srv.Close()
	c, _ := newWorkClient(srv.URL, srv.Client(), WorkConfig{Image: testImage, Platform: "linux/amd64", Entrypoint: []string{"/w"}, AllowedEnvKeys: []string{"HOME"}, InstanceID: testInstance, Limits: testLimits()})
	set := NewWorkSet()
	set.Add("rt", c)
	s := spec()
	s.Runtime = "rt"
	if _, err := set.RunJob(context.Background(), s); !errors.Is(err, ErrImageUnavailable) {
		t.Errorf("err = %v", err)
	}
}

func TestWorkSetSharesOneInstance(t *testing.T) {
	_, c := newFake(t)
	other, _ := newWorkClient("x", nil, WorkConfig{Image: testImage, Platform: "linux/amd64", Entrypoint: []string{"/w"}, AllowedEnvKeys: []string{"HOME"}, InstanceID: strings.Repeat("a", 32), Limits: testLimits()})
	set := NewWorkSet()
	set.Add("a", c)
	if err := set.Add("b", other); err == nil {
		t.Error("a client of another installation was added")
	}
}

func TestCheckAPIRetriesAfterATransientFailure(t *testing.T) {
	var calls int
	version := "1.52"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ApiVersion": version})
	}))
	defer srv.Close()
	c, _ := newWorkClient(srv.URL, srv.Client(), WorkConfig{Image: testImage, Platform: "linux/amd64", Entrypoint: []string{"/w"}, AllowedEnvKeys: []string{"HOME"}, InstanceID: testInstance, Limits: testLimits()})
	if err := c.checkAPI(context.Background()); err == nil {
		t.Fatal("the failed answer was accepted")
	}
	if err := c.checkAPI(context.Background()); err != nil {
		t.Fatalf("not asked again after a failure: %v", err)
	}
	// A good answer is remembered.
	if err := c.checkAPI(context.Background()); err != nil || calls != 2 {
		t.Errorf("err=%v calls=%d", err, calls)
	}

	// An expired context is no verdict either.
	calls = 1
	c2, _ := newWorkClient(srv.URL, srv.Client(), WorkConfig{Image: testImage, Platform: "linux/amd64", Entrypoint: []string{"/w"}, AllowedEnvKeys: []string{"HOME"}, InstanceID: testInstance, Limits: testLimits()})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c2.checkAPI(ctx); err == nil {
		t.Fatal("a cancelled context passed")
	}
	if err := c2.checkAPI(context.Background()); err != nil {
		t.Errorf("not asked again after a cancelled context: %v", err)
	}

	// A version that is too old is a verdict, remembered.
	calls, version = 1, "1.43"
	c3, _ := newWorkClient(srv.URL, srv.Client(), WorkConfig{Image: testImage, Platform: "linux/amd64", Entrypoint: []string{"/w"}, AllowedEnvKeys: []string{"HOME"}, InstanceID: testInstance, Limits: testLimits()})
	if c3.checkAPI(context.Background()) == nil || c3.checkAPI(context.Background()) == nil || calls != 2 {
		t.Errorf("too old: calls=%d", calls)
	}
}
