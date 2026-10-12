package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testInstance = "0123456789abcdef0123456789abcdef"
	testDigest   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testImage    = "registry.example/kestrelynx-worker@" + testDigest
	testCID      = "1111111111111111111111111111111111111111111111111111111111111111"
)

func testLimits() TransferLimits {
	return TransferLimits{MaxInputBytes: 1 << 20, MaxInputTarBytes: 2 << 20, MaxInputFiles: 8, MaxInputPathBytes: 64, LogMaxBytes: 1 << 10, MaxStdoutBytes: 2 << 10}
}

func testRes() Resources {
	return Resources{MemoryBytes: 64 << 20, NanoCPUs: 1e9, PidsLimit: 32, NofileLimit: 128, ShmSizeBytes: 1 << 20, TmpSizeBytes: 1 << 20, HomeSizeBytes: 1 << 20, ToolsSizeBytes: 1 << 20}
}

// fakeDocker is a minimal Engine API stand-in that records every request and
// applies the create body back as the inspect response, so a correct client
// round-trips unless a test overrides a field.
type fakeDocker struct {
	t  *testing.T
	mu sync.Mutex

	reqs        []string // "METHOD path" without query
	queries     []string
	createBody  []byte
	createName  string
	warnings    []string
	mutate      func(m map[string]any) // alters the inspect HostConfig/Config
	waitBlocks  bool
	waitStatus  int
	logsBody    []byte
	logsCode    int
	listResp    []map[string]any
	deleted     []string
	killed      []string
	inspectBody map[string]any
	loseCreate  bool // the create is applied but the response is dropped
	deleteFails bool
}

func (f *fakeDocker) paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reqs...)
}

func (f *fakeDocker) has(req string) bool {
	for _, r := range f.paths() {
		if r == req {
			return true
		}
	}
	return false
}

func (f *fakeDocker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.reqs = append(f.reqs, r.Method+" "+r.URL.Path)
	f.queries = append(f.queries, r.URL.RawQuery)
	f.mu.Unlock()
	p := r.URL.Path
	switch {
	case r.Method == "POST" && p == "/containers/create":
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.createBody, f.createName = b, r.URL.Query().Get("name")
		var m map[string]any
		json.Unmarshal(b, &m)
		f.inspectBody = m
		f.mu.Unlock()
		if f.loseCreate {
			panic(http.ErrAbortHandler)
		}
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"Id": testCID, "Warnings": f.warnings})
	case r.Method == "GET" && (p == "/containers/"+testCID+"/json" || p == "/containers/kestrelynx-work-01234567-job1/json"):
		if f.inspectBody == nil {
			w.WriteHeader(404)
			return
		}
		f.mu.Lock()
		m := map[string]any{"Id": testCID, "Name": "/" + f.createName, "Config": f.inspectBody, "HostConfig": f.inspectBody["HostConfig"]}
		f.mu.Unlock()
		// Config carries User, WorkingDir, Entrypoint and Labels from the body.
		hc := map[string]any{}
		for k, v := range m["HostConfig"].(map[string]any) {
			hc[k] = v
		}
		m["HostConfig"] = hc
		if f.mutate != nil {
			f.mutate(m)
		}
		json.NewEncoder(w).Encode(m)
	case r.Method == "PUT" && p == "/containers/"+testCID+"/archive":
		io.Copy(io.Discard, r.Body)
	case r.Method == "POST" && p == "/containers/"+testCID+"/start":
		w.WriteHeader(204)
	case r.Method == "POST" && p == "/containers/"+testCID+"/wait":
		if f.waitBlocks {
			<-r.Context().Done()
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"StatusCode": f.waitStatus})
	case r.Method == "GET" && p == "/containers/"+testCID+"/logs":
		if f.logsCode != 0 {
			w.WriteHeader(f.logsCode)
			return
		}
		w.Write(f.logsBody)
	case r.Method == "POST" && strings.HasPrefix(p, "/containers/") && strings.HasSuffix(p, "/kill"):
		f.mu.Lock()
		f.killed = append(f.killed, p)
		f.mu.Unlock()
		w.WriteHeader(204)
	case r.Method == "DELETE" && strings.HasPrefix(p, "/containers/"):
		if f.deleteFails {
			w.WriteHeader(500)
			return
		}
		f.mu.Lock()
		f.deleted = append(f.deleted, strings.TrimPrefix(p, "/containers/"))
		f.mu.Unlock()
		w.WriteHeader(204)
	case r.Method == "GET" && p == "/containers/json":
		json.NewEncoder(w).Encode(f.listResp)
	case r.Method == "GET" && p == "/version":
		json.NewEncoder(w).Encode(map[string]any{"ApiVersion": "1.52", "MinAPIVersion": "1.44"})
	case r.Method == "GET" && strings.HasPrefix(p, "/images/") && strings.HasSuffix(p, "/json"):
		json.NewEncoder(w).Encode(map[string]any{"Id": "sha256:index", "RepoDigests": []string{testImage}, "Os": "linux", "Architecture": "amd64",
			"Config": map[string]any{"Env": []string{"WORK_VERSION=1.2.3"}}})
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL.String())
		w.WriteHeader(500)
	}
}

func newFake(t *testing.T) (*fakeDocker, *WorkClient) {
	t.Helper()
	f := &fakeDocker{t: t}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := newWorkClient(srv.URL, srv.Client(), WorkConfig{
		Image: testImage, Platform: "linux/amd64", Entrypoint: []string{"/usr/local/bin/worker"}, Env: []string{"HOME=/home/worker"}, AllowedEnvKeys: []string{"HOME"},
		InstanceID: testInstance, Limits: testLimits(),
		OpTimeout: 2 * time.Second, TransferTimeout: 2 * time.Second, CleanupTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

// frames builds a multiplexed log stream with one frame per payload on the
// given stream type (1 stdout, 2 stderr).
func frames(stream byte, payloads ...string) []byte {
	var b []byte
	for _, p := range payloads {
		h := []byte{stream, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(h[4:], uint32(len(p)))
		b = append(append(b, h...), p...)
	}
	return b
}

func spec() JobSpec {
	return JobSpec{JobID: "job1", Inputs: []InputFile{{Path: "in.txt", Content: []byte("x")}}, Timeout: 5 * time.Second, Resources: testRes()}
}

var allowedRequests = []*regexp.Regexp{
	regexp.MustCompile(`^GET /version$`),
	regexp.MustCompile(`^GET /images/.+/json$`),
	regexp.MustCompile(`^POST /images/create$`),
	regexp.MustCompile(`^POST /containers/create$`),
	regexp.MustCompile(`^POST /containers/[0-9a-f]{64}/start$`),
	regexp.MustCompile(`^PUT /containers/[0-9a-f]{64}/archive$`),
	regexp.MustCompile(`^POST /containers/[0-9a-f]{64}/wait$`),
	regexp.MustCompile(`^GET /containers/[0-9a-f]{64}/logs$`),
	regexp.MustCompile(`^POST /containers/[0-9a-f]{64}/kill$`),
	regexp.MustCompile(`^DELETE /containers/[0-9a-f]{64}$`),
	regexp.MustCompile(`^GET /containers/json$`),
	regexp.MustCompile(`^GET /containers/[0-9a-f]{64}/json$`),
}

func TestRunJobSuccessUsesOnlyAllowedRequestsInOrder(t *testing.T) {
	f, c := newFake(t)
	f.logsBody = frames(1, "hello ", "world")
	res, err := c.RunJob(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || string(res.Stdout) != "hello world" {
		t.Fatalf("result = %+v", res)
	}
	got := f.paths()
	for _, r := range got {
		ok := false
		for _, re := range allowedRequests {
			ok = ok || re.MatchString(r)
		}
		if !ok {
			t.Errorf("request %q is not in the allow list", r)
		}
	}
	want := []string{
		"POST /containers/create", "GET /containers/" + testCID + "/json",
		"PUT /containers/" + testCID + "/archive", "POST /containers/" + testCID + "/start",
		"POST /containers/" + testCID + "/wait", "GET /containers/" + testCID + "/logs",
		"DELETE /containers/" + testCID,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("requests:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if len(f.killed) != 0 {
		t.Error("a container that exited was killed")
	}
	// Query strings are fixed too.
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, r := range f.reqs {
		switch r {
		case "PUT /containers/" + testCID + "/archive":
			if f.queries[i] != "path=%2F" {
				t.Errorf("put query = %q", f.queries[i])
			}
		case "POST /containers/" + testCID + "/wait":
			if f.queries[i] != "condition=not-running" {
				t.Errorf("wait query = %q", f.queries[i])
			}
		case "GET /containers/" + testCID + "/logs":
			if f.queries[i] != "stderr=0&stdout=1" {
				t.Errorf("get query = %q", f.queries[i])
			}
		case "DELETE /containers/" + testCID:
			if f.queries[i] != "force=true&v=true" {
				t.Errorf("delete query = %q", f.queries[i])
			}
		}
	}
}

func TestCreateBodyIsFixed(t *testing.T) {
	f, c := newFake(t)
	f.logsBody = frames(1, "hello ", "world")
	if _, err := c.RunJob(context.Background(), spec()); err != nil {
		t.Fatal(err)
	}
	if f.createName != "kestrelynx-work-01234567-job1" {
		t.Errorf("name = %q", f.createName)
	}
	want := `{
	  "Image": "` + testImage + `",
	  "Entrypoint": ["/usr/local/bin/worker"],
	  "User": "10001:10001",
	  "WorkingDir": "/work",
	  "Env": ["HOME=/home/worker"],
	  "Labels": {"io.kestrelynx.work":"1","io.kestrelynx.work.instance":"` + testInstance + `","io.kestrelynx.work.job":"job1","io.kestrelynx.work.image":"` + testDigest + `"},
	  "Healthcheck": {"Test": ["NONE"]},
	  "HostConfig": {
	    "ReadonlyRootfs": false,
	    "Tmpfs": {"/tmp":"rw,nosuid,nodev,size=1048576,mode=1777","/home/worker":"rw,nosuid,nodev,size=1048576,uid=10001,gid=10001,mode=0700",
	      "/opt/kestrelynx-tools":"rw,nosuid,nodev,size=1048576,exec,uid=10001,gid=10001,mode=0755",
	      "/var/tmp":"rw,nosuid,nodev,size=1048576,mode=0755","/run/lock":"rw,nosuid,nodev,size=1048576,mode=0755"},
	    "CapDrop": ["ALL"],
	    "SecurityOpt": ["no-new-privileges"],
	    "Privileged": false,
	    "PublishAllPorts": false,
	    "NetworkMode": "bridge",
	    "Memory": 67108864, "MemorySwap": 67108864, "NanoCpus": 1000000000, "PidsLimit": 32,
	    "Ulimits": [{"Name":"nofile","Soft":128,"Hard":128}],
	    "RestartPolicy": {"Name":"no"},
	    "AutoRemove": false,
	    "LogConfig": {"Type":"json-file","Config":{"max-size":"1024","max-file":"1"}},
	    "ShmSize": 1048576
	  }
	}`
	var a, b any
	if err := json.Unmarshal(f.createBody, &a); err != nil {
		t.Fatal(err)
	}
	json.Unmarshal([]byte(want), &b)
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	if string(ab) != string(bb) {
		t.Errorf("create body\n got %s\nwant %s", ab, bb)
	}
	for _, forbidden := range []string{"Binds", "Mounts", "Devices", "PortBindings", "PidMode", "IpcMode", "CapAdd", "Cmd", "ExposedPorts"} {
		if strings.Contains(string(f.createBody), `"`+forbidden+`"`) {
			t.Errorf("create body sets %s", forbidden)
		}
	}
}

func TestWarningsAndMismatchNeverStart(t *testing.T) {
	cases := map[string]func(f *fakeDocker){
		"warnings": func(f *fakeDocker) { f.warnings = []string{"Your kernel does not support memory swap capabilities"} },
		"memory": func(f *fakeDocker) {
			f.mutate = func(m map[string]any) { m["HostConfig"].(map[string]any)["Memory"] = 0 }
		},
		"pids": func(f *fakeDocker) {
			f.mutate = func(m map[string]any) { delete(m["HostConfig"].(map[string]any), "PidsLimit") }
		},
		"capdrop": func(f *fakeDocker) {
			f.mutate = func(m map[string]any) { m["HostConfig"].(map[string]any)["CapDrop"] = []string{} }
		},
		"secopt": func(f *fakeDocker) {
			f.mutate = func(m map[string]any) { m["HostConfig"].(map[string]any)["SecurityOpt"] = nil }
		},
		"readonly": func(f *fakeDocker) {
			f.mutate = func(m map[string]any) { m["HostConfig"].(map[string]any)["ReadonlyRootfs"] = true }
		},
		"tmpfs": func(f *fakeDocker) {
			f.mutate = func(m map[string]any) {
				m["HostConfig"].(map[string]any)["Tmpfs"] = map[string]string{"/tmp": "rw", "/home/worker": "rw"}
			}
		},
		"privileged": func(f *fakeDocker) {
			f.mutate = func(m map[string]any) { m["HostConfig"].(map[string]any)["Privileged"] = true }
		},
		"hostpid": func(f *fakeDocker) {
			f.mutate = func(m map[string]any) { m["HostConfig"].(map[string]any)["PidMode"] = "host" }
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f, c := newFake(t)
			setup(f)
			f.logsBody = frames(1, "hello ", "world")
			if _, err := c.RunJob(context.Background(), spec()); err == nil {
				t.Fatal("RunJob succeeded")
			}
			if f.has("POST /containers/"+testCID+"/start") || f.has("PUT /containers/"+testCID+"/archive") {
				t.Error("container was started or fed")
			}
			if len(f.deleted) != 1 {
				t.Errorf("deleted = %v", f.deleted)
			}
		})
	}
}

func TestTimeoutKillsAndDeletesWithoutResult(t *testing.T) {
	f, c := newFake(t)
	f.waitBlocks = true
	f.logsBody = frames(1, "hello ", "world")
	s := spec()
	s.Timeout = 300 * time.Millisecond
	res, err := c.RunJob(context.Background(), s)
	if !errors.Is(err, ErrJobTimeout) {
		t.Fatalf("err = %v", err)
	}
	if res.Stdout != nil {
		t.Error("timeout returned files")
	}
	if len(f.killed) != 1 || len(f.deleted) != 1 {
		t.Errorf("killed=%v deleted=%v", f.killed, f.deleted)
	}
	if f.has("GET /containers/" + testCID + "/logs") {
		t.Error("result was read after a timeout")
	}
}

func TestCancelKillsAndDeletes(t *testing.T) {
	f, c := newFake(t)
	f.waitBlocks = true
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	_, err := c.RunJob(ctx, spec())
	if err == nil || errors.Is(err, ErrJobTimeout) {
		t.Fatalf("err = %v, want a cancellation error", err)
	}
	if len(f.killed) != 1 || len(f.deleted) != 1 {
		t.Errorf("killed=%v deleted=%v", f.killed, f.deleted)
	}
}

func TestNonZeroExitWithoutResult(t *testing.T) {
	f, c := newFake(t)
	f.waitStatus, f.logsCode = 3, 404
	res, err := c.RunJob(context.Background(), spec())
	if err != nil || res.ExitCode != 3 || res.Stdout != nil {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if len(f.deleted) != 1 {
		t.Error("not deleted")
	}
}

func TestSuccessfulExitWithoutResultFails(t *testing.T) {
	f, c := newFake(t)
	f.logsCode = 404
	if _, err := c.RunJob(context.Background(), spec()); err == nil {
		t.Fatal("exit 0 with no result succeeded")
	}
	if len(f.deleted) != 1 {
		t.Error("not deleted")
	}
}

func TestBadLogsFailJobAndDeleteContainer(t *testing.T) {
	f, c := newFake(t)
	f.logsBody = frames(2, "boom")
	if _, err := c.RunJob(context.Background(), spec()); err == nil {
		t.Fatal("stderr frame accepted")
	}
	if len(f.deleted) != 1 {
		t.Error("not deleted")
	}
}

func TestReadLogs(t *testing.T) {
	const max = 16
	long := strings.Repeat("x", max+1)
	trunc := frames(1, "abcdef")
	bad := map[string][]byte{
		"stderr":        frames(2, "e"),
		"mixed":         append(frames(1, "ok"), frames(2, "e")...),
		"stdin":         frames(0, "i"),
		"reserved":      {1, 0, 9, 0, 0, 0, 0, 1, 'x'},
		"short header":  {1, 0, 0},
		"short payload": trunc[:len(trunc)-2],
		"header only":   trunc[:8],
		"over limit":    frames(1, long),
		"sum over":      frames(1, "123456789", "123456789"),
		"huge length":   {1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff},
	}
	for name, data := range bad {
		t.Run(name, func(t *testing.T) {
			if out, err := readLogs(bytes.NewReader(data), max); err == nil {
				t.Errorf("accepted: %q", out)
			}
		})
	}
	out, err := readLogs(bytes.NewReader(frames(1, "ab", "", "cd")), max)
	if err != nil || string(out) != "abcd" {
		t.Errorf("good = %q, %v", out, err)
	}
	if out, err := readLogs(bytes.NewReader(nil), max); err != nil || len(out) != 0 {
		t.Errorf("empty = %q, %v", out, err)
	}
	if out, err := readLogs(bytes.NewReader(frames(1, strings.Repeat("y", max))), max); err != nil || len(out) != max {
		t.Errorf("exact limit = %d, %v", len(out), err)
	}
	// Endless empty frames stop at the raw read bound instead of looping.
	if _, err := readLogs(bytes.NewReader(bytes.Repeat([]byte{1, 0, 0, 0, 0, 0, 0, 0}, 1000)), max); err == nil {
		t.Error("endless empty frames accepted")
	}
}

func TestArchiveGetIsNotAvailable(t *testing.T) {
	f, c := newFake(t)
	f.logsBody = frames(1, "ok")
	if _, err := c.RunJob(context.Background(), spec()); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.paths() {
		if strings.HasPrefix(r, "GET ") && strings.HasSuffix(r, "/archive") {
			t.Errorf("archive GET issued: %s", r)
		}
	}
}

func TestLogsOnlyAfterExit(t *testing.T) {
	_, c := newFake(t)
	c.remember(testCID, &ownedContainer{name: "n", jobID: "j", state: stateStarted})
	if _, err := c.getStdout(context.Background(), testCID); err == nil {
		t.Error("logs read before exit")
	}
}

func TestLogConfigAndShmMismatchNeverStart(t *testing.T) {
	for name, mod := range map[string]func(hc map[string]any){
		"shm":     func(hc map[string]any) { hc["ShmSize"] = 67108864 },
		"logtype": func(hc map[string]any) { hc["LogConfig"] = map[string]any{"Type": "none"} },
		"logsize": func(hc map[string]any) {
			hc["LogConfig"] = map[string]any{"Type": "json-file", "Config": map[string]string{"max-size": "-1", "max-file": "1"}}
		},
		"logfiles": func(hc map[string]any) {
			hc["LogConfig"] = map[string]any{"Type": "json-file", "Config": map[string]string{"max-size": "1024", "max-file": "5"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, c := newFake(t)
			f.mutate = func(m map[string]any) { mod(m["HostConfig"].(map[string]any)) }
			if _, err := c.RunJob(context.Background(), spec()); err == nil {
				t.Fatal("RunJob succeeded")
			}
			if f.has("POST /containers/"+testCID+"/start") || len(f.deleted) != 1 {
				t.Errorf("started or not deleted: %v", f.paths())
			}
		})
	}
}

func TestOwnershipIsRequired(t *testing.T) {
	f, c := newFake(t)
	other := strings.Repeat("2", 64)
	if err := c.removeContainer(context.Background(), other); err == nil {
		t.Error("removed an unowned container")
	}
	if _, err := c.InspectWork(context.Background(), other); err == nil {
		t.Error("inspected an unowned container")
	}
	if err := c.putInput(context.Background(), other, nil); err == nil {
		t.Error("put into an unowned container")
	}
	if _, err := c.getStdout(context.Background(), other); err == nil {
		t.Error("read from an unowned container")
	}
	if got := f.paths(); len(got) != 0 {
		t.Errorf("requests were sent: %v", got)
	}
	// Order is enforced for owned containers: no result before exit, no
	// input after start.
	c.remember(testCID, &ownedContainer{name: "n", jobID: "j", state: stateStarted})
	if _, err := c.getStdout(context.Background(), testCID); err == nil {
		t.Error("result read before exit")
	}
	if err := c.putInput(context.Background(), testCID, nil); err == nil {
		t.Error("input put after start")
	}
	if got := f.paths(); len(got) != 0 {
		t.Errorf("requests were sent: %v", got)
	}
}

func staleEntry(id string, mod func(labels map[string]string, names *[]string)) map[string]any {
	labels := map[string]string{
		labelWork: "1", labelInstance: testInstance, labelJob: "old", labelImage: testDigest,
	}
	names := []string{"/kestrelynx-work-01234567-old"}
	if mod != nil {
		mod(labels, &names)
	}
	return map[string]any{"Id": id, "Names": names, "Labels": labels}
}

func TestCleanupStaleRequiresEveryCondition(t *testing.T) {
	f, c := newFake(t)
	id := func(n string) string { return strings.Repeat(n, 64) }
	f.listResp = []map[string]any{
		staleEntry(id("a"), nil),
		staleEntry(id("b"), func(l map[string]string, _ *[]string) { l[labelImage] = "sha256:" + strings.Repeat("c", 64) }), // older release: removed
		staleEntry(id("1"), func(l map[string]string, _ *[]string) { delete(l, labelImage) }),
		staleEntry(id("2"), func(l map[string]string, _ *[]string) { l[labelImage] = "sha256:short" }),
		staleEntry(id("3"), func(l map[string]string, _ *[]string) { l[labelImage] = strings.ToUpper(testDigest) }),
		staleEntry(id("c"), func(_ map[string]string, n *[]string) { *n = []string{"/someone-elses"} }),
		staleEntry(id("d"), func(l map[string]string, _ *[]string) { l[labelInstance] = strings.Repeat("f", 32) }),
		staleEntry(id("e"), func(l map[string]string, _ *[]string) { delete(l, labelWork) }),
		staleEntry(id("f"), func(l map[string]string, _ *[]string) { l[labelJob] = "bad job!" }),
		staleEntry(id("9"), func(l map[string]string, n *[]string) {
			l[labelJob] = "other"
			*n = []string{"/kestrelynx-work-01234567-old"} // name does not match job label
		}),
	}
	n, err := c.CleanupStale(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("CleanupStale = %d, %v", n, err)
	}
	if len(f.deleted) != 2 || f.deleted[0] != id("a") || f.deleted[1] != id("b") {
		t.Errorf("deleted = %v", f.deleted)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, r := range f.reqs {
		if r == "GET /containers/json" {
			q := f.queries[i]
			if !strings.Contains(q, "all=true") || !strings.Contains(q, "filters=") {
				t.Errorf("list query = %q", q)
			}
		}
	}
}

func TestPullStreamErrorIsFailure(t *testing.T) {
	var pulled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/images/"):
			if !pulled {
				w.WriteHeader(404)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"RepoDigests": []string{testImage}, "Os": "linux", "Architecture": "amd64"})
		case r.Method == "GET" && r.URL.Path == "/version":
			json.NewEncoder(w).Encode(map[string]any{"ApiVersion": "1.52"})
		case r.Method == "POST" && r.URL.Path == "/images/create":
			if r.URL.Query().Get("fromImage") != "registry.example/kestrelynx-worker" || r.URL.Query().Get("tag") != testDigest {
				t.Errorf("pull query = %q", r.URL.RawQuery)
			}
			w.Write([]byte("{\"status\":\"Pulling from x\"}\n{\"errorDetail\":{\"message\":\"denied\"},\"error\":\"denied\"}\n"))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
		}
	}))
	defer srv.Close()
	c, _ := newWorkClient(srv.URL, srv.Client(), WorkConfig{Image: testImage, Platform: "linux/amd64", Entrypoint: []string{"/w"}, AllowedEnvKeys: []string{"HOME", "PATH", "npm_config_cache", "LANG"}, InstanceID: testInstance, Limits: testLimits()})
	err := c.EnsureImage(context.Background())
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("err = %v", err)
	}
}

func TestEnsureImageRejectsOtherDigest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			json.NewEncoder(w).Encode(map[string]any{"ApiVersion": "1.52"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"Id": testDigest, "Os": "linux", "Architecture": "amd64",
			"RepoDigests": []string{"registry.example/kestrelynx-worker@sha256:" + strings.Repeat("b", 64)}})
	}))
	defer srv.Close()
	c, _ := newWorkClient(srv.URL, srv.Client(), WorkConfig{Image: testImage, Platform: "linux/amd64", Entrypoint: []string{"/w"}, AllowedEnvKeys: []string{"HOME", "PATH", "npm_config_cache", "LANG"}, InstanceID: testInstance, Limits: testLimits()})
	if err := c.EnsureImage(context.Background()); err == nil {
		t.Fatal("accepted an image whose repo digests lack the pinned reference")
	}
}

func TestNewWorkClientValidation(t *testing.T) {
	ok := WorkConfig{Image: testImage, Platform: "linux/amd64", Entrypoint: []string{"/w"}, AllowedEnvKeys: []string{"HOME", "PATH", "npm_config_cache", "LANG"}, InstanceID: testInstance, Limits: testLimits()}
	if _, err := newWorkClient("x", nil, ok); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(c *WorkConfig){
		"tag only":   func(c *WorkConfig) { c.Image = "registry.example/w:latest" },
		"short hash": func(c *WorkConfig) { c.Image = "w@sha256:abc" },
		"upper repo": func(c *WorkConfig) { c.Image = "W@" + testDigest },
		"dotdot":     func(c *WorkConfig) { c.Image = "a/../b@" + testDigest },
		"instance":   func(c *WorkConfig) { c.InstanceID = "short" },
		"entrypoint": func(c *WorkConfig) { c.Entrypoint = nil },
		"limits":     func(c *WorkConfig) { c.Limits = TransferLimits{} },
		"stdout cap": func(c *WorkConfig) { c.Limits.MaxStdoutBytes = c.Limits.LogMaxBytes - 1 },
		"no allowed": func(c *WorkConfig) { c.AllowedEnvKeys = nil },
		"env":        func(c *WorkConfig) { c.Env = []string{"NOEQUALS"} },
	}
	for name, mod := range bad {
		cfg := ok
		mod(&cfg)
		if _, err := newWorkClient("x", nil, cfg); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestBuildInputTar(t *testing.T) {
	data, err := buildInputTar([]InputFile{
		{Path: "b/c.txt", Content: []byte("C")}, {Path: "a.txt", Content: []byte("A")},
	}, inLim(100))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(bytes.NewReader(data))
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		if h.Uid != 0 || h.Gid != 0 || !h.ModTime.Equal(tarMtime) {
			t.Errorf("%s: owner/mtime %d:%d %v", h.Name, h.Uid, h.Gid, h.ModTime)
		}
		if h.Typeflag == tar.TypeDir && h.Mode != 0o755 || h.Typeflag == tar.TypeReg && h.Mode != 0o644 {
			t.Errorf("%s: mode %o", h.Name, h.Mode)
		}
	}
	if got := strings.Join(names, ","); got != "work/,work/a.txt,work/b/,work/b/c.txt" {
		t.Errorf("entries = %s", got)
	}
	for name, in := range map[string][]InputFile{
		"dotdot":    {{Path: "../x"}},
		"absolute":  {{Path: "/x"}},
		"empty":     {{Path: ""}},
		"dot":       {{Path: "./x"}},
		"trailing":  {{Path: "x/"}},
		"dup":       {{Path: "x"}, {Path: "x"}},
		"filedir":   {{Path: "x"}, {Path: "x/y"}},
		"backslash": {{Path: `a\b`}},
		"toolarge":  {{Path: "x", Content: make([]byte, 101)}},
		"longpath":  {{Path: strings.Repeat("p", 65)}},
		"manyfiles": manyInputs(9),
	} {
		if _, err := buildInputTar(in, inLim(100)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func inLim(bytes int64) TransferLimits {
	l := testLimits()
	l.MaxInputBytes = bytes
	return l
}

func manyInputs(n int) []InputFile {
	var in []InputFile
	for i := 0; i < n; i++ {
		in = append(in, InputFile{Path: "f" + string(rune('a'+i))})
	}
	return in
}

func TestBuildInputTarWholeArchiveLimit(t *testing.T) {
	l := testLimits()
	l.MaxInputTarBytes = 1024 // headers alone exceed this
	if _, err := buildInputTar([]InputFile{{Path: "a"}, {Path: "b"}, {Path: "c"}}, l); err == nil {
		t.Error("archive over the total limit accepted")
	}
}

func TestEnvValidation(t *testing.T) {
	base := WorkConfig{Image: testImage, Platform: "linux/amd64", Entrypoint: []string{"/w"}, AllowedEnvKeys: []string{"HOME", "PATH", "npm_config_cache", "LANG"}, InstanceID: testInstance, Limits: testLimits()}
	for _, env := range [][]string{
		{"HOME=/home/worker", "PATH=/bin"},
		{"npm_config_cache=/tmp/c"},
	} {
		cfg := base
		cfg.Env = env
		if _, err := newWorkClient("x", nil, cfg); err != nil {
			t.Errorf("%v rejected: %v", env, err)
		}
	}
	for _, env := range [][]string{
		{"GITHUB_TOKEN=x"}, {"slack_secret=x"}, {"DB_PASSWORD=x"}, {"API_KEY=x"}, {"SSH_KEY_PATH=x"},
		{"NOEQUALS"}, {"=v"}, {"A B=c"}, {"1A=c"}, {"A=1", "A=2"},
	} {
		cfg := base
		cfg.Env = env
		if _, err := newWorkClient("x", nil, cfg); err == nil {
			t.Errorf("%v accepted", env)
		}
	}
	cfg := base
	cfg.Env, cfg.AllowedEnvKeys = []string{"HOME=/h", "LANG=C"}, []string{"HOME"}
	if _, err := newWorkClient("x", nil, cfg); err == nil {
		t.Error("name outside the allowed set accepted")
	}
}

func TestLoadOrCreateInstanceID(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	id, err := LoadOrCreateInstanceID(dir)
	if err != nil || !instanceIDRE.MatchString(id) {
		t.Fatalf("id=%q err=%v", id, err)
	}
	again, err := LoadOrCreateInstanceID(dir)
	if err != nil || again != id {
		t.Fatalf("again=%q err=%v", again, err)
	}
	st, err := os.Stat(filepath.Join(dir, instanceIDFile))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("stat %v %v", st, err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("temporary files left: %v", ents)
	}
	os.WriteFile(filepath.Join(dir, instanceIDFile), []byte("garbage"), 0o600)
	if _, err := LoadOrCreateInstanceID(dir); err == nil {
		t.Error("malformed id accepted")
	}
}

func TestJobSpecValidation(t *testing.T) {
	f, c := newFake(t)
	for name, mod := range map[string]func(s *JobSpec){
		"job id":    func(s *JobSpec) { s.JobID = "../x" },
		"timeout":   func(s *JobSpec) { s.Timeout = 0 },
		"resources": func(s *JobSpec) { s.Resources.PidsLimit = 0 },
		"input":     func(s *JobSpec) { s.Inputs = []InputFile{{Path: "../x"}} },
	} {
		s := spec()
		mod(&s)
		if _, err := c.RunJob(context.Background(), s); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if got := f.paths(); len(got) != 0 {
		t.Errorf("requests were sent: %v", got)
	}
}

func TestLostCreateResponseDeletesMatchingContainer(t *testing.T) {
	f, c := newFake(t)
	f.loseCreate = true
	if _, err := c.RunJob(context.Background(), spec()); err == nil {
		t.Fatal("RunJob succeeded")
	}
	if len(f.deleted) != 1 || f.deleted[0] != testCID {
		t.Errorf("deleted = %v", f.deleted)
	}
	if f.has("POST /containers/" + testCID + "/start") {
		t.Error("started")
	}
	if !f.has("GET /containers/kestrelynx-work-01234567-job1/json") {
		t.Error("no lookup by name")
	}
}

func TestLostCreateResponseLeavesForeignContainer(t *testing.T) {
	for name, mod := range map[string]func(m map[string]any){
		"instance": func(m map[string]any) {
			m["Config"].(map[string]any)["Labels"].(map[string]any)[labelInstance] = "other"
		},
		"image": func(m map[string]any) {
			m["Config"].(map[string]any)["Labels"].(map[string]any)[labelImage] = "sha256:" + strings.Repeat("c", 64)
		},
		"label": func(m map[string]any) { delete(m["Config"].(map[string]any)["Labels"].(map[string]any), labelWork) },
		"job":   func(m map[string]any) { m["Config"].(map[string]any)["Labels"].(map[string]any)[labelJob] = "other" },
		"name":  func(m map[string]any) { m["Name"] = "/someone-elses" },
	} {
		t.Run(name, func(t *testing.T) {
			f, c := newFake(t)
			f.loseCreate = true
			f.mutate = mod
			if _, err := c.RunJob(context.Background(), spec()); err == nil {
				t.Fatal("RunJob succeeded")
			}
			if len(f.deleted) != 0 {
				t.Errorf("deleted a container that is not ours: %v", f.deleted)
			}
		})
	}
}

func TestLostCreateResponseNothingCreated(t *testing.T) {
	f, c := newFake(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			panic(http.ErrAbortHandler)
		}
		w.WriteHeader(404) // the lookup by name finds nothing
	}))
	defer srv.Close()
	_ = f
	c2, _ := newWorkClient(srv.URL, srv.Client(), c.cfg)
	if _, err := c2.RunJob(context.Background(), spec()); err == nil {
		t.Fatal("RunJob succeeded")
	}
}

func TestFailedDeleteIsRetried(t *testing.T) {
	f, c := newFake(t)
	f.logsBody = frames(1, "hello ", "world")
	f.deleteFails = true
	res, err := c.RunJob(context.Background(), spec())
	if !errors.Is(err, ErrCleanup) || string(res.Stdout) != "hello world" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	oc, err := c.own(testCID)
	if err != nil || oc.state != stateDeletePending {
		t.Fatalf("owned = %+v, %v", oc, err)
	}
	// A pending delete is not skipped as a live job: CleanupStale retries it.
	f.deleteFails = false
	n, err := c.CleanupStale(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("CleanupStale = %d, %v", n, err)
	}
	if len(f.deleted) != 1 {
		t.Errorf("deleted = %v", f.deleted)
	}
	if _, err := c.own(testCID); err == nil {
		t.Error("still owned after a successful retry")
	}
}

func TestRunJobRetriesPendingDeleteFirst(t *testing.T) {
	f, c := newFake(t)
	f.logsBody = frames(1, "hello ", "world")
	f.deleteFails = true
	if _, err := c.RunJob(context.Background(), spec()); !errors.Is(err, ErrCleanup) {
		t.Fatal(err)
	}
	f.deleteFails = false
	if _, err := c.RunJob(context.Background(), spec()); err != nil {
		t.Fatal(err)
	}
	// One delete from the retry, one from the second job's own cleanup.
	if len(f.deleted) != 2 {
		t.Errorf("deleted = %v", f.deleted)
	}
}

// tarModes returns the mode of every entry of a tar by name.
func tarModes(t *testing.T, data []byte) map[string]int64 {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(data))
	out := map[string]int64{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out[h.Name] = h.Mode
	}
}
