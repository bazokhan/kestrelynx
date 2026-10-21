package kubework

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // the WebSocket handshake defines this hash
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type recorded struct {
	method, path, query, auth, body string
}

// apiServer is a TLS server that records what it is asked and answers from
// a handler.
func apiServer(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server, *[]recorded, string) {
	t.Helper()
	var mu sync.Mutex
	var seen []recorded
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, recorded{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), string(b)})
		mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("tok-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(dir, "ca.crt")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(ca, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{APIServer: srv.URL, TokenFile: tok, CAFile: ca, Namespace: "kestrelynx-work"})
	if err != nil {
		t.Fatal(err)
	}
	return c, srv, &seen, tok
}

func TestClientRequestTable(t *testing.T) {
	c, _, seen, _ := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/version":
			io.WriteString(w, `{"major":"1","minor":"31+"}`)
		case strings.HasSuffix(r.URL.Path, "/log"):
			io.WriteString(w, "log text")
		case r.Method == http.MethodDelete:
			w.WriteHeader(404)
			io.WriteString(w, `{"kind":"Status","reason":"NotFound","message":"gone"}`)
		default:
			io.WriteString(w, `{"kind":"Pod","metadata":{"name":"x"}}`)
		}
	})
	ctx := context.Background()
	name := PodName(testInstance, "j1")
	if _, err := c.CreatePod(ctx, map[string]any{"kind": "Pod"}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetPod(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err := c.DeletePod(ctx, name, "uid-x"); err != nil {
		t.Fatalf("deleting a Pod that is gone is no error: %v", err)
	}
	if _, err := c.PodLog(ctx, name, WorkContainer, 100); err != nil {
		t.Fatal(err)
	}
	if major, minor, err := c.ServerVersion(ctx); err != nil || major != 1 || minor != 31 {
		t.Fatalf("version %d.%d %v", major, minor, err)
	}
	want := []recorded{
		{"POST", "/api/v1/namespaces/kestrelynx-work/pods", "dryRun=All&fieldValidation=Strict", "Bearer tok-1", `{"kind":"Pod"}`},
		{"GET", "/api/v1/namespaces/kestrelynx-work/pods/" + name, "", "Bearer tok-1", ""},
		{"DELETE", "/api/v1/namespaces/kestrelynx-work/pods/" + name, "", "Bearer tok-1", ""},
		{"GET", "/api/v1/namespaces/kestrelynx-work/pods/" + name + "/log", "container=work&limitBytes=100", "Bearer tok-1", ""},
		{"GET", "/version", "", "Bearer tok-1", ""},
	}
	for i, w := range want {
		g := (*seen)[i]
		if g.method != w.method || g.path != w.path || g.query != w.query || g.auth != w.auth {
			t.Errorf("request %d = %+v, want %+v", i, g, w)
		}
	}
	var del struct {
		Preconditions struct{ UID string } `json:"preconditions"`
	}
	if err := json.Unmarshal([]byte((*seen)[2].body), &del); err != nil || del.Preconditions.UID != "uid-x" {
		t.Errorf("delete body %q", (*seen)[2].body)
	}
}

func TestClientRefusesWhatIsNotInTheTable(t *testing.T) {
	c, _, seen, _ := apiServer(t, func(w http.ResponseWriter, r *http.Request) {})
	ctx := context.Background()
	for name, call := range map[string]func() error{
		"name outside work pods": func() error { _, err := c.GetPod(ctx, "../secrets/x"); return err },
		"foreign pod name":       func() error { _, err := c.GetPod(ctx, "kube-apiserver"); return err },
		"delete without uid":     func() error { return c.DeletePod(ctx, PodName(testInstance, "j"), "") },
		"log of another container": func() error {
			_, err := c.PodLog(ctx, PodName(testInstance, "j"), "sidecar", 10)
			return err
		},
		"attach to a foreign pod": func() error { return c.AttachInput(ctx, "kube-apiserver", []byte("x")) },
	} {
		if err := call(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if len(*seen) != 0 {
		t.Errorf("requests were sent: %+v", *seen)
	}
}

func TestClientReadsTheTokenEachTime(t *testing.T) {
	c, _, seen, tok := apiServer(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{}`) })
	if _, err := c.GetPod(context.Background(), PodName(testInstance, "j")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tok, []byte("tok-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetPod(context.Background(), PodName(testInstance, "j")); err != nil {
		t.Fatal(err)
	}
	if (*seen)[0].auth != "Bearer tok-1" || (*seen)[1].auth != "Bearer tok-2" {
		t.Errorf("auth = %q %q", (*seen)[0].auth, (*seen)[1].auth)
	}
}

func TestClientErrors(t *testing.T) {
	status := 403
	body := `{"kind":"Status","reason":"Forbidden","message":"exceeded quota: work"}`
	c, _, _, _ := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		if status == 307 {
			http.Redirect(w, r, "https://elsewhere.invalid/", 307)
			return
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	})
	ctx := context.Background()
	_, err := c.CreatePod(ctx, map[string]any{}, false)
	ae, ok := err.(*APIError)
	if !ok || ae.Code != 403 || !strings.Contains(ae.Message, "exceeded quota") {
		t.Fatalf("error = %#v", err)
	}
	status = 307
	if _, err := c.GetPod(ctx, PodName(testInstance, "j")); err == nil {
		t.Error("a redirect was followed or taken as success")
	}
	status, body = 200, strings.Repeat("a", maxObjectBytes+10)
	if _, err := c.GetPod(ctx, PodName(testInstance, "j")); err == nil {
		t.Error("an oversize answer was accepted")
	}
	status, body = 200, `not json`
	if _, err := c.GetPod(ctx, PodName(testInstance, "j")); err == nil {
		t.Error("an answer that is not JSON was accepted")
	}
}

func TestClientRejectsABadServerAndNamespace(t *testing.T) {
	if _, err := New(Options{APIServer: "http://insecure.invalid", Namespace: "ns"}); err == nil {
		t.Error("a plain http API server was accepted")
	}
	if _, err := New(Options{APIServer: "https://x.invalid", Namespace: "Bad_Name"}); err == nil {
		t.Error("a bad namespace was accepted")
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if _, err := New(Options{Namespace: "ns"}); err == nil {
		t.Error("no address outside a cluster was accepted")
	}
}

func TestClientListFollowsPages(t *testing.T) {
	c, _, seen, _ := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("continue") == "" {
			io.WriteString(w, `{"metadata":{"continue":"c1"},"items":[{"a":1}]}`)
			return
		}
		io.WriteString(w, `{"metadata":{},"items":[{"a":2}]}`)
	})
	items, err := c.ListPods(context.Background(), "a=b")
	if err != nil || len(items) != 2 {
		t.Fatalf("%v %v", items, err)
	}
	if !strings.Contains((*seen)[0].query, "labelSelector=a%3Db") || !strings.Contains((*seen)[1].query, "continue=c1") {
		t.Errorf("queries %q %q", (*seen)[0].query, (*seen)[1].query)
	}
}

func TestOwnImageID(t *testing.T) {
	c, _, _, _ := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"status":{"containerStatuses":[{"name":"kestrelynx","imageID":"docker.io/x/y@sha256:`+strings.Repeat("a", 64)+`"},{"name":"side","imageID":"z"}]}}`)
	})
	id, err := c.OwnImageID(context.Background(), "kestrelynx-abc-123", "kestrelynx")
	if err != nil || !strings.HasSuffix(id, strings.Repeat("a", 64)) {
		t.Fatalf("%q %v", id, err)
	}
	if _, err := c.OwnImageID(context.Background(), "kestrelynx-abc-123", ""); err == nil {
		t.Error("an unnamed container among two was chosen")
	}
	if _, err := c.OwnImageID(context.Background(), "../x", "kestrelynx"); err == nil {
		t.Error("a bad Pod name was accepted")
	}
}

// attachServer answers the WebSocket upgrade of an attach and records the
// messages the client sends.
type attachServer struct {
	mu       sync.Mutex
	stdin    bytes.Buffer
	closed   bool
	query    string
	protocol string // chosen sub-protocol
	status   string // message sent on the error channel
	refuse   int
	// padLines headers of padBytes each are added to the upgrade response.
	padLines, padBytes int
	// stall makes the server keep the connection open and say and read
	// nothing after the upgrade; stallBeforeUpgrade does it before the response.
	stall, stallBeforeUpgrade bool
	release                   chan struct{}
}

func (a *attachServer) handler(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.query = r.URL.RawQuery
	a.mu.Unlock()
	if a.refuse != 0 {
		w.WriteHeader(a.refuse)
		io.WriteString(w, `{"kind":"Status","message":"forbidden: pods/attach"}`)
		return
	}
	hj := w.(http.Hijacker)
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if a.stallBeforeUpgrade {
		<-a.release
		return
	}
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + wsGUID)) //nolint:gosec
	io.WriteString(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: "+base64.StdEncoding.EncodeToString(sum[:])+"\r\nSec-WebSocket-Protocol: "+a.protocol+"\r\n")
	for i := 0; i < a.padLines; i++ {
		io.WriteString(rw, "X-Pad: "+strings.Repeat("a", a.padBytes)+"\r\n")
	}
	io.WriteString(rw, "\r\n")
	rw.Flush()
	if a.stall {
		<-a.release
		return
	}
	br := bufio.NewReader(rw)
	for {
		op, payload, masked, err := readClientFrame(br)
		if err != nil || !masked {
			return
		}
		if op == wsOpClose {
			return
		}
		if op != wsOpBinary || len(payload) == 0 {
			continue
		}
		a.mu.Lock()
		switch payload[0] {
		case attachChanStdin:
			a.stdin.Write(payload[1:])
		case attachChanCloseSig:
			a.closed = true
		}
		closed := a.closed
		a.mu.Unlock()
		if closed {
			writeServerFrame(rw, wsOpBinary, append([]byte{attachChanError}, a.status...))
			writeServerFrame(rw, wsOpClose, []byte{0x03, 0xE8})
			rw.Flush()
			return
		}
	}
}

func readClientFrame(br *bufio.Reader) (op byte, payload []byte, masked bool, err error) {
	var h [2]byte
	if _, err = io.ReadFull(br, h[:]); err != nil {
		return
	}
	op, masked = h[0]&0x0F, h[1]&0x80 != 0
	n := int(h[1] & 0x7F)
	switch n {
	case 126:
		var b [2]byte
		if _, err = io.ReadFull(br, b[:]); err != nil {
			return
		}
		n = int(b[0])<<8 | int(b[1])
	case 127:
		var b [8]byte
		if _, err = io.ReadFull(br, b[:]); err != nil {
			return
		}
		n = 0
		for _, x := range b {
			n = n<<8 | int(x)
		}
	}
	var mask [4]byte
	if _, err = io.ReadFull(br, mask[:]); err != nil {
		return
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(br, payload); err != nil {
		return
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return
}

func writeServerFrame(w io.Writer, op byte, payload []byte) {
	hdr := []byte{0x80 | op}
	switch n := len(payload); {
	case n < 126:
		hdr = append(hdr, byte(n))
	default:
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	}
	w.Write(append(hdr, payload...))
}

func TestAttachSendsTheInputAndClosesStdin(t *testing.T) {
	as := &attachServer{protocol: attachProtocol, status: `{"status":"Success"}`}
	c, _, _, _ := apiServer(t, as.handler)
	data := bytes.Repeat([]byte("0123456789"), 20000) // several chunks
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.AttachInput(ctx, PodName(testInstance, "j"), data); err != nil {
		t.Fatal(err)
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if !bytes.Equal(as.stdin.Bytes(), data) || !as.closed {
		t.Errorf("stdin %d bytes (want %d), closed %v", as.stdin.Len(), len(data), as.closed)
	}
	for _, want := range []string{"container=receive", "stdin=true", "stdout=false", "stderr=false", "tty=false"} {
		if !strings.Contains(as.query, want) {
			t.Errorf("query %q lacks %s", as.query, want)
		}
	}
}

func TestAttachFailures(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	t.Run("refused upgrade", func(t *testing.T) {
		as := &attachServer{refuse: 403}
		c, _, _, _ := apiServer(t, as.handler)
		err := c.AttachInput(ctx, PodName(testInstance, "j"), []byte("x"))
		if e, ok := err.(*WSStatusError); !ok || e.Code != 403 {
			t.Fatalf("error = %#v", err)
		}
	})
	t.Run("another protocol", func(t *testing.T) {
		as := &attachServer{protocol: "channel.k8s.io", status: `{"status":"Success"}`}
		c, _, _, _ := apiServer(t, as.handler)
		if err := c.AttachInput(ctx, PodName(testInstance, "j"), []byte("x")); err == nil || !strings.Contains(err.Error(), "protocol") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("failure status", func(t *testing.T) {
		as := &attachServer{protocol: attachProtocol, status: `{"status":"Failure","reason":"InternalError","message":"container not running"}`}
		c, _, _, _ := apiServer(t, as.handler)
		if err := c.AttachInput(ctx, PodName(testInstance, "j"), []byte("x")); err == nil || !strings.Contains(err.Error(), "container not running") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestAttachRefusesAnOversizeUpgradeHead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for name, as := range map[string]*attachServer{
		"many headers":    {protocol: attachProtocol, status: `{"status":"Success"}`, padLines: 200, padBytes: 200},
		"one long header": {protocol: attachProtocol, status: `{"status":"Success"}`, padLines: 1, padBytes: 6000},
	} {
		t.Run(name, func(t *testing.T) {
			c, _, _, _ := apiServer(t, as.handler)
			err := c.AttachInput(ctx, PodName(testInstance, "j"), []byte("x"))
			if err == nil || !strings.Contains(err.Error(), "upgrade response") {
				t.Fatalf("error = %v", err)
			}
			as.mu.Lock()
			defer as.mu.Unlock()
			if as.stdin.Len() != 0 {
				t.Error("input was sent over a connection with an oversize head")
			}
		})
	}
	// A head within the bound is fine.
	as := &attachServer{protocol: attachProtocol, status: `{"status":"Success"}`, padLines: 20, padBytes: 200}
	c, _, _, _ := apiServer(t, as.handler)
	if err := c.AttachInput(ctx, PodName(testInstance, "j"), []byte("x")); err != nil {
		t.Errorf("a head of 4 KB: %v", err)
	}
}

func TestAttachEndsWhenTheContextIsCancelledAndThePeerStalls(t *testing.T) {
	for name, as := range map[string]*attachServer{
		"stalled before the upgrade": {stallBeforeUpgrade: true, release: make(chan struct{})},
		"stalled after the upgrade":  {protocol: attachProtocol, stall: true, release: make(chan struct{})},
	} {
		t.Run(name, func(t *testing.T) {
			defer close(as.release)
			c, _, _, _ := apiServer(t, as.handler)
			ctx, cancel := context.WithCancel(context.Background())
			go func() { time.Sleep(300 * time.Millisecond); cancel() }()
			start := time.Now()
			err := c.AttachInput(ctx, PodName(testInstance, "j"), []byte("x"))
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, want the context's", err)
			}
			if d := time.Since(start); d > 3*time.Second {
				t.Errorf("returned after %s", d)
			}
		})
	}
}

func TestAttachUsesTheEarlierOfTheTwoDeadlines(t *testing.T) {
	as := &attachServer{protocol: attachProtocol, stall: true, release: make(chan struct{})}
	defer close(as.release)
	c, _, _, _ := apiServer(t, as.handler)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := c.AttachInput(ctx, PodName(testInstance, "j"), []byte("x")); err == nil {
		t.Fatal("no error")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("returned after %s", d)
	}
}
