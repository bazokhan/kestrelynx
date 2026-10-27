package notify

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMrkdwnToPlain(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"*bold*", "bold"},
		{"`code`", "code"},
		{"<https://example.com|label>", "label (https://example.com)"},
		{"<https://example.com|https://example.com>", "https://example.com"},
		{"a &amp; b &lt;c&gt;", "a & b <c>"},
		{"◆ libcurl", "◆ libcurl"},
	}
	for _, tc := range cases {
		if got := mrkdwnToPlain(tc.in); got != tc.want {
			t.Errorf("mrkdwnToPlain(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestEmailBodyContainsPackage(t *testing.T) {
	r := sampleReport()
	msgs := buildEmailMessages(Message{Report: r}, LanguageEN)
	body := emailBody(msgs)
	for _, pkg := range []string{"libc-bin", "setuptools", "e2fsprogs"} {
		if !strings.Contains(body, pkg) {
			t.Fatalf("body missing package %q:\n%s", pkg, body)
		}
	}
	subj := emailSubject(msgs)
	if !strings.Contains(subj, "KestreLynx") {
		t.Errorf("subject = %q", subj)
	}
}

func TestEmailNotifier_STARTTLS(t *testing.T) {
	srv := startTestSMTP(t, smtpModeSTARTTLS)
	defer srv.Close()

	n := EmailNotifier{
		Host: "127.0.0.1", Port: srv.Port, TLS: "starttls",
		Username: "user", Password: "pass",
		From: "kestrelynx@example.com", To: []string{"ops@example.com"},
		DialContext: srv.DialContext,
		TLSConfig:   srv.ClientTLS,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n.Send(ctx, Message{Report: sampleReport()}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := srv.Got()
	if !strings.Contains(got.Data, "kestrelynx@example.com") || !strings.Contains(got.Data, "From:") {
		t.Errorf("missing From in message:\n%s", got.Data)
	}
	if !strings.Contains(got.Data, "To: ops@example.com") {
		t.Errorf("missing To in message:\n%s", got.Data)
	}
	if !strings.Contains(got.Data, "Subject:") {
		t.Errorf("missing Subject:\n%s", got.Data)
	}
	if !strings.Contains(got.Data, "libc-bin") {
		t.Errorf("message body missing package libc-bin:\n%s", got.Data)
	}
	if got.From != "kestrelynx@example.com" {
		t.Errorf("MAIL FROM = %q", got.From)
	}
	if len(got.To) != 1 || got.To[0] != "ops@example.com" {
		t.Errorf("RCPT = %v", got.To)
	}
	if !got.UsedSTARTTLS {
		t.Error("expected STARTTLS")
	}
	if !got.Authed {
		t.Error("expected AUTH")
	}
}

func TestEmailNotifier_ImplicitTLS(t *testing.T) {
	srv := startTestSMTP(t, smtpModeImplicitTLS)
	defer srv.Close()

	n := EmailNotifier{
		Host: "127.0.0.1", Port: srv.Port, TLS: "tls",
		From: "kestrelynx@example.com", To: []string{"ops@example.com"},
		DialContext: srv.DialContext,
		TLSConfig:   srv.ClientTLS,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n.Send(ctx, Message{Report: sampleReport()}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := srv.Got()
	if !got.UsedImplicitTLS {
		t.Error("expected implicit TLS connection")
	}
	if got.UsedSTARTTLS {
		t.Error("STARTTLS should not run on implicit TLS")
	}
}

func TestEmailNotifier_RequiresSTARTTLS(t *testing.T) {
	srv := startTestSMTP(t, smtpModePlain)
	defer srv.Close()

	n := EmailNotifier{
		Host: "127.0.0.1", Port: srv.Port, TLS: "starttls",
		Username: "user", Password: "secret-password-value",
		From: "kestrelynx@example.com", To: []string{"ops@example.com"},
		DialContext: srv.DialContext,
		TLSConfig:   srv.ClientTLS,
	}
	err := n.Send(context.Background(), Message{Report: sampleReport()})
	if err == nil {
		t.Fatal("expected error when server offers no STARTTLS")
	}
	if strings.Contains(err.Error(), "secret-password-value") {
		t.Errorf("error leaked password: %v", err)
	}
	got := srv.Got()
	if got.Authed || got.Data != "" {
		t.Errorf("must fail before AUTH/DATA; got %+v", got)
	}
}

func TestEncodeSubjectNonASCII(t *testing.T) {
	got := encodeSubject("KestreLynx — スキャン結果")
	if !strings.HasPrefix(got, "=?utf-8?") && !strings.HasPrefix(got, "=?UTF-8?") {
		t.Errorf("expected RFC 2047 encoding, got %q", got)
	}
	if got := encodeSubject("KestreLynx scan results"); got != "KestreLynx scan results" {
		t.Errorf("ASCII subject should stay plain: %q", got)
	}
}

// --- test SMTP server ---

type smtpMode int

const (
	smtpModeSTARTTLS smtpMode = iota
	smtpModeImplicitTLS
	smtpModePlain
)

type smtpCapture struct {
	From           string
	To             []string
	Data           string
	UsedSTARTTLS  bool
	UsedImplicitTLS bool
	Authed         bool
}

type testSMTP struct {
	Port      int
	ClientTLS *tls.Config
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	ln     net.Listener
	server *tls.Config
	mode   smtpMode
	mu     sync.Mutex
	cap    smtpCapture
}

func (s *testSMTP) Got() smtpCapture {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cap
}

func (s *testSMTP) Close() {
	_ = s.ln.Close()
}

func startTestSMTP(t *testing.T, mode smtpMode) *testSMTP {
	t.Helper()
	cert, conf := testCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if mode == smtpModeImplicitTLS {
		ln = tls.NewListener(ln, conf)
	}
	srv := &testSMTP{
		Port:   ln.Addr().(*net.TCPAddr).Port,
		ln:     ln,
		server: conf,
		mode:   mode,
		ClientTLS: &tls.Config{
			RootCAs:            cert,
			ServerName:         "127.0.0.1",
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
		},
	}
	srv.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, ln.Addr().String())
	}
	go srv.serve()
	return srv
}

func (s *testSMTP) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *testSMTP) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if s.mode == smtpModeImplicitTLS {
		s.mu.Lock()
		s.cap.UsedImplicitTLS = true
		s.mu.Unlock()
	}
	br := bufio.NewReader(c)
	bw := bufio.NewWriter(c)
	write := func(line string) {
		fmt.Fprintf(bw, "%s\r\n", line)
		_ = bw.Flush()
	}
	write("220 localhost ESMTP test")
	startTLS := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		cmd := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(cmd, "EHLO") || strings.HasPrefix(cmd, "HELO"):
			write("250-localhost")
			if s.mode == smtpModeSTARTTLS && !startTLS {
				write("250-STARTTLS")
			}
			write("250-AUTH PLAIN LOGIN")
			write("250 OK")
		case cmd == "STARTTLS":
			if s.mode != smtpModeSTARTTLS || startTLS {
				write("502 not allowed")
				continue
			}
			write("220 ready")
			tlsConn := tls.Server(c, s.server)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			c = tlsConn
			br = bufio.NewReader(c)
			bw = bufio.NewWriter(c)
			startTLS = true
			s.mu.Lock()
			s.cap.UsedSTARTTLS = true
			s.mu.Unlock()
		case strings.HasPrefix(cmd, "AUTH"):
			s.mu.Lock()
			s.cap.Authed = true
			s.mu.Unlock()
			write("235 ok")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			addr := extractSMTPAddr(line)
			s.mu.Lock()
			s.cap.From = addr
			s.mu.Unlock()
			write("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			addr := extractSMTPAddr(line)
			s.mu.Lock()
			s.cap.To = append(s.cap.To, addr)
			s.mu.Unlock()
			write("250 ok")
		case cmd == "DATA":
			write("354 end with .")
			var data strings.Builder
			for {
				l, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" || l == ".\n" {
					break
				}
				data.WriteString(l)
			}
			s.mu.Lock()
			s.cap.Data = data.String()
			s.mu.Unlock()
			write("250 ok")
		case cmd == "QUIT":
			write("221 bye")
			return
		case cmd == "RSET":
			write("250 ok")
		case cmd == "NOOP":
			write("250 ok")
		default:
			write("502 unimplemented")
		}
	}
}

func extractSMTPAddr(line string) string {
	i := strings.Index(line, ":")
	if i < 0 {
		return ""
	}
	s := strings.TrimSpace(line[i+1:])
	s = strings.TrimPrefix(s, "<")
	s = strings.TrimSuffix(s, ">")
	return s
}

func testCert(t *testing.T) (*x509.CertPool, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	tlsCert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
	return pool, &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: tls.VersionTLS12}
}
