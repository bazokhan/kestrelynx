package kubework

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // the WebSocket handshake defines this hash; it proves nothing about security
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// A minimal WebSocket client (RFC 6455), enough for the Kubernetes attach
// protocol: one binary-message connection, masked client frames, control
// frames answered, no extensions, no compression. It exists so that the
// process needs no Kubernetes client library or WebSocket package.

const (
	wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xA

	// wsMaxFrame bounds a frame the server may send; the channel messages of
	// an attach are tiny.
	wsMaxFrame = 1 << 20
	// wsWriteChunk is the size of the binary messages the input is cut into.
	wsWriteChunk = 32 << 10
)

// wsConn is a WebSocket connection after the handshake.
type wsConn struct {
	conn     net.Conn
	br       *bufio.Reader
	protocol string
}

// wsDial opens a WebSocket to the URL path (with its query) of the API server
// at base, offering the sub-protocols, with the bearer token. The server's
// certificate is checked against tlsConfig. A response other than 101
// Switching Protocols is an error carrying the status line and the start of
// the body (a Kubernetes Status object explaining a refusal).
func wsDial(ctx context.Context, base *url.URL, pathAndQuery, token string, tlsConfig *tls.Config, protocols []string) (*wsConn, error) {
	host := base.Host
	if base.Port() == "" {
		host = net.JoinHostPort(base.Hostname(), "443")
	}
	d := &net.Dialer{Timeout: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("connect to the API server: %w", err)
	}
	cfg := tlsConfig.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName = base.Hostname()
	}
	cfg.NextProtos = []string{"http/1.1"}
	tc := tls.Client(raw, cfg)
	// The handshake and the upgrade end when the context does, whatever the
	// peer does.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			tc.Close()
		case <-stop:
		}
	}()
	if dl, ok := ctx.Deadline(); ok {
		tc.SetDeadline(dl)
	} else {
		tc.SetDeadline(time.Now().Add(30 * time.Second))
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, ctxOr(ctx, fmt.Errorf("TLS handshake with the API server: %w", err))
	}
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		tc.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	var req strings.Builder
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\nHost: %s\r\n", pathAndQuery, base.Host)
	req.WriteString("Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n")
	fmt.Fprintf(&req, "Sec-WebSocket-Key: %s\r\n", key)
	if len(protocols) > 0 {
		fmt.Fprintf(&req, "Sec-WebSocket-Protocol: %s\r\n", strings.Join(protocols, ", "))
	}
	fmt.Fprintf(&req, "Authorization: Bearer %s\r\n\r\n", token)
	if _, err := io.WriteString(tc, req.String()); err != nil {
		tc.Close()
		return nil, ctxOr(ctx, fmt.Errorf("send the upgrade request: %w", err))
	}
	br := bufio.NewReader(tc)
	head, err := readUpgradeHead(br)
	if err != nil {
		tc.Close()
		return nil, ctxOr(ctx, fmt.Errorf("read the upgrade response: %w", err))
	}
	// The body of a refusal is read from the connection through the response;
	// a successful upgrade has none, and the frames that follow are read from
	// br, which the parse below does not touch.
	resp, err := http.ReadResponse(bufio.NewReader(io.MultiReader(bytes.NewReader(head), br)), &http.Request{Method: http.MethodGet})
	if err != nil {
		tc.Close()
		return nil, ctxOr(ctx, fmt.Errorf("read the upgrade response: %w", err))
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		tc.Close()
		return nil, &WSStatusError{Code: resp.StatusCode, Body: string(body)}
	}
	sum := sha1.Sum([]byte(key + wsGUID)) //nolint:gosec // see import
	if resp.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) ||
		!strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		tc.Close()
		return nil, errors.New("the upgrade response is not a WebSocket handshake")
	}
	tc.SetDeadline(time.Time{})
	return &wsConn{conn: tc, br: br, protocol: resp.Header.Get("Sec-WebSocket-Protocol")}, nil
}

// ctxOr returns the context's error when the context has ended, since the
// failure of a connection it closed is its doing, and err otherwise.
func ctxOr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// maxUpgradeHeadBytes bounds the status line and headers of the upgrade
// response together.
const maxUpgradeHeadBytes = 16 << 10

// readUpgradeHead reads the response's status line and headers, up to the
// empty line, and refuses a response whose head is longer than
// maxUpgradeHeadBytes. Nothing after the empty line is consumed.
func readUpgradeHead(br *bufio.Reader) ([]byte, error) {
	var head []byte
	for {
		line, err := br.ReadSlice('\n')
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				return nil, errors.New("the response head has a line that is too long")
			}
			return nil, err
		}
		head = append(head, line...)
		if len(head) > maxUpgradeHeadBytes {
			return nil, fmt.Errorf("the response head is over %d bytes", maxUpgradeHeadBytes)
		}
		if len(line) == 2 && line[0] == '\r' || len(line) == 1 {
			return head, nil
		}
	}
}

// WSStatusError is a refusal of the WebSocket upgrade.
type WSStatusError struct {
	Code int
	Body string
}

func (e *WSStatusError) Error() string {
	return fmt.Sprintf("the API server refused the WebSocket upgrade with status %d: %s", e.Code, strings.TrimSpace(e.Body))
}

// readMessage returns the next complete data message. Control frames are
// handled on the way: a ping is answered, a pong dropped, a close ends the
// reading with io.EOF.
func (c *wsConn) readMessage(deadline time.Time) (opcode byte, payload []byte, err error) {
	c.conn.SetReadDeadline(deadline)
	var msg []byte
	var msgOp byte
	for {
		fin, op, data, err := c.readFrame()
		if err != nil {
			return 0, nil, err
		}
		switch op {
		case wsOpPing:
			if err := c.writeFrame(wsOpPong, data); err != nil {
				return 0, nil, err
			}
			continue
		case wsOpPong:
			continue
		case wsOpClose:
			c.writeFrame(wsOpClose, data)
			return 0, nil, io.EOF
		case wsOpText, wsOpBinary:
			if msg != nil {
				return 0, nil, errors.New("a new message began before the last one ended")
			}
			msgOp = op
			msg = append([]byte{}, data...)
		case wsOpContinuation:
			if msg == nil {
				return 0, nil, errors.New("a continuation frame has nothing to continue")
			}
			msg = append(msg, data...)
		default:
			return 0, nil, fmt.Errorf("unknown WebSocket opcode %#x", op)
		}
		if len(msg) > wsMaxFrame {
			return 0, nil, errors.New("a WebSocket message is too large")
		}
		if fin {
			return msgOp, msg, nil
		}
	}
}

func (c *wsConn) readFrame() (fin bool, op byte, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(c.br, h[:]); err != nil {
		return
	}
	fin = h[0]&0x80 != 0
	if h[0]&0x70 != 0 {
		err = errors.New("a WebSocket frame uses a reserved bit")
		return
	}
	op = h[0] & 0x0F
	if h[1]&0x80 != 0 {
		err = errors.New("the server sent a masked frame")
		return
	}
	n := uint64(h[1] & 0x7F)
	switch n {
	case 126:
		var b [2]byte
		if _, err = io.ReadFull(c.br, b[:]); err != nil {
			return
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err = io.ReadFull(c.br, b[:]); err != nil {
			return
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if n > wsMaxFrame {
		err = errors.New("a WebSocket frame is too large")
		return
	}
	if op >= 0x8 && (n > 125 || !fin) {
		err = errors.New("a control frame is malformed")
		return
	}
	payload = make([]byte, n)
	_, err = io.ReadFull(c.br, payload)
	return
}

// writeFrame sends one final, masked frame.
func (c *wsConn) writeFrame(op byte, payload []byte) error {
	var hdr []byte
	hdr = append(hdr, 0x80|op)
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, 0x80|byte(n))
	case n <= 0xFFFF:
		hdr = append(hdr, 0x80|126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 0x80|127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	hdr = append(hdr, mask[:]...)
	masked := make([]byte, n)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := c.conn.Write(append(hdr, masked...)); err != nil {
		return err
	}
	return nil
}

// writeBinary sends one binary message.
func (c *wsConn) writeBinary(deadline time.Time, payload []byte) error {
	c.conn.SetWriteDeadline(deadline)
	return c.writeFrame(wsOpBinary, payload)
}

// close sends a close frame and closes the connection.
func (c *wsConn) close() {
	c.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	c.writeFrame(wsOpClose, []byte{0x03, 0xE8})
	c.conn.Close()
}
