package kubework

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

// The attach protocol over WebSocket (v5.channel.k8s.io): every message is
// one channel byte and its data. Channel 0 carries standard input, 3 the final
// status of the stream as a JSON Status object. A message on channel 255 whose
// data is the number of an input channel closes that channel, which is how the
// end of the input is told to the container (a container with stdinOnce then
// sees the end of its standard input).
const (
	attachProtocol     = "v5.channel.k8s.io"
	attachChanStdin    = 0
	attachChanError    = 3
	attachChanCloseSig = 255
)

// attachStdin connects to the container's attach endpoint, sends data to its
// standard input in chunks, closes the input and waits for the stream to end.
// Nothing the container writes is read back except the final status. A non-
// success status, a connection that ends before the input was sent, or a
// protocol other than v5 is an error.
func attachStdin(ctx context.Context, base *url.URL, token string, tlsConfig *tls.Config, namespace, pod, container string, data []byte) error {
	q := url.Values{}
	q.Set("container", container)
	q.Set("stdin", "true")
	q.Set("stdout", "false")
	q.Set("stderr", "false")
	q.Set("tty", "false")
	p := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/pods/" + url.PathEscape(pod) + "/attach?" + q.Encode()
	c, err := wsDial(ctx, base, p, token, tlsConfig, []string{attachProtocol})
	if err != nil {
		return err
	}
	defer c.close()
	// A cancelled context ends any read or write that waits on the peer.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			c.conn.Close()
		case <-done:
		}
	}()
	if c.protocol != attachProtocol {
		return fmt.Errorf("the API server chose the attach protocol %q, not %s", c.protocol, attachProtocol)
	}
	deadline := time.Now().Add(5 * time.Minute)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	// The first message on a v5 stream may be a status or nothing; reading is
	// done after the input was written, but the connection is also watched
	// for an early end by checking for a message between chunks.
	for off := 0; off < len(data); off += wsWriteChunk {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := min(off+wsWriteChunk, len(data))
		msg := append([]byte{attachChanStdin}, data[off:end]...)
		if err := c.writeBinary(deadline, msg); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("send the input: %w", err)
		}
	}
	if err := c.writeBinary(deadline, []byte{attachChanCloseSig, attachChanStdin}); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("close the input: %w", err)
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		op, msg, err := c.readMessage(deadline)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read the end of the attach stream: %w", err)
		}
		if op != wsOpBinary || len(msg) == 0 {
			continue
		}
		if msg[0] != attachChanError {
			continue
		}
		return checkAttachStatus(msg[1:])
	}
}

// checkAttachStatus reads the Status object of the error channel. An empty
// message is no news.
func checkAttachStatus(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil
	}
	var st struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("the attach stream ended with a status that cannot be read: %w", err)
	}
	if st.Status == "Success" {
		return nil
	}
	return fmt.Errorf("the attach stream ended with %s: %s", strings.ToLower(st.Reason), clip(st.Message, 200))
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
