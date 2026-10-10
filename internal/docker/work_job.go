package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"
)

// InputFile is one file placed under /work before the container starts.
// Path is relative to /work, for example "src/package.json".
type InputFile struct {
	Path    string
	Content []byte
}

// JobSpec describes one job.
type JobSpec struct {
	// JobID names the container (with the instance id) and labels it. It
	// must be unique among live jobs of this instance.
	JobID string
	// Inputs are written under /work before start.
	Inputs []InputFile
	// Timeout bounds the whole job, from container creation to deletion.
	Timeout time.Duration
	// Resources are the limits applied to the container.
	Resources Resources
}

// JobResult is what a finished job left behind. The client does not
// interpret Stdout; the job's own protocol decides what it means.
type JobResult struct {
	// ExitCode is the container's exit code.
	ExitCode int
	// Stdout is the container's standard output, exactly as logged. It is nil
	// when the job exited non-zero and its output could not be read.
	Stdout []byte
}

var (
	// ErrJobTimeout reports that the job's deadline passed; the container was
	// killed and deleted and there is no result.
	ErrJobTimeout = errors.New("work job deadline exceeded")
	// ErrCleanup wraps a failure to delete the job's container. The result,
	// if any, is still returned next to it.
	ErrCleanup = errors.New("work container cleanup failed")
)

// Input entries are owned by root and not writable by the job user (uid
// 10001), so a job can read /work but cannot grow it: the host's disk is only
// consumed through the capped log and the tmpfs mounts.
var (
	inputModeFile int64 = 0o644
	inputModeDir  int64 = 0o755
	tarMtime            = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
)

// capWriter accumulates bytes and fails as soon as the total would exceed
// max, so an oversized archive is refused while it is being built.
type capWriter struct {
	buf bytes.Buffer
	max int64
}

func (w *capWriter) Write(p []byte) (int, error) {
	if int64(w.buf.Len())+int64(len(p)) > w.max {
		return 0, fmt.Errorf("input archive is over the %d byte limit", w.max)
	}
	return w.buf.Write(p)
}

// validRelPath checks a path that must stay inside its base directory:
// non-empty, relative, clean, no "." or ".." elements, no backslash or NUL.
func validRelPath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\\x00") {
		return fmt.Errorf("path %q is empty, absolute or contains a forbidden character", p)
	}
	if path.Clean(p) != p {
		return fmt.Errorf("path %q is not clean", p)
	}
	for _, e := range strings.Split(p, "/") {
		if e == "." || e == ".." || e == "" {
			return fmt.Errorf("path %q has an invalid element", p)
		}
	}
	return nil
}

// buildInputTar builds the archive PUT at "/": a work/ directory and the
// input files below it, every entry owned by root with fixed mode and mtime. Intermediate directories are added automatically. Duplicate or
// conflicting paths are rejected.
func buildInputTar(inputs []InputFile, lim TransferLimits) ([]byte, error) {
	if len(inputs) > lim.MaxInputFiles {
		return nil, fmt.Errorf("input has %d files, over the %d file limit", len(inputs), lim.MaxInputFiles)
	}
	files := map[string][]byte{}
	dirs := map[string]bool{}
	var total int64
	for _, in := range inputs {
		if err := validRelPath(in.Path); err != nil {
			return nil, fmt.Errorf("input: %w", err)
		}
		if len(in.Path) > lim.MaxInputPathBytes {
			return nil, fmt.Errorf("input path of %d bytes is over the %d byte limit", len(in.Path), lim.MaxInputPathBytes)
		}
		if _, dup := files[in.Path]; dup {
			return nil, fmt.Errorf("input: duplicate path %q", in.Path)
		}
		total += int64(len(in.Content))
		if total > lim.MaxInputBytes {
			return nil, fmt.Errorf("input exceeds %d bytes", lim.MaxInputBytes)
		}
		files[in.Path] = in.Content
		for d := path.Dir(in.Path); d != "."; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	for f := range files {
		if dirs[f] {
			return nil, fmt.Errorf("input: %q is both a file and a directory", f)
		}
	}
	var names []string
	for d := range dirs {
		names = append(names, d)
	}
	for f := range files {
		names = append(names, f)
	}
	sort.Strings(names)

	buf := &capWriter{max: lim.MaxInputTarBytes}
	tw := tar.NewWriter(buf)
	put := func(name string, dir bool, content []byte) error {
		h := &tar.Header{Name: name, Uid: 0, Gid: 0, ModTime: tarMtime, Format: tar.FormatPAX}
		if dir {
			h.Typeflag, h.Mode, h.Name = tar.TypeDir, inputModeDir, name+"/"
		} else {
			h.Typeflag, h.Mode, h.Size = tar.TypeReg, inputModeFile, int64(len(content))
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		_, err := tw.Write(content)
		return err
	}
	if err := put("work", true, nil); err != nil {
		return nil, err
	}
	for _, n := range names {
		var err error
		if dirs[n] {
			err = put("work/"+n, true, nil)
		} else {
			err = put("work/"+n, false, files[n])
		}
		if err != nil {
			return nil, fmt.Errorf("write input tar: %w", err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("write input tar: %w", err)
	}
	return buf.buf.Bytes(), nil
}

// readLogs strictly decodes the multiplexed log stream of a container
// without a TTY: frames of an 8-byte header (stream type, three zero bytes,
// big-endian payload length) and the payload. Only stdout frames are
// accepted; any other stream type, non-zero reserved bytes, a frame cut short,
// or a total over max fails the read. raw is the unread response body.
func readLogs(raw io.Reader, max int64) ([]byte, error) {
	// Frame headers add 8 bytes per frame; bound the raw read so a stream of
	// tiny frames cannot be consumed without end.
	lr := &io.LimitedReader{R: raw, N: 9*max + 8}
	var out []byte
	var hdr [8]byte
	for {
		_, err := io.ReadFull(lr, hdr[:])
		if errors.Is(err, io.EOF) {
			break // clean end between frames
		}
		if err != nil {
			return nil, fmt.Errorf("log frame header cut short: %w", err)
		}
		if hdr[0] != 1 {
			return nil, fmt.Errorf("log frame of stream type %d; only stdout is accepted", hdr[0])
		}
		if hdr[1] != 0 || hdr[2] != 0 || hdr[3] != 0 {
			return nil, errors.New("log frame header has non-zero reserved bytes")
		}
		n := int64(binary.BigEndian.Uint32(hdr[4:]))
		if int64(len(out))+n > max {
			return nil, fmt.Errorf("stdout is over the %d byte limit", max)
		}
		start := len(out)
		out = append(out, make([]byte, n)...)
		if _, err := io.ReadFull(lr, out[start:]); err != nil {
			return nil, fmt.Errorf("log frame payload cut short: %w", err)
		}
	}
	if lr.N == 0 {
		return nil, errors.New("log stream is over the read limit")
	}
	return out, nil
}

type waitResponse struct {
	StatusCode int `json:"StatusCode"`
	Error      *struct {
		Message string `json:"Message"`
	} `json:"Error"`
}

// RunJob runs one job: create and verify the container, put the inputs,
// start, wait for exit within spec.Timeout, read the result, and delete the
// container. The container is deleted whatever happens (with its anonymous volumes). When the deadline
// passes or ctx is cancelled the container is killed and deleted and the
// call fails with no result; it never returns an empty success. If deleting
// the container fails after the job itself succeeded, RunJob returns BOTH
// the result and a non-nil error wrapping ErrCleanup; callers must check
// errors.Is(err, ErrCleanup) before discarding the result. When the job
// failed, the result is empty and any delete failure is joined into the
// returned error.
func (c *WorkClient) RunJob(ctx context.Context, spec JobSpec) (res JobResult, err error) {
	if !jobIDRE.MatchString(spec.JobID) {
		return JobResult{}, fmt.Errorf("invalid job id %q", spec.JobID)
	}
	if spec.Timeout <= 0 {
		return JobResult{}, errors.New("job timeout must be positive")
	}
	if err := spec.Resources.validate(); err != nil {
		return JobResult{}, err
	}
	input, err := buildInputTar(spec.Inputs, c.cfg.Limits)
	if err != nil {
		return JobResult{}, err
	}

	// A container whose delete failed earlier may still hold this job's name.
	if _, err := c.retryPending(ctx); err != nil {
		c.log.Warn("retrying earlier work container deletes failed", "err", err)
	}

	jctx, cancel := context.WithTimeout(ctx, spec.Timeout)
	defer cancel()

	id, err := c.createContainer(jctx, spec.JobID, spec.Resources)
	if err != nil {
		return JobResult{}, c.classify(ctx, jctx, err)
	}
	defer func() {
		if cerr := c.removeContainer(jctx, id); cerr != nil {
			err = errors.Join(err, fmt.Errorf("%w: %w", ErrCleanup, cerr))
		}
	}()

	res, err = c.runCreated(jctx, id, input)
	if err != nil {
		return JobResult{}, c.classify(ctx, jctx, err)
	}
	return res, nil
}

// classify turns an error caused by the job deadline into ErrJobTimeout and
// leaves a caller cancellation as is.
func (c *WorkClient) classify(parent, jctx context.Context, err error) error {
	if parent.Err() == nil && errors.Is(jctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", ErrJobTimeout, err)
	}
	return err
}

func (c *WorkClient) runCreated(ctx context.Context, id string, input []byte) (JobResult, error) {
	if err := c.putInput(ctx, id, input); err != nil {
		return JobResult{}, err
	}
	if err := c.stateIs(id, stateCreated); err != nil {
		return JobResult{}, err
	}
	octx, cancel := c.withTimeout(ctx, c.cfg.OpTimeout)
	err := c.call(octx, startOp(id), nil, http.StatusNoContent)
	cancel()
	if err != nil {
		return JobResult{}, fmt.Errorf("start work container: %w", err)
	}
	c.setState(id, stateStarted)

	var wr waitResponse
	if err := c.call(ctx, waitOp(id), &wr, http.StatusOK); err != nil {
		return JobResult{}, fmt.Errorf("wait for work container: %w", err)
	}
	if wr.Error != nil && wr.Error.Message != "" {
		return JobResult{}, fmt.Errorf("wait for work container: %s", wr.Error.Message)
	}
	c.setState(id, stateExited)

	stdout, err := c.getStdout(ctx, id)
	if err != nil {
		if wr.StatusCode != 0 && ctx.Err() == nil {
			// A failed job may have produced no usable output; the exit code
			// is the answer.
			c.log.Warn("no readable output from a failed work job", "container", shortID(id), "exit", wr.StatusCode, "err", err)
			return JobResult{ExitCode: wr.StatusCode}, nil
		}
		return JobResult{}, err
	}
	return JobResult{ExitCode: wr.StatusCode, Stdout: stdout}, nil
}

func (c *WorkClient) putInput(ctx context.Context, id string, input []byte) error {
	if err := c.stateIs(id, stateCreated); err != nil {
		return err
	}
	octx, cancel := c.withTimeout(ctx, c.cfg.TransferTimeout)
	defer cancel()
	if err := c.call(octx, putArchiveOp(id, input), nil, http.StatusOK); err != nil {
		return fmt.Errorf("put work input: %w", err)
	}
	return nil
}

func (c *WorkClient) getStdout(ctx context.Context, id string) ([]byte, error) {
	if err := c.stateIs(id, stateExited); err != nil {
		return nil, err
	}
	octx, cancel := c.withTimeout(ctx, c.cfg.TransferTimeout)
	defer cancel()
	op := logsOp(id)
	resp, err := c.do(octx, op)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, &statusError{op: op, status: resp.StatusCode, body: strings.TrimSpace(string(b))}
	}
	out, err := readLogs(resp.Body, c.cfg.Limits.MaxStdoutBytes)
	if err != nil {
		return nil, fmt.Errorf("work output: %w", err)
	}
	return out, nil
}
