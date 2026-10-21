package docker

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/kitsunetrail/kestrelynx/internal/workexec"
	"io"
	"net/http"
	"strings"
)

// The job types are shared with the other executors; these names keep the
// Docker package's own vocabulary.
type (
	InputFile = workexec.InputFile
	InputKind = workexec.InputKind
	JobSpec   = workexec.JobSpec
	JobResult = workexec.JobResult
)

const (
	KindInput   = workexec.KindInput
	KindTool    = workexec.KindTool
	KindProgram = workexec.KindProgram
)

var (
	// ErrJobTimeout reports that the job's deadline passed; the container was
	// killed and deleted and there is no result.
	ErrJobTimeout = workexec.ErrJobTimeout
	// ErrCleanup wraps a failure to delete the job's container. The result,
	// if any, is still returned next to it.
	ErrCleanup = workexec.ErrCleanup
)

var tarMtime = workexec.TarMtime

// buildInputTar builds the archive PUT at "/": a work/ directory and the input
// files below it.
func buildInputTar(inputs []InputFile, lim TransferLimits) ([]byte, error) {
	return workexec.BuildInputTar(inputs, lim, "work")
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
	if err := validateResources(spec.Resources); err != nil {
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
