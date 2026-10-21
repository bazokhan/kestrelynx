package kubework

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/workexec"
)

// waiter follows one Pod. Every read of the Pod checks that it is the Pod that
// was created (its UID) and that it still has the form that was asked for.
type waiter struct {
	r         *Runner
	requested map[string]any
	name, uid string
	node      string
	started   bool
}

// finalState is what is read of a Pod whose work container has ended.
type finalState struct {
	workExit    int
	workImageID string
}

// pullFailures are the waiting reasons that mean an image cannot be had.
var pullFailures = map[string]bool{
	"ErrImagePull": true, "ImagePullBackOff": true, "InvalidImageName": true, "ErrImageNeverPull": true,
	"RegistryUnavailable": true,
}

// read gets the Pod and checks its identity and form.
func (w *waiter) read(ctx context.Context) (podView, error) {
	obj, err := w.r.cfg.API.GetPod(ctx, w.name)
	if err != nil {
		return podView{}, fmt.Errorf("read the Pod: %w", err)
	}
	v, err := viewOf(obj)
	if err != nil {
		return podView{}, err
	}
	if v.Metadata.UID != w.uid {
		return podView{}, errors.New("the Pod is not the one that was created (its UID changed)")
	}
	node, err := CheckPod(w.requested, obj, true, w.node)
	if err != nil {
		return podView{}, fmt.Errorf("the Pod is not the one asked for: %w", err)
	}
	w.node = node
	return v, nil
}

func (w *waiter) sameUID(ctx context.Context) error {
	_, err := w.read(ctx)
	return err
}

func (w *waiter) sleep(ctx context.Context) error {
	t := time.NewTimer(w.r.cfg.Poll)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// untilReceiveRuns waits for the receiving init container to be running, which
// is when its standard input can be attached.
func (w *waiter) untilReceiveRuns(ctx context.Context) error {
	for {
		v, err := w.read(ctx)
		if err != nil {
			if ctx.Err() != nil && !w.started {
				return unavailable(false, ReasonPodNotStarted, "the work Pod did not start in time")
			}
			return err
		}
		if c := v.container(v.Status.InitContainerStatuses, ReceiveContainer); c != nil {
			switch {
			case c.State.Running != nil:
				w.started = true
				return nil
			case c.State.Terminated != nil:
				return fmt.Errorf("the receiving container ended (%s) before the input was sent", c.State.Terminated.Reason)
			case c.State.Waiting != nil && pullFailures[c.State.Waiting.Reason]:
				return fmt.Errorf("%w: the image of the receiving container cannot be pulled (%s)", workexec.ErrImageUnavailable, c.State.Waiting.Reason)
			}
		}
		if v.Status.Phase == "Failed" || v.Status.Phase == "Succeeded" {
			return fmt.Errorf("the Pod ended (%s %s) before the input was sent", v.Status.Phase, v.Status.Reason)
		}
		if err := w.sleep(ctx); err != nil {
			if !w.started {
				return unavailable(false, ReasonPodNotStarted, "the work Pod did not start in time")
			}
			return err
		}
	}
}

// untilWorkEnds waits for the work container to end and returns what it ended
// with.
func (w *waiter) untilWorkEnds(ctx context.Context) (finalState, error) {
	for {
		v, err := w.read(ctx)
		if err != nil {
			return finalState{}, err
		}
		if c := v.container(v.Status.InitContainerStatuses, ReceiveContainer); c != nil && c.State.Terminated != nil && c.State.Terminated.ExitCode != 0 {
			return finalState{}, fmt.Errorf("the receiving container failed (%s)%s", c.State.Terminated.Reason, w.receiveStatus(ctx))
		}
		if c := v.container(v.Status.ContainerStatuses, WorkContainer); c != nil {
			switch {
			case c.State.Terminated != nil:
				return finalState{workExit: c.State.Terminated.ExitCode, workImageID: c.ImageID}, nil
			case c.State.Waiting != nil && pullFailures[c.State.Waiting.Reason]:
				return finalState{}, fmt.Errorf("%w: the image of the work container cannot be pulled (%s)", workexec.ErrImageUnavailable, c.State.Waiting.Reason)
			}
		}
		if v.Status.Phase == "Failed" && v.Status.Reason == "DeadlineExceeded" {
			return finalState{}, fmt.Errorf("%w: the Pod passed its deadline", workexec.ErrJobTimeout)
		}
		if v.Status.Phase == "Failed" || v.Status.Phase == "Succeeded" {
			if c := v.container(v.Status.ContainerStatuses, WorkContainer); c == nil || c.State.Terminated == nil {
				return finalState{}, fmt.Errorf("the Pod ended (%s %s) without the work container having run", v.Status.Phase, v.Status.Reason)
			}
		}
		if err := w.sleep(ctx); err != nil {
			return finalState{}, err
		}
	}
}

// receiveStatus adds the receiving container's status line, which is made of
// two fixed words, to an error message.
func (w *waiter) receiveStatus(ctx context.Context) string {
	b, err := w.r.cfg.API.PodLog(ctx, w.name, ReceiveContainer, 256)
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(b))
	if strings.HasPrefix(line, "KESTRELYNX-STATUS ") && len(line) <= 64 && !strings.ContainsAny(line, "\n\r") {
		return ": " + line
	}
	return ""
}
