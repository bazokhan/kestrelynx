package kubework

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// DefaultCollectInterval is how often leftover Pods are collected.
const DefaultCollectInterval = 10 * time.Minute

// Collect removes the work Pods that no job will ever remove: those of an
// earlier start of this installation (their jobs are gone with the process
// that ran them), and those of this start that have outlived any job (a
// deletion that failed, a crash between creation and deletion). A Pod whose
// labels or name do not have the shape of one this program creates is left
// alone, whatever its other labels claim. A Pod is removed on the condition
// that it still has the UID that was listed. It returns how many Pods it
// removed and the errors of the ones it could not.
func (r *Runner) Collect(ctx context.Context, now time.Time) (int, error) {
	pods, err := r.cfg.API.ListPods(ctx, r.selector())
	if err != nil {
		return 0, fmt.Errorf("list the work Pods: %w", err)
	}
	var errs []error
	removed := 0
	for _, obj := range pods {
		v, err := viewOf(obj)
		if err != nil || v.Metadata.UID == "" {
			continue
		}
		l := v.Metadata.Labels
		if !r.isOurs(v) {
			continue
		}
		stale := l[LabelSession] != r.cfg.SessionID
		if !stale {
			created, err := time.Parse(time.RFC3339, v.Metadata.CreationTimestamp)
			if err != nil || now.Sub(created) < r.maxAge() {
				continue
			}
		}
		if err := r.deletePod(v.Metadata.Name, v.Metadata.UID); err != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", v.Metadata.Name, err))
			continue
		}
		removed++
	}
	return removed, errors.Join(errs...)
}

// isOurs says whether a listed Pod has the name and labels of a work Pod of
// this installation.
func (r *Runner) isOurs(v podView) bool {
	l := v.Metadata.Labels
	return len(l) == 4 && l[LabelWork] == LabelWorkValue && l[LabelInstance] == r.cfg.InstanceID &&
		sessionRE.MatchString(l[LabelSession]) && jobRE.MatchString(l[LabelJob]) &&
		v.Metadata.Name == PodNamePrefix+r.cfg.InstanceID+"-"+l[LabelJob] && nameRE.MatchString(v.Metadata.Name)
}

// maxAge is how old a Pod of this start may be before it is collected: more
// than any job may run, with room for the deletion that should have happened.
func (r *Runner) maxAge() time.Duration {
	if r.cfg.PodMaxAge > 0 {
		return r.cfg.PodMaxAge
	}
	return 70 * time.Minute
}

// RunCollector collects once at once and then every interval until ctx ends,
// independent of any job. Errors are logged; the next round tries again.
func (r *Runner) RunCollector(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultCollectInterval
	}
	round := func() {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		n, err := r.Collect(cctx, time.Now())
		if err != nil {
			r.log().Warn("work Pods could not all be collected", "removed", n, "err", err)
		} else if n > 0 {
			r.log().Info("removed work Pods left behind", "removed", n)
		}
	}
	round()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			round()
		}
	}
}
