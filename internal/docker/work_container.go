package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// containerState tracks how far a container this client owns has progressed;
// it decides which operations are allowed on it.
type containerState int

const (
	stateCreated       containerState = iota // created, not started: input may be put
	stateStarted                             // started, not yet known to have exited
	stateExited                              // wait returned: the output may be read
	stateDeletePending                       // a delete failed; the container is not running work and must be deleted again
)

type ownedContainer struct {
	name  string
	jobID string
	state containerState
}

func (c *WorkClient) containerName(jobID string) string {
	return workNamePfx + c.cfg.InstanceID[:8] + "-" + jobID
}

func (c *WorkClient) remember(id string, oc *ownedContainer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.owned[id] = oc
}

func (c *WorkClient) forget(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.owned, id)
}

// own returns the record for id, or an error when this client neither created
// nor matched that container. Every operation on a container id goes through
// it.
func (c *WorkClient) own(id string) (*ownedContainer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	oc, ok := c.owned[id]
	if !ok {
		return nil, fmt.Errorf("container %s is not owned by this work client", shortID(id))
	}
	return oc, nil
}

func (c *WorkClient) setState(id string, s containerState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if oc, ok := c.owned[id]; ok {
		oc.state = s
	}
}

func (c *WorkClient) stateIs(id string, want containerState) error {
	oc, err := c.own(id)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if oc.state != want {
		return fmt.Errorf("container %s is in state %d, want %d", shortID(id), oc.state, want)
	}
	return nil
}

// createBody is the wire shape of POST /containers/create, restricted to the
// fields this client sets.
type createBody struct {
	Image      string            `json:"Image"`
	Entrypoint []string          `json:"Entrypoint"`
	Cmd        []string          `json:"Cmd,omitempty"`
	User       string            `json:"User"`
	WorkingDir string            `json:"WorkingDir"`
	Env        []string          `json:"Env"`
	Labels     map[string]string `json:"Labels"`
	Host       hostConfig        `json:"HostConfig"`
}

type ulimit struct {
	Name string `json:"Name"`
	Soft int64  `json:"Soft"`
	Hard int64  `json:"Hard"`
}

type hostConfig struct {
	ReadonlyRootfs  bool              `json:"ReadonlyRootfs"`
	Tmpfs           map[string]string `json:"Tmpfs"`
	CapDrop         []string          `json:"CapDrop"`
	SecurityOpt     []string          `json:"SecurityOpt"`
	Privileged      bool              `json:"Privileged"`
	PublishAllPorts bool              `json:"PublishAllPorts"`
	NetworkMode     string            `json:"NetworkMode"`
	Memory          int64             `json:"Memory"`
	MemorySwap      int64             `json:"MemorySwap"`
	NanoCpus        int64             `json:"NanoCpus"`
	PidsLimit       int64             `json:"PidsLimit"`
	Ulimits         []ulimit          `json:"Ulimits"`
	RestartPolicy   restartPolicy     `json:"RestartPolicy"`
	AutoRemove      bool              `json:"AutoRemove"`
	LogConfig       logConfig         `json:"LogConfig"`
	ShmSize         int64             `json:"ShmSize"`
}

type logConfig struct {
	Type   string            `json:"Type"`
	Config map[string]string `json:"Config"`
}

type restartPolicy struct {
	Name string `json:"Name"`
}

func tmpfsOpts(size int64, extra string) string {
	return fmt.Sprintf("rw,nosuid,nodev,size=%d,%s", size, extra)
}

func (r Resources) validate() error {
	if r.MemoryBytes <= 0 || r.NanoCPUs <= 0 || r.PidsLimit <= 0 || r.NofileLimit <= 0 ||
		r.ShmSizeBytes <= 0 || r.TmpSizeBytes <= 0 || r.HomeSizeBytes <= 0 {
		return errors.New("every work resource value must be positive")
	}
	return nil
}

// buildCreateBody generates the one container configuration this client
// creates. Only the job id and resource values vary between jobs.
func (c *WorkClient) buildCreateBody(jobID string, r Resources) createBody {
	return createBody{
		Image:      c.cfg.Image,
		Entrypoint: append([]string(nil), c.cfg.Entrypoint...),
		User:       workUser,
		WorkingDir: workDir,
		Env:        append([]string{}, c.cfg.Env...),
		Labels: map[string]string{
			labelWork:     "1",
			labelInstance: c.cfg.InstanceID,
			labelJob:      jobID,
			labelImage:    c.digest,
		},
		Host: hostConfig{
			Tmpfs: map[string]string{
				tmpMount:  tmpfsOpts(r.TmpSizeBytes, "mode=1777"),
				homeMount: tmpfsOpts(r.HomeSizeBytes, fmt.Sprintf("uid=%d,gid=%d,mode=0700", workUID, workGID)),
			},
			CapDrop:       []string{"ALL"},
			SecurityOpt:   []string{"no-new-privileges"},
			NetworkMode:   "bridge",
			Memory:        r.MemoryBytes,
			MemorySwap:    r.MemoryBytes,
			NanoCpus:      r.NanoCPUs,
			PidsLimit:     r.PidsLimit,
			Ulimits:       []ulimit{{Name: "nofile", Soft: r.NofileLimit, Hard: r.NofileLimit}},
			RestartPolicy: restartPolicy{Name: "no"},
			// A single capped log file bounds what the job can make the host
			// store through stdout.
			LogConfig: logConfig{Type: "json-file", Config: map[string]string{
				"max-size": strconv.FormatInt(c.cfg.Limits.LogMaxBytes, 10), "max-file": "1"}},
			ShmSize: r.ShmSizeBytes,
		},
	}
}

type createResponse struct {
	ID       string   `json:"Id"`
	Warnings []string `json:"Warnings"`
}

// workInspect is the part of GET /containers/{id}/json used to confirm the
// configuration the daemon actually applied.
type workInspect struct {
	ID     string `json:"Id"`
	Config struct {
		User       string            `json:"User"`
		WorkingDir string            `json:"WorkingDir"`
		Entrypoint []string          `json:"Entrypoint"`
		Labels     map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		ReadonlyRootfs  bool              `json:"ReadonlyRootfs"`
		Tmpfs           map[string]string `json:"Tmpfs"`
		CapAdd          []string          `json:"CapAdd"`
		CapDrop         []string          `json:"CapDrop"`
		SecurityOpt     []string          `json:"SecurityOpt"`
		Privileged      bool              `json:"Privileged"`
		PublishAllPorts bool              `json:"PublishAllPorts"`
		PortBindings    map[string]any    `json:"PortBindings"`
		Binds           []string          `json:"Binds"`
		Mounts          []any             `json:"Mounts"`
		Devices         []any             `json:"Devices"`
		NetworkMode     string            `json:"NetworkMode"`
		PidMode         string            `json:"PidMode"`
		IpcMode         string            `json:"IpcMode"`
		Memory          int64             `json:"Memory"`
		MemorySwap      int64             `json:"MemorySwap"`
		NanoCpus        int64             `json:"NanoCpus"`
		PidsLimit       *int64            `json:"PidsLimit"`
		Ulimits         []ulimit          `json:"Ulimits"`
		RestartPolicy   restartPolicy     `json:"RestartPolicy"`
		AutoRemove      bool              `json:"AutoRemove"`
		LogConfig       logConfig         `json:"LogConfig"`
		ShmSize         int64             `json:"ShmSize"`
	} `json:"HostConfig"`
	State struct {
		Status   string `json:"Status"`
		Running  bool   `json:"Running"`
		ExitCode int    `json:"ExitCode"`
	} `json:"State"`
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// tmpfsMatches compares option lists as sets so the daemon's ordering or
// added defaults do not matter, while a missing or different requested
// option does.
func tmpfsMatches(want, got string) bool {
	have := map[string]bool{}
	for _, o := range strings.Split(got, ",") {
		have[o] = true
	}
	for _, o := range strings.Split(want, ",") {
		if !have[o] {
			return false
		}
	}
	return true
}

// verifyInspect returns a description of every way the applied configuration
// differs from the requested one; empty means it matches.
func verifyInspect(want createBody, got workInspect) []string {
	var bad []string
	chk := func(ok bool, what string) {
		if !ok {
			bad = append(bad, what)
		}
	}
	h, w := got.HostConfig, want.Host
	chk(got.Config.User == want.User, "User")
	chk(got.Config.WorkingDir == want.WorkingDir, "WorkingDir")
	chk(slices.Equal(got.Config.Entrypoint, want.Entrypoint), "Entrypoint")
	chk(h.ReadonlyRootfs == w.ReadonlyRootfs, "ReadonlyRootfs")
	chk(len(h.Tmpfs) == len(w.Tmpfs), "Tmpfs")
	for path, opts := range w.Tmpfs {
		chk(tmpfsMatches(opts, h.Tmpfs[path]), "Tmpfs "+path)
	}
	chk(sameSet(h.CapDrop, w.CapDrop) && len(h.CapAdd) == 0, "CapDrop/CapAdd")
	nnp := false
	for _, s := range h.SecurityOpt {
		if s == "no-new-privileges" || s == "no-new-privileges:true" || s == "no-new-privileges=true" {
			nnp = true
		}
		if strings.HasPrefix(s, "seccomp=unconfined") || strings.HasPrefix(s, "apparmor=unconfined") || strings.HasPrefix(s, "seccomp:unconfined") || strings.HasPrefix(s, "apparmor:unconfined") {
			chk(false, "SecurityOpt "+s)
		}
	}
	chk(nnp, "SecurityOpt no-new-privileges")
	chk(!h.Privileged, "Privileged")
	chk(!h.PublishAllPorts && len(h.PortBindings) == 0, "ports")
	chk(len(h.Binds) == 0 && len(h.Mounts) == 0 && len(h.Devices) == 0, "Binds/Mounts/Devices")
	chk(h.NetworkMode == w.NetworkMode, "NetworkMode")
	chk(h.PidMode != "host" && !strings.HasPrefix(h.PidMode, "container:"), "PidMode")
	chk(h.IpcMode != "host" && !strings.HasPrefix(h.IpcMode, "container:"), "IpcMode")
	chk(h.Memory == w.Memory, "Memory")
	chk(h.MemorySwap == w.MemorySwap, "MemorySwap")
	chk(h.NanoCpus == w.NanoCpus, "NanoCpus")
	chk(h.PidsLimit != nil && *h.PidsLimit == w.PidsLimit, "PidsLimit")
	chk(len(h.Ulimits) == 1 && h.Ulimits[0] == w.Ulimits[0], "Ulimits")
	chk(h.RestartPolicy.Name == "no" || h.RestartPolicy.Name == "", "RestartPolicy")
	chk(!h.AutoRemove, "AutoRemove")
	chk(h.LogConfig.Type == w.LogConfig.Type && h.LogConfig.Config["max-size"] == w.LogConfig.Config["max-size"] &&
		h.LogConfig.Config["max-file"] == w.LogConfig.Config["max-file"], "LogConfig")
	chk(h.ShmSize == w.ShmSize, "ShmSize")
	for k, v := range want.Labels {
		chk(got.Config.Labels[k] == v, "Label "+k)
	}
	return bad
}

// createContainer creates the job's container, then inspects it. A
// non-empty create warning (the daemon accepted a request but could not
// apply something, such as a resource limit) or an applied configuration
// that differs from the request deletes the container and fails; nothing is
// started.
func (c *WorkClient) createContainer(ctx context.Context, jobID string, r Resources) (string, error) {
	name := c.containerName(jobID)
	body := c.buildCreateBody(jobID, r)
	raw, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("encode create body: %w", err)
	}
	octx, cancel := c.withTimeout(ctx, c.cfg.OpTimeout)
	var cr createResponse
	err = c.call(octx, containerCreateOp(name, raw), &cr, http.StatusCreated)
	cancel()
	if err != nil {
		err = fmt.Errorf("create work container: %w", err)
		var se *statusError
		if !errors.As(err, &se) {
			// The daemon may have created the container even though the
			// response never arrived (transport error, expired context,
			// unreadable body). Look it up by its deterministic name.
			if rerr := c.recoverByName(ctx, name, jobID); rerr != nil {
				err = errors.Join(err, rerr)
			}
		}
		return "", err
	}
	if !validContainerID(cr.ID) {
		err := fmt.Errorf("create work container: malformed container id %q", cr.ID)
		if rerr := c.recoverByName(ctx, name, jobID); rerr != nil {
			err = errors.Join(err, rerr)
		}
		return "", err
	}
	c.remember(cr.ID, &ownedContainer{name: name, jobID: jobID, state: stateCreated})

	fail := func(err error) (string, error) {
		if derr := c.removeContainer(ctx, cr.ID); derr != nil {
			err = errors.Join(err, derr)
		}
		return "", err
	}
	if len(cr.Warnings) > 0 {
		return fail(fmt.Errorf("create work container: daemon warnings: %s", strings.Join(cr.Warnings, "; ")))
	}
	var ins workInspect
	octx, cancel = c.withTimeout(ctx, c.cfg.OpTimeout)
	err = c.inspectOwned(octx, cr.ID, &ins)
	cancel()
	if err != nil {
		return fail(err)
	}
	if bad := verifyInspect(body, ins); len(bad) > 0 {
		return fail(fmt.Errorf("work container configuration differs from the request: %s", strings.Join(bad, ", ")))
	}
	return cr.ID, nil
}

// recoverByName handles a create whose outcome is unknown. It inspects the
// container by its deterministic name and, only when the management label,
// instance id, job id, image digest and name all match what this client would
// have created, deletes it. Anything else under that name is not ours and is
// left alone. A container that does not exist is not an error.
func (c *WorkClient) recoverByName(ctx context.Context, name, jobID string) error {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.cfg.CleanupTimeout)
	defer cancel()
	var ins struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := c.call(cctx, containerInspectByNameOp(name), &ins, http.StatusOK); err != nil {
		if hasStatus(err, http.StatusNotFound) {
			return nil
		}
		return fmt.Errorf("look up work container %s after an unconfirmed create: %w", name, err)
	}
	l := ins.Config.Labels
	if !validContainerID(ins.ID) || ins.Name != "/"+name || l[labelWork] != "1" || l[labelInstance] != c.cfg.InstanceID ||
		l[labelJob] != jobID || l[labelImage] != c.digest {
		c.log.Warn("a container with the work name exists but is not this client's; left alone", "name", name)
		return fmt.Errorf("container %s exists but does not match this client's ownership conditions", name)
	}
	c.remember(ins.ID, &ownedContainer{name: name, jobID: jobID, state: stateStarted})
	return c.removeContainer(ctx, ins.ID)
}

func (c *WorkClient) inspectOwned(ctx context.Context, id string, out *workInspect) error {
	if _, err := c.own(id); err != nil {
		return err
	}
	if err := c.call(ctx, containerInspectOp(id), out, http.StatusOK); err != nil {
		return fmt.Errorf("inspect work container: %w", err)
	}
	return nil
}

// InspectWork returns the applied configuration of a container this client
// owns.
func (c *WorkClient) InspectWork(ctx context.Context, id string) (WorkInspect, error) {
	var ins workInspect
	ctx, cancel := c.withTimeout(ctx, c.cfg.OpTimeout)
	defer cancel()
	if err := c.inspectOwned(ctx, id, &ins); err != nil {
		return WorkInspect{}, err
	}
	return WorkInspect{
		Memory: ins.HostConfig.Memory, MemorySwap: ins.HostConfig.MemorySwap,
		NanoCPUs: ins.HostConfig.NanoCpus, PidsLimit: derefInt64(ins.HostConfig.PidsLimit),
		CapDrop: ins.HostConfig.CapDrop, SecurityOpt: ins.HostConfig.SecurityOpt,
		ReadonlyRootfs: ins.HostConfig.ReadonlyRootfs, Tmpfs: ins.HostConfig.Tmpfs,
		LogMaxSize: ins.HostConfig.LogConfig.Config["max-size"], LogMaxFile: ins.HostConfig.LogConfig.Config["max-file"],
		ShmSize: ins.HostConfig.ShmSize,
		Running: ins.State.Running, ExitCode: ins.State.ExitCode,
	}, nil
}

// WorkInspect is the subset of a work container's applied configuration and
// state exposed to callers.
type WorkInspect struct {
	Memory, MemorySwap, NanoCPUs, PidsLimit, ShmSize int64
	LogMaxSize, LogMaxFile                           string
	CapDrop, SecurityOpt                             []string
	ReadonlyRootfs                                   bool
	Tmpfs                                            map[string]string
	Running                                          bool
	ExitCode                                         int
}

func derefInt64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// removeContainer kills (when it may still be running) and deletes an owned
// container. It uses a fresh context bounded by the cleanup timeout so that
// an expired or cancelled job context cannot leave the container behind. A
// container that is already gone is not an error.
func (c *WorkClient) removeContainer(ctx context.Context, id string) error {
	oc, err := c.own(id)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.cfg.CleanupTimeout)
	defer cancel()

	c.mu.Lock()
	needKill := oc.state != stateExited && oc.state != stateDeletePending
	c.mu.Unlock()
	if needKill {
		// 409: not running, 404: already gone. Both are fine.
		if err := c.call(cctx, killOp(id), nil, http.StatusNoContent, http.StatusConflict, http.StatusNotFound); err != nil {
			c.log.Warn("kill work container failed", "container", shortID(id), "err", err)
		}
	}
	if err := c.call(cctx, deleteOp(id), nil, http.StatusNoContent, http.StatusNotFound); err != nil {
		// Keep it owned but no longer "running": a later CleanupStale or
		// RunJob retries the delete instead of skipping it as a live job.
		c.setState(id, stateDeletePending)
		c.log.Error("delete work container failed", "container", shortID(id), "name", oc.name, "err", err)
		return fmt.Errorf("delete work container %s: %w", oc.name, err)
	}
	c.forget(id)
	return nil
}

type listedContainer struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Labels map[string]string `json:"Labels"`
}

// matchesWork reports whether a listed container is one this client
// instance created: the management label, instance id, job id format and the
// deterministic name must all agree, and the work image digest label must be
// well formed. The digest need not equal the current work image: containers
// left by an earlier release of the work image are still this instance's own
// and must not be stranded by an update. One matching label is never enough.
func (c *WorkClient) matchesWork(lc listedContainer) (string, bool) {
	if !validContainerID(lc.ID) {
		return "", false
	}
	l := lc.Labels
	job := l[labelJob]
	if l[labelWork] != "1" || l[labelInstance] != c.cfg.InstanceID || !digestRE.MatchString(l[labelImage]) || !jobIDRE.MatchString(job) {
		return "", false
	}
	want := "/" + c.containerName(job)
	for _, n := range lc.Names {
		if n == want {
			return job, true
		}
	}
	return "", false
}

// retryPending deletes again every owned container whose earlier delete
// failed, and returns how many it removed.
func (c *WorkClient) retryPending(ctx context.Context) (int, error) {
	c.mu.Lock()
	var ids []string
	for id, oc := range c.owned {
		if oc.state == stateDeletePending {
			ids = append(ids, id)
		}
	}
	c.mu.Unlock()
	sort.Strings(ids)
	removed := 0
	var errs []error
	for _, id := range ids {
		if err := c.removeContainer(ctx, id); err != nil {
			errs = append(errs, err)
			continue
		}
		removed++
	}
	return removed, errors.Join(errs...)
}

// CleanupStale kills and deletes work containers left by an earlier run of
// this instance (after a crash or an interrupted job). It returns how many
// it removed. Containers that match only some of the ownership conditions
// (including a missing or malformed image digest label) are left alone.
func (c *WorkClient) CleanupStale(ctx context.Context) (int, error) {
	removed, perr := c.retryPending(ctx)
	var errs []error
	if perr != nil {
		errs = append(errs, perr)
	}
	octx, cancel := c.withTimeout(ctx, c.cfg.OpTimeout)
	var list []listedContainer
	err := c.call(octx, listWorkOp(c.cfg.InstanceID), &list, http.StatusOK)
	cancel()
	if err != nil {
		return removed, errors.Join(append(errs, fmt.Errorf("list stale work containers: %w", err))...)
	}
	for _, lc := range list {
		job, ok := c.matchesWork(lc)
		if !ok {
			c.log.Warn("work container matches only some ownership conditions; left alone", "container", shortID(lc.ID), "names", lc.Names)
			continue
		}
		c.mu.Lock()
		_, mine := c.owned[lc.ID]
		c.mu.Unlock()
		if mine {
			continue // a job running in this process, not stale
		}
		c.remember(lc.ID, &ownedContainer{name: c.containerName(job), jobID: job, state: stateStarted})
		if err := c.removeContainer(ctx, lc.ID); err != nil {
			errs = append(errs, err)
			continue
		}
		removed++
	}
	return removed, errors.Join(errs...)
}
