package docker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// These tests run against a real Docker daemon and only when
// KESTRELYNX_DOCKER_IT=1. They use a busybox image pinned by digest and
// create only containers labelled with a random instance id of their own.

const itImage = "busybox@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e"

func itResources() Resources {
	return Resources{
		MemoryBytes: 64 << 20, NanoCPUs: 500_000_000, PidsLimit: 64, NofileLimit: 256, ShmSizeBytes: 4 << 20,
		TmpSizeBytes: 8 << 20, HomeSizeBytes: 8 << 20,
	}
}

func itClient(t *testing.T, script string) *WorkClient {
	t.Helper()
	if os.Getenv("KESTRELYNX_DOCKER_IT") != "1" {
		t.Skip("set KESTRELYNX_DOCKER_IT=1 to run against a real Docker daemon")
	}
	sock := os.Getenv("KESTRELYNX_DOCKER_SOCK")
	if sock == "" {
		sock = "/var/run/docker.sock"
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	c, err := NewWork(sock, WorkConfig{
		Image:          itImage,
		Entrypoint:     []string{"/bin/sh", "-c", script, "worker"},
		AllowedEnvKeys: []string{"PATH", "HOME"},
		Env:            []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/home/worker"},
		InstanceID:     hex.EncodeToString(b[:]),
		Limits:         TransferLimits{MaxInputBytes: 1 << 20, MaxInputTarBytes: 2 << 20, MaxInputFiles: 100, MaxInputPathBytes: 256, LogMaxBytes: 64 << 10, MaxStdoutBytes: 128 << 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Safety net: nothing of this instance may remain, even on failure.
		if _, err := c.CleanupStale(context.Background()); err != nil {
			t.Errorf("cleanup: %v", err)
		}
		assertNoLeftovers(t, c)
	})
	if err := c.EnsureImage(context.Background()); err != nil {
		t.Fatalf("EnsureImage: %v", err)
	}
	return c
}

func assertNoLeftovers(t *testing.T, c *WorkClient) {
	t.Helper()
	var list []listedContainer
	if err := c.call(context.Background(), listWorkOp(c.cfg.InstanceID), &list, 200); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("work containers left behind: %+v", list)
	}
}

func TestIntegrationRunJob(t *testing.T) {
	c := itClient(t, `
tr a-z A-Z < /work/in.txt
id -u
if touch /work/should-fail 2>/dev/null; then echo work-writable; else echo work-denied; fi
if mkdir /work/d 2>/dev/null; then echo work-mkdir; else echo mkdir-denied; fi
if touch /etc/should-fail 2>/dev/null; then echo etc-writable; else echo etc-denied; fi
if echo x > /home/worker/ok 2>/dev/null; then echo home-ok; else echo home-no; fi
if echo x > /tmp/ok 2>/dev/null; then echo tmp-ok; else echo tmp-no; fi
printf 'bin\001\303\251\n'
printf 'bad\377\n'
echo to-stderr >&2
`)
	res, err := c.RunJob(context.Background(), JobSpec{
		JobID:     "it-run",
		Inputs:    []InputFile{{Path: "in.txt", Content: []byte("hello\n")}, {Path: "sub/x.txt", Content: []byte("x")}},
		Timeout:   time.Minute,
		Resources: itResources(),
	})
	if err != nil {
		t.Fatalf("RunJob: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d", res.ExitCode)
	}
	want := "HELLO\n10001\nwork-denied\nmkdir-denied\netc-denied\nhome-ok\ntmp-ok\nbin\x01\u00e9\nbad\ufffd\n"
	if string(res.Stdout) != want {
		t.Errorf("stdout = %q, want %q", res.Stdout, want)
	}
	assertNoLeftovers(t, c)
}

func TestIntegrationNonZeroExit(t *testing.T) {
	c := itClient(t, `exit 7`)
	res, err := c.RunJob(context.Background(), JobSpec{JobID: "it-fail", Timeout: time.Minute, Resources: itResources()})
	if err != nil {
		t.Fatalf("RunJob: %v", err)
	}
	if res.ExitCode != 7 {
		t.Fatalf("result = %+v", res)
	}
	assertNoLeftovers(t, c)
}

func TestIntegrationLimitsAppliedAndStaleCleanup(t *testing.T) {
	c := itClient(t, `sleep 300`)
	ctx := context.Background()
	id, err := c.createContainer(ctx, "it-inspect", itResources())
	if err != nil {
		t.Fatalf("createContainer: %v", err)
	}
	ins, err := c.InspectWork(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	r := itResources()
	if ins.Memory != r.MemoryBytes || ins.MemorySwap != r.MemoryBytes || ins.PidsLimit != r.PidsLimit || ins.NanoCPUs != r.NanoCPUs {
		t.Errorf("limits not applied: %+v", ins)
	}
	if ins.ShmSize != r.ShmSizeBytes || ins.LogMaxSize != "65536" || ins.LogMaxFile != "1" {
		t.Errorf("log/shm settings: %+v", ins)
	}
	if len(ins.CapDrop) != 1 || ins.CapDrop[0] != "ALL" || ins.ReadonlyRootfs {
		t.Errorf("security settings: %+v", ins)
	}
	t.Logf("applied: %+v", ins)

	// A second client with the same instance id and image finds the container
	// by labels, name and digest, as after a crash, and removes it.
	c2, err := newWorkClient(c.baseURL, c.httpClient, c.cfg)
	if err != nil {
		t.Fatal(err)
	}
	n, err := c2.CleanupStale(ctx)
	if err != nil || n != 1 {
		t.Fatalf("CleanupStale = %d, %v", n, err)
	}
	assertNoLeftovers(t, c)
}

func TestIntegrationTimeoutKills(t *testing.T) {
	c := itClient(t, `echo partial; sleep 300`)
	start := time.Now()
	res, err := c.RunJob(context.Background(), JobSpec{JobID: "it-timeout", Timeout: 4 * time.Second, Resources: itResources()})
	if !errors.Is(err, ErrJobTimeout) {
		t.Fatalf("err = %v, want ErrJobTimeout", err)
	}
	if res.Stdout != nil || res.ExitCode != 0 {
		t.Errorf("timed-out job returned a result: %+v", res)
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("took %v", d)
	}
	assertNoLeftovers(t, c)
}

func TestIntegrationPullFailureReportsStreamError(t *testing.T) {
	c := itClient(t, `true`)
	c2, err := newWorkClient(c.baseURL, c.httpClient, WorkConfig{
		Image:      "busybox@sha256:" + strings.Repeat("0", 64),
		Entrypoint: []string{"/bin/true"}, AllowedEnvKeys: []string{"PATH"}, InstanceID: c.cfg.InstanceID, Limits: c.cfg.Limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = c2.EnsureImage(context.Background())
	if err == nil {
		t.Fatal("EnsureImage of a nonexistent digest succeeded")
	}
	t.Logf("pull error: %v", err)
}

// A job that logs more than the max-size cannot make the host store more:
// the single log file is rotated, so the client sees at most the limit, and
// only the tail of what was written (the beginning is lost).
func TestIntegrationLogCap(t *testing.T) {
	c := itClient(t, `yes 0123456789abcdef | head -c 400000`)
	res, err := c.RunJob(context.Background(), JobSpec{JobID: "it-logcap", Timeout: time.Minute, Resources: itResources()})
	if err != nil {
		t.Fatalf("RunJob: %v", err)
	}
	t.Logf("stdout bytes read back: %d (log max-size %d)", len(res.Stdout), c.cfg.Limits.LogMaxBytes)
	if int64(len(res.Stdout)) > c.cfg.Limits.LogMaxBytes {
		t.Errorf("read back %d bytes, over the log cap", len(res.Stdout))
	}
	assertNoLeftovers(t, c)
}
