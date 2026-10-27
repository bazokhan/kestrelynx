package remediation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// The integration tests of containers started with docker run take a real
// container through the plan and the Dockerfile pull request stage: the
// container is listed by the Docker adapter, scanned by the real Trivy under
// the digest of its image, compared with the real registry, and the pull
// request is written to a fake GitHub. They run only when
// KESTRELYNX_DOCKER_IT=1, against the Docker daemon, with Trivy and its
// database cached and with network access to Docker Hub. Optional settings:
//
//	KESTRELYNX_DOCKER_SOCK  the Docker socket (default /var/run/docker.sock)
//	KESTRELYNX_TRIVY_BIN    the trivy executable (default ~/.local/bin/trivy)
//	KESTRELYNX_TRIVY_CACHE  its cache directory (default ~/.cache/trivy)
//
// Every container and image they make is named krl-drun-it-<random> and is
// removed when the test ends.

const (
	drunBase       = "alpine:3.20.0"
	drunNamePrefix = "krl-drun-it-"
)

type drunEnv struct {
	ctx    context.Context
	sock   string
	trivy  scanner.Trivy
	conds  scanner.ScanConditions
	client *docker.Client
}

func drunSetup(t *testing.T) *drunEnv {
	t.Helper()
	if os.Getenv("KESTRELYNX_DOCKER_IT") != "1" {
		t.Skip("set KESTRELYNX_DOCKER_IT=1 to run containers started with docker run against a Docker daemon")
	}
	sock := os.Getenv("KESTRELYNX_DOCKER_SOCK")
	if sock == "" {
		sock = "/var/run/docker.sock"
	}
	drunSock = sock
	home, _ := os.UserHomeDir()
	bin := os.Getenv("KESTRELYNX_TRIVY_BIN")
	if bin == "" {
		bin = filepath.Join(home, ".local", "bin", "trivy")
	}
	cache := os.Getenv("KESTRELYNX_TRIVY_CACHE")
	if cache == "" {
		cache = filepath.Join(home, ".cache", "trivy")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	t.Cleanup(cancel)
	tr := scanner.Trivy{BinPath: bin, Severity: []string{"HIGH", "CRITICAL"}, CacheDir: cache, SkipDBUpdate: true, DockerHost: sock}
	conds, err := tr.CurrentConditions(ctx)
	if err != nil {
		t.Fatalf("trivy conditions: %v", err)
	}
	return &drunEnv{ctx: ctx, sock: sock, trivy: tr, conds: conds, client: docker.New(sock)}
}

func drunRandom(t *testing.T) string {
	t.Helper()
	var b [5]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b[:])
}

// drunSock is the Docker socket of the test: the adapter, Trivy and every
// docker command use it.
var drunSock string

// dockerCmd is a docker command against the socket of the test.
func dockerCmd(args ...string) *exec.Cmd {
	cmd := exec.Command("docker", args...)
	cmd.Env = append(os.Environ(), "DOCKER_HOST=unix://"+drunSock)
	return cmd
}

func dockerCLI(t *testing.T, args ...string) string {
	t.Helper()
	out, err := dockerCmd(args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// imageExists tells whether the daemon has the image. Only the daemon's answer
// that there is no such image is false; any other failure is an error.
func imageExists(ref string) (bool, error) {
	out, err := dockerCmd("image", "inspect", "--format", "{{.Id}}", ref).CombinedOutput()
	switch {
	case err == nil:
		return true, nil
	case strings.Contains(string(out), "No such image"):
		return false, nil
	}
	return false, fmt.Errorf("docker image inspect %s: %v\n%s", ref, err, out)
}

// drunSet is the containers and images one test made. When the test ends the
// containers are removed first, then every image by its ID (an image that is
// already gone, as a build in place may leave it, is not an error), and what is
// left of either is reported.
type drunSet struct {
	t          *testing.T
	containers []string
	images     []string // IDs
	tags       []string
}

func newDrunSet(t *testing.T) *drunSet {
	t.Helper()
	s := &drunSet{t: t}
	t.Cleanup(s.cleanup)
	return s
}

func (s *drunSet) cleanup() {
	t := s.t
	for _, c := range s.containers {
		if out, err := dockerCmd("rm", "-f", c).CombinedOutput(); err != nil && !strings.Contains(string(out), "No such container") {
			t.Errorf("remove container %s: %v\n%s", c, err, out)
		}
	}
	for _, ref := range append(append([]string(nil), s.images...), s.tags...) {
		if out, err := dockerCmd("rmi", "-f", ref).CombinedOutput(); err != nil && !strings.Contains(string(out), "No such image") {
			t.Errorf("remove image %s: %v\n%s", ref, err, out)
		}
	}
	for _, c := range s.containers {
		out, err := dockerCmd("ps", "-a", "-q", "--filter", "name=^"+c+"$").Output()
		if err != nil {
			t.Errorf("check for container %s: %v", c, err)
		} else if strings.TrimSpace(string(out)) != "" {
			t.Errorf("container %s is left behind", c)
		}
	}
	for _, ref := range append(append([]string(nil), s.images...), s.tags...) {
		if exists, err := imageExists(ref); err != nil {
			t.Errorf("check for image %s: %v", ref, err)
		} else if exists {
			t.Errorf("image %s is left behind", ref)
		}
	}
}

// imageID is the ID the daemon gives the image ref names; the image is removed
// by it when the test ends.
func (s *drunSet) track(ref string) string {
	s.t.Helper()
	id := dockerCLI(s.t, "image", "inspect", "--format", "{{.Id}}", ref)
	s.images = append(s.images, id)
	return id
}

// build builds the tag from a Dockerfile on the base with the marker file.
func (s *drunSet) build(tag, dockerfile, marker string) {
	s.t.Helper()
	dir := s.t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		s.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "marker.txt"), []byte(marker), 0o644); err != nil {
		s.t.Fatal(err)
	}
	dockerCLI(s.t, "build", "-q", "-t", tag, dir)
	s.tags = append(s.tags, tag)
	s.track(tag)
}

// run starts the container from the tag and keeps the image it runs.
func (s *drunSet) run(name, tag string) {
	s.t.Helper()
	s.containers = append(s.containers, name)
	dockerCLI(s.t, "run", "-d", "--name", name, tag, "sleep", "3600")
	s.images = append(s.images, dockerCLI(s.t, "inspect", "--format", "{{.Image}}", name))
}

func (e *drunEnv) observe(t *testing.T, name string) inventory.Container {
	t.Helper()
	cs, err := e.client.RunningContainers(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("container %s is not listed", name)
	return inventory.Container{}
}

// input scans the container's image as a cycle does and returns the plan input
// of the container.
func (e *drunEnv) input(t *testing.T, c inventory.Container, mayFail bool) (ImageInput, bool) {
	t.Helper()
	key, resolved := inventory.EntityKeyOf(c.Image)
	target := scanner.ScanTarget{
		Subject:  inventory.ImageSubject{Ref: c.Image.Ref, Key: key, Resolved: resolved},
		Registry: c.Image.Registry, Source: scanner.SourceLocal,
	}
	scan := e.trivy.Scan(e.ctx, target)
	// The chain of values that pins the scan to the container's image.
	t.Logf("chain: listed ImageID %v | scan target %s %v | scanned image %v | pinned %v | err %v",
		c.Image.Config, target.Subject.Ref, target.Subject.Key.Digest, scan.ScannedKey.Digest, scan.Pinned, scan.Err != nil)
	in := ImageInput{Scan: scan, Conditions: e.conds, Target: target, Services: []ServiceRef{{Container: c.Name}}}
	if scan.Err != nil || !scan.Pinned {
		if !mayFail {
			t.Fatalf("scan of %s: err %v pinned %v", c.Image.Ref, scan.Err, scan.Pinned)
		}
		return in, false
	}
	return in, true
}

func (e *drunEnv) planner(t *testing.T, gh GitHubReader, dockerfiles []DockerfileMapping) (*Planner, *registry.Client) {
	t.Helper()
	budget := registry.NewBudget(500)
	reg := registry.New(registry.Options{Budget: budget, MaxTagPages: 10})
	p, err := NewPlanner(Config{
		Registry: reg, Scanner: e.trivy, Prepared: e.conds, Budget: budget,
		Limits: Limits{MaxCandidateScans: 3, MaxBaselineRescans: 3, MaxTagPages: 10},
		GitHub: gh, Dockerfiles: dockerfiles,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p, reg
}

// TestIntegrationDockerRunContainerDockerfilePullRequest takes a container
// started with docker run to a Dockerfile pull request. In the second case the
// tag is moved to a newer build after the container was started, so the
// container keeps an image that no tag names and the listing refers to it by
// its ID. In the third the tag is built again in place, which may remove the
// old image altogether; what the daemon does decides whether it can be scanned.
func TestIntegrationDockerRunContainerDockerfilePullRequest(t *testing.T) {
	e := drunSetup(t)
	dockerCLI(t, "pull", "-q", drunBase)

	for _, mode := range []string{"tag intact", "tag moved to a newer build", "tag built again in place"} {
		t.Run(mode, func(t *testing.T) {
			id := drunRandom(t)
			cname, tag := drunNamePrefix+id, drunNamePrefix+id+":1"
			df := "FROM " + drunBase + "\nCOPY marker.txt /marker.txt\n"
			set := newDrunSet(t)
			set.build(tag, df, "first\n")
			set.run(cname, tag)
			switch mode {
			case "tag moved to a newer build":
				newer := drunNamePrefix + id + ":2"
				set.build(newer, df, "second\n")
				dockerCLI(t, "tag", newer, tag)
			case "tag built again in place":
				set.build(tag, df, "second\n")
			}

			c := e.observe(t, cname)
			if c.Workload.Known() || c.WorkloadKey() != "container/"+cname {
				t.Fatalf("container = %+v, key %q", c, c.WorkloadKey())
			}
			t.Logf("listed image reference %q, config digest %v", c.Image.Ref, c.Image.Config)
			// A build in place may remove the image the old container runs; only
			// then may the scan fail.
			gone := false
			if mode == "tag built again in place" {
				exists, err := imageExists(c.Image.Ref)
				if err != nil {
					t.Fatal(err)
				}
				gone = !exists
			}
			in, ok := e.input(t, c, gone)
			if gone {
				if ok || in.Scan.Err == nil || !strings.Contains(in.Scan.Err.Error(), "No such image") {
					t.Fatalf("the image %s is gone from the daemon, but the scan gave ok=%v err=%v", c.Image.Ref, ok, in.Scan.Err)
				}
				t.Logf("the image of the old container is gone from the daemon, so it cannot be scanned")
			} else if len(in.Scan.DiffIDs) == 0 {
				t.Fatalf("the scan reports no layer IDs: %+v", in.Scan.Subject)
			}

			h := newPRHarness(t)
			h.gh.commitFiles(testRepo, "main", map[string]string{"Dockerfile": df, "marker.txt": "x\n"})
			h.gh.humanMoved = map[string]bool{}
			mapping := DockerfileMapping{Workload: "container/" + cname, Repository: testRepo, BaseBranch: "main", Path: "Dockerfile"}
			p, reg := e.planner(t, prReader{h.gh}, []DockerfileMapping{mapping})
			plan := p.Plan(e.ctx, []ImageInput{in})
			if gone {
				if len(plan.DockerfileItems) != 0 {
					t.Errorf("Dockerfile items for an image that cannot be scanned: %+v", plan.DockerfileItems)
				}
				if n := len(h.gh.pulls(testRepo)); n != 0 {
					t.Errorf("pulls = %d", n)
				}
				return
			}

			if len(plan.DockerfileItems) != 1 {
				t.Fatalf("Dockerfile items = %d: %+v", len(plan.DockerfileItems), plan.DockerfileItems)
			}
			it := plan.DockerfileItems[0]
			if it.Category != CategoryPRCandidate || it.Candidate == nil {
				t.Fatalf("item = %s/%s (%s)", it.Category, it.Reason, it.Detail)
			}
			if len(it.Workloads) != 1 || it.Workloads[0] != "container/"+cname || it.BaseRef != drunBase {
				t.Errorf("workloads %v base %q", it.Workloads, it.BaseRef)
			}
			en := it.Entities[0]
			t.Logf("layers %+v, candidate %s, targets %d resolved %d", en.Layers, it.Candidate.Tag, it.Counts.Targets, it.Counts.Resolved)
			if en.Layers.Status != "confirmed" {
				t.Errorf("layers = %+v", en.Layers)
			}

			stage := func() PRStageResult {
				h.clock = h.clock.Add(24 * time.Hour)
				now := h.clock
				s, err := NewPRStage(PRStageConfig{GitHub: h.gh, Source: h.gh, Resolver: reg, Store: h.store, Limits: h.limits, Now: func() time.Time { return now }})
				if err != nil {
					t.Fatal(err)
				}
				return s.Run(e.ctx, PRStageInput{Plan: plan, Containers: []inventory.Container{c}})
			}
			u := onlyUnit(t, stage())
			wantStatus(t, u, PRStatusCreated, "")
			pulls := h.gh.pulls(testRepo)
			if len(pulls) != 1 {
				t.Fatalf("pulls = %d", len(pulls))
			}
			pr := pulls[0]
			if !strings.HasPrefix(pr.HeadRef, "kestrelynx/dockerfile/"+cname+"-") {
				t.Errorf("branch = %q", pr.HeadRef)
			}
			f, err := h.gh.ReadFile(e.ctx, testRepo, pr.HeadSHA, "Dockerfile")
			if err != nil || !strings.HasPrefix(string(f.Content), "FROM alpine:3.20.") || strings.HasPrefix(string(f.Content), "FROM "+drunBase+"\n") {
				t.Errorf("edited Dockerfile %q err %v", f.Content, err)
			}
			for _, want := range []string{"`container/" + cname + "`", textFor(BodyEN).SourceNote, "Layer check: `confirmed`"} {
				if !strings.Contains(pr.Body, want) {
					t.Errorf("the body lacks %q:\n%s", want, pr.Body)
				}
			}
			m, err := parsePRMarker(pr.Body)
			if err != nil || m.Kind != "dockerfile" || m.verify(testRepoID) != nil || !m.branchMatches(pr.HeadRef) {
				t.Errorf("marker %+v err %v", m, err)
			}

			// The next cycle plans the same update and opens nothing more.
			again, _ := e.input(t, e.observe(t, cname), false)
			plan = p.Plan(e.ctx, []ImageInput{again})
			writes := h.gh.writeCount()
			u2 := onlyUnit(t, stage())
			wantStatus(t, u2, PRStatusOpen, "")
			if h.gh.writeCount() != writes || len(h.gh.pulls(testRepo)) != 1 {
				t.Errorf("second cycle wrote: writes %d -> %d, pulls %d", writes, h.gh.writeCount(), len(h.gh.pulls(testRepo)))
			}
		})
	}
}
