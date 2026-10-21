//go:build unix

package runner

import (
	"io/fs"
	"strings"
	"testing"
	"time"
)

// k8sMountInfo is a work container's mount table: a read-only root, the input
// as a read-only memory volume, memory volumes for the scratch directories
// (mounted without nosuid/nodev/noexec, which a Pod cannot set), and the
// termination message file bind-mounted.
const k8sMountInfo = `1 0 8:1 / / ro,relatime - overlay overlay ro,lowerdir=x
2 1 0:5 / /proc rw,nosuid,nodev,noexec - proc proc rw
3 1 0:6 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
4 3 0:7 / /dev/shm rw,nosuid,nodev,noexec - tmpfs shm rw,size=65536k
5 1 8:1 /etc/hosts /etc/hosts rw,relatime - ext4 /dev/sda1 rw
6 1 0:20 / /tmp rw,relatime - tmpfs tmpfs rw,size=524288k
7 1 0:21 / /home/worker rw,relatime - tmpfs tmpfs rw,size=524288k
8 1 0:22 / /opt/kestrelynx-tools rw,relatime - tmpfs tmpfs rw,size=262144k
9 1 0:23 / /work ro,relatime - tmpfs tmpfs ro,size=180000k
10 1 8:1 /var/lib/kubelet/x /root/.kestrelynx-termination/work rw,relatime - ext4 /dev/sda1 rw
`

type fakeProbe struct {
	open, exists, create map[string]bool
}

func (p fakeProbe) CanOpen(s string) bool   { return p.open[s] }
func (p fakeProbe) Exists(s string) bool    { return p.exists[s] }
func (p fakeProbe) CanCreate(s string) bool { return p.create[s] }

func k8sImage() fakeFS {
	img := cleanImage()
	img["/"].children = append(img["/"].children, "work")
	img["/work"] = &fakeEntry{mode: fs.ModeDir | 0o755, uid: 10002, children: []string{"job.json", "src"}}
	img["/work/job.json"] = &fakeEntry{mode: 0o644, uid: 10002}
	img["/work/src"] = &fakeEntry{mode: fs.ModeDir | 0o755, uid: 10002}
	return img
}

func k8sCfg(t *testing.T, mounts string, fsys SelfCheckFS, probe KubernetesProbe) *SelfCheckConfig {
	t.Helper()
	cfg := checkCfg(t, mounts, fsys)
	k := DefaultKubernetesCheck()
	k.Probe = probe
	cfg.Kubernetes = k
	return cfg
}

func TestKubernetesSelfCheckAcceptsAWorkPod(t *testing.T) {
	cfg := k8sCfg(t, k8sMountInfo, k8sImage(), fakeProbe{})
	if err := cfg.selfCheck(); err != nil {
		t.Fatal(err)
	}
}

func TestKubernetesSelfCheckRefuses(t *testing.T) {
	cases := map[string]struct {
		mounts string
		mod    func(fakeFS)
		probe  fakeProbe
		want   string
	}{
		"root writable":             {strings.Replace(k8sMountInfo, "/ ro,relatime - overlay overlay ro", "/ rw,relatime - overlay overlay rw", 1), nil, fakeProbe{}, "root filesystem"},
		"work writable":             {strings.Replace(k8sMountInfo, "/work ro,relatime - tmpfs tmpfs ro,size", "/work rw,relatime - tmpfs tmpfs rw,size", 1), nil, fakeProbe{}, "/work"},
		"work not tmpfs":            {strings.Replace(k8sMountInfo, "/work ro,relatime - tmpfs tmpfs ro,size=180000k", "/work ro,relatime - ext4 /dev/sdb ro", 1), nil, fakeProbe{}, "/work"},
		"work without size":         {strings.Replace(k8sMountInfo, "ro,size=180000k", "ro", 1), nil, fakeProbe{}, "/work"},
		"extra volume":              {k8sMountInfo + "11 1 0:30 / /data rw - ext4 /dev/sdb rw\n", nil, fakeProbe{}, "unexpected mount"},
		"scratch is disk":           {strings.Replace(k8sMountInfo, "/tmp rw,relatime - tmpfs tmpfs rw,size=524288k", "/tmp rw,relatime - ext4 /dev/sdb rw", 1), nil, fakeProbe{}, "memory volume"},
		"scratch no size":           {strings.Replace(k8sMountInfo, "/tmp rw,relatime - tmpfs tmpfs rw,size=524288k", "/tmp rw,relatime - tmpfs tmpfs rw", 1), nil, fakeProbe{}, "size"},
		"termination open":          {k8sMountInfo, nil, fakeProbe{open: map[string]bool{"/root/.kestrelynx-termination/work": true}}, "termination"},
		"default termination":       {k8sMountInfo, nil, fakeProbe{exists: map[string]bool{"/dev/termination-log": true}}, "termination-log"},
		"token mounted":             {k8sMountInfo, nil, fakeProbe{exists: map[string]bool{"/var/run/secrets/kubernetes.io": true}}, "token"},
		"root creatable":            {k8sMountInfo, nil, fakeProbe{create: map[string]bool{"/.kestrelynx-selfcheck": true}}, "can be created"},
		"work creatable":            {k8sMountInfo, nil, fakeProbe{create: map[string]bool{"/work/.kestrelynx-selfcheck": true}}, "can be created"},
		"work file of the job user": {k8sMountInfo, func(f fakeFS) { f["/work/job.json"].uid = 10001 }, fakeProbe{}, "owned by uid"},
		"work file of root":         {k8sMountInfo, func(f fakeFS) { f["/work/src"].uid = 0 }, fakeProbe{}, "owned by uid"},
		"work file writable":        {k8sMountInfo, func(f fakeFS) { f["/work/job.json"].writable = true }, fakeProbe{}, "writable"},
		"work link":                 {k8sMountInfo, func(f fakeFS) { f["/work/job.json"].mode = fs.ModeSymlink | 0o777 }, fakeProbe{}, "link"},
	}
	for name, c := range cases {
		img := k8sImage()
		if c.mod != nil {
			c.mod(img)
		}
		cfg := k8sCfg(t, c.mounts, img, c.probe)
		cfg.MaxTime = time.Minute
		err := cfg.selfCheck()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, c.want)
		}
	}
}

func TestKubernetesEnvironmentHoldsThePodLayout(t *testing.T) {
	e := KubernetesEnvironment()
	if e.SelfCheck.Kubernetes == nil || e.ArchiveUID != 10002 || e.SelfCheck.UID != 10001 {
		t.Errorf("environment = %+v", e)
	}
	if k := e.SelfCheck.Kubernetes; k.WorkUID != 10002 || k.DefaultTerminationPath != "/dev/termination-log" {
		t.Errorf("check = %+v", k)
	}
}
