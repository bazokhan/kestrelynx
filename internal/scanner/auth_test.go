package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/regauth"
)

const scanPW = "ghp_scannersecretvalue"

// writeAuthProbeTrivy writes a fake trivy that records the DOCKER_CONFIG it
// was given, the config.json inside it and their permissions, whether any
// TRIVY_* variable reached it, and its arguments. With fail set it then quotes
// the password on stderr and exits 1.
func writeAuthProbeTrivy(t *testing.T, outDir, stdout string, fail bool) string {
	t.Helper()
	dir := t.TempDir()
	stdoutFile := filepath.Join(dir, "stdout.json")
	if err := os.WriteFile(stdoutFile, []byte(stdout), 0o644); err != nil {
		t.Fatal(err)
	}
	tail := fmt.Sprintf("cat %q", stdoutFile)
	if fail {
		tail = fmt.Sprintf("echo \"unauthorized: bad login %s\" >&2; exit 1", scanPW)
	}
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s' "$DOCKER_CONFIG" > %[1]q/docker_config_dir
env | grep '^TRIVY_' > %[1]q/trivy_env || : > %[1]q/trivy_env
for a in "$@"; do printf '%%s\n' "$a" >> %[1]q/args; done
if [ -n "$DOCKER_CONFIG" ]; then
  cp "$DOCKER_CONFIG/config.json" %[1]q/config.json
  stat -c '%%a' "$DOCKER_CONFIG/config.json" > %[1]q/file_mode
  stat -c '%%a' "$DOCKER_CONFIG" > %[1]q/dir_mode
  ls "$DOCKER_CONFIG" > %[1]q/dir_files
fi
%[2]s
`, outDir, tail)
	bin := filepath.Join(dir, "trivy")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func probeRead(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// fakeChallenger answers every repository with the same challenges: ch for
// the registry's /v2/ endpoint and, unless repoCh is set, for the repository.
type fakeChallenger struct {
	ch, repoCh *regauth.Challenge
	err        error
	asked      []string
}

func chal(scheme, realm string) *regauth.Challenge {
	return &regauth.Challenge{Scheme: scheme, RealmHost: realm}
}

func (f *fakeChallenger) Challenges(_ context.Context, repo string) ([]regauth.Challenge, error) {
	f.asked = append(f.asked, repo)
	if f.err != nil {
		return nil, f.err
	}
	second := f.ch
	if f.repoCh != nil {
		second = f.repoCh
	}
	return []regauth.Challenge{*f.ch, *second}, nil
}

var basicChallenge = &fakeChallenger{ch: chal("basic", "")}

func authStore(t *testing.T, hosts ...string) *regauth.Store {
	t.Helper()
	var creds []regauth.Credential
	for _, h := range hosts {
		creds = append(creds, regauth.New(h, "me", scanPW, nil))
	}
	s, err := regauth.NewStore(creds)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestScan_RegistryLoginReachesOnlyItsHost(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	for _, comparison := range []bool{false, true} {
		t.Run(fmt.Sprintf("comparison=%v", comparison), func(t *testing.T) {
			// TRIVY_PASSWORD would reach every registry; comparison mode
			// removes it, and the login must not depend on it either way.
			t.Setenv("TRIVY_PASSWORD", "ambient-must-not-matter")
			out := t.TempDir()
			target := registryTarget(t, "ghcr.io/org/app:1", "ghcr.io/org/app", digest, "linux", "amd64")
			bin := writeAuthProbeTrivy(t, out, trivyJSONRegistry("linux", "amd64", "ghcr.io/org/app@"+digest), false)
			tr := Trivy{BinPath: bin, Auth: authStore(t, "ghcr.io", "quay.io"), Challenger: &fakeChallenger{ch: chal("bearer", "ghcr.io")}}
			if comparison {
				tr.SkipDBUpdate, tr.CacheDir = true, t.TempDir()
			}
			scan := tr.Scan(context.Background(), target)
			if scan.Err != nil || !scan.Pinned {
				t.Fatalf("scan = %+v", scan)
			}
			cfgDir := probeRead(t, out, "docker_config_dir")
			if cfgDir == "" {
				t.Fatal("DOCKER_CONFIG was not set for a scan of the login's own host")
			}
			var cfg struct {
				Auths map[string]struct {
					Auth string `json:"auth"`
				} `json:"auths"`
			}
			if err := json.Unmarshal([]byte(probeRead(t, out, "config.json")), &cfg); err != nil {
				t.Fatal(err)
			}
			if len(cfg.Auths) != 1 || cfg.Auths["ghcr.io"].Auth != base64.StdEncoding.EncodeToString([]byte("me:"+scanPW)) {
				t.Errorf("config = %+v, want the login of ghcr.io alone", cfg)
			}
			if got := probeRead(t, out, "file_mode"); got != "600" {
				t.Errorf("config.json mode = %s, want 600", got)
			}
			if got := probeRead(t, out, "dir_mode"); got != "700" {
				t.Errorf("config dir mode = %s, want 700", got)
			}
			if got := probeRead(t, out, "dir_files"); got != "config.json" {
				t.Errorf("config dir holds %q", got)
			}
			if _, err := os.Stat(cfgDir); !os.IsNotExist(err) {
				t.Errorf("the config directory %s was not removed (%v)", cfgDir, err)
			}
			if strings.Contains(probeRead(t, out, "args"), scanPW) {
				t.Error("the password is on the command line")
			}
			if comparison && probeRead(t, out, "trivy_env") != "" {
				t.Errorf("TRIVY_* variables reached a comparison scan: %q", probeRead(t, out, "trivy_env"))
			}
			if probeRead(t, out, "trivy_env") != "" && strings.Contains(probeRead(t, out, "trivy_env"), scanPW) {
				t.Error("the password is in a TRIVY_* variable")
			}
		})
	}
}

func TestScan_NoLoginForOtherHostsOrLocalScans(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	t.Setenv("DOCKER_CONFIG", "") // keep the probe independent of the environment
	cases := map[string]ScanTarget{
		"another registry": registryTarget(t, "nginx:1", "docker.io/library/nginx", digest, "linux", "amd64"),
		"a lookalike host": registryTarget(t, "x:1", "ghcr.io.evil.example/org/app", digest, "linux", "amd64"),
		"local store":      pinnedTarget(t, "ghcr.io/org/app:1", "sha256:"+strings.Repeat("c", 64)),
	}
	for name, target := range cases {
		out := t.TempDir()
		bin := writeAuthProbeTrivy(t, out, trivyJSONRegistry("linux", "amd64"), false)
		Trivy{BinPath: bin, Auth: authStore(t, "ghcr.io"), Challenger: basicChallenge}.Scan(context.Background(), target)
		if cfg := probeRead(t, out, "config.json"); strings.Contains(cfg, `"auth":`) {
			t.Errorf("%s: the scan was given a login: %s", name, cfg)
		}
	}
}

func TestScan_DockerHubLoginUsesTheHubKey(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	out := t.TempDir()
	target := registryTarget(t, "acme/app:1", "docker.io/acme/app", digest, "linux", "amd64")
	bin := writeAuthProbeTrivy(t, out, trivyJSONRegistry("linux", "amd64", "docker.io/acme/app@"+digest), false)
	Trivy{BinPath: bin, Auth: authStore(t, "docker.io"), Challenger: basicChallenge}.Scan(context.Background(), target)
	if cfg := probeRead(t, out, "config.json"); !strings.Contains(cfg, `"https://index.docker.io/v1/"`) {
		t.Errorf("config = %s", cfg)
	}
}

func TestScan_FailureNeverShowsThePassword(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	out := t.TempDir()
	target := registryTarget(t, "ghcr.io/org/app:1", "ghcr.io/org/app", digest, "linux", "amd64")
	bin := writeAuthProbeTrivy(t, out, "", true)
	scan := Trivy{BinPath: bin, Auth: authStore(t, "ghcr.io"), Challenger: basicChallenge}.Scan(context.Background(), target)
	if scan.Err == nil {
		t.Fatal("expected a failure")
	}
	if strings.Contains(scan.Err.Error(), scanPW) || !strings.Contains(scan.Err.Error(), "bad login") {
		t.Errorf("err = %v", scan.Err)
	}
	if cfgDir := probeRead(t, out, "docker_config_dir"); cfgDir != "" {
		if _, err := os.Stat(cfgDir); !os.IsNotExist(err) {
			t.Errorf("the config directory %s was left behind after a failure", cfgDir)
		}
	}
}

func TestScan_LoginFollowsTheChallenge(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	target := registryTarget(t, "ghcr.io/org/app:1", "ghcr.io/org/app", digest, "linux", "amd64")
	for name, tc := range map[string]struct {
		store      *regauth.Store
		challenger AuthChallenger
		sent       bool
		note       string
	}{
		"basic":                              {authStore(t, "ghcr.io"), &fakeChallenger{ch: chal("basic", "")}, true, ""},
		"bearer, same host":                  {authStore(t, "ghcr.io"), &fakeChallenger{ch: chal("bearer", "ghcr.io")}, true, ""},
		"bearer, listed host":                {tokenHostStore(t), &fakeChallenger{ch: chal("bearer", "auth.example.com")}, true, ""},
		"bearer, foreign host":               {authStore(t, "ghcr.io"), &fakeChallenger{ch: chal("bearer", "evil.example.org")}, false, "token_hosts"},
		"no login needed":                    {authStore(t, "ghcr.io"), &fakeChallenger{ch: chal("none", "")}, false, "without a login"},
		"unsupported scheme":                 {authStore(t, "ghcr.io"), &fakeChallenger{ch: chal("other", "")}, false, "not supported"},
		"challenge not readable":             {authStore(t, "ghcr.io"), &fakeChallenger{err: errors.New("connection refused")}, false, "could not be read"},
		"/v2/ names a foreign token service": {authStore(t, "ghcr.io"), &fakeChallenger{ch: chal("bearer", "evil.example.org"), repoCh: chal("bearer", "ghcr.io")}, false, "token_hosts"},
		"repository names a foreign one":     {authStore(t, "ghcr.io"), &fakeChallenger{ch: chal("bearer", "ghcr.io"), repoCh: chal("bearer", "evil.example.org")}, false, "token_hosts"},
		"no challenger configured":           {authStore(t, "ghcr.io"), nil, false, "no way to check"},
	} {
		out := t.TempDir()
		bin := writeAuthProbeTrivy(t, out, "", true) // fails, so that the note shows
		tr := Trivy{BinPath: bin, Auth: tc.store}
		if tc.challenger != nil {
			tr.Challenger = tc.challenger
		}
		scan := tr.Scan(context.Background(), target)
		gotSent := strings.Contains(probeRead(t, out, "config.json"), `"auth":`)
		if gotSent != tc.sent {
			t.Errorf("%s: login passed on = %v, want %v", name, gotSent, tc.sent)
		}
		if scan.Err == nil {
			t.Fatalf("%s: expected the fake trivy's failure", name)
		}
		hasNote := strings.Contains(scan.Err.Error(), "registry login was not passed on")
		if hasNote != !tc.sent || (tc.note != "" && !strings.Contains(scan.Err.Error(), tc.note)) {
			t.Errorf("%s: err = %v", name, scan.Err)
		}
		if strings.Contains(scan.Err.Error(), scanPW) {
			t.Errorf("%s: the error shows the password: %v", name, scan.Err)
		}
	}
}

func tokenHostStore(t *testing.T) *regauth.Store {
	t.Helper()
	s, err := regauth.NewStore([]regauth.Credential{regauth.New("ghcr.io", "me", scanPW, []string{"auth.example.com"})})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestScan_ChallengeIsAskedForTheTargetRepositoryOnly(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	ch := &fakeChallenger{ch: chal("basic", "")}
	for _, target := range []ScanTarget{
		registryTarget(t, "nginx:1", "docker.io/library/nginx", digest, "linux", "amd64"),
		pinnedTarget(t, "ghcr.io/org/app:1", "sha256:"+strings.Repeat("c", 64)),
	} {
		out := t.TempDir()
		Trivy{BinPath: writeAuthProbeTrivy(t, out, trivyJSONRegistry("linux", "amd64"), false), Auth: authStore(t, "ghcr.io"), Challenger: ch}.Scan(context.Background(), target)
	}
	if len(ch.asked) != 0 {
		t.Errorf("the registry was asked about %v, though no login applied", ch.asked)
	}
}

func TestScan_FailureTextHoldsNoEncodedLogin(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	target := registryTarget(t, "ghcr.io/org/app:1", "ghcr.io/org/app", digest, "linux", "amd64")
	pair := base64.StdEncoding.EncodeToString([]byte("me:" + scanPW))
	dir := t.TempDir()
	bin := filepath.Join(dir, "trivy")
	script := "#!/bin/sh\necho 'GET failed: Authorization: Basic " + pair + " and auth=" + pair + " and Bearer abc.def.ghi' >&2\nexit 1\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	scan := Trivy{BinPath: bin, Auth: authStore(t, "ghcr.io"), Challenger: basicChallenge}.Scan(context.Background(), target)
	if scan.Err == nil {
		t.Fatal("expected a failure")
	}
	for _, leak := range []string{pair, scanPW, "abc.def.ghi"} {
		if strings.Contains(scan.Err.Error(), leak) {
			t.Errorf("error shows %q: %v", leak, scan.Err)
		}
	}
	if !strings.Contains(scan.Err.Error(), "GET failed") {
		t.Errorf("the rest of the message should stay: %v", scan.Err)
	}
}

// A scan that is not given a login still gets a Docker config directory of
// its own with no logins, so the login of whoever runs the program is unused.
func TestScan_NoLoginScanUsesAnEmptyDockerConfig(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".docker"), 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(home, ".docker", "config.json"), []byte(`{"auths":{"quay.io":{"auth":"c2VjcmV0"}}}`), 0o600)
	t.Setenv("HOME", home)
	t.Setenv("DOCKER_CONFIG", filepath.Join(home, ".docker"))
	for name, tr := range map[string]Trivy{
		"no store":       {},
		"other host":     {Auth: authStore(t, "ghcr.io"), Challenger: basicChallenge},
		"login withheld": {Auth: authStore(t, "quay.io"), Challenger: &fakeChallenger{ch: chal("bearer", "evil.example.org")}},
	} {
		out := t.TempDir()
		tr.BinPath = writeAuthProbeTrivy(t, out, trivyJSONRegistry("linux", "amd64"), false)
		target := registryTarget(t, "quay.io/org/app:1", "quay.io/org/app", digest, "linux", "amd64")
		if name == "other host" {
			target = registryTarget(t, "docker.io/org/app:1", "docker.io/org/app", digest, "linux", "amd64")
		}
		tr.Scan(context.Background(), target)
		dir := probeRead(t, out, "docker_config_dir")
		if dir == "" || dir == filepath.Join(home, ".docker") {
			t.Errorf("%s: DOCKER_CONFIG = %q; want a directory of the scan's own", name, dir)
			continue
		}
		if cfg := probeRead(t, out, "config.json"); strings.Contains(cfg, "c2VjcmV0") || strings.Contains(cfg, "quay.io") {
			t.Errorf("%s: config = %s", name, cfg)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("%s: %s was not removed", name, dir)
		}
	}
}

func TestParseReport_ComposeLabels(t *testing.T) {
	report := func(labels string) []byte {
		return []byte(`{"ArtifactName":"x","Metadata":{"ImageConfig":{"os":"linux","architecture":"amd64","config":{"Labels":` + labels + `}}},"Results":[]}`)
	}
	scan, err := ParseReport(report(`{"com.docker.compose.project":"kltest","com.docker.compose.service":"app","maintainer":"x"}`))
	if err != nil || scan.ComposeProject != "kltest" || scan.ComposeService != "app" {
		t.Errorf("scan = %q %q, %v", scan.ComposeProject, scan.ComposeService, err)
	}
	for _, l := range []string{`null`, `{}`, `{"maintainer":"x"}`} {
		scan, err = ParseReport(report(l))
		if err != nil || scan.ComposeProject != "" || scan.ComposeService != "" {
			t.Errorf("%s: %q %q %v", l, scan.ComposeProject, scan.ComposeService, err)
		}
	}
	long := strings.Repeat("a", 300)
	if scan, _ = ParseReport(report(`{"com.docker.compose.project":"` + long + `"}`)); scan.ComposeProject != "" {
		t.Error("an oversized label must be ignored")
	}
	scan, err = ParseReport([]byte(`{"ArtifactName":"x","Metadata":{},"Results":[]}`))
	if err != nil || scan.ComposeProject != "" {
		t.Errorf("no image config: %v", err)
	}
}
