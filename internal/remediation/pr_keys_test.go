package remediation

import (
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/github"
)

func TestTargetKeySetOrderAndCollisions(t *testing.T) {
	a := TargetKey(1, "main", "compose.yml", []string{"services.web.image", "services.worker.image"})
	b := TargetKey(1, "main", "compose.yml", []string{"services.worker.image", "services.web.image"})
	if a != b {
		t.Error("location order changes the target key")
	}
	others := []string{
		TargetKey(1, "main", "compose.yml", []string{"services.web.image"}),
		TargetKey(2, "main", "compose.yml", []string{"services.web.image", "services.worker.image"}),
		TargetKey(1, "dev", "compose.yml", []string{"services.web.image", "services.worker.image"}),
		TargetKey(1, "main", "other.yml", []string{"services.web.image", "services.worker.image"}),
		// A separator inside a name must not make two sets collide.
		TargetKey(1, "main", "compose.yml", []string{"services.web.image\",\"services.worker.image"}),
	}
	seen := map[string]bool{a: true}
	for i, k := range others {
		if seen[k] {
			t.Errorf("key %d collides", i)
		}
		seen[k] = true
	}
	if len(a) != 64 {
		t.Errorf("key %q is not hex SHA-256", a)
	}
}

func TestUpdateAndAttemptKeys(t *testing.T) {
	tk := TargetKey(1, "main", "compose.yml", []string{"services.web.image"})
	u1 := UpdateKey(tk, "nginx:1.25.3", "1.25.4", topDigest('1'))
	if u1 != UpdateKey(tk, "docker.io/library/nginx:1.25.3", "1.25.4", topDigest('1')) {
		t.Error("two spellings of the same reference give different update keys")
	}
	if u1 == UpdateKey(tk, "nginx:1.25.3", "1.25.4", topDigest('2')) || u1 == UpdateKey(tk, "nginx:1.25.3", "1.25.5", topDigest('1')) {
		t.Error("another candidate gives the same update key")
	}
	ch := []FileChange{{Path: "compose.yml", Mode: "100644", BlobSHA: hex40('b')}}
	a1 := AttemptKey(u1, hex40('1'), hex40('a'), ch)
	a2 := AttemptKey(u1, hex40('2'), hex40('a'), ch)
	if a1 == a2 {
		t.Error("a new base gives the same attempt key")
	}
	if a1 != AttemptKey(u1, hex40('1'), hex40('a'), []FileChange{{Path: "compose.yml", Mode: "100755", BlobSHA: hex40('b')}}) {
		t.Error("the mode, copied from the base, changes the attempt key")
	}
	two := []FileChange{{Path: "b", BlobSHA: hex40('1')}, {Path: "a", BlobSHA: hex40('2')}}
	rev := []FileChange{two[1], two[0]}
	if AttemptKey(u1, hex40('1'), hex40('a'), two) != AttemptKey(u1, hex40('1'), hex40('a'), rev) {
		t.Error("change order changes the attempt key")
	}
}

func TestBranchName(t *testing.T) {
	key := strings.Repeat("ab", 32)
	b, err := BranchName([]string{"worker", "Web_UI"}, "1.25.4", key)
	if err != nil || b != "kestrelynx/compose/web-ui-and-1-1.25.4-abababababab" {
		t.Errorf("branch = %q, %v", b, err)
	}
	b, err = BranchName([]string{strings.Repeat("x", 400)}, "v1.2.3-bookworm", key)
	if err != nil || len(b) > 255 || !strings.HasSuffix(b, "-v1.2.3-bookworm-abababababab") || !github.ValidBranch(b) {
		t.Errorf("long display: %q (%d), %v", b, len(b), err)
	}
	b, err = BranchName([]string{"!!!"}, "1..2", key)
	if err != nil || b != "kestrelynx/compose/service-1.2-abababababab" {
		t.Errorf("unsafe parts: %q, %v", b, err)
	}
	if _, err := BranchName([]string{"web"}, "1.0.0", "short"); err == nil {
		t.Error("a short attempt key was accepted")
	}
}

func TestComposeUnitTitle(t *testing.T) {
	if got := composeUnitTitle("nginx", "1.25.4", "deploy/compose.yml"); got != "Update nginx to 1.25.4 in deploy/compose.yml" {
		t.Errorf("title = %q", got)
	}
	if got := composeUnitTitle("a\nb", "1", "p"); strings.ContainsAny(got, "\n\r") {
		t.Errorf("control character kept: %q", got)
	}
}
