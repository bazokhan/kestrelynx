package registry

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"
)

// serveCustomConfig registers an image manifest tagged v1 whose config blob
// is the given body, which must name linux/amd64 to pass the platform check.
func serveCustomConfig(f *fakeRegistry, body string) {
	d := sha(body)
	f.route("/v2/team/app/blobs/"+d, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	})
	m := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"digest":%q,"size":3},"layers":[]}`, mediaOCIManifest, d)
	f.serveManifest("team/app", mediaOCIManifest, m, "v1")
}

func TestResolve_RootFSAndOnBuild(t *testing.T) {
	const d1 = "sha256:5d4427064ecc46e3c2add169e9b5eafc7ed2be7861081ec925938ab628ac0e25"
	const d2 = "sha256:146826fa3ca090520765c1cee50f779ead1662bfd94d413cff5b9ba519b23a7a"
	head := `{"os":"linux","architecture":"amd64"`
	cases := []struct {
		name    string
		body    string
		rootfs  string
		diffIDs []string
		onBuild bool
	}{
		{"layers", head + `,"rootfs":{"type":"layers","diff_ids":["` + d1 + `","` + d2 + `"]},"config":{"Cmd":["python3"]}}`, "layers", []string{d1, d2}, false},
		{"no rootfs", head + `}`, "", nil, false},
		{"empty rootfs", head + `,"rootfs":{}}`, "", nil, false},
		{"other type", head + `,"rootfs":{"type":"other","diff_ids":["` + d1 + `"]}}`, "other", []string{d1}, false},
		{"onbuild", head + `,"rootfs":{"type":"layers","diff_ids":["` + d1 + `"]},"config":{"OnBuild":["RUN make"]}}`, "layers", []string{d1}, true},
		{"empty onbuild", head + `,"config":{"OnBuild":[]}}`, "", nil, false},
		{"null onbuild", head + `,"config":{"OnBuild":null}}`, "", nil, false},
		{"null config", head + `,"config":null}`, "", nil, false},
		{"unreadable onbuild", head + `,"config":{"OnBuild":"RUN make"}}`, "", nil, true},
		{"unreadable config", head + `,"config":[1]}`, "", nil, true},
		// A malformed rootfs leaves the layers unusable; it does not fail the
		// platform resolution.
		{"malformed rootfs", head + `,"rootfs":{"type":"layers","diff_ids":"x"}}`, "", nil, false},
		{"rootfs not an object", head + `,"rootfs":7}`, "", nil, false},
	}
	for _, tc := range cases {
		f := newFakeRegistry(t)
		serveCustomConfig(f, tc.body)
		got, err := f.client(Options{}).Resolve(context.Background(), f.repo("team/app"), "v1", linuxAMD64)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got.RootFSType != tc.rootfs || !reflect.DeepEqual(got.DiffIDs, tc.diffIDs) || got.OnBuild != tc.onBuild {
			t.Errorf("%s: rootfs=%q diffIDs=%v onBuild=%v, want %q %v %v", tc.name, got.RootFSType, got.DiffIDs, got.OnBuild, tc.rootfs, tc.diffIDs, tc.onBuild)
		}
		if !got.PlatformVerified {
			t.Errorf("%s: PlatformVerified = false", tc.name)
		}
	}
}

func TestResolve_RootFSNotReadFromUnverifiedConfig(t *testing.T) {
	// A config that does not hash to the digest the manifest names is refused
	// before anything in it is used.
	f := newFakeRegistry(t)
	good := `{"os":"linux","architecture":"amd64","rootfs":{"type":"layers","diff_ids":["sha256:a"]}}`
	d := sha(good)
	f.route("/v2/team/app/blobs/"+d, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"os":"linux","architecture":"amd64","rootfs":{"type":"layers","diff_ids":["sha256:evil"]}}`)
	})
	m := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"digest":%q,"size":3},"layers":[]}`, mediaOCIManifest, d)
	f.serveManifest("team/app", mediaOCIManifest, m, "v1")
	got, err := f.client(Options{}).Resolve(context.Background(), f.repo("team/app"), "v1", linuxAMD64)
	if !errors.Is(err, ErrDigestMismatch) || got.DiffIDs != nil {
		t.Errorf("got %+v, err %v; want ErrDigestMismatch and no layers", got, err)
	}
}

func TestResolve_Env(t *testing.T) {
	head := `{"os":"linux","architecture":"amd64"`
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"env", head + `,"config":{"Env":["PATH=/usr/bin","NODE_VERSION=22.23.4"]}}`, []string{"PATH=/usr/bin", "NODE_VERSION=22.23.4"}},
		{"repeated", head + `,"config":{"Env":["A=1","A=2"]}}`, []string{"A=1", "A=2"}},
		{"no env", head + `,"config":{"Cmd":["x"]}}`, nil},
		{"null env", head + `,"config":{"Env":null}}`, nil},
		{"no config", head + `}`, nil},
		{"unreadable env", head + `,"config":{"Env":"A=1"}}`, nil},
		{"unreadable config", head + `,"config":[1]}`, nil},
	}
	for _, tc := range cases {
		f := newFakeRegistry(t)
		serveCustomConfig(f, tc.body)
		got, err := f.client(Options{}).Resolve(context.Background(), f.repo("team/app"), "v1", linuxAMD64)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !reflect.DeepEqual(got.Env, tc.want) {
			t.Errorf("%s: Env = %v, want %v", tc.name, got.Env, tc.want)
		}
	}
}
