package inventory

import "testing"

func TestRuntimeVersionEnv(t *testing.T) {
	for eco, want := range map[Ecosystem]string{
		EcosystemNodeRuntime: "NODE_VERSION", EcosystemPythonRuntime: "PYTHON_VERSION", EcosystemNpm: "", EcosystemPip: "", "": "",
	} {
		if got := RuntimeVersionEnv(eco); got != want {
			t.Errorf("RuntimeVersionEnv(%q) = %q, want %q", eco, got, want)
		}
	}
}
