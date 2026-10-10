package remediation

import "testing"

func svcFile(build string) string {
	return "services:\n  web:\n    image: example/web:1\n" + build + "  other:\n    image: nginx:1.25.3\n"
}

func TestDeriveComposeDockerfile(t *testing.T) {
	tests := []struct {
		name        string
		compose     string
		composePath string
		want        DockerfileLocation
	}{
		{"string form, file at the root", svcFile("    build: .\n"), "compose.yml", DockerfileLocation{Path: "Dockerfile"}},
		{"string form, subdirectory", svcFile("    build: ./app\n"), "compose.yml", DockerfileLocation{Path: "app/Dockerfile"}},
		{"string form relative to a nested Compose file", svcFile("    build: ../app\n"), "deploy/compose.yml", DockerfileLocation{Path: "app/Dockerfile"}},
		{"string form to the repository root from a subdirectory", svcFile("    build: ..\n"), "deploy/compose.yml", DockerfileLocation{Path: "Dockerfile"}},
		{"string form with trailing slash", svcFile("    build: app/\n"), "compose.yml", DockerfileLocation{Path: "app/Dockerfile"}},
		{"quoted string form", svcFile("    build: \"./app\"\n"), "compose.yml", DockerfileLocation{Path: "app/Dockerfile"}},
		{"long form defaults", svcFile("    build:\n      context: ./app\n"), "compose.yml", DockerfileLocation{Path: "app/Dockerfile"}},
		{"long form without context", svcFile("    build:\n      dockerfile: docker/Dockerfile.web\n"), "compose.yml", DockerfileLocation{Path: "docker/Dockerfile.web"}},
		{"long form with dockerfile and target", svcFile("    build:\n      context: app\n      dockerfile: docker/Dockerfile\n      target: runtime\n"), "deploy/compose.yml", DockerfileLocation{Path: "deploy/app/docker/Dockerfile", Target: "runtime"}},
		{"dockerfile above the context but inside the repository", svcFile("    build:\n      context: app\n      dockerfile: ../Dockerfile.shared\n"), "compose.yml", DockerfileLocation{Path: "Dockerfile.shared"}},
		{"args and labels are ignored", svcFile("    build:\n      context: .\n      args:\n        V: \"1\"\n      labels:\n        a: b\n"), "compose.yml", DockerfileLocation{Path: "Dockerfile"}},
		{"flow mapping", "services:\n  web: {build: {context: app, target: dev}}\n", "compose.yml", DockerfileLocation{Path: "app/Dockerfile", Target: "dev"}},
		{"anchored build mapping is read, not edited", "x-b: &b\n  context: app\nservices:\n  web:\n    build:\n      context: app\n", "compose.yml", DockerfileLocation{Path: "app/Dockerfile"}},
		{"CRLF and BOM", "\xef\xbb\xbfservices:\r\n  web:\r\n    build: ./app\r\n", "compose.yml", DockerfileLocation{Path: "app/Dockerfile"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, prob := DeriveComposeDockerfile([]byte(tc.compose), tc.composePath, "web")
			if prob != nil {
				t.Fatalf("problem: %v", prob)
			}
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestDeriveComposeDockerfileRefusals(t *testing.T) {
	tests := []struct {
		name    string
		compose string
		path    string
		service string
		reason  Reason
	}{
		{"no build", "services:\n  web:\n    image: nginx:1.25.3\n", "compose.yml", "web", ReasonComposeNoBuild},
		{"service missing", "services:\n  web:\n    build: .\n", "compose.yml", "api", ReasonComposeServiceMissing},
		{"no services", "name: x\n", "compose.yml", "web", ReasonComposeServiceMissing},
		{"remote https context", svcFile("    build: https://example.com/repo.git\n"), "compose.yml", "web", ReasonComposeBuildRemote},
		{"remote git ssh context", svcFile("    build: git@github.com:example/repo.git\n"), "compose.yml", "web", ReasonComposeBuildRemote},
		{"remote github shorthand", svcFile("    build: github.com/example/repo\n"), "compose.yml", "web", ReasonComposeBuildRemote},
		{"remote context in long form", svcFile("    build:\n      context: https://example.com/a.tar.gz\n"), "compose.yml", "web", ReasonComposeBuildRemote},
		{"git scheme", svcFile("    build:\n      context: git://example.com/repo\n"), "compose.yml", "web", ReasonComposeBuildRemote},
		{"dockerfile_inline", svcFile("    build:\n      context: .\n      dockerfile_inline: |\n        FROM alpine:3.19.1\n"), "compose.yml", "web", ReasonComposeBuildInline},
		{"additional_contexts", svcFile("    build:\n      context: .\n      additional_contexts:\n        base: ./base\n"), "compose.yml", "web", ReasonComposeBuildAdditional},
		{"context leaves the repository", svcFile("    build: ../app\n"), "compose.yml", "web", ReasonComposeBuildPath},
		{"context leaves the repository from a subdirectory", svcFile("    build: ../../app\n"), "deploy/compose.yml", "web", ReasonComposeBuildPath},
		{"absolute context", svcFile("    build: /srv/app\n"), "compose.yml", "web", ReasonComposeBuildPath},
		{"home context", svcFile("    build: ~/app\n"), "compose.yml", "web", ReasonComposeBuildPath},
		{"backslash context", svcFile("    build: 'app\\\\x'\n"), "compose.yml", "web", ReasonComposeBuildPath},
		{"dockerfile leaves the repository", svcFile("    build:\n      context: app\n      dockerfile: ../../Dockerfile\n"), "compose.yml", "web", ReasonComposeBuildPath},
		{"absolute dockerfile", svcFile("    build:\n      context: app\n      dockerfile: /etc/Dockerfile\n"), "compose.yml", "web", ReasonComposeBuildPath},
		{"variable in string form", svcFile("    build: ${CTX}\n"), "compose.yml", "web", ReasonComposeVariable},
		{"variable in context", svcFile("    build:\n      context: ./$DIR\n"), "compose.yml", "web", ReasonComposeVariable},
		{"variable in dockerfile", svcFile("    build:\n      context: .\n      dockerfile: Dockerfile.${ENV:-dev}\n"), "compose.yml", "web", ReasonComposeVariable},
		{"variable in target", svcFile("    build:\n      context: .\n      target: ${T}\n"), "compose.yml", "web", ReasonComposeVariable},
		{"escaped dollar still counts as a variable", svcFile("    build: ./a$$b\n"), "compose.yml", "web", ReasonComposeVariable},
		{"target not a stage name", svcFile("    build:\n      context: .\n      target: \"a b\"\n"), "compose.yml", "web", ReasonComposeBuildShape},
		{"context not a string", svcFile("    build:\n      context: 12\n"), "compose.yml", "web", ReasonComposeNotString},
		{"context a list", svcFile("    build:\n      context: [a, b]\n"), "compose.yml", "web", ReasonComposeNotString},
		{"empty string build", svcFile("    build: \"\"\n"), "compose.yml", "web", ReasonComposeBuildPath},
		{"null build", svcFile("    build:\n"), "compose.yml", "web", ReasonComposeNotString},
		{"build is a list", svcFile("    build:\n      - .\n"), "compose.yml", "web", ReasonComposeBuildShape},
		{"build is an alias", "x: &b .\nservices:\n  web:\n    build: *b\n", "compose.yml", "web", ReasonComposeAnchorAlias},
		{"merge key in build", "x: &b\n  context: .\nservices:\n  web:\n    build:\n      <<: *b\n", "compose.yml", "web", ReasonComposeMergeKey},
		{"merge key in service", "x: &s\n  build: .\nservices:\n  web:\n    <<: *s\n", "compose.yml", "web", ReasonComposeMergeKey},
		{"extends", "services:\n  web:\n    extends:\n      file: base.yml\n      service: web\n    build: .\n", "compose.yml", "web", ReasonComposeIncludeExtends},
		{"include", "include:\n  - other.yml\nservices:\n  web:\n    build: .\n", "compose.yml", "web", ReasonComposeIncludeExtends},
		{"duplicate key", "services:\n  web:\n    build: .\n    build: ./x\n", "compose.yml", "web", ReasonComposeInvalid},
		{"not YAML", "services: [\n", "compose.yml", "web", ReasonComposeInvalid},
		{"two documents", "services:\n  web:\n    build: .\n---\nservices: {}\n", "compose.yml", "web", ReasonComposeInvalid},
		{"bad compose path", "services:\n  web:\n    build: .\n", "../compose.yml", "web", ReasonComposeInvalid},
		{"empty service", "services:\n  web:\n    build: .\n", "compose.yml", "", ReasonComposeInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, prob := DeriveComposeDockerfile([]byte(tc.compose), tc.path, tc.service)
			if prob == nil {
				t.Fatalf("derived %+v", got)
			}
			if prob.Reason != tc.reason {
				t.Errorf("reason = %q (%s), want %q", prob.Reason, prob.Detail, tc.reason)
			}
			if got != (DockerfileLocation{}) {
				t.Errorf("location %+v returned with a problem", got)
			}
		})
	}
}

func TestAgreeDockerfileLocation(t *testing.T) {
	d := DockerfileLocation{Path: "app/Dockerfile", Target: "runtime"}
	for name, tc := range map[string]struct {
		explicit DockerfileLocation
		ok       bool
	}{
		"same":                   {DockerfileLocation{Path: "app/Dockerfile", Target: "runtime"}, true},
		"stage case differs":     {DockerfileLocation{Path: "app/Dockerfile", Target: "Runtime"}, true},
		"other path":             {DockerfileLocation{Path: "Dockerfile", Target: "runtime"}, false},
		"path case differs":      {DockerfileLocation{Path: "app/dockerfile", Target: "runtime"}, false},
		"other stage":            {DockerfileLocation{Path: "app/Dockerfile", Target: "build"}, false},
		"explicit omits a stage": {DockerfileLocation{Path: "app/Dockerfile"}, false},
	} {
		prob := AgreeDockerfileLocation(d, tc.explicit)
		if (prob == nil) != tc.ok {
			t.Errorf("%s: %v", name, prob)
		}
		if prob != nil && prob.Reason != ReasonDockerfileMappingDiffers {
			t.Errorf("%s: reason = %q", name, prob.Reason)
		}
	}
	if prob := AgreeDockerfileLocation(DockerfileLocation{Path: "Dockerfile"}, DockerfileLocation{Path: "Dockerfile", Target: "x"}); prob == nil {
		t.Error("derived without a stage agreed with an explicit stage")
	}
	if prob := AgreeDockerfileLocation(DockerfileLocation{Path: "Dockerfile"}, DockerfileLocation{Path: "Dockerfile"}); prob != nil {
		t.Errorf("both without a stage: %v", prob)
	}
}
