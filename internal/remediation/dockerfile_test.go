package remediation

import (
	"reflect"
	"strings"
	"testing"
)

func mustParseDockerfile(t *testing.T, src string) *Dockerfile {
	t.Helper()
	d, prob := ParseDockerfile([]byte(src))
	if prob != nil {
		t.Fatalf("ParseDockerfile: %v", prob)
	}
	return d
}

func TestParseDockerfileStages(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []DockerfileStage // Index, Name, Image, Platform, Line, OnBuild
	}{
		{"single", "FROM python:3.12.3-slim\nRUN true\n",
			[]DockerfileStage{{Index: 0, Image: "python:3.12.3-slim", Line: 1}}},
		{"lower case keywords and AS", "from golang:1.22.1 as Build\nfrom alpine:3.19.1\n",
			[]DockerfileStage{{Index: 0, Name: "Build", Image: "golang:1.22.1", Line: 1}, {Index: 1, Image: "alpine:3.19.1", Line: 2}}},
		{"platform flag", "FROM --platform=linux/amd64 node:20.11.1 AS web\n",
			[]DockerfileStage{{Name: "web", Image: "node:20.11.1", Platform: "linux/amd64", Line: 1}}},
		{"platform flag upper case", "FROM --PLATFORM=linux/arm64 node:20.11.1\n",
			[]DockerfileStage{{Image: "node:20.11.1", Platform: "linux/arm64", Line: 1}}},
		{"comments and blank lines", "# a comment\n\n   # indented\nFROM a:1.2.3\n\n# FROM b:9.9.9\nFROM c:4.5.6\n",
			[]DockerfileStage{{Image: "a:1.2.3", Line: 4}, {Index: 1, Image: "c:4.5.6", Line: 7}}},
		{"leading whitespace before keyword", "  \tFROM a:1.2.3\n",
			[]DockerfileStage{{Image: "a:1.2.3", Line: 1}}},
		{"continuation inside FROM", "FROM \\\n  --platform=linux/amd64 \\\n  a:1.2.3 \\\n  AS x\n",
			[]DockerfileStage{{Name: "x", Image: "a:1.2.3", Platform: "linux/amd64", Line: 1}}},
		{"continuation with trailing space after backslash", "FROM a:1.2.3 \\ \n AS x\nRUN true\n",
			[]DockerfileStage{{Name: "x", Image: "a:1.2.3", Line: 1}}},
		{"comment line inside a continuation", "RUN echo a \\\n# FROM nope:1.1.1\n  && echo b\nFROM a:1.2.3\n",
			[]DockerfileStage{{Image: "a:1.2.3", Line: 4}}},
		{"blank line inside a continuation", "FROM a:1.2.3 \\\n\n AS x\n",
			[]DockerfileStage{{Name: "x", Image: "a:1.2.3", Line: 1}}},
		{"FROM text in a continued RUN is not an instruction", "FROM a:1.2.3\nRUN echo hi \\\nFROM b:2.0.0\n",
			[]DockerfileStage{{Image: "a:1.2.3", Line: 1}}},
		{"CRLF", "FROM a:1.2.3 AS x\r\nRUN true \\\r\n  && true\r\nFROM x\r\n",
			[]DockerfileStage{{Name: "x", Image: "a:1.2.3", Line: 1}, {Index: 1, Image: "x", Line: 4}}},
		{"BOM", "\xef\xbb\xbfFROM a:1.2.3\n",
			[]DockerfileStage{{Image: "a:1.2.3", Line: 1}}},
		{"no trailing newline", "FROM a:1.2.3",
			[]DockerfileStage{{Image: "a:1.2.3", Line: 1}}},
		{"backtick escape directive", "# escape=`\nFROM a:1.2.3 `\n AS x\nRUN true \\\nFROM b:2.0.0\n",
			[]DockerfileStage{{Name: "x", Image: "a:1.2.3", Line: 2}, {Index: 1, Image: "b:2.0.0", Line: 5}}},
		{"backslash at end is not a continuation under a backtick escape", "# escape=`\nFROM a:1.2.3\nRUN dir C:\\\nFROM b:2.0.0\n",
			[]DockerfileStage{{Image: "a:1.2.3", Line: 2}, {Index: 1, Image: "b:2.0.0", Line: 4}}},
		{"ONBUILD marks the stage", "FROM a:1.2.3 AS x\nONBUILD RUN make\nFROM b:2.0.0\n",
			[]DockerfileStage{{Name: "x", Image: "a:1.2.3", Line: 1, OnBuild: true}, {Index: 1, Image: "b:2.0.0", Line: 3}}},
		{"ARG before FROM", "ARG V=1.2.3\nFROM a:${V}\n",
			[]DockerfileStage{{Image: "a:${V}", Line: 2}}},
		{"image with registry port", "FROM localhost:5000/team/app:1.2.3\n",
			[]DockerfileStage{{Image: "localhost:5000/team/app:1.2.3", Line: 1}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := mustParseDockerfile(t, tc.in)
			if len(d.Stages) != len(tc.want) {
				t.Fatalf("stages = %+v, want %d", d.Stages, len(tc.want))
			}
			for i, w := range tc.want {
				g := d.Stages[i]
				g.imageOffs = nil
				if !reflect.DeepEqual(g, w) {
					t.Errorf("stage %d = %+v, want %+v", i, g, w)
				}
			}
		})
	}
}

func TestParseDockerfileHeredocs(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		stages []string
	}{
		{"RUN heredoc hides FROM", "FROM a:1.2.3\nRUN <<EOF\nFROM b:2.0.0\necho hi\nEOF\nFROM c:3.0.0\n", []string{"a:1.2.3", "c:3.0.0"}},
		{"dash heredoc with tab-indented delimiter", "FROM a:1.2.3\nRUN <<-EOF\n\tFROM b:2.0.0\n\tEOF\nFROM c:3.0.0\n", []string{"a:1.2.3", "c:3.0.0"}},
		{"dash heredoc does not strip spaces", "FROM a:1.2.3\nRUN <<-EOF\n  EOF\nFROM b:2.0.0\nEOF\nFROM c:3.0.0\n", []string{"a:1.2.3", "c:3.0.0"}},
		{"double quoted delimiter", "FROM a:1.2.3\nRUN <<\"END\"\nFROM b:2.0.0\nEND\nFROM c:3.0.0\n", []string{"a:1.2.3", "c:3.0.0"}},
		{"single quoted delimiter", "FROM a:1.2.3\nRUN <<'END'\nFROM b:2.0.0\nEND\nFROM c:3.0.0\n", []string{"a:1.2.3", "c:3.0.0"}},
		{"COPY heredoc", "FROM a:1.2.3\nCOPY <<EOF /etc/x\nFROM b:2.0.0\nEOF\nFROM c:3.0.0\n", []string{"a:1.2.3", "c:3.0.0"}},
		{"ADD heredoc", "FROM a:1.2.3\nADD <<EOF /etc/x\nFROM b:2.0.0\nEOF\n", []string{"a:1.2.3"}},
		{"file descriptor prefix", "FROM a:1.2.3\nRUN cat 3<<EOF\nFROM b:2.0.0\nEOF\n", []string{"a:1.2.3"}},
		{"two heredocs on one instruction", "FROM a:1.2.3\nRUN cat <<A <<B\nFROM x:1.0.0\nA\nFROM y:1.0.0\nB\nFROM c:3.0.0\n", []string{"a:1.2.3", "c:3.0.0"}},
		{"heredoc after a continuation", "FROM a:1.2.3\nRUN echo start \\\n && cat <<EOF\nFROM b:2.0.0\nEOF\nFROM c:3.0.0\n", []string{"a:1.2.3", "c:3.0.0"}},
		{"backslash line inside a heredoc is not a continuation", "FROM a:1.2.3\nRUN <<EOF\necho \\\nEOF\nFROM c:3.0.0\n", []string{"a:1.2.3", "c:3.0.0"}},
		{"comment inside heredoc body", "FROM a:1.2.3\nRUN <<EOF\n# FROM b:2.0.0\nEOF\nFROM c:3.0.0\n", []string{"a:1.2.3", "c:3.0.0"}},
		{"delimiter with trailing space is not a delimiter", "FROM a:1.2.3\nRUN <<EOF\nEOF \nFROM b:2.0.0\nEOF\nFROM c:3.0.0\n", []string{"a:1.2.3", "c:3.0.0"}},
		{"CRLF heredoc", "FROM a:1.2.3\r\nRUN <<EOF\r\nFROM b:2.0.0\r\nEOF\r\nFROM c:3.0.0\r\n", []string{"a:1.2.3", "c:3.0.0"}},
		{"here-string is not a heredoc", "FROM a:1.2.3\nRUN cat <<< hello\nFROM b:2.0.0\n", []string{"a:1.2.3", "b:2.0.0"}},
		{"ENV with << is not a heredoc", "FROM a:1.2.3\nENV X=<<EOF\nFROM b:2.0.0\n", []string{"a:1.2.3", "b:2.0.0"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := mustParseDockerfile(t, tc.in)
			var got []string
			for _, s := range d.Stages {
				got = append(got, s.Image)
			}
			if !reflect.DeepEqual(got, tc.stages) {
				t.Errorf("stages = %v, want %v", got, tc.stages)
			}
		})
	}
}

func TestParseDockerfileDirectives(t *testing.T) {
	d := mustParseDockerfile(t, "# syntax=docker/dockerfile:1.7\n# check=error=true\nFROM a:1.2.3\n")
	if d.Syntax != "docker/dockerfile:1.7" || d.HasEscape {
		t.Errorf("syntax=%q escape=%v", d.Syntax, d.HasEscape)
	}
	d = mustParseDockerfile(t, "#escape = `\nFROM a:1.2.3\n")
	if !d.HasEscape {
		t.Error("escape directive not seen")
	}
	// Directives only count at the top: after a blank line, a comment or an
	// instruction they are comments.
	for _, in := range []string{
		"\n# syntax=evil/frontend\nFROM a:1.2.3\n",
		"# hello\n# syntax=evil/frontend\nFROM a:1.2.3\n",
		"FROM a:1.2.3\n# syntax=evil/frontend\n",
		"FROM a:1.2.3\n# escape=`\n",
	} {
		d := mustParseDockerfile(t, in)
		if d.Syntax != "" || d.HasEscape {
			t.Errorf("%q: directive honored below the top: %+v", in, d)
		}
	}
	// An unknown "# name=value" line is a comment and ends the directives.
	d = mustParseDockerfile(t, "# foo=bar\n# syntax=evil/frontend\nFROM a:1.2.3\n")
	if d.Syntax != "" {
		t.Errorf("syntax after an unknown directive honored: %q", d.Syntax)
	}
	// A directive written in the BOM-prefixed first line counts.
	d = mustParseDockerfile(t, "\xef\xbb\xbf# syntax=evil/frontend\nFROM a:1.2.3\n")
	if d.Syntax != "evil/frontend" {
		t.Errorf("BOM first line: syntax = %q", d.Syntax)
	}
}

func TestParseDockerfileRefusals(t *testing.T) {
	tests := map[string]string{
		"empty":                     "",
		"only comments":             "# nothing\n",
		"no FROM":                   "RUN true\n",
		"FROM without image":        "FROM\n",
		"FROM only flag":            "FROM --platform=linux/amd64\n",
		"unknown flag":              "FROM --foo=bar a:1.2.3\n",
		"flag without value":        "FROM --platform a:1.2.3\n",
		"repeated platform flag":    "FROM --platform=a --platform=b x:1.0.0\n",
		"AS without name":           "FROM a:1.2.3 AS\n",
		"extra operand":             "FROM a:1.2.3 AS x y\n",
		"not AS":                    "FROM a:1.2.3 x\n",
		"bad stage name":            "FROM a:1.2.3 AS 1x\n",
		"duplicate stage name":      "FROM a:1.2.3 AS x\nFROM b:2.0.0 AS X\n",
		"unterminated heredoc":      "FROM a:1.2.3\nRUN <<EOF\necho\n",
		"repeated syntax directive": "# syntax=docker/dockerfile:1\n# syntax=docker/dockerfile:1\nFROM a:1.2.3\n",
		"bad escape directive":      "# escape=x\nFROM a:1.2.3\n",
		"NUL byte":                  "FROM a:1.2.3\x00\n",
		"UTF-16 BOM":                "\xff\xfeF\x00R\x00",
		"too large":                 "FROM a:1.2.3\n" + strings.Repeat("# x\n", maxDockerfileBytes/4+1),
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			d, prob := ParseDockerfile([]byte(in))
			if prob == nil || d != nil {
				t.Fatalf("accepted: %+v", d)
			}
			if prob.Reason != ReasonDockerfileInvalid {
				t.Errorf("reason = %q", prob.Reason)
			}
		})
	}
}

func TestResolveBase(t *testing.T) {
	multi := "FROM golang:1.22.1 AS build\nRUN go build\n\nFROM build AS test\nRUN go test\n\nFROM debian:12.5.1-slim AS runtime\nCOPY --from=build /out /out\n"
	tests := []struct {
		name      string
		in        string
		target    string
		image     string
		chain     []int
		stage     int
		line      int
		platform  string
		disp      DockerfileDisposition
		reason    Reason
		onBuild   bool
		editable  bool
		tagOfBase string
	}{
		{name: "last stage is the default", in: multi, image: "debian:12.5.1-slim", chain: []int{2}, stage: 2, line: 7, disp: DockerfilePinned, editable: true},
		{name: "named target", in: multi, target: "build", image: "golang:1.22.1", chain: []int{0}, stage: 0, line: 1, disp: DockerfilePinned, editable: true},
		{name: "target compared without case", in: multi, target: "RunTime", image: "debian:12.5.1-slim", chain: []int{2}, stage: 2, line: 7, disp: DockerfilePinned, editable: true},
		{name: "follows a stage reference", in: multi, target: "test", image: "golang:1.22.1", chain: []int{1, 0}, stage: 0, line: 1, disp: DockerfilePinned, editable: true},
		{name: "reference compared without case", in: "FROM a:1.2.3 AS Base\nFROM BASE AS x\n", image: "a:1.2.3", chain: []int{1, 0}, stage: 0, line: 1, disp: DockerfilePinned, editable: true},
		{name: "name that matches no earlier stage is an image", in: "FROM later AS first\nFROM a:1.2.3 AS later\n", target: "first", image: "later", chain: []int{0}, stage: 0, line: 1, disp: DockerfileFloating},
		{name: "own name is not a reference", in: "FROM a AS a\n", image: "a", chain: []int{0}, stage: 0, line: 1, disp: DockerfileFloating},
		{name: "platform kept", in: "FROM --platform=linux/amd64 a:1.2.3\n", image: "a:1.2.3", chain: []int{0}, stage: 0, line: 1, platform: "linux/amd64", disp: DockerfilePinned, editable: true},
		{name: "floating tag", in: "FROM python:3.12-slim\n", image: "python:3.12-slim", chain: []int{0}, stage: 0, line: 1, disp: DockerfileFloating},
		{name: "implicit latest", in: "FROM alpine\n", image: "alpine", chain: []int{0}, stage: 0, line: 1, disp: DockerfileFloating},
		{name: "latest", in: "FROM alpine:latest\n", image: "alpine:latest", chain: []int{0}, stage: 0, line: 1, disp: DockerfileFloating},
		{name: "digest only", in: "FROM alpine@sha256:" + strings.Repeat("a", 64) + "\n", image: "alpine@sha256:" + strings.Repeat("a", 64), chain: []int{0}, stage: 0, line: 1, disp: DockerfileExcluded, reason: ReasonDockerfileDigest},
		{name: "tag and digest", in: "FROM alpine:3.19.1@sha256:" + strings.Repeat("a", 64) + "\n", image: "alpine:3.19.1@sha256:" + strings.Repeat("a", 64), chain: []int{0}, stage: 0, line: 1, disp: DockerfileExcluded, reason: ReasonDockerfileDigest},
		{name: "scratch", in: "FROM scratch\nCOPY a /a\n", image: "scratch", chain: []int{0}, stage: 0, line: 1, disp: DockerfileExcluded, reason: ReasonDockerfileScratch},
		{name: "scratch behind a stage", in: "FROM scratch AS base\nFROM base\n", image: "scratch", chain: []int{1, 0}, stage: 0, line: 1, disp: DockerfileExcluded, reason: ReasonDockerfileScratch},
		{name: "prerelease tag", in: "FROM node:21.0.0-rc.1\n", image: "node:21.0.0-rc.1", chain: []int{0}, stage: 0, line: 1, disp: DockerfileExcluded, reason: ReasonDockerfileTagUnsupported},
		{name: "four part tag", in: "FROM a:1.2.3.4\n", image: "a:1.2.3.4", chain: []int{0}, stage: 0, line: 1, disp: DockerfileExcluded, reason: ReasonDockerfileTagUnsupported},
		{name: "variable in the image", in: "ARG V=1.2.3\nFROM a:${V}\n", image: "a:${V}", chain: []int{0}, stage: 0, line: 2, disp: DockerfileManual, reason: ReasonDockerfileVariable},
		{name: "variable as the whole image", in: "ARG BASE=a:1.2.3\nFROM $BASE\n", image: "$BASE", chain: []int{0}, stage: 0, line: 2, disp: DockerfileManual, reason: ReasonDockerfileVariable},
		{name: "variable in platform", in: "FROM --platform=$BUILDPLATFORM a:1.2.3\n", image: "a:1.2.3", chain: []int{0}, stage: 0, line: 1, platform: "$BUILDPLATFORM", disp: DockerfileManual, reason: ReasonDockerfileVariable},
		{name: "variable in an intermediate stage", in: "FROM --platform=$BUILDPLATFORM a:1.2.3 AS b\nFROM b\n", image: "a:1.2.3", chain: []int{1, 0}, stage: 0, line: 1, platform: "$BUILDPLATFORM", disp: DockerfileManual, reason: ReasonDockerfileVariable},
		{name: "platform on an intermediate FROM", in: "FROM a:1.2.3 AS b\nFROM --platform=linux/arm64 b\n", image: "a:1.2.3", chain: []int{1, 0}, stage: 0, line: 1, disp: DockerfileManual, reason: ReasonDockerfileStagePlatform},
		{name: "official frontend", in: "# syntax=docker/dockerfile:1.7\nFROM a:1.2.3\n", image: "a:1.2.3", chain: []int{0}, stage: 0, line: 2, disp: DockerfilePinned, editable: true},
		{name: "official frontend with registry prefix and digest", in: "# syntax=docker.io/docker/dockerfile@sha256:" + strings.Repeat("b", 64) + "\nFROM a:1.2.3\n", image: "a:1.2.3", chain: []int{0}, stage: 0, line: 2, disp: DockerfilePinned, editable: true},
		{name: "other frontend", in: "# syntax=ghcr.io/example/frontend:1\nFROM a:1.2.3\n", image: "a:1.2.3", chain: []int{0}, stage: 0, line: 2, disp: DockerfileManual, reason: ReasonDockerfileFrontend},
		{name: "frontend that merely starts like the official one", in: "# syntax=docker/dockerfile-evil:1\nFROM a:1.2.3\n", image: "a:1.2.3", chain: []int{0}, stage: 0, line: 2, disp: DockerfileManual, reason: ReasonDockerfileFrontend},
		{name: "escape directive", in: "# escape=`\nFROM a:1.2.3\n", image: "a:1.2.3", chain: []int{0}, stage: 0, line: 2, disp: DockerfileManual, reason: ReasonDockerfileEscape},
		{name: "ONBUILD in the inherited stage", in: "FROM a:1.2.3 AS base\nONBUILD RUN make\nFROM base\n", image: "a:1.2.3", chain: []int{1, 0}, stage: 0, line: 1, disp: DockerfilePinned, onBuild: true},
		{name: "ONBUILD in the target itself does not count", in: "FROM a:1.2.3\nONBUILD RUN make\n", image: "a:1.2.3", chain: []int{0}, stage: 0, line: 1, disp: DockerfilePinned, editable: true},
		{name: "ONBUILD in an unrelated stage does not count", in: "FROM a:1.2.3 AS other\nONBUILD RUN make\nFROM b:2.0.0\n", image: "b:2.0.0", chain: []int{1}, stage: 1, line: 3, disp: DockerfilePinned, editable: true},
		{name: "tag split across continuation lines", in: "FROM a:1.2.\\\n3\n", image: "a:1.2.3", chain: []int{0}, stage: 0, line: 1, disp: DockerfileManual, reason: ReasonDockerfileAmbiguous},
		{name: "quoted image operand", in: "FROM \"a:1.2.3\"\n", image: "\"a:1.2.3\"", chain: []int{0}, stage: 0, line: 1, disp: DockerfileManual, reason: ReasonDockerfileInvalid},
		{name: "image with host and port", in: "FROM registry.example:5000/team/app:1.2.3\n", image: "registry.example:5000/team/app:1.2.3", chain: []int{0}, stage: 0, line: 1, disp: DockerfilePinned, editable: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := mustParseDockerfile(t, tc.in)
			b, prob := d.ResolveBase(tc.target)
			if prob != nil {
				t.Fatalf("ResolveBase: %v", prob)
			}
			if b.Image != tc.image || !reflect.DeepEqual(b.Chain, tc.chain) || b.Stage != tc.stage || b.Line != tc.line || b.Platform != tc.platform {
				t.Errorf("base = image %q chain %v stage %d line %d platform %q", b.Image, b.Chain, b.Stage, b.Line, b.Platform)
			}
			if b.Disposition != tc.disp || b.Reason != tc.reason || b.OnBuildInherited != tc.onBuild {
				t.Errorf("disposition %q reason %q onbuild %v (%s), want %q %q %v", b.Disposition, b.Reason, b.OnBuildInherited, b.Detail, tc.disp, tc.reason, tc.onBuild)
			}
			if b.AutoEditable() != tc.editable {
				t.Errorf("AutoEditable = %v, want %v", b.AutoEditable(), tc.editable)
			}
		})
	}
}

func TestResolveBaseProblems(t *testing.T) {
	d := mustParseDockerfile(t, "FROM a:1.2.3 AS base\nFROM b:2.0.0 AS app\n")
	for _, target := range []string{"missing", "bas", "base ", "1"} {
		if _, prob := d.ResolveBase(target); prob == nil || prob.Reason != ReasonDockerfileTargetMissing {
			t.Errorf("target %q: %v", target, prob)
		}
	}
	// A stage without a name can only be the default target.
	d = mustParseDockerfile(t, "FROM a:1.2.3\n")
	if _, prob := d.ResolveBase("a:1.2.3"); prob == nil {
		t.Error("an image name matched as a stage name")
	}
}

func editDockerfile(src, target, current, newTag string) (DockerfileEdit, *DockerfileProblem) {
	return EditDockerfileBaseTag(DockerfileEditRequest{Content: []byte(src), Target: target, Current: current, NewTag: newTag})
}

func TestEditDockerfileBaseTag(t *testing.T) {
	const bom = "\xef\xbb\xbf"
	tests := []struct {
		name    string
		in      string
		target  string
		current string
		newTag  string
		want    string
		old     string
		new     string
	}{
		{"simple", "FROM python:3.12.3-slim\nRUN pip install x\n", "", "python:3.12.3-slim", "3.12.7-slim",
			"FROM python:3.12.7-slim\nRUN pip install x\n", "python:3.12.3-slim", "python:3.12.7-slim"},
		{"keeps platform flag and AS name", "FROM --platform=linux/amd64 node:20.11.1 AS web\nRUN true\n", "", "node:20.11.1", "20.18.0",
			"FROM --platform=linux/amd64 node:20.18.0 AS web\nRUN true\n", "node:20.11.1", "node:20.18.0"},
		{"lower case keywords", "from alpine:3.19.1 as x\n", "x", "alpine:3.19.1", "3.19.3", "from alpine:3.19.3 as x\n", "alpine:3.19.1", "alpine:3.19.3"},
		{"target other than the last", "FROM golang:1.22.1 AS build\nRUN go build\nFROM debian:12.5.1-slim\n", "build", "golang:1.22.1", "1.22.8",
			"FROM golang:1.22.8 AS build\nRUN go build\nFROM debian:12.5.1-slim\n", "golang:1.22.1", "golang:1.22.8"},
		{"last stage leaves the earlier FROM alone", "FROM golang:1.22.1 AS build\nFROM debian:12.5.1-slim\n", "", "debian:12.5.1-slim", "12.9.1-slim",
			"FROM golang:1.22.1 AS build\nFROM debian:12.9.1-slim\n", "debian:12.5.1-slim", "debian:12.9.1-slim"},
		{"through a stage reference", "FROM debian:12.5.1 AS base\nRUN apt-get update\nFROM base AS app\nCOPY . .\n", "app", "debian:12.5.1", "12.9.1",
			"FROM debian:12.9.1 AS base\nRUN apt-get update\nFROM base AS app\nCOPY . .\n", "debian:12.5.1", "debian:12.9.1"},
		{"same tag text elsewhere is not touched", "# python:3.12.3-slim\nFROM python:3.12.3-slim\nENV V=python:3.12.3-slim\nLABEL base=\"python:3.12.3-slim\"\n", "", "python:3.12.3-slim", "3.12.7-slim",
			"# python:3.12.3-slim\nFROM python:3.12.7-slim\nENV V=python:3.12.3-slim\nLABEL base=\"python:3.12.3-slim\"\n", "python:3.12.3-slim", "python:3.12.7-slim"},
		{"the same FROM text in two stages edits only the target's", "FROM a:1.2.3 AS x\nFROM a:1.2.3 AS y\n", "y", "a:1.2.3", "1.2.4",
			"FROM a:1.2.3 AS x\nFROM a:1.2.4 AS y\n", "a:1.2.3", "a:1.2.4"},
		{"CRLF", "FROM a:1.2.3 AS x\r\nRUN true\r\n", "", "a:1.2.3", "1.2.4", "FROM a:1.2.4 AS x\r\nRUN true\r\n", "a:1.2.3", "a:1.2.4"},
		{"BOM", bom + "# syntax=docker/dockerfile:1\nFROM a:1.2.3\n", "", "a:1.2.3", "1.2.4", bom + "# syntax=docker/dockerfile:1\nFROM a:1.2.4\n", "a:1.2.3", "a:1.2.4"},
		{"continuation lines around the tag", "FROM \\\n  --platform=linux/amd64 \\\n  a:1.2.3 \\\n  AS x\nRUN true\n", "", "a:1.2.3", "1.2.4",
			"FROM \\\n  --platform=linux/amd64 \\\n  a:1.2.4 \\\n  AS x\nRUN true\n", "a:1.2.3", "a:1.2.4"},
		{"FROM after a heredoc", "FROM a:1.2.3\nRUN <<EOF\nFROM b:9.9.9\nEOF\nFROM c:4.0.0\n", "", "c:4.0.0", "4.0.1",
			"FROM a:1.2.3\nRUN <<EOF\nFROM b:9.9.9\nEOF\nFROM c:4.0.1\n", "c:4.0.0", "c:4.0.1"},
		{"FROM before a heredoc that mentions an identical FROM", "FROM a:1.2.3\nRUN <<EOF\nFROM a:1.2.3\nEOF\n", "", "a:1.2.3", "1.2.4",
			"FROM a:1.2.4\nRUN <<EOF\nFROM a:1.2.3\nEOF\n", "a:1.2.3", "a:1.2.4"},
		{"tag at the end without a newline", "FROM a:1.2.3", "", "a:1.2.3", "1.2.4", "FROM a:1.2.4", "a:1.2.3", "a:1.2.4"},
		{"registry with port", "FROM registry.example:5000/team/app:1.2.3\n", "", "registry.example:5000/team/app:1.2.3", "1.2.4",
			"FROM registry.example:5000/team/app:1.2.4\n", "registry.example:5000/team/app:1.2.3", "registry.example:5000/team/app:1.2.4"},
		{"docker hub spellings agree", "FROM docker.io/library/python:3.12.3\n", "", "python:3.12.3", "3.12.7",
			"FROM docker.io/library/python:3.12.7\n", "docker.io/library/python:3.12.3", "docker.io/library/python:3.12.7"},
		{"ONBUILD in the target itself", "FROM a:1.2.3\nONBUILD RUN make\n", "", "a:1.2.3", "1.2.4", "FROM a:1.2.4\nONBUILD RUN make\n", "a:1.2.3", "a:1.2.4"},
		{"tag as long as the replacement shrinks", "FROM a:1.2.30\n", "", "a:1.2.30", "1.2.4", "FROM a:1.2.4\n", "a:1.2.30", "a:1.2.4"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := []byte(tc.in)
			res, prob := editDockerfile(tc.in, tc.target, tc.current, tc.newTag)
			if prob != nil {
				t.Fatalf("edit: %v", prob)
			}
			if string(res.Content) != tc.want {
				t.Errorf("content =\n%q\nwant\n%q", res.Content, tc.want)
			}
			if res.Change.Old != tc.old || res.Change.New != tc.new {
				t.Errorf("change = %+v", res.Change)
			}
			if string(in) != tc.in {
				t.Error("the input was modified")
			}
		})
	}
}

func TestEditDockerfileBaseTagRefusals(t *testing.T) {
	sha := "sha256:" + strings.Repeat("a", 64)
	tests := []struct {
		name    string
		in      string
		target  string
		current string
		newTag  string
		reason  Reason
	}{
		{"floating tag", "FROM python:3.12-slim\n", "", "python:3.12-slim", "3.12.7-slim", ReasonDockerfileNotEditable},
		{"digest", "FROM python@" + sha + "\n", "", "python:3.12.3", "3.12.7", ReasonDockerfileDigest},
		{"scratch", "FROM scratch\n", "", "python:3.12.3", "3.12.7", ReasonDockerfileScratch},
		{"variable", "ARG V=3.12.3\nFROM python:$V\n", "", "python:3.12.3", "3.12.7", ReasonDockerfileVariable},
		{"other frontend", "# syntax=example/frontend:1\nFROM python:3.12.3\n", "", "python:3.12.3", "3.12.7", ReasonDockerfileFrontend},
		{"escape directive", "# escape=`\nFROM python:3.12.3\n", "", "python:3.12.3", "3.12.7", ReasonDockerfileEscape},
		{"inherited ONBUILD", "FROM python:3.12.3 AS base\nONBUILD RUN make\nFROM base\n", "", "python:3.12.3", "3.12.7", ReasonDockerfileOnBuild},
		{"tag split across lines", "FROM python:3.12.\\\n3\n", "", "python:3.12.3", "3.12.7", ReasonDockerfileAmbiguous},
		{"missing target", "FROM python:3.12.3\n", "app", "python:3.12.3", "3.12.7", ReasonDockerfileTargetMissing},
		{"other repository", "FROM python:3.12.3\n", "", "node:3.12.3", "3.12.7", ReasonDockerfileSourceMismatch},
		{"other tag", "FROM python:3.12.3\n", "", "python:3.12.4", "3.12.7", ReasonDockerfileSourceMismatch},
		{"same tag", "FROM python:3.12.3\n", "", "python:3.12.3", "3.12.3", ReasonDockerfileInvalid},
		{"invalid new tag", "FROM python:3.12.3\n", "", "python:3.12.3", "3.12.7 && rm", ReasonDockerfileInvalid},
		{"empty new tag", "FROM python:3.12.3\n", "", "python:3.12.3", "", ReasonDockerfileInvalid},
		{"current without tag", "FROM python:3.12.3\n", "", "python", "3.12.7", ReasonDockerfileInvalid},
		{"current with digest", "FROM python:3.12.3\n", "", "python:3.12.3@" + sha, "3.12.7", ReasonDockerfileInvalid},
		{"unparsable file", "RUN true\n", "", "python:3.12.3", "3.12.7", ReasonDockerfileInvalid},
		{"unterminated heredoc hides the FROM", "FROM python:3.12.3\nRUN <<EOF\nFROM python:3.12.3\n", "", "python:3.12.3", "3.12.7", ReasonDockerfileInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, prob := editDockerfile(tc.in, tc.target, tc.current, tc.newTag)
			if prob == nil {
				t.Fatalf("edited: %q", res.Content)
			}
			if prob.Reason != tc.reason {
				t.Errorf("reason = %q (%s), want %q", prob.Reason, prob.Detail, tc.reason)
			}
			if res.Content != nil {
				t.Error("content returned with a problem")
			}
		})
	}
}

func TestVerifyDockerfileEditCatchesOtherChanges(t *testing.T) {
	orig := []byte("FROM a:1.2.3 AS x\nRUN true\nFROM x\n")
	od := mustParseDockerfile(t, string(orig))
	b, _ := od.ResolveBase("")
	span := composeSpan{start: b.tagStart, end: b.tagEnd, repl: "1.2.4"}
	ch := DockerfileChange{Stage: 0, Line: 1, Old: "a:1.2.3", New: "a:1.2.4"}
	good := spliceSpans(orig, []composeSpan{span})
	if prob := verifyDockerfileEdit(orig, good, span, od, "", ch); prob != nil {
		t.Fatalf("a correct edit failed verification: %v", prob)
	}
	for name, bad := range map[string]string{
		"extra byte before":   "#\nFROM a:1.2.4 AS x\nRUN true\nFROM x\n",
		"instruction changed": "FROM a:1.2.4 AS x\nRUN false\nFROM x\n",
		"name changed":        "FROM a:1.2.4 AS y\nRUN true\nFROM y\n",
		"stage dropped":       "FROM a:1.2.4 AS x\nRUN true\n",
		"wrong tag written":   "FROM a:1.2.5 AS x\nRUN true\nFROM x\n",
	} {
		if prob := verifyDockerfileEdit(orig, []byte(bad), span, od, "", ch); prob == nil {
			t.Errorf("%s: verification passed", name)
		}
	}
}

func TestIsOfficialDockerfileFrontend(t *testing.T) {
	for v, want := range map[string]bool{
		"docker/dockerfile":                   true,
		"docker/dockerfile:1":                 true,
		"docker/dockerfile:1.7-labs":          true,
		"docker.io/docker/dockerfile:1":       true,
		"index.docker.io/docker/dockerfile:1": true,
		"docker/dockerfile-upstream:master":   true,
		"docker/dockerfile@sha256:abc":        true,
		"  docker/dockerfile:1  ":             true,
		"":                                    false,
		"ghcr.io/docker/dockerfile:1":         false,
		"example/dockerfile:1":                false,
		"docker/dockerfile2:1":                false,
		"xdocker/dockerfile:1":                false,
	} {
		if got := IsOfficialDockerfileFrontend(v); got != want {
			t.Errorf("%q = %v, want %v", v, got, want)
		}
	}
}

// Every prefix and every single-byte deletion of a representative file is
// parsed, resolved and edited without a panic, and an edit that succeeds
// always changes exactly the tag.
func TestDockerfileMalformedInputsDoNotPanic(t *testing.T) {
	src := "\xef\xbb\xbf# syntax=docker/dockerfile:1\r\nFROM --platform=linux/amd64 python:3.12.3-slim AS base\r\nRUN <<-EOF\r\n\tFROM x:1.0.0\r\n\tEOF\r\nRUN a \\\r\n # c\r\n  && b\r\nFROM base AS app\r\nONBUILD RUN true\r\n"
	check := func(in []byte) {
		res, prob := EditDockerfileBaseTag(DockerfileEditRequest{Content: in, Target: "app", Current: "python:3.12.3-slim", NewTag: "3.12.7-slim"})
		if prob != nil {
			return
		}
		want := strings.Replace(string(in), "python:3.12.3-slim", "python:3.12.7-slim", 1)
		if string(res.Content) != want {
			t.Fatalf("edit of %q = %q", in, res.Content)
		}
	}
	for i := 0; i <= len(src); i++ {
		check([]byte(src[:i]))
	}
	for i := range src {
		check([]byte(src[:i] + src[i+1:]))
	}
	check([]byte(src))
}

func TestDockerfileONBUILDHeredoc(t *testing.T) {
	src := "FROM python:3.12.3 AS base\nONBUILD COPY <<EOF /Dockerfile\nFROM alpine:3.19.1\nEOF\nFROM base AS app\nRUN true\n"
	d := mustParseDockerfile(t, src)
	if len(d.Stages) != 2 || d.Stages[0].Name != "base" || d.Stages[1].Name != "app" || !d.Stages[0].OnBuild {
		t.Fatalf("stages = %+v", d.Stages)
	}
	b, prob := d.ResolveBase("")
	if prob != nil || b.Stage != 0 || b.Image != "python:3.12.3" || !b.OnBuildInherited || b.AutoEditable() {
		t.Fatalf("base = %+v, %v", b, prob)
	}
	if _, prob := editDockerfile(src, "", "python:3.12.3", "3.12.7"); prob == nil || prob.Reason != ReasonDockerfileOnBuild {
		t.Errorf("edit through inherited ONBUILD: %v", prob)
	}

	// Without the inheriting stage the edit goes through and the body stays.
	src2 := "FROM python:3.12.3\nONBUILD RUN <<'END OF FILE'\nFROM alpine:3.19.1\nEND OF FILE\nRUN true\n"
	res, prob := editDockerfile(src2, "", "python:3.12.3", "3.12.7")
	if prob != nil {
		t.Fatal(prob)
	}
	if want := strings.Replace(src2, "python:3.12.3", "python:3.12.7", 1); string(res.Content) != want {
		t.Errorf("content = %q", res.Content)
	}
	if got := mustParseDockerfile(t, src2); len(got.Stages) != 1 {
		t.Errorf("stages = %+v", got.Stages)
	}
	// ONBUILD ADD, lower case, with a JSON-free exec-looking word.
	if got := mustParseDockerfile(t, "FROM a:1.2.3\nonbuild add <<EOF /x\nFROM b:2.0.0\nEOF\n"); len(got.Stages) != 1 {
		t.Errorf("onbuild add: %+v", got.Stages)
	}
	// ONBUILD of an instruction without heredocs does not swallow lines.
	if got := mustParseDockerfile(t, "FROM a:1.2.3\nONBUILD ENV X=<<EOF\nFROM b:2.0.0\n"); len(got.Stages) != 2 {
		t.Errorf("onbuild env: %+v", got.Stages)
	}
}

func TestDockerfileEscapedEscapeDoesNotContinue(t *testing.T) {
	src := "FROM python:3.12.3 AS base\nRUN echo \\\\\nFROM debian:12.5.1 AS runtime\n"
	d := mustParseDockerfile(t, src)
	if len(d.Stages) != 2 || d.Stages[1].Name != "runtime" || d.Stages[1].Line != 3 {
		t.Fatalf("stages = %+v", d.Stages)
	}
	res, prob := editDockerfile(src, "", "debian:12.5.1", "12.9.1")
	if prob != nil {
		t.Fatal(prob)
	}
	if want := "FROM python:3.12.3 AS base\nRUN echo \\\\\nFROM debian:12.9.1 AS runtime\n"; string(res.Content) != want {
		t.Errorf("content = %q", res.Content)
	}

	for name, tc := range map[string]struct {
		in     string
		stages int
	}{
		"single escape continues":            {"FROM a:1.2.3\nRUN echo \\\nFROM b:2.0.0\n", 1},
		"single escape then spaces":          {"FROM a:1.2.3\nRUN echo \\ \t\nFROM b:2.0.0\n", 1},
		"double escape then spaces":          {"FROM a:1.2.3\nRUN echo \\\\ \nFROM b:2.0.0\n", 2},
		"escape alone on its line":           {"FROM a:1.2.3\nRUN echo a \\\n\\\nFROM b:2.0.0\n", 1},
		"escape alone after a full line":     {"FROM a:1.2.3\nRUN echo a\n\\\nFROM b:2.0.0\n", 2},
		"two escapes alone on their line":    {"FROM a:1.2.3\nRUN echo a\n\\\\\nFROM b:2.0.0\n", 2},
		"escape after a space":               {"FROM a:1.2.3\nRUN echo a \\\nFROM b:2.0.0\n", 1},
		"backtick: backslash is plain":       {"# escape=`\nFROM a:1.2.3\nRUN dir C:\\\nFROM b:2.0.0\n", 2},
		"backtick: single continues":         {"# escape=`\nFROM a:1.2.3\nRUN echo `\nFROM b:2.0.0\n", 1},
		"backtick: doubled does not":         {"# escape=`\nFROM a:1.2.3\nRUN echo ``\nFROM b:2.0.0\n", 2},
		"trailing escape on the last line":   {"FROM a:1.2.3\nRUN echo \\", 1},
		"escape at the end of a FROM":        {"FROM a:1.2.3 \\\nAS x\n", 1},
		"continued line ending in a doubled": {"FROM a:1.2.3\nRUN echo \\\n a \\\\\nFROM b:2.0.0\n", 2},
	} {
		if got := mustParseDockerfile(t, tc.in); len(got.Stages) != tc.stages {
			t.Errorf("%s: %d stages, want %d", name, len(got.Stages), tc.stages)
		}
	}
}

func TestDockerfileDirectivesAfterWhitespaceAndBOM(t *testing.T) {
	const bom = "\xef\xbb\xbf"
	for name, in := range map[string]string{
		"space":            " # escape=`\nFROM a:1.2.3\n",
		"tab":              "\t# escape=`\nFROM a:1.2.3\n",
		"spaces and tabs":  " \t \t#escape=`\nFROM a:1.2.3\n",
		"BOM":              bom + "# escape=`\nFROM a:1.2.3\n",
		"BOM then space":   bom + "  # escape=`\nFROM a:1.2.3\n",
		"second directive": "# syntax=docker/dockerfile:1\n\t# escape=`\nFROM a:1.2.3\n",
		"CRLF":             "\t# escape=`\r\nFROM a:1.2.3\r\n",
	} {
		d := mustParseDockerfile(t, in)
		if !d.HasEscape {
			t.Errorf("%s: escape directive missed", name)
			continue
		}
		b, prob := d.ResolveBase("")
		if prob != nil || b.Disposition != DockerfileManual || b.Reason != ReasonDockerfileEscape {
			t.Errorf("%s: base = %+v, %v", name, b, prob)
		}
	}
	for name, in := range map[string]string{
		"tab":         "\t# syntax=example/frontend:1\nFROM a:1.2.3\n",
		"space":       "   # syntax=example/frontend:1\nFROM a:1.2.3\n",
		"BOM and tab": bom + "\t# syntax=example/frontend:1\nFROM a:1.2.3\n",
	} {
		d := mustParseDockerfile(t, in)
		if d.Syntax == "" {
			t.Errorf("%s: syntax directive missed", name)
		}
	}
	d := mustParseDockerfile(t, "\t# syntax=example/frontend:1\nFROM a:1.2.3\n")
	if b, _ := d.ResolveBase(""); b.Reason != ReasonDockerfileFrontend {
		t.Errorf("tab-indented syntax: %+v", b)
	}
	// A blank line, a comment or an instruction ends the directives even when
	// indented.
	for _, in := range []string{
		"  \n# escape=`\nFROM a:1.2.3\n",
		"\t# note\n# escape=`\nFROM a:1.2.3\n",
		"FROM a:1.2.3\n\t# escape=`\n",
	} {
		if d := mustParseDockerfile(t, in); d.HasEscape {
			t.Errorf("%q: directive honored", in)
		}
	}
	// The backtick escape moves instruction boundaries.
	src := "\t# escape=`\nFROM a:1.2.3 AS x\nRUN echo `\nFROM b:2.0.0 AS y\nRUN dir C:\\\nFROM c:3.0.0\n"
	d = mustParseDockerfile(t, src)
	var imgs []string
	for _, s := range d.Stages {
		imgs = append(imgs, s.Image)
	}
	if !reflect.DeepEqual(imgs, []string{"a:1.2.3", "c:3.0.0"}) {
		t.Errorf("stages = %v", imgs)
	}
	// The offsets stay on the original bytes after a BOM and indentation.
	d = mustParseDockerfile(t, bom+"  # syntax=docker/dockerfile:1\nFROM a:1.2.3\n")
	b, _ := d.ResolveBase("")
	if !b.AutoEditable() {
		t.Fatalf("base = %+v", b)
	}
	res, prob := editDockerfile(bom+"  # syntax=docker/dockerfile:1\nFROM a:1.2.3\n", "", "a:1.2.3", "1.2.4")
	if prob != nil || string(res.Content) != bom+"  # syntax=docker/dockerfile:1\nFROM a:1.2.4\n" {
		t.Errorf("edit = %q, %v", res.Content, prob)
	}
}

func TestDockerfileHeredocTokenizing(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		stages int
	}{
		{"quoted delimiter with spaces", "FROM a:1.2.3\nRUN <<'END OF FILE'\nFROM b:2.0.0\nEND OF FILE\nFROM c:3.0.0\n", 2},
		{"double quoted delimiter with spaces", "FROM a:1.2.3\nRUN cat <<\"END OF FILE\" > /x\nFROM b:2.0.0\nEND OF FILE\nFROM c:3.0.0\n", 2},
		{"unquoted first word of a quoted delimiter is not the delimiter", "FROM a:1.2.3\nRUN <<'END OF FILE'\nEND\nFROM b:2.0.0\nEND OF FILE\n", 1},
		{"concatenated quoting", "FROM a:1.2.3\nRUN <<E\"N\"D\nFROM b:2.0.0\nEND\nFROM c:3.0.0\n", 2},
		{"JSON form with << inside a string", "FROM a:1.2.3\nRUN [\"echo\", \"text <<EOF\"]\nFROM b:2.0.0\n", 2},
		{"JSON form COPY", "FROM a:1.2.3\nCOPY [\"<<EOF\", \"/x\"]\nFROM b:2.0.0\n", 2},
		{"JSON form behind ONBUILD", "FROM a:1.2.3\nONBUILD RUN [\"sh\", \"-c\", \"cat <<EOF\"]\nFROM b:2.0.0\n", 2},
		{"shell form that looks like JSON but is not", "FROM a:1.2.3\nRUN [ -f x ] && cat <<EOF\nFROM b:2.0.0\nEOF\nFROM c:3.0.0\n", 2},
		{"<< inside quotes in shell form is not a heredoc", "FROM a:1.2.3\nRUN echo 'cat <<EOF'\nFROM b:2.0.0\n", 2},
		{"<< inside double quotes", "FROM a:1.2.3\nRUN echo \"x <<EOF\"\nFROM b:2.0.0\n", 2},
		{"escaped quote does not open a quote", "FROM a:1.2.3\nRUN echo \\' <<EOF\nFROM b:2.0.0\nEOF\nFROM c:3.0.0\n", 2},
		{"quote with an escaped quote inside", "FROM a:1.2.3\nRUN echo \"a \\\" b\" <<EOF\nFROM b:2.0.0\nEOF\nFROM c:3.0.0\n", 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := mustParseDockerfile(t, tc.in)
			if len(d.Stages) != tc.stages {
				var imgs []string
				for _, s := range d.Stages {
					imgs = append(imgs, s.Image)
				}
				t.Errorf("stages = %v, want %d", imgs, tc.stages)
			}
		})
	}
	// The body of a heredoc with a spaced delimiter is untouched by an edit.
	src := "FROM a:1.2.3\nRUN <<'END OF FILE'\nFROM a:1.2.3\nEND OF FILE\n"
	res, prob := editDockerfile(src, "", "a:1.2.3", "1.2.4")
	if prob != nil || string(res.Content) != "FROM a:1.2.4\nRUN <<'END OF FILE'\nFROM a:1.2.3\nEND OF FILE\n" {
		t.Errorf("edit = %q, %v", res.Content, prob)
	}
}

func TestDockerfileHeredocOperatorWithBlanks(t *testing.T) {
	src := "FROM alpine:3.19.1 AS real\nRUN cat << EOF > /Dockerfile\nFROM alpine:3.19.1 AS fake\nEOF\n"
	d := mustParseDockerfile(t, src)
	if len(d.Stages) != 1 || d.Stages[0].Name != "real" {
		t.Fatalf("stages = %+v", d.Stages)
	}
	res, prob := editDockerfile(src, "", "alpine:3.19.1", "3.19.3")
	if prob != nil || string(res.Content) != "FROM alpine:3.19.3 AS real\nRUN cat << EOF > /Dockerfile\nFROM alpine:3.19.1 AS fake\nEOF\n" {
		t.Errorf("edit = %q, %v", res.Content, prob)
	}
	for name, tc := range map[string]struct {
		in     string
		stages int
	}{
		"tab after the operator":    {"FROM a:1.2.3\nRUN cat <<\tEOF\nFROM b:2.0.0\nEOF\nFROM c:3.0.0\n", 2},
		"dash and blanks":           {"FROM a:1.2.3\nRUN cat <<-  EOF\n\tFROM b:2.0.0\n\tEOF\nFROM c:3.0.0\n", 2},
		"quoted delimiter":          {"FROM a:1.2.3\nRUN cat << 'END OF FILE'\nFROM b:2.0.0\nEND OF FILE\nFROM c:3.0.0\n", 2},
		"fd prefix":                 {"FROM a:1.2.3\nRUN cat 3<< EOF\nFROM b:2.0.0\nEOF\nFROM c:3.0.0\n", 2},
		"COPY":                      {"FROM a:1.2.3\nCOPY << EOF /x\nFROM b:2.0.0\nEOF\nFROM c:3.0.0\n", 2},
		"behind ONBUILD":            {"FROM a:1.2.3\nONBUILD RUN cat << EOF\nFROM b:2.0.0\nEOF\nFROM c:3.0.0\n", 2},
		"in exec form it is text":   {"FROM a:1.2.3\nRUN [\"echo\", \"<<\", \"EOF\"]\nFROM b:2.0.0\n", 2},
		"operator alone at the end": {"FROM a:1.2.3\nRUN cat <<\nFROM b:2.0.0\n", 2},
		"not in ENV":                {"FROM a:1.2.3\nENV X << EOF\nFROM b:2.0.0\n", 2},
	} {
		if got := mustParseDockerfile(t, tc.in); len(got.Stages) != tc.stages {
			t.Errorf("%s: %d stages, want %d", name, len(got.Stages), tc.stages)
		}
	}
}

func TestDockerfileHeredocDoubleQuotedDelimiter(t *testing.T) {
	// Inside double quotes a backslash is removed only before ", \ and $, so
	// the delimiter below keeps its backslash and the line E\`OF closes it.
	src := "FROM alpine:3.19.1 AS a\nRUN cat <<\"E\\`OF\"\nFROM alpine:3.19.1 AS fake\nE\\`OF\nFROM alpine:3.19.1 AS b\n"
	d := mustParseDockerfile(t, src)
	var names []string
	for _, s := range d.Stages {
		names = append(names, s.Name)
	}
	if !reflect.DeepEqual(names, []string{"a", "b"}) {
		t.Errorf("stages = %v", names)
	}
	for in, want := range map[string]string{
		`"E\"OF"`:    `E"OF`,
		`"E\\OF"`:    `E\OF`,
		`"E\$OF"`:    `E$OF`,
		"\"E\\`OF\"": "E\\`OF",
		`"E\xOF"`:    `E\xOF`,
		`'E\OF'`:     `E\OF`,
		`E\ OF`:      `E OF`,
		`"A B"C`:     `A BC`,
	} {
		if got := unquoteShellWord(in); got != want {
			t.Errorf("unquote(%s) = %q, want %q", in, got, want)
		}
	}
}
