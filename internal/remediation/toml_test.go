package remediation

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseTOML(t *testing.T) {
	doc := "# comment\n" +
		"version = 1\n" +
		"requires-python = \">=3.12\"\n" +
		"ratio = 1.5\n" +
		"on = true\n" +
		"when = 2026-10-09T03:00:00Z\n" +
		"literal = 'C:\\path'\n" +
		"escaped = \"a\\tb\\u00e9\"\n" +
		"multi = \"\"\"\nline1\nline2 \\\n   joined\"\"\"\n" +
		"raw = '''\nraw\\n\n'''\n" +
		"arr = [\n  1, 2, # two\n  3,\n]\n" +
		"dotted.key = \"v\"\n" +
		"inline = { name = \"x\", n = [ 1, 2 ], sub = { a = 1 } }\n" +
		"\n[[package]]\nname = \"a\"\nsource = { registry = \"https://pypi.org/simple\" }\n\n" +
		"[package.metadata]\nrequires-dist = [{ name = \"b\", specifier = \">=1\" }]\n\n" +
		"[[package]]\nname = \"b\"\n\n" +
		"[tool.uv]\nflag = false\n"
	got, err := parseTOML([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if got["version"] != int64(1) || got["requires-python"] != ">=3.12" || got["ratio"] != 1.5 || got["on"] != true {
		t.Errorf("scalars = %v", got)
	}
	if got["when"] != "2026-10-09T03:00:00Z" {
		t.Errorf("date = %v", got["when"])
	}
	if got["literal"] != `C:\path` || got["escaped"] != "a\tbé" {
		t.Errorf("strings = %q, %q", got["literal"], got["escaped"])
	}
	if got["multi"] != "line1\nline2 joined" {
		t.Errorf("multi = %q", got["multi"])
	}
	if got["raw"] != "raw\\n\n" {
		t.Errorf("raw = %q", got["raw"])
	}
	if !reflect.DeepEqual(got["arr"], []any{int64(1), int64(2), int64(3)}) {
		t.Errorf("arr = %v", got["arr"])
	}
	if got["dotted"].(map[string]any)["key"] != "v" {
		t.Errorf("dotted = %v", got["dotted"])
	}
	in := got["inline"].(map[string]any)
	if in["name"] != "x" || in["sub"].(map[string]any)["a"] != int64(1) {
		t.Errorf("inline = %v", in)
	}
	pkgs := got["package"].([]any)
	if len(pkgs) != 2 || pkgs[0].(map[string]any)["name"] != "a" || pkgs[1].(map[string]any)["name"] != "b" {
		t.Fatalf("packages = %v", pkgs)
	}
	meta := pkgs[0].(map[string]any)["metadata"].(map[string]any)
	if req := meta["requires-dist"].([]any)[0].(map[string]any); req["specifier"] != ">=1" {
		t.Errorf("metadata = %v", meta)
	}
	if got["tool"].(map[string]any)["uv"].(map[string]any)["flag"] != false {
		t.Errorf("tool = %v", got["tool"])
	}
}

func TestParseTOMLRejects(t *testing.T) {
	for name, doc := range map[string]string{
		"unterminated string": "a = \"x\n",
		"duplicate key":       "a = 1\na = 2\n",
		"garbage after":       "a = 1 b = 2\n",
		"bad escape":          "a = \"\\q\"\n",
		"unterminated array":  "a = [1, 2\n",
		"missing value":       "a =\n",
		"bare word":           "a = nope\n",
		"key without value":   "a\n",
		"table over value":    "a = 1\n[a]\nb = 2\n",
		"unterminated multi":  "a = \"\"\"x\n",
	} {
		if _, err := parseTOML([]byte(doc)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, err := parseTOML([]byte("a = \"\xff\"\n")); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("invalid UTF-8: %v", err)
	}
}
