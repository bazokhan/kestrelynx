package remediation

import (
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/toolfetch"
)

// managerChoice is the release of a package manager an update runs with.
type managerChoice struct {
	version      string
	source       string
	specHash     string
	declarations []ToolDeclaration
}

// packageManagerRE is the form of the packageManager field: a name, an exact
// version and optionally a hash written "+<algorithm>.<hex>".
var packageManagerRE = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9._-]*)@([^+]+)(?:\+([a-z0-9]+)\.([0-9A-Fa-f]+))?$`)

// hashHexLengths are the algorithms a packageManager hash may use and the
// length of their digests in hex.
var hashHexLengths = map[string]int{"sha1": 40, "sha224": 56, "sha256": 64, "sha384": 96, "sha512": 128}

// resolveNodeManager chooses the release of npm or pnpm from the declarations
// in package.json: packageManager, devEngines.packageManager and engines.<name>.
// A version the project declares exactly is the one to run; ranges only have to
// allow the version run otherwise.
func resolveNodeManager(in ToolSpecInput, top map[string]json.RawMessage) (managerChoice, *UnsupportedError) {
	name := string(in.Manager)
	var out managerChoice
	var decls []declared
	var points []string

	if raw, ok := top["packageManager"]; ok {
		var field string
		if json.Unmarshal(raw, &field) != nil {
			return out, unsupported(ReasonManagerSpecInvalid, "package.json packageManager is not a string")
		}
		m := packageManagerRE.FindStringSubmatch(strings.TrimSpace(field))
		if m == nil {
			return out, unsupported(ReasonManagerSpecInvalid, "package.json packageManager %q is not written as name@version", clip(field, 80))
		}
		if m[1] != name {
			return out, unsupported(ReasonManagerSpecConflict, "package.json packageManager names %s, and the unit's lockfile is %s's", clip(m[1], 40), name)
		}
		v, ok := fullVersion(m[2])
		if !ok || strings.HasPrefix(m[2], "v") || strings.HasPrefix(m[2], "=") {
			if sv, valid := parseSemver(m[2]); valid && len(sv.pre) > 0 {
				return out, unsupported(ReasonManagerSpecUnsupported, "package.json packageManager asks for the pre-release %s %s", name, clip(m[2], 40))
			}
			return out, unsupported(ReasonManagerSpecInvalid, "package.json packageManager version %q is not an exact version", clip(m[2], 40))
		}
		if m[3] != "" {
			if n, known := hashHexLengths[m[3]]; !known || len(m[4]) != n {
				return out, unsupported(ReasonManagerSpecInvalid, "package.json packageManager hash is not <algorithm>.<hex> with sha1, sha224, sha256, sha384 or sha512")
			}
			if _, err := hex.DecodeString(m[4]); err != nil {
				return out, unsupported(ReasonManagerSpecInvalid, "package.json packageManager hash is not hexadecimal")
			}
			out.specHash = m[3] + "." + strings.ToLower(m[4])
		}
		decls = append(decls, declared{"packageManager", name + "@" + m[2], pointSet(v)})
		points = append(points, m[2])
		out.declarations = append(out.declarations, ToolDeclaration{Source: "packageManager", Value: clip(field, 160)})
	}

	dev, uerr := objectField(top, "devEngines", ReasonManagerSpecInvalid)
	if uerr != nil {
		return out, uerr
	}
	if raw, ok := dev["packageManager"]; ok {
		entries, uerr := entryList(raw, "devEngines.packageManager", ReasonManagerSpecInvalid)
		if uerr != nil {
			return out, uerr
		}
		seen := 0
		for _, e := range entries {
			if e.name != name {
				return out, unsupported(ReasonManagerSpecConflict, "devEngines.packageManager names %s, and the unit's lockfile is %s's", clip(e.name, 40), name)
			}
			if seen++; seen > 1 {
				return out, unsupported(ReasonManagerSpecInvalid, "devEngines.packageManager names %s more than once", name)
			}
			if e.version == "" {
				continue
			}
			set, ok := rangeSet(e.version)
			if !ok {
				return out, unsupported(ReasonManagerSpecInvalid, "devEngines.packageManager version %q is not a range that is read", clip(e.version, 80))
			}
			if v, exact := fullVersion(e.version); exact {
				set = pointSet(v)
				points = append(points, strings.TrimPrefix(strings.TrimPrefix(e.version, "v"), "="))
			}
			decls = append(decls, declared{"devEngines.packageManager", e.version, set})
			out.declarations = append(out.declarations, ToolDeclaration{Source: "devEngines.packageManager", Value: clip(e.version, 100)})
		}
	}

	engines, uerr := objectField(top, "engines", ReasonManagerSpecInvalid)
	if uerr != nil {
		return out, uerr
	}
	if raw, ok := engines[name]; ok {
		var text string
		if json.Unmarshal(raw, &text) != nil {
			return out, unsupported(ReasonManagerSpecInvalid, "engines.%s is not a string", name)
		}
		set, ok := rangeSet(text)
		if !ok {
			return out, unsupported(ReasonManagerSpecInvalid, "engines.%s %q is not a range that is read", name, clip(text, 80))
		}
		if v, exact := fullVersion(text); exact {
			set = pointSet(v)
			points = append(points, strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(text), "v"), "="))
		}
		decls = append(decls, declared{"engines." + name, text, set})
		out.declarations = append(out.declarations, ToolDeclaration{Source: "engines." + name, Value: clip(text, 100)})
	}

	if uerr := consistency(decls, ReasonManagerSpecConflict, name); uerr != nil {
		return out, uerr
	}

	def := toolfetch.DefaultVersion(toolfetch.Manager(in.Manager), defaultNodeRuntime)
	defV, ok := fullVersion(def)
	if !ok {
		return out, unsupported(ReasonManagerSpecUnsupported, "no default version of %s is set for %s", name, defaultNodeRuntime)
	}
	if len(points) > 0 {
		// Consistency makes the exact versions one, and it is inside every range
		// that was declared. The release is the one the project names; the
		// fetching package judges the rest (that it exists, is old enough and runs
		// on this Node.js).
		if ok, why := toolfetch.CheckVersion(toolfetch.Manager(in.Manager), points[0]); !ok {
			return out, unsupported(ReasonManagerSpecUnsupported, "the project declares %s %s: %s", name, clip(points[0], 40), why)
		}
		out.version, out.source = points[0], toolSourceDeclared
		return out, nil
	}
	for _, d := range decls {
		if !d.set.contains(defV) {
			return out, unsupported(ReasonManagerSpecUnsupported, "%s %s does not allow %s %s, which updates run with when the project names no exact version", d.source, clip(d.value, 80), name, def)
		}
	}
	out.version, out.source = def, toolSourceDefault
	if len(decls) > 0 {
		out.source = toolSourceDefaultInRange
	}
	return out, nil
}
