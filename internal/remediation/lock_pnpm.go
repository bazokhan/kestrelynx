package remediation

import (
	"strings"
)

// parsePnpm reads pnpm-lock.yaml (lockfileVersion '9.0') of a single project
// with the one importer ".". manifest is the project's package.json, which
// must be valid and agree with the importer on the direct dependencies.
func parsePnpm(manifest, lock []byte) (*lockfile, error) {
	pj, err := readManifest(manifest)
	if err != nil {
		return nil, err
	}
	if pj.workspaces {
		return nil, unsupported(ReasonWorkspaceUnsupported, "package.json declares workspaces")
	}
	doc, err := readPnpmLock(lock)
	if err != nil {
		return nil, unsupported(ReasonUnparsableSource, "pnpm-lock.yaml cannot be read: %v", err)
	}
	if !doc.versionIsScalar || doc.versionText != "9.0" {
		return nil, unsupported(ReasonUnsupportedLockfile, "pnpm-lock.yaml has lockfileVersion %q; only '9.0' is read", doc.versionText)
	}
	importers := gmap(doc.top["importers"])
	if len(importers) != 1 {
		return nil, unsupported(ReasonWorkspaceUnsupported, "pnpm-lock.yaml has %d importers; only the single importer \".\" is read", len(importers))
	}
	rawImp, ok := importers["."]
	if !ok {
		return nil, unsupported(ReasonWorkspaceUnsupported, "pnpm-lock.yaml has no importer \".\"")
	}
	imp := pnpmImporterOf(gmap(rawImp))
	if _, present := doc.top["catalogs"]; present {
		return nil, unsupported(ReasonUnsupportedLockfile, "pnpm-lock.yaml uses catalogs")
	}
	if len(gmap(doc.top["patchedDependencies"])) > 0 {
		return nil, unsupported(ReasonUnsupportedLockfile, "pnpm-lock.yaml records patched dependencies")
	}
	packages := map[string]pnpmPackage{}
	for k, v := range gmap(doc.top["packages"]) {
		packages[k] = pnpmPackageOf(gmap(v))
	}
	snapshots := gmap(doc.top["snapshots"])
	overrides := gmap(doc.top["overrides"])

	if err := checkPnpmManifest(pj.deps["dependencies"], pj.deps["devDependencies"], pj.deps["optionalDependencies"], pj.deps["peerDependencies"], imp); err != nil {
		return nil, err
	}

	l := newLockfile(ManagerPnpm)

	// directKeys are the snapshot keys the importer requires itself.
	directKeys := map[string]bool{}
	for _, deps := range []map[string]pnpmDep{imp.Dependencies, imp.DevDependencies, imp.OptionalDependencies} {
		for name, d := range deps {
			if strings.HasPrefix(d.Specifier, "catalog:") {
				return nil, unsupported(ReasonUnsupportedLockfile, "pnpm-lock.yaml uses a catalog specifier for %s", name)
			}
			if pnpmNonRegistryVersion(d.Version) {
				l.add(name, SourceOccurrence{Path: "importers[.]." + name, Version: d.Version, Direct: true,
					ManualReason: ReasonNonRegistrySource, Detail: "required as " + d.Version})
				continue
			}
			directKeys[name+"@"+d.Version] = true
		}
	}

	hasSnapshot := map[string]bool{}
	for key := range snapshots {
		base := pnpmBase(key)
		name, ver, ok := splitPnpmKey(base)
		if !ok {
			return nil, unsupported(ReasonUnparsableSource, "pnpm-lock.yaml has the snapshot key %q", key)
		}
		pk, ok := packages[base]
		if !ok {
			return nil, unsupported(ReasonUnparsableSource, "pnpm-lock.yaml has the snapshot %q without a packages entry", key)
		}
		hasSnapshot[base] = true
		l.add(name, pnpmOccurrence(key, ver, directKeys[key], pk))
	}
	for key, pk := range packages {
		if hasSnapshot[key] {
			continue
		}
		name, ver, ok := splitPnpmKey(key)
		if !ok {
			return nil, unsupported(ReasonUnparsableSource, "pnpm-lock.yaml has the packages key %q", key)
		}
		l.add(name, pnpmOccurrence(key, ver, directKeys[key], pk))
	}

	for k := range overrides {
		// Keys look like name, name@range or parent>name.
		if i := strings.LastIndex(k, ">"); i >= 0 {
			k = k[i+1:]
		}
		l.force(nameWithoutRange(k), "the lockfile records an override for it")
	}
	return l.finish(), nil
}

type pnpmImporter struct {
	Dependencies         map[string]pnpmDep
	DevDependencies      map[string]pnpmDep
	OptionalDependencies map[string]pnpmDep
}

type pnpmDep struct {
	Specifier string
	Version   string
}

type pnpmPackage struct {
	Resolution struct {
		Integrity string
		Tarball   string
		Directory string
		Type      string
	}
}

// gmap and gstr read a converted YAML value.
func gmap(v any) map[string]any { m, _ := v.(map[string]any); return m }
func gstr(v any) string         { s, _ := v.(string); return s }

func pnpmImporterOf(m map[string]any) pnpmImporter {
	deps := func(v any) map[string]pnpmDep {
		out := map[string]pnpmDep{}
		for name, d := range gmap(v) {
			dm := gmap(d)
			out[name] = pnpmDep{Specifier: gstr(dm["specifier"]), Version: gstr(dm["version"])}
		}
		return out
	}
	return pnpmImporter{Dependencies: deps(m["dependencies"]), DevDependencies: deps(m["devDependencies"]), OptionalDependencies: deps(m["optionalDependencies"])}
}

func pnpmPackageOf(m map[string]any) pnpmPackage {
	var pk pnpmPackage
	r := gmap(m["resolution"])
	pk.Resolution.Integrity, pk.Resolution.Tarball = gstr(r["integrity"]), gstr(r["tarball"])
	pk.Resolution.Directory, pk.Resolution.Type = gstr(r["directory"]), gstr(r["type"])
	return pk
}

// pnpmBase drops the peer-context suffix of a snapshot key.
func pnpmBase(key string) string {
	if i := strings.IndexByte(key, '('); i >= 0 {
		return key[:i]
	}
	return key
}

// splitPnpmKey splits name@version; a leading "@" is a scope.
func splitPnpmKey(key string) (name, ver string, ok bool) {
	if len(key) < 2 {
		return "", "", false
	}
	i := strings.IndexByte(key[1:], '@')
	if i < 0 || key[:i+1] == "" || key[i+2:] == "" {
		return "", "", false
	}
	return key[:i+1], key[i+2:], true
}

// pnpmNonRegistryVersion reports a version that names a local path, a link, a
// repository or a URL instead of a registry version.
func pnpmNonRegistryVersion(v string) bool {
	return strings.ContainsAny(pnpmBase(v), ":/")
}

func pnpmOccurrence(path, ver string, direct bool, pk pnpmPackage) SourceOccurrence {
	o := SourceOccurrence{Path: path, Version: pnpmBase(ver), Direct: direct}
	r := pk.Resolution
	switch {
	case pnpmNonRegistryVersion(ver):
		o.ManualReason, o.Detail = ReasonNonRegistrySource, "required as "+pnpmBase(ver)
	case r.Tarball != "" || r.Directory != "" || r.Type != "":
		o.ManualReason, o.Detail = ReasonNonRegistrySource, "not resolved from the registry by integrity"
	case r.Integrity == "":
		o.ManualReason, o.Detail = ReasonNonRegistrySource, "no integrity in its resolution"
	}
	return o
}

// checkPnpmManifest requires that the importer lists what package.json
// declares, with the same specifiers, and nothing package.json does not
// declare (peer dependencies may be installed into the importer).
func checkPnpmManifest(deps, dev, opt, peer map[string]string, imp pnpmImporter) error {
	declared := map[string]string{}
	for _, m := range []map[string]string{deps, dev, opt} {
		for n, spec := range m {
			declared[n] = spec
		}
	}
	locked := map[string]string{}
	for _, m := range []map[string]pnpmDep{imp.Dependencies, imp.DevDependencies, imp.OptionalDependencies} {
		for n, d := range m {
			locked[n] = d.Specifier
		}
	}
	for n, spec := range declared {
		got, ok := locked[n]
		if !ok {
			return unsupported(ReasonUnsupportedLockfile, "package.json declares %s, which the lockfile's importer does not list", n)
		}
		if got != spec {
			return unsupported(ReasonUnsupportedLockfile, "package.json asks for %s %q but the lockfile was made for %q", n, spec, got)
		}
	}
	for n := range locked {
		if _, ok := declared[n]; ok {
			continue
		}
		if _, ok := peer[n]; !ok {
			return unsupported(ReasonUnsupportedLockfile, "the lockfile's importer lists %s, which package.json does not declare", n)
		}
	}
	return nil
}
