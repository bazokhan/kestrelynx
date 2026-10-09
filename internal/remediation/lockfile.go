package remediation

import (
	"fmt"
	"sort"
)

// UnsupportedError means a dependency file is read but not in a form the plan
// handles, so its unit goes to a person. Reason is a fixed code and Detail
// says what was seen.
type UnsupportedError struct {
	Reason Reason
	Detail string
}

func (e *UnsupportedError) Error() string { return fmt.Sprintf("%s: %s", e.Reason, e.Detail) }

func unsupported(reason Reason, format string, args ...any) *UnsupportedError {
	return &UnsupportedError{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// lockedPackage is every occurrence of one package name in a unit's files.
type lockedPackage struct {
	name string // the spelling in the file
	occs []SourceOccurrence
}

// lockfile is what a parser makes of a unit's dependency files: the
// occurrences of each package, by matching key (the name itself for npm and
// pnpm, the PEP 503 name for Python).
type lockfile struct {
	manager DependencyManager
	pkgs    map[string]*lockedPackage
	// forced names packages whose version is fixed by something other than
	// the lockfile (an override, a source table), with the reason.
	forced map[string]string
}

func newLockfile(m DependencyManager) *lockfile {
	return &lockfile{manager: m, pkgs: map[string]*lockedPackage{}, forced: map[string]string{}}
}

// key is the matching key of a package name.
func (l *lockfile) key(name string) string {
	if l.manager.scheme() == schemePEP440 {
		return normalizePyName(name)
	}
	return name
}

func (l *lockfile) add(name string, o SourceOccurrence) {
	k := l.key(name)
	p := l.pkgs[k]
	if p == nil {
		p = &lockedPackage{name: name}
		l.pkgs[k] = p
	}
	p.occs = append(p.occs, o)
}

func (l *lockfile) force(name, why string) {
	l.forced[l.key(name)] = why
}

func (l *lockfile) lookup(name string) *lockedPackage { return l.pkgs[l.key(name)] }

// sortOccurrences makes the order of occurrences independent of map order.
func sortOccurrences(os []SourceOccurrence) {
	sort.SliceStable(os, func(i, j int) bool {
		if os[i].Path != os[j].Path {
			return os[i].Path < os[j].Path
		}
		return os[i].Version < os[j].Version
	})
}

// finish orders the occurrences of every package.
func (l *lockfile) finish() *lockfile {
	for _, p := range l.pkgs {
		sortOccurrences(p.occs)
	}
	return l
}
