// Semantic layer of the Block Kit rendering: one package finding as a card of
// plain values (names, versions, ids, counts, facts), independent of how a
// view lays it out. The renderers in cardrender.go turn a card into blocks;
// nothing here knows about Slack markup beyond the CVE links and the
// untrusted-text escaping the existing helpers already provide.
package notify

import (
	"fmt"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	rtevidence "github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// topMode says how a card shows its representative CVE.
type topMode int

const (
	// topNone shows no CVE line.
	topNone topMode = iota
	// topShort is the compact form: id plus KEV or EPSS (the watch rows).
	// Nothing is shown when the intel behind it is degraded.
	topShort
	// topCompact is topShort, falling back to id plus severity when triage
	// is off or its intel is degraded (the diff's one-line rows).
	topCompact
	// topFull is id, severity and the exploitation facts (act now, thread).
	topFull
	// topPlain is id plus severity only, for views with no intel to cite.
	topPlain
)

// runtimeMode says how much of a card's runtime state is shown.
type runtimeMode int

const (
	// rtNone shows nothing.
	rtNone runtimeMode = iota
	// rtShort is the one-line "▶ in use (running)" form for an in-use package.
	rtShort
	// rtInUse is the full fact block, for an in-use package only.
	rtInUse
	// rtAll is the full fact block plus the not-in-use and unavailable states.
	rtAll
)

// cardCVE is a package's representative vulnerability: the strongest one.
type cardCVE struct {
	ID            string
	Severity      string
	EPSS          string // epssString result
	KEV           bool
	Ransomware    bool
	IntelDegraded bool
	// Intel is true when triage is on and its KEV/EPSS data is trustworthy,
	// i.e. when EPSS and KEV facts may be cited at all.
	Intel bool
}

// cardRef is one reference link of a vulnerability: the scanner's advisory
// (Kind "advisory"), the vendor advisory from the KEV notes ("vendor"), or a
// discussion thread ("discussion"). Label is the analyzer's own label, which
// only the discussion kind displays.
type cardRef struct {
	Kind  string
	Label string
	URL   string
}

// cardRuntime is a package's runtime-usage state as separate facts.
type cardRuntime struct {
	Usage         rtevidence.Usage // "" when runtime evidence was never attached
	ShortWord     string           // in use: "running" / "loaded" / "executed"
	Facts         inUseFacts       // in use: valid when FactsOK
	FactsOK       bool
	UnavailReason string // unavailable: the reason text
}

// cardAge is how long a finding has been open.
type cardAge struct {
	Known     bool
	Days      int // 0 means first seen today
	FirstSeen string
}

// pkgCard is one package finding as values. A view picks which of these to
// show; the card itself carries every value its builder was asked for.
type pkgCard struct {
	Name      string
	Ecosystem string // language packages only
	Installed string
	Fixed     string // fixed version(s); "" when there is none
	FixNote   string // what to do when there is no fix; "" when none applies
	Risk      analyze.Risk
	Critical  int
	High      int

	Changes []string // diff views: what changed for this package

	Top      cardCVE
	HasTop   bool
	TopMode  topMode
	MoreCVEs int // CVEs folded behind Top (hint form)
	Hint     bool

	Others      []string // thread: further CVE ids, raw
	OthersExtra int
	Title       string
	Refs        []cardRef

	RuntimeMode runtimeMode
	Runtime     cardRuntime

	Age cardAge

	SeeActNow bool // end-of-life act-now package: points at the Act now section

	// BaseWait is set when the finding lives in the base image of a
	// Dockerfile-built image and the plan found no newer tag of that base.
	BaseWait *baseWait
}

// cardOpts selects which values newPkgCard collects.
type cardOpts struct {
	top     topMode
	hint    bool // keep the "(+N more CVEs)" hint on the representative CVE
	notes   bool // fix note under "none" (otherwise the end-of-life row text only)
	runtime runtimeMode
	// thread collects the title, references and other CVE ids, and the age.
	thread bool
	// refs collects the references without the rest of the thread values.
	refs   bool
	change *state.Change
	age    func(image, pkg string) (time.Time, bool)
}

// cardRefsOf lists v's reference links in display order: the scanner's
// advisory first, then the references from the KEV notes.
func cardRefsOf(v analyze.VulnRef) []cardRef {
	var refs []cardRef
	if v.URL != "" {
		refs = append(refs, cardRef{Kind: "advisory", URL: v.URL})
	}
	for _, ref := range v.Refs {
		refs = append(refs, cardRef{Kind: ref.Kind, Label: ref.Label, URL: ref.URL})
	}
	return refs
}

// riskValue is the display value of an upgrade risk, without a label.
func riskValue(r analyze.Risk, msg messages) string {
	switch r {
	case analyze.RiskDistroUpdate:
		return msg.RiskValueDistroUpdate
	case analyze.RiskSafe:
		return msg.RiskValueSafe
	case analyze.RiskCaution:
		return msg.RiskValueCaution
	case analyze.RiskUnknown:
		return msg.RiskValueUnknown
	default:
		return ""
	}
}

// cardRuntimeOf collects the runtime facts of rt.
func cardRuntimeOf(rt analyze.Runtime, msg messages) cardRuntime {
	c := cardRuntime{Usage: rt.Usage}
	switch rt.Usage {
	case rtevidence.UsageInUse:
		c.ShortWord = runtimeShortWord(rt.EvidenceKinds, msg)
		c.Facts, c.FactsOK = runtimeInUseFacts(rt, msg)
	case rtevidence.UsageUnavailable:
		c.UnavailReason = reasonText(rt.Reason, msg)
	}
	return c
}

// newPkgCard collects one package group's values for a view. image is the
// reference the group belongs to (the age lookup is keyed on it).
func newPkgCard(r analyze.Report, image string, g analyze.PackageGroup, o cardOpts, msg messages) pkgCard {
	c := pkgCard{
		Name:        g.Package,
		Installed:   g.InstalledVer,
		Risk:        g.Risk,
		Critical:    g.Critical,
		High:        g.High,
		TopMode:     o.top,
		Hint:        o.hint,
		RuntimeMode: o.runtime,
	}
	if g.Class == "lang" {
		c.Ecosystem = langTag(g.Ecosystem)
	}
	switch {
	case g.Status == scanner.StatusFixed:
		c.Fixed = g.FixedVer
	case analyze.IsEOL(g):
		c.FixNote = msg.EOLPackageText
		if o.notes {
			c.FixNote = msg.FixNoteEOL
		}
	case o.notes && g.Status == scanner.StatusAffected:
		c.FixNote = msg.FixNoteMitigate
	case o.notes && g.Status == scanner.StatusWontFix:
		c.FixNote = msg.FixNoteWontFix
	}

	if top := g.TopVuln(); top.ID != "" && o.top != topNone {
		c.HasTop = true
		c.Top = cardCVE{
			ID:            top.ID,
			Severity:      string(top.Severity),
			EPSS:          epssString(top),
			KEV:           top.KEV,
			Ransomware:    top.Ransomware,
			IntelDegraded: r.Intel.Degraded(),
			Intel:         r.Triage && !r.Intel.Degraded(),
		}
		if rest := len(g.Vulns) - 1; rest > 0 {
			c.MoreCVEs = rest
		}
		if o.thread || o.refs {
			c.Refs = cardRefsOf(top)
		}
		if o.thread {
			c.Title = top.Title
			if len(g.Vulns) > 1 {
				ids := make([]string, 0, len(g.Vulns)-1)
				for _, v := range g.Vulns[1:] {
					ids = append(ids, v.ID)
				}
				if len(ids) > alsoIDsMax {
					c.OthersExtra = len(ids) - alsoIDsMax
					ids = ids[:alsoIDsMax]
				}
				c.Others = ids
			}
		}
	}

	if o.runtime != rtNone {
		c.Runtime = cardRuntimeOf(g.Runtime, msg)
	}
	if o.change != nil {
		c.Changes = changeParts(*o.change, g, msg)
	}
	if o.thread && o.age != nil {
		if t, ok := o.age(image, g.Package); ok {
			c.Age = cardAge{Known: true, Days: openDays(t, r.GeneratedAt), FirstSeen: t.Format("2006-01-02")}
		}
	}
	return c
}

// changeParts are the pieces of a package's "Change" line, in display order:
// the new CVE ids when the change carries some for this group, then the
// kind's own label. A plain new finding has no change line.
func changeParts(c state.Change, g analyze.PackageGroup, msg messages) []string {
	var parts []string
	if ids := groupNewIDs(c, g); len(ids) > 0 {
		shown, extra := ids, 0
		if len(ids) > newIDsMax {
			shown, extra = ids[:newIDsMax], len(ids)-newIDsMax
		}
		links := make([]string, len(shown))
		for i, id := range shown {
			links[i] = cardIDLink(id)
		}
		s := fmt.Sprintf(msg.CardNewCVEs, strings.Join(links, ", "))
		if extra > 0 {
			s += fmt.Sprintf(msg.MoreCount, extra)
		}
		parts = append(parts, s)
	}
	switch c.Kind {
	case state.KindEscalated:
		parts = append(parts, fmt.Sprintf(msg.EscalatedTo, priorityLabel(analyze.MaxPriority(c.Groups), msg)))
	case state.KindNowFixable:
		parts = append(parts, msg.FixNowAvailable)
	case state.KindUnmuted:
		parts = append(parts, fmt.Sprintf(msg.Unmuted, unmutedReason(changeReasonGroups(c), msg)))
	}
	return parts
}

// stripLeadDash drops the " — " an inline suffix format starts with, for
// reuse of the same wording as a line of its own.
func stripLeadDash(s string) string { return strings.TrimPrefix(s, " — ") }
