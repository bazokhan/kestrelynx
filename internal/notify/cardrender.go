// Card renderers: a pkgCard (cards.go) turned into the lines and blocks of
// one view. The lines are "label: value" pairs; every label comes from the
// messages dictionary, and the values keep the formats the plain-text
// renderers already use (versions, CVE links, EPSS, paths in inline code).
package notify

import (
	"fmt"
	"strings"

	rtevidence "github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// renderer carries what every card needs to render: the dictionary and the
// size limits sections are packed against.
type renderer struct {
	msg messages
	lim RenderLimits
}

// kv is one "label: value" line.
func kv(label, value string) string { return label + ": " + value }

// titleLine is the card's bold name line, with the ecosystem of a language
// package in brackets after one space.
func (c pkgCard) titleLine() string {
	s := boldLine("◆ ", boldMrkdwn(c.Name))
	if c.Ecosystem != "" {
		s += " [" + escMrkdwn(c.Ecosystem) + "]"
	}
	return s
}

// fixedValue is the value of the fixed-in line: the fixed version(s), or
// "none" with what to do about it.
func (rd renderer) fixedValue(c pkgCard) string {
	if c.Fixed != "" {
		return escMrkdwn(c.Fixed)
	}
	v := rd.msg.LblFixedNone
	if c.FixNote != "" {
		v += " — " + c.FixNote
	}
	return v
}

func (rd renderer) countsValue(c pkgCard) string {
	return fmt.Sprintf(rd.msg.CardCounts, c.Critical, c.High)
}

func (rd renderer) changeLine(c pkgCard) string {
	if len(c.Changes) == 0 {
		return ""
	}
	return kv(rd.msg.LblChange, strings.Join(c.Changes, " · "))
}

// topLine is the representative-CVE line, or "" when the card shows none.
func (rd renderer) topLine(c pkgCard) string {
	if !c.HasTop {
		return ""
	}
	t := c.Top
	parts := []string{cardIDLink(t.ID)}
	switch c.TopMode {
	case topFull:
		parts = append(parts, escMrkdwn(t.Severity))
		if t.IntelDegraded {
			parts = append(parts, rd.msg.EvidenceSeverityOnly)
		} else {
			parts = append(parts, fmt.Sprintf(rd.msg.EvidenceEPSSPrefix, escMrkdwn(t.EPSS)))
		}
	case topPlain:
		parts = append(parts, escMrkdwn(t.Severity))
	case topShort, topCompact:
		switch {
		case !t.Intel && c.TopMode == topCompact:
			parts = append(parts, escMrkdwn(t.Severity))
		case !t.Intel:
			return ""
		case t.KEV:
			parts = append(parts, rd.msg.CardKEVShort)
		default:
			parts = append(parts, fmt.Sprintf(rd.msg.EvidenceEPSSPrefix, escMrkdwn(t.EPSS)))
		}
	default:
		return ""
	}
	line := kv(rd.msg.LblTopCVE, strings.Join(parts, " · "))
	if c.Hint && c.MoreCVEs > 0 {
		line += fmt.Sprintf(rd.msg.EvidenceMoreCVEs, c.MoreCVEs)
	}
	return line
}

// exploitLine is the exploitation-facts line (CISA KEV, ransomware), shown
// only where the intel behind it is trustworthy.
func (rd renderer) exploitLine(c pkgCard) string {
	if !c.HasTop || c.TopMode != topFull || c.Top.IntelDegraded {
		return ""
	}
	var parts []string
	if c.Top.KEV {
		parts = append(parts, rd.msg.EvidenceKEV)
	}
	if c.Top.Ransomware {
		parts = append(parts, rd.msg.EvidenceRansomware)
	}
	if len(parts) == 0 {
		return ""
	}
	return kv(rd.msg.LblExploitation, strings.Join(parts, " · "))
}

func (rd renderer) refsLine(c pkgCard) string {
	links := refLinksSafe(c.Refs, rd.msg)
	if len(links) == 0 {
		return ""
	}
	return kv(rd.msg.LblReferences, strings.Join(links, " · "))
}

// evidenceLines are the lines of a card's evidence section: the
// representative CVE, its exploitation facts, and — where the view collected
// them — its title, the reference links and the other CVE ids.
func (rd renderer) evidenceLines(c pkgCard) []string {
	var lines []string
	if l := rd.topLine(c); l != "" {
		lines = append(lines, l)
	}
	if l := rd.exploitLine(c); l != "" {
		lines = append(lines, l)
	}
	if c.Title != "" {
		lines = append(lines, kv(rd.msg.LblSummary, escMrkdwn(c.Title)))
	}
	if l := rd.refsLine(c); l != "" {
		lines = append(lines, l)
	}
	if len(c.Others) > 0 {
		links := make([]string, len(c.Others))
		for i, id := range c.Others {
			links[i] = cardIDLink(id)
		}
		l := kv(rd.msg.LblOtherCVEs, strings.Join(links, ", "))
		if c.OthersExtra > 0 {
			l += fmt.Sprintf(rd.msg.MoreCount, c.OthersExtra)
		}
		lines = append(lines, l)
	}
	return lines
}

// runtimeLines are the lines of a card's runtime section. Only an in-use
// package yields the evidence, exposure and privilege facts, all from the
// one representative container; the not-in-use and unavailable states are
// shown only by the views that ask for them (rtAll).
func (rd renderer) runtimeLines(c pkgCard) []string {
	rt := c.Runtime
	switch c.RuntimeMode {
	case rtNone:
		return nil
	case rtShort:
		if rt.Usage != rtevidence.UsageInUse {
			return nil
		}
		return []string{kv(rd.msg.LblRuntime, fmt.Sprintf(rd.msg.InUsePrefix, rt.ShortWord))}
	}
	switch rt.Usage {
	case rtevidence.UsageInUse:
		lines := []string{kv(rd.msg.LblRuntime, rd.msg.InUseFallbackArrow)}
		if !rt.FactsOK {
			return lines
		}
		f := rt.Facts
		lines = append(lines, kv(rd.msg.LblEvidence, f.EvidenceBare))
		last := lastSeenText(f.LastSeen, rd.msg)
		var parts []string
		label := ""
		switch {
		case f.Exposure != "":
			label = rd.msg.LblExposure
			parts = append(parts, f.Exposure)
			if f.HighPrivilege {
				parts = append(parts, rd.msg.HighPrivilegeNote)
			}
		case f.HighPrivilege:
			label = rd.msg.LblPrivilege
			parts = append(parts, rd.msg.HighPrivilegeNote)
		}
		switch {
		case label != "":
			if last != "" {
				parts = append(parts, last)
			}
			lines = append(lines, kv(label, strings.Join(parts, " · ")))
		case !f.LastSeen.IsZero():
			lines = append(lines, kv(rd.msg.LblLastSeen, f.LastSeen.Format("01-02 15:04")))
		}
		return lines
	case rtevidence.UsageNotObserved:
		if c.RuntimeMode == rtAll {
			return []string{kv(rd.msg.LblRuntime, rd.msg.ThreadNotObserved)}
		}
	case rtevidence.UsageUnavailable:
		if c.RuntimeMode == rtAll {
			return []string{kv(rd.msg.LblRuntime, fmt.Sprintf(rd.msg.ThreadRuntimeUnavailable, rt.UnavailReason))}
		}
	}
	return nil
}

// ageText is the card's elapsed-time context line, "" when unknown.
func (rd renderer) ageText(c pkgCard) string {
	if !c.Age.Known {
		return ""
	}
	if c.Age.Days > 0 {
		return fmt.Sprintf(rd.msg.CardAgeLine, c.Age.Days, c.Age.FirstSeen)
	}
	return rd.msg.CardAgeToday
}

// detailHeadLines are the first section of a detail or thread card: name,
// change, installed and fixed versions, upgrade risk and finding counts.
func (rd renderer) detailHeadLines(c pkgCard) []string {
	lines := []string{c.titleLine()}
	if l := rd.changeLine(c); l != "" {
		lines = append(lines, l)
	}
	lines = append(lines, kv(rd.msg.LblInstalled, escMrkdwn(c.Installed)), kv(rd.msg.LblFixed, rd.fixedValue(c)))
	if v := riskValue(c.Risk, rd.msg); v != "" {
		lines = append(lines, kv(rd.msg.LblUpgradeRisk, v))
	}
	lines = append(lines, kv(rd.msg.LblFindings, rd.countsValue(c)))
	return lines
}

// detailCard is the channel's detail card: a head section, an evidence
// section and a runtime section, each present only when it has content.
func (rd renderer) detailCard(c pkgCard) []Block {
	blocks := sectionBlocks(rd.detailHeadLines(c), rd.lim.MaxTextUnits)
	blocks = append(blocks, sectionBlocks(rd.evidenceLines(c), rd.lim.MaxTextUnits)...)
	blocks = append(blocks, sectionBlocks(rd.runtimeLines(c), rd.lim.MaxTextUnits)...)
	return blocks
}

// threadCard is the thread's card: the head, evidence and runtime sections,
// then the age as context. A section with no values is not built. The view
// puts the divider in front.
func (rd renderer) threadCard(c pkgCard) []Block {
	blocks := rd.detailCard(c)
	if age := rd.ageText(c); age != "" {
		blocks = append(blocks, contextBlock(age))
	}
	return blocks
}

// contTitle heads the continuation of a card that had to be cut between its
// sections: the package name and its installed version.
// The name and version are shortened: the heading must stay small however
// long they are.
func (rd renderer) contTitle(c pkgCard) string {
	name := boldLine("◆ ", boldMrkdwnCapped(c.Name, contNameUnits))
	if c.Ecosystem != "" {
		name += " [" + capEscaped(escMrkdwn(c.Ecosystem), contNameUnits) + "]"
	}
	return name + rd.msg.ThreadContinued + "\n" + kv(rd.msg.LblInstalled, capEscaped(escMrkdwn(c.Installed), contNameUnits))
}

// contNameUnits caps a name or version repeated in a continuation heading.
const contNameUnits = 200

// capEscaped shortens already-escaped text to at most max UTF-16 units with
// an ellipsis, never inside an entity.
func capEscaped(s string, max int) string {
	if utf16Len(s) <= max {
		return s
	}
	var b strings.Builder
	n := 0
	for _, a := range runeAtoms(s) {
		if n+a.n > max-1 {
			break
		}
		b.WriteString(a.text)
		n += a.n
	}
	return b.String() + "…"
}

// imageHeadingCapped is imageHeading with the label shortened, for the
// heading a continuation message repeats.
func (rd renderer) imageHeadingCapped(label string) string {
	return boldLine(rd.msg.LblImage+": ", boldMrkdwnCapped(label, contNameUnits))
}

// compactLines are the lines of a card shown as one section: name, change,
// installed and fixed versions on one line (the upgrade risk in parentheses
// after the fixed version), counts, the representative CVE and the short
// runtime state.
func (rd renderer) compactLines(c pkgCard) []string {
	lines := []string{c.titleLine()}
	if l := rd.changeLine(c); l != "" {
		lines = append(lines, l)
	}
	fixed := rd.fixedValue(c)
	if v := riskValue(c.Risk, rd.msg); v != "" && c.Fixed != "" {
		fixed += " (" + v + ")"
	}
	lines = append(lines,
		kv(rd.msg.LblInstalled, escMrkdwn(c.Installed))+" · "+kv(rd.msg.LblFixed, fixed),
		kv(rd.msg.LblFindings, rd.countsValue(c)))
	if l := rd.topLine(c); l != "" {
		lines = append(lines, l)
	}
	if c.SeeActNow {
		lines = append(lines, kv(rd.msg.LblDetails, rd.msg.CardSeeActNow))
	}
	lines = append(lines, rd.runtimeLines(c)...)
	return lines
}

// imageHeading is the bold image line that opens an image's cards.
func (rd renderer) imageHeading(label string) string {
	return boldLine(rd.msg.LblImage+": ", boldMrkdwn(label))
}
