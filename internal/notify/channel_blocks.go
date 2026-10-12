// Block Kit rendering of the channel message: the full open-findings view and
// the diff-mode view, laid out as sections, dividers and contexts and split
// across messages when one would not hold them.
package notify

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// FooterKind selects the closing note of the channel message's first message.
type FooterKind int

const (
	// FooterNone adds nothing.
	FooterNone FooterKind = iota
	// FooterThreadNotice points at the thread posted under the message.
	FooterThreadNotice
	// FooterLastReport links the last posted thread, on a day none is posted.
	FooterLastReport
)

// ChannelFooter is the closing note of the channel message. The note sits at
// the end of the first message, because the thread is attached to it.
type ChannelFooter struct {
	Kind FooterKind
	// Permalink is the last thread's link, for FooterLastReport.
	Permalink string
}

// BuildChannelMessages renders the channel message for m (the full
// open-findings view, or the diff view when m.Diff is set) as one or more
// Slack messages. Only the first carries the footer.
func BuildChannelMessages(m Message, footer ChannelFooter, lang Language) []SlackMessage {
	return buildChannelMessages(m, footer, messagesFor(lang), defaultRenderLimits)
}

func buildChannelMessages(m Message, footer ChannelFooter, msg messages, lim RenderLimits) []SlackMessage {
	lim = lim.normalized()
	v := &chView{
		r:       m.Report,
		full:    m.FullReport,
		holding: m.Holding,
		msg:     msg,
		rd:      renderer{msg: msg, lim: lim},
		byRef:   imagesByRef(m.Report),
	}
	if m.Diff != nil {
		d := *m.Diff
		v.d = &d
		v.buildDiff()
	} else {
		v.buildFull()
	}
	return splitUnits(v.l.units, splitSpec{
		lim: lim,
		lead: func(n, total int) string {
			return headerLine(v.r, msg) + fmt.Sprintf(msg.ChannelContinued, n, total)
		},
		cont: msg.ThreadContinued,
		fallback: func(info msgInfo) string {
			if info.n > 1 {
				return fmt.Sprintf(msg.FbContinued, v.dateText(), v.role, info.n, info.total)
			}
			return v.fallbackText()
		},
		footer:          footerText(footer, msg, lim),
		footerJoinsTail: true,
	})
}

// footerText is the footer's context text: the dictionary line without its
// surrounding newlines and italics.
func footerText(f ChannelFooter, msg messages, lim RenderLimits) string {
	switch f.Kind {
	case FooterThreadNotice:
		return strings.Trim(strings.TrimSpace(msg.ThreadPostedNotice), "_")
	case FooterLastReport:
		// The link is built only from a URL fit to be one; a permalink that
		// is not shows no footer rather than a broken link.
		if !validLinkURL(f.Permalink) {
			return ""
		}
		text := strings.TrimSpace(fmt.Sprintf(msg.LastReportLink, strings.ReplaceAll(f.Permalink, "&", "&amp;")))
		// A link too long for one context cannot be shown: no footer at all
		// rather than words that point nowhere.
		if utf16Len(text) > lim.MaxTextUnits {
			return ""
		}
		return text
	}
	return ""
}

// unresolvedNoteHead is what the identity-unconfirmed note is about: the
// note's own wording up to the reference list. A later message of a long
// list starts with it.
func unresolvedNoteHead(msg messages) string {
	return strings.TrimSuffix(trimNL(fmt.Sprintf(msg.UnresolvedRefsLine, msg.IdentityUnconfirmed, "")), " — ")
}

// unconfirmedNoteHead is unresolvedNoteHead for the held-findings note.
func unconfirmedNoteHead(msg messages) string {
	head, _, _ := strings.Cut(msg.UnconfirmedRefsLine, "%s")
	return strings.TrimSuffix(strings.TrimSpace(head), " —")
}

// headerLine is the product header line.
func headerLine(r analyze.Report, msg messages) string {
	if r.Environment.Name != "" {
		return trimNL(fmt.Sprintf(msg.HeaderNamed, escMrkdwn(r.Environment.Name), r.GeneratedAt.Format(timeLayout)))
	}
	return trimNL(fmt.Sprintf(msg.HeaderDefault, r.GeneratedAt.Format(timeLayout)))
}

// chView builds one channel message's units.
type chView struct {
	r       analyze.Report
	d       *state.Diff // nil in full mode
	full    bool        // the weekly full report in diff mode
	holding bool
	msg     messages
	rd      renderer
	byRef   map[string]analyze.ImageObservation
	ages    Ages // thread view only
	l       layout

	role string   // the role phrase, for the fallback text
	segs []string // the fallback text's count segments
}

// dateText is the generated-at time, preceded by the environment name when
// the environment has one.
func (v *chView) dateText() string {
	t := v.r.GeneratedAt.Format(timeLayout)
	if v.r.Environment.Name != "" {
		return "[" + escMrkdwn(v.r.Environment.Name) + "] " + t
	}
	return t
}

func (v *chView) fallbackText() string {
	if len(v.segs) == 0 {
		return fmt.Sprintf(v.msg.FbPlain, v.dateText(), v.role)
	}
	return fmt.Sprintf(v.msg.FbFull, v.dateText(), v.role, strings.Join(v.segs, " · "))
}

// --- full view ---

func (v *chView) buildFull() {
	v.role = v.msg.FbRoleEverythingOpen
	v.headSection("_" + v.msg.RoleEverythingOpen + "_")
	if !v.r.HasIssues() {
		v.l.group()
		v.l.section(v.rd.lim, []string{trimNL(v.msg.AllClear)}, false)
		v.unresolvedNotes(false)
		return
	}
	v.fullBody(true)
}

// headSection emits the header section — product header, scan counts and the
// role line — and the Sensor warning, if any.
func (v *chView) headSection(roleLine string) {
	lines := []string{
		headerLine(v.r, v.msg),
		trimNL(fmt.Sprintf(v.msg.ImagesScannedAffected, v.r.ImagesTotal, v.r.AffectedImageCount())),
	}
	if roleLine != "" {
		lines = append(lines, roleLine)
	}
	v.l.section(v.rd.lim, lines, false)
	if w := runtimeWarning(v.r, v.r.GeneratedAt, v.msg); w != "" {
		v.l.section(v.rd.lim, []string{trimNL(w)}, false)
	}
}

// fullBody lays out the complete open-findings view: the priority line, the
// intel warning, the categories and the summary group. It is shared by the
// full view and the weekly digest. intel says whether the intel warning is
// emitted here (the diff view emits it with its own head).
func (v *chView) fullBody(intel bool) {
	r, msg := v.r, v.msg
	var cats func()
	var summary func(start func())
	if r.Triage {
		pv := r.ByPriority()
		// ActNow is never filtered: a group eligible for muting is never
		// act_now by construction.
		pv.Watch = filterMuted(pv.Watch)
		pv.Low = filterMuted(pv.Low)
		v.prioritySection(triageSegments(r, pv, msg))
		if intel {
			v.intelSection()
		}
		cats = func() {
			v.eoslCategory(r.EOSLImages)
			v.eolPackagesCategory()
			v.actNowCategory(pv.ActNow)
			v.watchCategory(pv.Watch)
		}
		summary = func(start func()) {
			if n := analyze.GroupCount(pv.Low); n > 0 {
				start()
				lines := []string{trimNL(fmt.Sprintf(msg.LowHeading, n, n, len(pv.Low)))}
				if inUse := countInUse(pv.Low); inUse > 0 {
					lines[0] += fmt.Sprintf(msg.TriageLowInUseCount, inUse)
				}
				// The generic webhook is the only destination with per-package
				// detail beyond this count, and only when one is actually
				// configured.
				if r.GenericWebhookConfigured {
					lines = append(lines, trimNL(msg.DetailsInWebhook))
				}
				v.l.section(v.rd.lim, lines, false)
			}
		}
		v.segs = triageSegments(r, pv, msg)
	} else {
		p := summarize(r)
		v.prioritySection(headlineSegments(p, msg))
		collapsed := 0
		cats = func() {
			v.eoslCategory(r.EOSLImages)
			v.eolPackagesCategory()
			collapsed = v.actionableCategory(r.Actionable)
			v.statusCategory(msg.WatchSectionTitle, filterMuted(r.Watch))
			v.statusCategory(msg.WontFixSectionTitle, filterMuted(r.WontFix))
		}
		summary = func(start func()) {}
		defer func() {
			if collapsed > 0 {
				note := msg.LowerRiskSummarized
				if r.GenericWebhookConfigured {
					note = msg.LowerRiskSummarizedWebhook
				}
				v.l.section(v.rd.lim, []string{fmt.Sprintf(trimNL(note), collapsed)}, false)
			}
		}()
		v.segs = nonTriageSegments(r, msg)
	}
	cats()

	started := false
	start := func() {
		if !started {
			v.l.group()
			started = true
		}
	}
	summary(start)
	if n := mutedCount(r); n > 0 {
		start()
		v.l.section(v.rd.lim, []string{trimNL(fmt.Sprintf(msg.MutedLine, n))}, false)
	}
	if len(r.ScanErrors) > 0 {
		start()
		v.scanErrorsSection()
	}
	if r.Triage && r.Intel.StaleDays > 0 && !r.Intel.Degraded() {
		start()
		v.l.section(v.rd.lim, []string{trimNL(fmt.Sprintf(msg.IntelStale, r.Intel.StaleDays))}, false)
	}
	if r.Runtime != nil {
		start()
		inUse, notObserved, unavailable, _ := runtimeCounts(r)
		v.l.section(v.rd.lim, []string{emphasizeLabel(trimNL(fmt.Sprintf(msg.RuntimeSummaryCounts, inUse, notObserved, unavailable)))}, false)
		v.l.note(v.rd.lim, "", strings.Trim(strings.TrimSpace(msg.RuntimeSummaryNote), "_"), false)
	}
	v.unresolvedNotes(false)
}

func (v *chView) prioritySection(segs []string) {
	if len(segs) == 0 {
		return
	}
	v.l.section(v.rd.lim, []string{trimNL(fmt.Sprintf(v.msg.PriorityLine, strings.Join(segs, " · ")))}, false)
}

func (v *chView) intelSection() {
	if w := intelWarning(v.r, v.msg); w != "" {
		v.l.section(v.rd.lim, []string{trimNL(w)}, false)
	}
}

func (v *chView) scanErrorsSection() {
	lines := []string{trimNL(v.msg.ScanFailuresHeading)}
	for _, e := range v.r.ScanErrors {
		lines = append(lines, trimNL(fmt.Sprintf(v.msg.ScanFailureLine, escMrkdwn(refLabel(e.Image, v.byRef, v.msg)), escMrkdwn(e.Err))))
	}
	v.l.section(v.rd.lim, lines, false)
}

// unresolvedNotes emits the cross-cutting identity notes as contexts.
func (v *chView) unresolvedNotes(tail bool) {
	if line := unresolvedRefsLine(v.r, v.msg); line != "" {
		v.l.note(v.rd.lim, unresolvedNoteHead(v.msg), trimNL(line), tail)
	}
	if line := unconfirmedRefsLine(v.r, v.msg); line != "" {
		v.l.note(v.rd.lim, unconfirmedNoteHead(v.msg), trimNL(line), tail)
	}
}

// nonTriageSegments are the fallback segments of the triage-off view: the
// end-of-life counts, then the groups per fix status.
func nonTriageSegments(r analyze.Report, msg messages) []string {
	var seg []string
	if n := len(r.EOSLImages); n > 0 {
		seg = append(seg, fmt.Sprintf(msg.SegEOLBase, n))
	}
	if n := analyze.GroupCount(r.EOLPackageAlerts()); n > 0 {
		seg = append(seg, fmt.Sprintf(msg.SegEOLPackage, n))
	}
	if n := analyze.GroupCount(r.Actionable); n > 0 {
		seg = append(seg, fmt.Sprintf(msg.FbSegActionable, n))
	}
	if n := analyze.GroupCount(filterMuted(r.Watch)); n > 0 {
		seg = append(seg, fmt.Sprintf(msg.FbSegNoFix, n))
	}
	if n := analyze.GroupCount(filterMuted(r.WontFix)); n > 0 {
		seg = append(seg, fmt.Sprintf(msg.FbSegWontFix, n))
	}
	return seg
}

// --- image and card views ---

// imageHeadingOf builds an image view's heading from an image label; counts
// adds the per-image finding counts the triage-off view shows.
func (v *chView) imageHeadingOf(label string) imageView {
	return imageView{heading: v.rd.imageHeading(label), cont: v.rd.imageHeadingCapped(label), name: escMrkdwn(label)}
}

func (v *chView) imageOf(img analyze.ImageFindings, counts bool) imageView {
	label := imageLabel(img, v.byRef, v.msg)
	iv := v.imageHeadingOf(label)
	if counts {
		iv.extra = []string{imageEmoji(img) + " " + fmt.Sprintf(v.msg.CardCounts, img.CriticalCount(), img.TotalCount()-img.CriticalCount())}
	}
	return iv
}

func (v *chView) detail(c pkgCard) cardView {
	return cardView{detail: true, blocks: v.rd.detailCard(c), pkgs: 1, contTitle: v.rd.contTitle(c)}
}

func (v *chView) compact(c pkgCard) cardView {
	return cardView{lines: v.rd.compactLines(c), pkgs: 1, contTitle: v.rd.contTitle(c)}
}

// pseudo is a compact card made of plain lines (an end-of-life base image,
// a collapsed line), not counted as a package.
func pseudo(lines ...string) cardView { return cardView{lines: lines} }

// --- categories ---

func (v *chView) eoslCategory(imgs []string) {
	if len(imgs) == 0 {
		return
	}
	views := make([]imageView, 0, len(imgs))
	for _, img := range imgs {
		iv := v.imageHeadingOf(refLabel(img, v.byRef, v.msg))
		lines := []string{kv(v.msg.LblStatus, v.msg.CardEOSLStatus)}
		if n := v.r.FoldedEOLCount(img); n > 0 {
			lines = append(lines, fmt.Sprintf(v.msg.CardFoldedEOL, n))
		}
		iv.cards = []cardView{pseudo(lines...)}
		views = append(views, iv)
	}
	v.l.channelCategory(v.rd.lim, trimNL(v.msg.EOSLHeading), v.msg.ShortEOLBase, views)
}

func (v *chView) eolPackagesCategory() {
	imgs := v.r.EOLPackageAlerts()
	n := analyze.GroupCount(imgs)
	if n == 0 {
		return
	}
	var views []imageView
	for _, img := range imgs {
		iv := v.imageOf(img, !v.r.Triage)
		for _, g := range img.Packages {
			o := cardOpts{}
			// With triage on, an act_now group only points at Act now,
			// which shows it in full.
			see := v.r.Triage && g.Priority == analyze.PriorityActNow
			if v.r.Triage && !see {
				o.top = topShort
			}
			c := newPkgCard(v.r, img.Image, g, o, v.msg)
			c.SeeActNow = see
			cv := v.compact(c)
			if see {
				cv.pkgs = 0 // a pointer card is not a package shown here
			}
			iv.cards = append(iv.cards, cv)
		}
		views = append(views, iv)
	}
	v.l.channelCategory(v.rd.lim, trimNL(fmt.Sprintf(v.msg.EOLPackageHeading, n, v.msg.EOLSectionReason)), v.msg.ShortEOLPackage, views)
}

func (v *chView) actNowCategory(imgs []analyze.ImageFindings) {
	if len(imgs) == 0 {
		return
	}
	var views []imageView
	for _, img := range imgs {
		iv := v.imageOf(img, false)
		for _, g := range img.Packages {
			c := newPkgCard(v.r, img.Image, g, cardOpts{top: topFull, hint: true, notes: true, refs: true, runtime: rtInUse}, v.msg)
			iv.cards = append(iv.cards, v.detail(c))
		}
		views = append(views, iv)
	}
	n := analyze.GroupCount(imgs)
	v.l.channelCategory(v.rd.lim, trimNL(fmt.Sprintf(v.msg.ActNowHeading, n)), priorityShort(analyze.PriorityActNow, v.msg), views)
}

func (v *chView) watchCategory(imgs []analyze.ImageFindings) {
	if len(imgs) == 0 {
		return
	}
	var views []imageView
	for _, img := range imgs {
		iv := v.imageOf(img, false)
		for _, g := range img.Packages {
			c := newPkgCard(v.r, img.Image, g, cardOpts{top: topShort, runtime: rtShort}, v.msg)
			iv.cards = append(iv.cards, v.compact(c))
		}
		views = append(views, iv)
	}
	n := analyze.GroupCount(imgs)
	v.l.channelCategory(v.rd.lim, trimNL(fmt.Sprintf(v.msg.WatchHeading, n)), priorityShort(analyze.PriorityWatch, v.msg), views)
}

// priorityShort is the short name of a priority bucket: emoji and label.
func priorityShort(p analyze.Priority, msg messages) string {
	return priorityEmoji(p) + " " + priorityLabel(p, msg)
}

// actionableCategory lays out the triage-off fixable section: packages that
// need attention as cards, the rest as one collapsed line per image. It
// returns the number of packages collapsed.
func (v *chView) actionableCategory(imgs []analyze.ImageFindings) int {
	if len(imgs) == 0 {
		return 0
	}
	collapsed := 0
	var views []imageView
	for _, img := range imgs {
		iv := v.imageOf(img, true)
		var rest []analyze.PackageGroup
		for _, g := range img.Packages {
			if needsAttention(g) {
				iv.cards = append(iv.cards, v.compact(newPkgCard(v.r, img.Image, g, cardOpts{runtime: rtShort}, v.msg)))
			} else {
				rest = append(rest, g)
			}
		}
		if len(rest) > 0 {
			collapsed += len(rest)
			var crit, high int
			names := make([]string, 0, len(rest))
			for _, g := range rest {
				crit += g.Critical
				high += g.High
				names = append(names, escMrkdwn(g.Package))
			}
			iv.cards = append(iv.cards, pseudo(fmt.Sprintf(v.msg.CardCollapsed, len(rest), collapsedSeverity(crit, high), collapsedNames(names, v.msg))))
		}
		views = append(views, iv)
	}
	v.l.channelCategory(v.rd.lim, "*"+v.msg.ActionableTitle+"*", v.msg.ActionableTitle, views)
	return collapsed
}

// statusCategory lays out one triage-off section with every package as a
// card.
func (v *chView) statusCategory(title string, imgs []analyze.ImageFindings) {
	if len(imgs) == 0 {
		return
	}
	var views []imageView
	for _, img := range imgs {
		iv := v.imageOf(img, true)
		for _, g := range img.Packages {
			iv.cards = append(iv.cards, v.compact(newPkgCard(v.r, img.Image, g, cardOpts{runtime: rtShort}, v.msg)))
		}
		views = append(views, iv)
	}
	v.l.channelCategory(v.rd.lim, "*"+title+"*", title, views)
}

// --- diff view ---

func (v *chView) buildDiff() {
	r, d, msg := v.r, *v.d, v.msg
	hasChanges := d.HasChanges()
	early := !hasChanges && !v.full
	roleLine := ""
	switch {
	case !v.full && hasChanges:
		v.role = msg.FbRoleChanges
		roleLine = "_" + msg.RoleChangesSinceLastScan + "_"
	case early:
		v.role = msg.FbRoleNoChanges
		roleLine = strings.TrimSpace(msg.NoChangesSinceLastScan)
	default:
		v.role = msg.FbRoleWeekly
	}
	v.headSection(roleLine)
	if r.Triage && !early {
		v.intelSection()
	}

	// Replaced is itself a change, ahead of the "no changes" check.
	if len(d.Replaced) > 0 {
		v.l.group()
		lines := []string{trimNL(fmt.Sprintf(msg.ReplacedHeading, len(d.Replaced)))}
		for _, rep := range d.Replaced {
			lines = append(lines, trimNL(fmt.Sprintf(msg.ReplacedLine, escMrkdwn(rep.Ref), escMrkdwn(joinShortDigests(rep.PrevContentIDs)), escMrkdwn(joinShortDigests(rep.ContentIDs)))))
		}
		v.l.section(v.rd.lim, lines, false)
	}
	// A reference change is a change too: the same workload moved to another
	// tag or digest of its repository, with its history carried over.
	if len(d.RefChanges) > 0 {
		v.l.group()
		lines := make([]string, 0, len(d.RefChanges))
		for _, rc := range d.RefChanges {
			lines = append(lines, trimNL(fmt.Sprintf(msg.RefChangeLine, escMrkdwn(rc.Repository), escMrkdwn(refTagLabel(rc.PreviousRef)), escMrkdwn(refTagLabel(rc.Ref)))))
		}
		v.l.section(v.rd.lim, lines, false)
	}

	if early {
		v.diffSegs(0, 0, 0, len(d.Replaced), len(d.RefChanges))
		v.diffTail(false)
		return
	}

	eol := splitEOLChanges(d)
	v.newEOSLCategory(d, eol)
	eolN := v.eolChangesCategory(eol)

	var newN int
	if r.Triage {
		newN = v.triageChanges(d.Changes)
	} else {
		newN = v.changes(d.Changes)
	}
	resolvedN, resolvedLines := resolvedParts(d, v.byRef, msg)
	if resolvedN > 0 {
		v.l.group()
		v.l.section(v.rd.lim, append([]string{trimNL(fmt.Sprintf(msg.ResolvedHeading, resolvedN))}, resolvedLines...), false)
	}

	if v.full {
		// The weekly digest: the complete open-findings view follows, with
		// its own fallback counts.
		v.l.group()
		v.l.heading(v.rd.lim, []string{trimNL(msg.WeeklyFullReportHeading)})
		v.fullBody(false)
		return
	}
	v.diffSegs(newN, resolvedN, len(d.NewEOSL)+eolN, len(d.Replaced), len(d.RefChanges))
	v.diffTail(resolvedN > 0)
}

// diffSegs sets the fallback segments of a diff view: what changed, zero
// counts omitted.
func (v *chView) diffSegs(newN, resolvedN, eolNew, replaced, refChanged int) {
	msg := v.msg
	var seg []string
	if eolNew > 0 {
		seg = append(seg, fmt.Sprintf(msg.FbSegEOLNew, eolNew))
	}
	if newN > 0 {
		seg = append(seg, fmt.Sprintf(msg.FbSegNew, newN))
	}
	if resolvedN > 0 {
		seg = append(seg, fmt.Sprintf(msg.FbSegResolved, resolvedN))
	}
	if replaced > 0 {
		seg = append(seg, fmt.Sprintf(msg.FbSegReplaced, replaced))
	}
	if refChanged > 0 {
		seg = append(seg, fmt.Sprintf(msg.FbSegRefChanged, refChanged))
	}
	if n := len(v.r.ScanErrors); n > 0 {
		seg = append(seg, fmt.Sprintf(msg.FbSegScanFailed, n))
	}
	v.segs = seg
}

// diffTail closes a diff view that is not the weekly digest: scan failures
// (sharing the group of the resolved list when there is one), the open-now
// summary, the muted count and the identity notes. The open-now group is the
// tail the footer notice joins.
func (v *chView) diffTail(joinResolved bool) {
	r, d, msg := v.r, *v.d, v.msg
	if len(r.ScanErrors) > 0 {
		if !joinResolved {
			v.l.group()
		}
		v.scanErrorsSection()
	}
	v.l.group()
	v.l.section(v.rd.lim, v.openNowLines(r, d), true)
	if n := mutedCount(r); n > 0 {
		v.l.section(v.rd.lim, []string{trimNL(fmt.Sprintf(msg.MutedLine, n))}, true)
	}
	v.unresolvedNotes(true)
}

// openNowLines is the open-now summary: the counts, and on a line of its own
// the age of the oldest unresolved finding.
func (v *chView) openNowLines(r analyze.Report, d state.Diff) []string {
	msg := v.msg
	if !r.HasFindings() {
		var b strings.Builder
		writeNothingOpenNow(&b, d, v.holding, msg)
		return []string{emphasizeLabel(trimNL(b.String()))}
	}
	var seg []string
	var days int
	var ageFmt, staleFmt string
	if r.Triage {
		seg = openNowEOLSegments(d, true, msg)
		if d.OpenActNow > 0 {
			seg = append(seg, fmt.Sprintf(msg.OpenNowActNow, d.OpenActNow))
		}
		if d.OpenWatch > 0 {
			seg = append(seg, fmt.Sprintf(msg.SegWatch, d.OpenWatch))
		}
		if d.OpenLow > 0 {
			seg = append(seg, fmt.Sprintf(msg.SegLow, d.OpenLow))
		}
		days = d.OldestUrgentDays(r.GeneratedAt)
		ageFmt, staleFmt = msg.OldestActNowWatch, msg.OldestActNowWatchStale
	} else {
		seg = append(openNowEOLSegments(d, false, msg), fmt.Sprintf(msg.OpenNowCriticalHigh, d.OpenCritical, d.OpenHigh, d.OpenImages))
		days = d.OldestOpenDays(r.GeneratedAt)
		ageFmt, staleFmt = msg.OldestUnresolved, msg.OldestUnresolvedStale
	}
	lines := []string{emphasizeLabel(trimNL(fmt.Sprintf(msg.OpenNowPrefix, strings.Join(seg, " / "))))}
	if days > 0 {
		f := ageFmt
		if days >= staleDays {
			f = staleFmt
		}
		lines = append(lines, stripLeadDash(fmt.Sprintf(f, days)))
	}
	if r.GenericWebhookConfigured {
		lines = append(lines, trimNL(msg.DetailsInWebhook))
	}
	return lines
}

func (v *chView) newEOSLCategory(d state.Diff, eol eolChangeView) {
	if len(d.NewEOSL) == 0 {
		return
	}
	views := make([]imageView, 0, len(d.NewEOSL))
	for _, img := range d.NewEOSL {
		iv := v.imageHeadingOf(refLabel(img, v.byRef, v.msg))
		lines := []string{kv(v.msg.LblStatus, v.msg.CardEOSLStatus)}
		if n := eol.newEOSLNote[img]; n > 0 {
			lines = append(lines, fmt.Sprintf(v.msg.CardNewEOSLNote, n))
		}
		iv.cards = []cardView{pseudo(lines...)}
		views = append(views, iv)
	}
	v.l.channelCategory(v.rd.lim, trimNL(v.msg.HeadingNewEOSL), v.msg.ShortEOLBase, views)
}

// eolChangesCategory lays out the diff's end-of-life package changes and
// returns how many it counted.
func (v *chView) eolChangesCategory(eol eolChangeView) int {
	n := eol.count()
	if n == 0 {
		return 0
	}
	r, msg := v.r, v.msg
	rows := eol.rows
	if r.Triage {
		rows = append([]state.EOLChange(nil), eol.rows...)
		sort.SliceStable(rows, func(i, j int) bool {
			pi, pj := analyze.MaxPriority(rows[i].Groups), analyze.MaxPriority(rows[j].Groups)
			if pi.Rank() != pj.Rank() {
				return pi.Rank() > pj.Rank()
			}
			if rows[i].Image != rows[j].Image {
				return rows[i].Image < rows[j].Image
			}
			return rows[i].Package < rows[j].Package
		})
	}
	var views []imageView
	lastImage := ""
	for _, c := range rows {
		if c.Image != lastImage || len(views) == 0 {
			views = append(views, v.imageHeadingOf(refLabel(c.Image, v.byRef, msg)))
			lastImage = c.Image
		}
		iv := &views[len(views)-1]
		asChange := eolAsChange(c)
		for _, g := range c.Groups {
			iv.cards = append(iv.cards, v.changeCard(c.Image, asChange, g, false))
		}
	}
	for _, f := range eol.folds {
		var parts []string
		if f.newPackages > 0 {
			parts = append(parts, fmt.Sprintf(msg.EOLFoldNewPackages, f.newPackages))
		}
		if f.withNewCVEs > 0 {
			parts = append(parts, fmt.Sprintf(msg.EOLFoldWithNewCVEs, f.withNewCVEs))
		}
		iv := v.imageHeadingOf(refLabel(f.ref, v.byRef, msg))
		iv.cards = []cardView{pseudo(strings.Join(parts, ", ") + " (" + msg.CardBaseEOL + ")")}
		views = append(views, iv)
	}
	v.l.channelCategory(v.rd.lim, trimNL(fmt.Sprintf(msg.EOLPackagesChangedHeading, n, msg.EOLSectionReason)), v.msg.ShortEOLPackage, views)
	return n
}

// changeCard is the card of one package group of a change: a detail card for
// an act_now group (its evidence is the point), a compact one otherwise.
// runtime says whether the runtime state is shown.
func (v *chView) changeCard(image string, c state.Change, g analyze.PackageGroup, runtime bool) cardView {
	o := cardOpts{change: &c}
	if v.r.Triage && g.Priority == analyze.PriorityActNow {
		o.top, o.hint, o.notes, o.refs = topFull, true, true, true
		if runtime {
			o.runtime = rtInUse
		}
		return v.detail(newPkgCard(v.r, image, g, o, v.msg))
	}
	if len(groupNewIDs(c, g)) == 0 {
		o.top = topCompact
	}
	if runtime {
		o.runtime = rtShort
	}
	return v.compact(newPkgCard(v.r, image, g, o, v.msg))
}

// triageChanges lays out the new and changed findings, most urgent first. It
// returns the number of changes shown.
func (v *chView) triageChanges(changes []state.Change) int {
	if len(changes) == 0 {
		return 0
	}
	sorted := make([]state.Change, len(changes))
	copy(sorted, changes)
	// Sorted by the change's full priority (all groups, muted or not) —
	// priority is never touched by muting, so this order must not be
	// either.
	sort.SliceStable(sorted, func(i, j int) bool {
		pi, pj := analyze.MaxPriority(sorted[i].Groups), analyze.MaxPriority(sorted[j].Groups)
		if pi.Rank() != pj.Rank() {
			return pi.Rank() > pj.Rank()
		}
		if sorted[i].Image != sorted[j].Image {
			return sorted[i].Image < sorted[j].Image
		}
		return sorted[i].Package < sorted[j].Package
	})
	return v.changeList(visibleChanges(sorted))
}

// changes lays out the new and changed findings in report order (triage
// off). It returns the number of changes shown.
func (v *chView) changes(changes []state.Change) int {
	return v.changeList(visibleChanges(changes))
}

func (v *chView) changeList(visible []visibleChange) int {
	if len(visible) == 0 {
		return 0
	}
	var views []imageView
	lastImage := ""
	for _, vc := range visible {
		if vc.change.Image != lastImage || len(views) == 0 {
			views = append(views, v.imageHeadingOf(refLabel(vc.change.Image, v.byRef, v.msg)))
			lastImage = vc.change.Image
		}
		iv := &views[len(views)-1]
		for _, g := range vc.groups {
			iv.cards = append(iv.cards, v.changeCard(vc.change.Image, vc.change, g, true))
		}
	}
	v.l.channelCategory(v.rd.lim, trimNL(fmt.Sprintf(v.msg.NewSinceLastScanHeading, len(visible))), "", views)
	return len(visible)
}
