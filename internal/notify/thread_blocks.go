// Block Kit rendering of the thread report: everything currently open, with
// every package as a card carrying its evidence, references, runtime state
// and age, split across replies at card boundaries.
package notify

import (
	"fmt"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
)

// BuildThreadBlockMessages renders the full open-findings report as one or
// more Slack messages to post as replies under the channel message. It
// returns nil when nothing is open.
func BuildThreadBlockMessages(r analyze.Report, ages Ages, lang Language) []SlackMessage {
	return buildThreadBlockMessages(r, ages, messagesFor(lang), defaultRenderLimits)
}

func buildThreadBlockMessages(r analyze.Report, ages Ages, msg messages, lim RenderLimits) []SlackMessage {
	return buildThreadBlockMessagesWithPlan(r, ages, nil, msg, lim)
}

// buildThreadBlockMessagesWithPlan is buildThreadBlockMessages with the
// cycle's fix plan, which adds the base-image wait line to the cards it
// applies to. A nil plan renders the cards without it.
func buildThreadBlockMessagesWithPlan(r analyze.Report, ages Ages, plan *PlanInfo, msg messages, lim RenderLimits) []SlackMessage {
	if !r.HasFindings() {
		return nil
	}
	lim = lim.normalized()
	v := &chView{
		r:     r,
		msg:   msg,
		rd:    renderer{msg: msg, lim: lim},
		byRef: imagesByRef(r),
		ages:  ages,
		waits: newBaseWaitIndex(plan),
	}
	v.buildThread()

	units := v.l.units
	title := fmt.Sprintf(msg.ThreadTitle, r.GeneratedAt.Format(timeLayout))
	// The report title shares the first section with the first heading.
	if len(units) > 0 && len(units[0].blocks) > 0 && units[0].blocks[0].Kind == BlockSection &&
		utf16Len(title)+2+utf16Len(units[0].blocks[0].Text) <= lim.MaxTextUnits {
		first := units[0]
		first.blocks = append([]Block(nil), first.blocks...)
		first.blocks[0].Text = title + "\n\n" + first.blocks[0].Text
		units = append([]unit{first}, units[1:]...)
	} else {
		units = append([]unit{{blocks: []Block{sectionBlock(title)}}}, units...)
	}

	role := msg.FbRoleEverythingOpen
	return splitUnits(units, splitSpec{
		lim:  lim,
		cont: msg.ThreadContinued,
		fallback: func(info msgInfo) string {
			if info.catShort == "" {
				return role
			}
			short := info.catShort
			if info.contCat {
				short += msg.FbThreadCont
			}
			var text string
			if info.firstImage == "" {
				text = role + " — " + short
			} else {
				// The full name is what images are counted by; only its display is cut.
				text = fmt.Sprintf(msg.FbThread, role, short, capEscaped(info.firstImage, contNameUnits))
			}
			if info.images > 1 {
				text += fmt.Sprintf(msg.FbThreadMoreImage, info.images-1)
			}
			if info.pkgs > 0 {
				text += fmt.Sprintf(msg.FbThreadPackages, info.pkgs)
			}
			return text
		},
	})
}

func (v *chView) buildThread() {
	r, msg := v.r, v.msg
	if n := len(r.EOSLImages); n > 0 {
		views := make([]imageView, 0, n)
		for _, img := range r.EOSLImages {
			iv := v.imageHeadingOf(refLabel(img, v.byRef, msg))
			lines := []string{kv(msg.LblStatus, msg.CardEOSLStatus)}
			if k := r.FoldedEOLCount(img); k > 0 {
				lines = append(lines, fmt.Sprintf(msg.CardFoldedEOL, k))
			}
			// The description belongs to the image heading's section.
			iv.extra = lines
			views = append(views, iv)
		}
		v.l.threadCategory(v.rd.lim, fmt.Sprintf(msg.EOLBaseImagesHeading, n), msg.ShortEOLBase, views)
	}
	if imgs := r.EOLPackageAlerts(); len(imgs) > 0 {
		v.threadEOLPackages(imgs)
	}
	if r.Triage {
		pv := r.ByPriority()
		// ActNow is never filtered: a group eligible for muting is never
		// act_now by construction.
		pv.Watch = filterMuted(pv.Watch)
		pv.Low = filterMuted(pv.Low)
		if n := analyze.GroupCount(pv.ActNow); n > 0 {
			v.threadBucket(fmt.Sprintf(msg.ThreadActNowHeading, n), priorityShort(analyze.PriorityActNow, msg), pv.ActNow)
		}
		if n := analyze.GroupCount(pv.Watch); n > 0 {
			v.threadBucket(fmt.Sprintf(msg.ThreadWatchHeading, n), priorityShort(analyze.PriorityWatch, msg), pv.Watch)
		}
		if n := analyze.GroupCount(pv.Low); n > 0 {
			low := trimNL(fmt.Sprintf(msg.ThreadLowHeading, n))
			// The generic webhook is the only destination with per-package
			// detail beyond this count, and only when one is actually
			// configured.
			if r.GenericWebhookConfigured {
				low += msg.ThreadLowDetailsSuffix
			}
			lines := []string{low}
			if inUse := countInUse(pv.Low); inUse > 0 {
				lines = append(lines, trimNL(fmt.Sprintf(msg.ThreadLowInUseCount, inUse)))
			}
			v.l.closeCat()
			v.l.catShort = priorityShort(analyze.PriorityLow, msg)
			v.l.group()
			v.l.section(v.rd.lim, lines, false)
		}
	} else {
		// Never filtered: only affected/will_not_fix findings are ever
		// eligible for muting.
		if len(r.Actionable) > 0 {
			v.threadBucket("*"+msg.ActionableTitle+"*", msg.ActionableTitle, r.Actionable)
		}
		if watch := filterMuted(r.Watch); len(watch) > 0 {
			v.threadBucket("*"+msg.WatchSectionTitle+"*", msg.WatchSectionTitle, watch)
		}
		if wontFix := filterMuted(r.WontFix); len(wontFix) > 0 {
			v.threadBucket("*"+msg.WontFixSectionTitle+"*", msg.WontFixSectionTitle, wontFix)
		}
	}
	if n := mutedCount(r); n > 0 {
		v.l.closeCat()
		v.l.group()
		v.l.section(v.rd.lim, []string{trimNL(fmt.Sprintf(msg.MutedLine, n))}, false)
	}
	// Same cross-cutting "identity unconfirmed" summary as the channel message.
	if line := unresolvedRefsLine(r, msg); line != "" {
		v.l.closeCat()
		v.l.group()
		v.l.note(v.rd.lim, unresolvedNoteHead(msg), trimNL(line), false)
	}
}

// threadCardOpts are the values a thread card collects for g.
func (v *chView) threadCardOpts(g analyze.PackageGroup) cardOpts {
	o := cardOpts{top: topPlain, notes: true, runtime: rtAll, thread: true, age: v.ages.forGroup(g)}
	if v.r.Triage {
		o.top = topFull
	}
	return o
}

func (v *chView) threadCard(img analyze.ImageFindings, g analyze.PackageGroup) cardView {
	c := v.newCard(img, g, v.threadCardOpts(g))
	return cardView{detail: true, blocks: v.rd.threadCard(c), pkgs: 1, contTitle: v.rd.contTitle(c)}
}

// threadEOLPackages lays out the end-of-life packages not folded into a
// base-OS line. An act_now group is a pointer: the Act now section carries
// its full detail.
func (v *chView) threadEOLPackages(imgs []analyze.ImageFindings) {
	var views []imageView
	for _, img := range imgs {
		iv := v.imageOf(img, !v.r.Triage)
		for _, g := range img.Packages {
			if g.Priority == analyze.PriorityActNow {
				c := v.newCard(img, g, cardOpts{})
				c.SeeActNow = true
				cv := v.compact(c)
				cv.pkgs = 0 // a pointer card is not a package shown here
				iv.cards = append(iv.cards, cv)
				continue
			}
			iv.cards = append(iv.cards, v.threadCard(img, g))
		}
		views = append(views, iv)
	}
	v.l.threadCategory(v.rd.lim, fmt.Sprintf(v.msg.EOLPackagesThreadHeading, analyze.GroupCount(imgs), v.msg.EOLSectionReason), v.msg.ShortEOLPackage, views)
}

// threadBucket lays out one bucket, every package as a card.
func (v *chView) threadBucket(cat, short string, imgs []analyze.ImageFindings) {
	var views []imageView
	for _, img := range imgs {
		iv := v.imageOf(img, !v.r.Triage)
		for _, g := range img.Packages {
			iv.cards = append(iv.cards, v.threadCard(img, g))
		}
		views = append(views, iv)
	}
	v.l.threadCategory(v.rd.lim, cat, short, views)
}
