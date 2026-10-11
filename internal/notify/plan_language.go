package notify

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

// languageUnitOf finds the pull request unit of a language item, if any. The
// unit is the item's status whether or not it has a pull request.
func languageUnitOf(li remediation.LanguageItem, units []remediation.PRUnit) *remediation.PRUnit {
	for i, u := range units {
		if u.Kind == "language" && u.ItemKey == li.Key {
			return &units[i]
		}
	}
	return nil
}

// languageChange names the first package a unit moves and the clause for the
// others, for a Slack line.
func languageChange(u *remediation.PRLanguage, msg messages) (change, more string) {
	if u == nil || len(u.Packages) == 0 {
		return "", ""
	}
	p := u.Packages[0]
	change = fmt.Sprintf("%s %s → %s", escMrkdwn(p.Name), escMrkdwn(p.From), escMrkdwn(p.To))
	if n := len(u.Packages) - 1; n > 0 {
		more = fmt.Sprintf(msg.PlanDepMore, n)
	}
	return change, more
}

// languageServices names the services of a unit.
func languageServices(workloads []string) string {
	var names []string
	seen := map[string]bool{}
	for _, w := range workloads {
		n := workloadService(w)
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for i, n := range names {
		names[i] = escMrkdwn(n)
	}
	return strings.Join(names, ", ")
}

// languagePRLine is the Slack line of a lockfile pull request. The scope of
// the claim stays with it: the lockfile was scanned, the image was not.
func languagePRLine(format string, u remediation.PRUnit, msg messages) string {
	change, more := languageChange(u.Language, msg)
	line := fmt.Sprintf(format, mrkdwnLink(u.URL, fmt.Sprintf("#%d", u.Number)),
		languageServices(u.Workloads), escMrkdwn(u.Path), change, more)
	line += msg.PlanPRLangNote
	if u.Language != nil {
		major := false
		for _, e := range u.Language.ManifestEdits {
			major = major || e.Major
		}
		for _, p := range u.Language.Packages {
			major = major || p.Major
		}
		if major {
			line += msg.PlanPRLangMajorNote
		}
	}
	return line
}

// languageFromUpdateStage reports whether a language item's category is the
// outcome of the update stage rather than of the plan.
func languageFromUpdateStage(li remediation.LanguageItem) bool {
	if li.Update != nil || li.SourceCheck != nil {
		return true
	}
	switch li.Reason {
	case remediation.ReasonUpdateJobLimit, remediation.ReasonUpdateInputLimit,
		remediation.ReasonWorkImageNotConfigured, remediation.ReasonWorkImageUnavailable:
		return true
	}
	return false
}

// languageUpdateLines are the Slack lines about the update stage's outcome:
// the ones that need a person (manual, failed, a verified update whose pull
// request could not be opened) and the deferred ones. A verified update with a
// pull request is spoken for by the pull request line.
func languageUpdateLines(plan remediation.Plan, msg messages) (warn, adopted []string) {
	for _, li := range plan.LanguageItems {
		services := languageServices(li.Workloads)
		lock := escMrkdwn(li.Manager.LockfileName())
		reason := escMrkdwn(string(li.Reason))
		switch li.Category {
		case remediation.CategoryPRCandidate:
			u := languageUnitOf(li, plan.PullRequests)
			if u != nil && u.Number > 0 {
				continue
			}
			var view *remediation.PRLanguage
			status := string(remediation.PRStatusWriteDisabled)
			why := ""
			if u != nil {
				view, status, why = u.Language, string(u.Status), string(u.Reason)
			}
			change, more := languageChange(view, msg)
			if view == nil {
				change = escMrkdwn(li.Manager.LockfileName())
			}
			state := escMrkdwn(status)
			if why != "" {
				state += " (" + escMrkdwn(why) + ")"
			}
			line := fmt.Sprintf(msg.PlanDepNotOpenedLine, services, lock, change, more, state)
			if u != nil && (u.Status == remediation.PRStatusManual || u.Status == remediation.PRStatusFailed || u.Status == remediation.PRStatusWriteBlocked) {
				warn = append(warn, line)
			} else {
				adopted = append(adopted, line)
			}
		case remediation.CategoryManual, remediation.CategoryNotComparable:
			if languageFromUpdateStage(li) {
				warn = append(warn, fmt.Sprintf(msg.PlanDepManualLine, services, lock, reason))
			}
		case remediation.CategoryFailed:
			if languageFromUpdateStage(li) {
				warn = append(warn, fmt.Sprintf(msg.PlanDepFailedLine, services, lock, reason))
			}
		case remediation.CategoryDeferred:
			if languageFromUpdateStage(li) {
				adopted = append(adopted, fmt.Sprintf(msg.PlanDepDeferredLine, services, lock, reason))
			}
		}
	}
	return warn, adopted
}
