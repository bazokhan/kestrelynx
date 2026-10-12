package notify

import (
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
