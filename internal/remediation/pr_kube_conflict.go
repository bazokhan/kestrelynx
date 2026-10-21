package remediation

import (
	"fmt"
	"sort"
	"strings"
)

// kubeSourceConflict resolves every mapping of a manifest file against the
// content about to be edited and reports the places that two or more of them
// resolve to (a document without a namespace mapped from two namespaces, for
// example): one edit of such an image would change the containers of all of
// them, whatever each of them runs. It works on exactly the bytes the editor is
// given, so what is checked is what is edited. A file that does not parse is
// left to the editor, which refuses it.
func kubeSourceConflict(content []byte, fileMappings []KubernetesMapping) string {
	docs, prob := parseManifestDocuments(content)
	if prob != nil {
		return ""
	}
	at := map[string][]string{}
	for _, m := range fileMappings {
		t, ok := m.manifestTarget()
		if !ok {
			continue
		}
		site, prob := findManifestSite(docs, t)
		if prob != nil {
			continue
		}
		at[site.key()] = append(at[site.key()], m.Workload)
	}
	var clashes []string
	for _, ws := range at {
		if len(ws) > 1 {
			sort.Strings(ws)
			clashes = append(clashes, strings.Join(ws, ", "))
		}
	}
	if len(clashes) == 0 {
		return ""
	}
	sort.Strings(clashes)
	return fmt.Sprintf("these mappings resolve to the same container of the same document: %s", strings.Join(clashes, "; "))
}
