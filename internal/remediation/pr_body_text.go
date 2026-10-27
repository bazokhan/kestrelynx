package remediation

import "fmt"

// BodyLanguage selects the wording of pull request bodies. The empty value is
// English, the wording every deployment has always had.
type BodyLanguage string

const (
	// BodyEN is the historical English wording, pinned byte for byte.
	BodyEN BodyLanguage = "en"
	// BodyJA is the Japanese wording.
	BodyJA BodyLanguage = "ja"
)

// validate reports whether l names a wording.
func (l BodyLanguage) validate() error {
	switch l {
	case "", BodyEN, BodyJA:
		return nil
	}
	return fmt.Errorf("remediation: unknown pull request language %q (allowed: en, ja)", string(l))
}

// prText is every sentence of a pull request body that depends on the
// language. A field is a format string; one with two or more verbs uses
// explicit argument indexes so a translation can reorder them. The marker, the
// keys, names, versions, digests, paths and example commands are arguments and
// never part of the text.
type prText struct {
	// Section headings, without the Markdown prefix.
	HeadWhat, HeadChange, HeadVerification                          string
	HeadVulnTargets, HeadManifestEdits                              string
	HeadChain, LChainIntro, LChainLine, LChainViaLine, LSourceBasis string
	LSourceBasisPositions, LChainCarried                            string

	// Shared pieces.
	ListSep      string // between items of a code list
	ListMore     string // after a cut list: %d
	LineMore     string // a list line: %d
	LineMoreFor  string // a list line: %d more for package %s
	LineMorePkgs string // a list line: %d
	None         string // a list line
	NoFiles      string
	CutNote      string

	// Vulnerability lists.
	TitleResolved, TitleRemaining, TitleIntroduced    string
	TitleRemainingTargeted, TitleOtherRemaining       string
	TitleOtherResolvedImage, TitleOtherRemainingImage string
	ListTitle                                         string // %[1]s title, %[2]d count
	VulnLine                                          string // %[1]s id, %[2]s package, %[3]s ecosystem, %[4]s class
	VulnSeverity, VulnKEV, VulnPriority               string
	VulnLineLang                                      string // %[1]s id, %[2]s package
	SourceVulnLine                                    string // %[1]s id, %[2]s package, %[3]s version
	SourceFixed                                       string

	// Scan sentences shared by the image bodies.
	VerRecord    string // %[1]s generated at, %[2]s baseline, %[3]s candidate
	DBBuilt      string
	SeverityEnd  string // %s
	ScopeEnd     string // %s
	ConfigDigest string
	PlatformPart string
	Locations    string
	DigestNote   string

	// SourceNote follows the workloads in Dockerfile and language bodies that
	// name a container started outside Compose.
	SourceNote string

	// Compose bodies.
	CWhat, CRunning, CServices, CWorkloads, CAlso, CChange string
	CVerRunning, CCandidate, CScanned                      string
	CTargets                                               string // %[1]d resolved, %[2]d remaining
	COther                                                 string // %[1]d no longer reported, %[2]d remaining, %[3]d introduced

	// Dockerfile bodies.
	DWhat, DBaseNow, DEdited, DWorkloads, DChange           string
	DRunning, DCurrentBase, DCandidateBase, DLayer, DVerRec string
	DTargets, DOther, DScanned                              string

	// Kubernetes bodies.
	HeadPremises, HeadDeploy                       string
	KWhat, KRunning, KDeclared, KContainers, KAlso string
	KPremiseSource, KPremiseOwner, KCronJob        string
	KReflect, KChainsIntro, KChainLine, KNoChains  string
	KUnconfirmed, KUnchanged                       string
	KOwnerNative, KOwnerHelm, KOwnerArgo           string
	KOwnerFluxKust, KOwnerFluxHelm, KChainSep      string

	// Kustomize bodies reuse the Kubernetes lines and add these.
	KustWhat, KustContainers, KustViaInit string
	KustPremiseEntry, KustPremiseSet      string

	// Helm values bodies reuse the Kustomize lines and add these.
	HelmWhat, HelmPremiseKey, HelmFluxRelease, HelmNoRelease string
	HelmQuoted                                               string

	// Language package bodies.
	LWhat, LDir, LManager, LWorkloads, LFiles                                   string
	LEntryOne, LEntryMany                                                       string
	LMajorPkgs, LMajorEdits, LChangeIntro, LPkgLine, LMajor                     string
	LEditsIntro, LEditsMajor, LEditLine                                         string
	LOps, LNoOps, LStep, LScratch                                               string
	LEnvRuntime, LEnvPip, LEnvTool, LEnvToolDefault                             string
	LEnvToolSource, LEnvNone                                                    string
	LEnvToolDeclared, LEnvToolInRange                                           string
	LEnvRuntimeWhy, LEnvWhySep, LEnvBasisFile, LEnvBasisRange, LEnvBasisDefault string
	LEnvExcludedEOL, LEnvExcludedEngines, LEnvExcludedDecl, LEnvFloor           string
	LEnvPyBasisFile, LEnvPyBasisRange, LEnvPyExcludedEOL, LEnvPyExcludedDecl    string
	LDeprecatedGained, LDeprecatedChanged, LDeprecatedLost, LDeprecatedPresent  string
	LFollowedTitle, LFollowedLine, LFollowedMove                                string
	LEntries, LTruncated, LTitleChanged, LTitleAdded                            string
	LTitleRemoved, LLookup, LNote                                               string
	LSourceHead, LBefore, LAfter, LSourceCounts, LListCut                       string
	LBothScans, LDBBuilt, LScanTail                                             string
	LInstallCheck                                                               string
	RegistryNpm, RegistryPyPI                                                   string
	RelDirect, RelTransitive, RelMixed, RelUnknown                              string
}

// textFor returns the wording of l; any unknown value falls back to English,
// but NewPRStage rejects those before they get here.
func textFor(l BodyLanguage) *prText {
	if l == BodyJA {
		return &jaPRText
	}
	return &enPRText
}

var enPRText = prText{
	HeadWhat:              "What",
	HeadChange:            "Change",
	HeadVerification:      "Verification",
	HeadVulnTargets:       "Vulnerabilities this update targets",
	HeadManifestEdits:     "Manifest edits",
	HeadChain:             "Packages updated along with the fix",
	LChainIntro:           "These packages required older versions of the packages above and were updated within the ranges in %s.\n\n",
	LChainLine:            "- %[1]s: %[2]s to %[3]s (it required %[4]s %[5]s)\n",
	LChainViaLine:         "- %[1]s: %[2]s to %[3]s (%[6]s, which it brings in, required %[4]s %[5]s)\n",
	LSourceBasisPositions: "- The findings of the two scans were compared by package, version and vulnerability ID; the number of lockfile entries and of requirements that point to a version with a vulnerability was compared too; and every requirement into an entry with a vulnerability that the original did not have as it is was checked place by place against the original\n",
	LChainCarried:         "- %[1]d vulnerabilities stay at the same place in a version the update moved to (for example %[2]s for %[3]s %[4]s to %[5]s); the update does not fix them.\n",
	LSourceBasis:          "- The findings of the two scans were compared by package, version and vulnerability ID, and the number of lockfile entries and of requirements that point to a version with a vulnerability was compared too\n",

	ListSep:      ", ",
	ListMore:     " and %d more",
	LineMore:     "- and %d more\n",
	LineMoreFor:  "- and %[1]d more for %[2]s\n",
	LineMorePkgs: "- and %d more packages\n",
	None:         "- none\n",
	NoFiles:      "no files",
	CutNote:      "\n_The rest of this description was cut to fit the length limit._\n",

	TitleResolved:            "Resolved",
	TitleRemaining:           "Remaining",
	TitleIntroduced:          "Introduced",
	TitleRemainingTargeted:   "Remaining among the targeted findings",
	TitleOtherRemaining:      "Other findings that remain in the candidate base image",
	TitleOtherResolvedImage:  "Other findings the candidate image no longer reports",
	TitleOtherRemainingImage: "Other findings that remain in the candidate image",
	ListTitle:                "\n**%[1]s (%[2]d)**\n\n",
	VulnLine:                 "- %[1]s in %[2]s (%[3]s, %[4]s)",
	VulnSeverity:             ", severity %s",
	VulnKEV:                  ", in the CISA KEV catalog",
	VulnPriority:             ", priority %s",
	VulnLineLang:             "- %[1]s in %[2]s",
	SourceVulnLine:           "- %[1]s in %[2]s %[3]s",
	SourceFixed:              ", fixed in %s",

	VerRecord:    "- Verification record: plan generated at %[1]s, baseline scan %[2]s, candidate scan %[3]s\n",
	DBBuilt:      " with the vulnerability database built at %s",
	SeverityEnd:  ". Severity range: %s.",
	ScopeEnd:     " Scope: %s.",
	ConfigDigest: ", config digest %s",
	PlatformPart: ", platform %s",
	Locations:    "- Locations: %s\n",
	DigestNote:   "  - The running digest comes from the container runtime; whether it is the image config digest or an index or manifest digest is not confirmed.\n",

	CWhat:       "KestreLynx proposes a new image tag for %[1]d Compose service(s) in %[2]s of %[3]s.\n\n",
	CRunning:    "- Running image: %s\n",
	CServices:   "- Services edited: %s\n",
	CWorkloads:  "- Workloads running them: %s\n",
	CAlso:       "- Also running this image, not edited (no Compose mapping): %s\n",
	CChange:     "- %[1]s: %[2]s to %[3]s\n",
	CVerRunning: "- Running: %s",
	CCandidate:  "- Candidate: %[1]s, tag digest %[2]s, platform manifest %[3]s, config digest %[4]s, platform %[5]s\n",
	CScanned:    "Both images were scanned by Trivy %s",
	CTargets:    "- Findings this update targets (fixed findings of the running image): resolved %[1]d, remaining %[2]d\n",
	COther:      "- Other findings of the running image, outside this update's targets (such as findings with no fixed version): %[1]d no longer reported for the candidate image, %[2]d remaining in the candidate image. Findings introduced by the candidate image: %[3]d\n",

	DWhat:          "KestreLynx proposes a newer tag for the base image of %[1]s in %[2]s.\n\n",
	DBaseNow:       "- Base image now: %s\n",
	DEdited:        "- Edited: the FROM of stage %[1]d, line %[2]d\n",
	DWorkloads:     "- Workloads built from it: %s\n",
	SourceNote:     "- Source of a `container/` workload: the link between that container and the repository and file named above comes from the mappings in the KestreLynx configuration and was not checked by KestreLynx; a match of the base image layers or of the package names and versions does not show that the container was built from this repository\n",
	DChange:        "- FROM on line %[1]d: %[2]s to %[3]s\n",
	DRunning:       "- Running image: %s",
	DCurrentBase:   "- Current base image: %[1]s, tag digest %[2]s, platform manifest %[3]s, config digest %[4]s, platform %[5]s\n",
	DCandidateBase: "- Candidate base image: %[1]s, tag digest %[2]s, platform manifest %[3]s, config digest %[4]s, platform %[5]s\n",
	DLayer:         "- Layer check: %[1]s; the current base image has %[2]d layer(s) and the running image %[3]d. A match shows that the filesystem layers agree; it does not show how the image was built.\n",
	DVerRec:        "- Verification record: plan generated at %[1]s, scan of the current base %[2]s, scan of the candidate base %[3]s\n",
	DTargets:       "- Findings this update targets (fixed findings of the running image in the base image's layers): resolved %[1]d, remaining %[2]d\n",
	DOther:         "- Other findings of the compared base images that remain in the candidate base image: %[1]d; introduced by the candidate base image: %[2]d\n",
	DScanned:       "Both base images were scanned by Trivy %s",

	HeadPremises:     "What this change relies on",
	HeadDeploy:       "After merging",
	KWhat:            "KestreLynx proposes a new image tag for %[1]d container(s) in %[2]s of %[3]s.\n\n",
	KRunning:         "- Running image: %s\n",
	KDeclared:        "- Image declared in the Pod specs: %s\n",
	KContainers:      "- Containers edited: %s\n",
	KAlso:            "- Also running this image, not edited (no manifest mapping): %s\n",
	KPremiseSource:   "- This file is taken to be the one the cluster is deployed from, with the final value of the image: another file, a Helm values file or a setting of a GitOps tool may override it. KestreLynx did not check this.\n",
	KPremiseOwner:    "- No other tool is taken to own this image tag. Only Flux image automation markers on the edited lines and Argo CD Image Updater write-back files in the directory were looked for.\n",
	KCronJob:         "- Jobs that already exist are not affected: a change to a CronJob applies to the Jobs it starts after the change is applied, and the Pod template of an existing Job cannot be changed.\n",
	KReflect:         "- Merging this pull request may deploy the change: a tool outside KestreLynx (Argo CD, Flux or a CI job) can apply a merged change automatically. KestreLynx does not deploy it and does not know whether such a tool is set up. Review the change before merging.\n",
	KChainsIntro:     "- Management tools detected on the workloads, read from markers on the objects (claims, not verified facts):\n",
	KChainLine:       "  - %[1]s: %[2]s\n",
	KNoChains:        "- No management tool was detected for these workloads. That does not mean there is none: Argo CD tracking by label is not read, and Jobs and Pods are not checked for markers.\n",
	KUnchanged:       "\nContainers of the same Pod template that use the same image and are not changed, so they keep its tag: %s\n",
	KUnconfirmed:     "- Not confirmed: whether the change was rolled out after merging, and whether the findings are gone from the running image.\n",
	KOwnerNative:     "%[1]s %[2]s",
	KOwnerHelm:       "Helm release %[1]s in %[2]s",
	KOwnerArgo:       "Argo CD application %s",
	KOwnerFluxKust:   "Flux Kustomization %[1]s in %[2]s",
	KOwnerFluxHelm:   "Flux HelmRelease %[1]s in %[2]s",
	KChainSep:        " -> ",
	KustWhat:         "KestreLynx proposes a new tag for the Kustomize images entry %[1]s in %[2]s of %[3]s, which sets the image of %[4]d container(s).\n\n",
	KustContainers:   "- Containers the edit is declared to act on (the configuration lists them): %s\n",
	KustViaInit:      "- Ordinary init containers among them, checked through the status of their Pods and the scan of the container of the same Pod that ran the same image: %s\n",
	KustPremiseEntry: "- The entry is taken to act on those containers and no others. KestreLynx does not render the kustomization. It checked only that the running images are the entry's result, and that no container outside the list, in the same namespace (or the same Helm release or Flux Kustomization) or in the same Pod template, declares the same image.\n",
	KustPremiseSet:   "- The list of containers is taken to be complete. Only the containers named in the configuration were checked one by one.\n",
	HelmWhat:         "KestreLynx proposes a new image tag at the key %[1]s of the Helm values file %[2]s of %[3]s, which sets the image of %[4]d container(s).\n\n",
	HelmPremiseKey:   "- The key is taken to hold the final value of the image. KestreLynx does not render the chart. It did not check that no other values file, no `--set` of a CI job, and no setting of Argo CD (parameters, valuesObject, valuesFrom) overrides it, and that no other tool owns the tag; it checked only that the value in this file matches the running images, that no container outside the list, in the same namespace (or the same Helm release or Flux Kustomization) or in the same Pod template, declares the same image, and that the Flux image automation markers and Argo CD Image Updater write-back files are absent.\n",
	HelmFluxRelease:  "- Flux HelmRelease management markers were detected on these workloads (read from markers on the objects, so a claim, not a verified fact): %s. The `spec.values` of a HelmRelease is not read here and can take precedence over this file.\n",
	HelmQuoted:       "- The new tag is written in double quotes, which the old one did not have: without them it would not be read as a string (Helm reads YAML 1.1, where `1.10` is a number and `on` a boolean).\n",
	HelmNoRelease:    "- No Helm release and no Flux HelmRelease was detected for these workloads, so it is not known that this values file is what deploys them.\n",

	LWhat:               "KestreLynx proposes updating %[1]d package %[2]s in %[3]s of %[4]s with %[5]s.\n\n",
	LDir:                "- Dependency directory: %s\n",
	LManager:            "- Package manager: %s\n",
	LWorkloads:          "- Workloads running these packages: %s\n",
	LFiles:              "- Files changed: %s\n",
	LEntryOne:           "entry",
	LEntryMany:          "entries",
	LMajorPkgs:          "**%d package(s) move to another major version (for 0.x, another minor version). Review these first: the application may need changes.**\n",
	LMajorEdits:         "**%d manifest edit(s) allow a new major version and no longer allow the one before; see Manifest edits below.**\n",
	LChangeIntro:        "Running version to version after the update, with how the project requires the package:\n\n",
	LPkgLine:            "- %[1]s: %[2]s to %[3]s (%[4]s)",
	LMajor:              " — **major version change**",
	LEditsIntro:         "The version specifier of these direct dependencies did not allow a fixed version, so it was edited before the lockfile was updated.\n\n",
	LEditsMajor:         "**%d edit(s) below allow a new major version (for 0.x, a new minor version) and no longer allow the one before. Review these first: the application may need changes.**\n\n",
	LEditLine:           "- %[1]s, %[2]s, %[3]s: %[4]s to %[5]s",
	LEnvRuntime:         "- Runtime: %[1]s %[2]s, from the official image %[3]s\n",
	LEnvRuntimeWhy:      "- Runtime: %[1]s %[2]s (%[4]s), from the official image %[3]s\n",
	LEnvWhySep:          "; ",
	LEnvBasisFile:       "the major version %s name(s)",
	LEnvBasisRange:      "the lowest series updates run on that %s allow",
	LEnvBasisDefault:    "the project declares no Node.js version, so the newest series in long-term support among those updates run on",
	LEnvExcludedEOL:     "Node.js %[1]s is not used because its support ended on %[2]s",
	LEnvExcludedEngines: "Node.js %[1]s is not used because %[2]s %[3]s needs Node.js %[4]s",
	LEnvExcludedDecl:    "Node.js %s is not used because a declaration does not allow it",
	LEnvFloor:           "- The packages the update added or changed were checked: the engines.node of each allows Node.js %s, the lowest version the declarations allow\n",
	LEnvPyBasisFile:     "the minor version %s name(s)",
	LEnvPyBasisRange:    "the lowest series updates run on that %s allow",
	LEnvPyExcludedEOL:   "Python %[1]s is not used because its support ended on %[2]s",
	LEnvPyExcludedDecl:  "Python %s is not used because a declaration does not allow the Python of that image",
	LEnvPip:             "- pip: %s, the one in that image\n",
	LEnvTool:            "- Package manager: %[1]s %[2]s (%[3]s), archive sha256 %[4]s\n",
	LEnvToolDefault:     "the version this build selects when the project declares none",
	LEnvToolSource:      "source %s",
	LEnvToolDeclared:    "the exact version the project declares",
	LEnvToolInRange:     "this build's default version, which the version ranges the project declares allow",
	LFollowedTitle:      "Entries whose dependencies moved to newer versions along with the update",
	LFollowedLine:       "- %[1]s: %[2]s\n",
	LFollowedMove:       "%[1]s %[2]s to %[3]s",
	LDeprecatedGained:   "- %s gained a deprecation note. Its author deprecated it on npm, which has nothing to do with this update\n",
	LDeprecatedChanged:  "- The deprecation note of %s changed. Its author changed it on npm, which has nothing to do with this update\n",
	LDeprecatedPresent:  "- %s is deprecated on npm. The note belongs to the updated version, and equals what npm publishes for it\n",
	LDeprecatedLost:     "- %s lost its deprecation note. Its author removed it on npm, which has nothing to do with this update\n",
	LEnvNone:            "- Versions that ran: no record of them (this update was made before they were recorded)\n",
	LOps:                "**Operations run**\n\n",
	LNoOps:              "- none recorded\n",
	LStep:               "- %[1]s, exit code %[2]d",
	LScratch:            " (run on a scratch copy; its result was only compared)",
	LEntries:            "\n**Lockfile entries**: %[1]d added, %[2]d changed, %[3]d removed",
	LTruncated:          " (the lists are cut)",
	LTitleChanged:       "Changed",
	LTitleAdded:         "Added",
	LTitleRemoved:       "Removed",
	LLookup:             "Every version the update added or changed was looked up in %[1]s and compared with the distribution the lockfile points at.\n",
	LNote:               "\n- Note from the run: %s\n",
	LSourceHead:         "\n**Scan of the dependency files before and after (Trivy, filesystem mode)**\n\n",
	LBefore:             "- Before: %s\n",
	LAfter:              "- After: %s\n",
	LSourceCounts:       "- Resolved %[1]d, remaining %[2]d, introduced %[3]d (over every package of the files, not only the updated ones)\n",
	LListCut:            "- The lists below are cut\n",
	LBothScans:          "\nBoth scans used Trivy %s",
	LDBBuilt:            ", the vulnerability database built at %s",
	LScanTail:           ", the same severity range (%s) and the same settings; the repository's own Trivy configuration, ignore files and VEX documents were not read.\n",
	LInstallCheck:       "- Before merging, run a CI job that installs from the lockfile (for example %s)\n",
	RegistryNpm:         "the npm registry",
	RegistryPyPI:        "PyPI",
	RelDirect:           "direct dependency",
	RelTransitive:       "transitive dependency",
	RelMixed:            "direct and transitive dependency",
	RelUnknown:          "relation not known",
}

var jaPRText = prText{
	HeadWhat:              "概要",
	HeadChange:            "変更内容",
	HeadVerification:      "確認したこと",
	HeadVulnTargets:       "この更新が対象とする脆弱性",
	HeadManifestEdits:     "manifest の編集",
	HeadChain:             "あわせて更新したパッケージ",
	LChainIntro:           "上のパッケージの古い版を要求していたため、%s の範囲内で更新しました。\n\n",
	LChainLine:            "- %[1]s: %[2]s から %[3]s へ（%[4]s %[5]s を要求していた）\n",
	LChainViaLine:         "- %[1]s: %[2]s から %[3]s へ（これが使う %[6]s が %[4]s %[5]s を要求していた）\n",
	LSourceBasisPositions: "- 2 つのスキャンの所見は、パッケージ・版・脆弱性 ID で比べたほか、脆弱性のある版を指す lockfile のエントリ数と依存の数も比べ、脆弱性のあるエントリを指す依存のうち更新前になかったものは、更新前と位置ごとに照合しました\n",
	LChainCarried:         "- 更新で版が変わった位置に、同じ脆弱性が %[1]d 件残っています(例: %[3]s %[4]s から %[5]s の %[2]s)。この更新では直りません。\n",
	LSourceBasis:          "- 2 つのスキャンの所見は、パッケージ・版・脆弱性 ID で比べたほか、脆弱性のある版を指す lockfile のエントリ数と依存の数も比べました\n",

	ListSep:      "、",
	ListMore:     "、ほか %d 件",
	LineMore:     "- ほか %d 件\n",
	LineMoreFor:  "- %[2]s について、ほか %[1]d 件\n",
	LineMorePkgs: "- ほか %d 個のパッケージ\n",
	None:         "- なし\n",
	NoFiles:      "ファイルなし",
	CutNote:      "\n_長さの上限に収めるため、この説明の残りを省略しました。_\n",

	TitleResolved:            "解消",
	TitleRemaining:           "残存",
	TitleIntroduced:          "新規",
	TitleRemainingTargeted:   "対象の検出結果のうち残存",
	TitleOtherRemaining:      "候補のベースイメージに残るその他の検出結果",
	TitleOtherResolvedImage:  "候補のイメージで検出されなくなるその他の検出結果",
	TitleOtherRemainingImage: "候補のイメージに残るその他の検出結果",
	ListTitle:                "\n**%[1]s (%[2]d)**\n\n",
	VulnLine:                 "- %[2]s の %[1]s (%[3]s、%[4]s)",
	VulnSeverity:             "、重大度 %s",
	VulnKEV:                  "、CISA KEV カタログに掲載",
	VulnPriority:             "、優先度 %s",
	VulnLineLang:             "- %[2]s の %[1]s",
	SourceVulnLine:           "- %[2]s %[3]s の %[1]s",
	SourceFixed:              "、修正版 %s",

	VerRecord:    "- 確認の記録: 計画の生成時刻 %[1]s、変更前のスキャン %[2]s、候補のスキャン %[3]s\n",
	DBBuilt:      "。脆弱性データベースの作成時刻は %s です",
	SeverityEnd:  "。重大度の範囲は %s です。",
	ScopeEnd:     "対象範囲は %s です。",
	ConfigDigest: "、config digest %s",
	PlatformPart: "、プラットフォーム %s",
	Locations:    "- 場所: %s\n",
	DigestNote:   "  - 稼働中の digest はコンテナランタイムから得たもので、イメージの config digest か、index または manifest の digest かは確認していません。\n",

	CWhat:       "KestreLynx は、%[3]s の %[2]s にある %[1]d 件の Compose サービスについて、新しいイメージタグを提案します。\n\n",
	CRunning:    "- 稼働中のイメージ: %s\n",
	CServices:   "- 編集したサービス: %s\n",
	CWorkloads:  "- これらを実行しているワークロード: %s\n",
	CAlso:       "- 同じイメージを実行していますが編集していないもの (Compose の対応付けなし): %s\n",
	CChange:     "- %[1]s: %[2]s から %[3]s へ\n",
	CVerRunning: "- 稼働中: %s",
	CCandidate:  "- 候補: %[1]s、タグの digest %[2]s、プラットフォームの manifest %[3]s、config digest %[4]s、プラットフォーム %[5]s\n",
	CScanned:    "両方のイメージを Trivy %s でスキャンしました",
	CTargets:    "- この更新が対象とする検出結果 (稼働中のイメージの修正可能な検出結果): 解消 %[1]d 件、残存 %[2]d 件\n",
	COther:      "- 稼働中のイメージのその他の検出結果 (この更新の対象外。修正版の報告がないものなど) のうち、候補のイメージで検出されなくなるもの: %[1]d 件、候補のイメージに残るもの: %[2]d 件。候補のイメージで新たに入る検出結果: %[3]d 件\n",

	DWhat:          "KestreLynx は、%[2]s の %[1]s にあるベースイメージについて、新しいタグを提案します。\n\n",
	DBaseNow:       "- 現在のベースイメージ: %s\n",
	DEdited:        "- 編集した箇所: ステージ %[1]d の FROM (%[2]d 行目)\n",
	DWorkloads:     "- このイメージから作られるワークロード: %s\n",
	SourceNote:     "- `container/` のワークロードのソース: そのコンテナと上記のリポジトリ・ファイルとの対応は KestreLynx の設定の対応付けによるもので、KestreLynx は確かめていない。ベースイメージのレイヤーやパッケージの名前と版が一致しても、コンテナがこのリポジトリからビルドされたことを示さない\n",
	DChange:        "- %[1]d 行目の FROM: %[2]s から %[3]s へ\n",
	DRunning:       "- 稼働中のイメージ: %s",
	DCurrentBase:   "- 現在のベースイメージ: %[1]s、タグの digest %[2]s、プラットフォームの manifest %[3]s、config digest %[4]s、プラットフォーム %[5]s\n",
	DCandidateBase: "- 候補のベースイメージ: %[1]s、タグの digest %[2]s、プラットフォームの manifest %[3]s、config digest %[4]s、プラットフォーム %[5]s\n",
	DLayer:         "- レイヤーの確認: %[1]s。現在のベースイメージのレイヤーは %[2]d 層、稼働中のイメージは %[3]d 層です。一致が示すのはファイルシステムのレイヤーが揃っていることだけで、イメージの作られ方は示しません。\n",
	DVerRec:        "- 確認の記録: 計画の生成時刻 %[1]s、現在のベースのスキャン %[2]s、候補のベースのスキャン %[3]s\n",
	DTargets:       "- この更新が対象とする検出結果 (稼働中のイメージの修正可能な検出結果のうち、ベースイメージのレイヤーにあるもの): 解消 %[1]d 件、残存 %[2]d 件\n",
	DOther:         "- 比較した両ベースイメージのその他の検出結果のうち、候補のベースイメージに残るもの: %[1]d 件、候補のベースイメージで新たに入るもの: %[2]d 件\n",
	DScanned:       "両方のベースイメージを Trivy %s でスキャンしました",

	HeadPremises:     "この変更の前提",
	HeadDeploy:       "マージ後",
	KWhat:            "KestreLynx は、%[3]s の %[2]s にある %[1]d 個のコンテナについて、新しいイメージのタグを提案します。\n\n",
	KRunning:         "- 稼働中のイメージ: %s\n",
	KDeclared:        "- Pod の spec が指すイメージ: %s\n",
	KContainers:      "- 編集するコンテナ: %s\n",
	KAlso:            "- 同じイメージで稼働しているが編集しないもの(マニフェストの対応付けがない): %s\n",
	KPremiseSource:   "- このファイルがクラスタへの配備元であり、イメージの最終的な値がここにあるものとして扱います。別のファイル、Helm の values、GitOps ツールの設定がこの値を上書きしている場合があります。KestreLynx はこれを確認していません。\n",
	KPremiseOwner:    "- 他のツールがこのイメージのタグを管理していないものとして扱います。確認したのは、編集する行の Flux image automation の目印と、同じディレクトリの Argo CD Image Updater の書き戻しファイルだけです。\n",
	KCronJob:         "- すでにある Job には反映されません。CronJob の変更は、適用後に開始される Job から効き、既存の Job の Pod テンプレートは変更できません。\n",
	KReflect:         "- このプルリクエストをマージすると、変更がそのまま配備される場合があります。KestreLynx の外のツール(Argo CD、Flux、CI)が、マージされた変更を自動で反映できるためです。KestreLynx は配備を行わず、そのようなツールがあるかどうかも分かりません。マージ前に変更を確認してください。\n",
	KChainsIntro:     "- ワークロードで検出した管理ツール(オブジェクトの目印から読んだもので、検証済みの事実ではありません):\n",
	KChainLine:       "  - %[1]s: %[2]s\n",
	KNoChains:        "- これらのワークロードでは管理ツールを検出できませんでした。ないことを意味しません。Argo CD のラベルによる追跡は読まず、Job と Pod は目印を調べていません。\n",
	KUnchanged:       "\n同じ Pod テンプレートで同じイメージを使うが、変更しないコンテナ(現在のタグのまま残ります): %s\n",
	KUnconfirmed:     "- 未確認: マージ後にロールアウトされたか、稼働中のイメージから所見が消えたか。\n",
	KOwnerNative:     "%[1]s %[2]s",
	KOwnerHelm:       "Helm リリース %[1]s(%[2]s)",
	KOwnerArgo:       "Argo CD アプリケーション %s",
	KOwnerFluxKust:   "Flux Kustomization %[1]s(%[2]s)",
	KOwnerFluxHelm:   "Flux HelmRelease %[1]s(%[2]s)",
	KChainSep:        " -> ",
	KustWhat:         "KestreLynx は、%[3]s の %[2]s にある Kustomize の images の項目 %[1]s について、新しいタグを提案します。この項目は %[4]d 個のコンテナのイメージを決めます。\n\n",
	KustContainers:   "- 編集が作用するものとして宣言されたコンテナ(設定に列挙されたもの): %s\n",
	KustViaInit:      "- そのうち通常の init container(Pod の status と、同じ Pod の同じイメージを動かしたコンテナのスキャンで確認): %s\n",
	KustPremiseEntry: "- この項目が、列挙したコンテナだけに作用するものとして扱います。kustomization は描画しません。確認したのは、稼働中のイメージが項目の結果と一致すること、そして列挙にないコンテナ(同じ namespace、または同じ Helm リリース・Flux Kustomization のもの、または同じ Pod テンプレートのもの)が同じイメージを宣言していないことだけです。\n",
	KustPremiseSet:   "- 列挙したコンテナが作用先のすべてであるものとして扱います。コンテナ単位で確認したのは、設定に挙げたものだけです。\n",
	HelmWhat:         "KestreLynx は、%[3]s の Helm の values ファイル %[2]s のキー %[1]s について、新しいイメージのタグを提案します。このキーは %[4]d 個のコンテナのイメージを決めます。\n\n",
	HelmPremiseKey:   "- このキーが、イメージの最終的な値を持つものとして扱います。チャートは描画しません。他の values ファイル、CI の `--set`、Argo CD の設定(parameters、valuesObject、valuesFrom)が上書きしていないこと、他のツールがタグを管理していないことは確認していません。確認したのは、このファイルの値が稼働中のイメージと一致すること、列挙にないコンテナ(同じ namespace、または同じ Helm リリース・Flux Kustomization のもの、または同じ Pod テンプレートのもの)が同じイメージを宣言していないこと、Flux image automation の目印と Argo CD Image Updater の書き戻しファイルがないことだけです。\n",
	HelmFluxRelease:  "- 次のワークロードで Flux HelmRelease の管理マーカーを検出しました(オブジェクトの目印から読んだもので、検証済みの事実ではありません): %s。HelmRelease の `spec.values` はここでは読まず、このファイルより優先されることがあります。\n",
	HelmQuoted:       "- 新しいタグは、元のタグにはなかった二重引用符で囲んで書きます。囲まないと文字列として読まれないためです(Helm は YAML 1.1 で読み、`1.10` は数値、`on` は真偽値になります)。\n",
	HelmNoRelease:    "- これらのワークロードでは Helm リリースも Flux HelmRelease も検出できなかったため、この values ファイルが配備に使われるかは分かりません。\n",

	LWhat:               "KestreLynx は、%[4]s の %[3]s にある %[1]d 件のパッケージ%[2]sを %[5]s で更新することを提案します。\n\n",
	LDir:                "- 依存関係のディレクトリ: %s\n",
	LManager:            "- パッケージマネージャー: %s\n",
	LWorkloads:          "- これらのパッケージを実行しているワークロード: %s\n",
	LFiles:              "- 変更したファイル: %s\n",
	LEntryOne:           "エントリ",
	LEntryMany:          "エントリ",
	LMajorPkgs:          "**%d 件のパッケージが別のメジャーバージョンに上がります (0.x では別のマイナーバージョン)。アプリケーションの変更が必要になることがあるため、最初に確認してください。**\n",
	LMajorEdits:         "**%d 件の manifest の編集で、新しいメジャーバージョンを許可し、それまで許可していたメジャーバージョンを許可しなくなります。下の「manifest の編集」を参照してください。**\n",
	LChangeIntro:        "更新前の稼働中の版から更新後の版へ、プロジェクトがそのパッケージをどう要求しているかとあわせて示します。\n\n",
	LPkgLine:            "- %[1]s: %[2]s から %[3]s へ (%[4]s)",
	LMajor:              " — **メジャーバージョンの変更**",
	LEditsIntro:         "これらの直接依存のバージョン指定は修正済みの版を許可していなかったため、lockfile の更新前に編集しました。\n\n",
	LEditsMajor:         "**以下の %d 件の編集は、新しいメジャーバージョン (0.x では新しいマイナーバージョン) を許可し、それまで許可していたメジャーバージョン (0.x ではマイナーバージョン) を許可しなくなります。アプリケーションの変更が必要になることがあるため、最初に確認してください。**\n\n",
	LEditLine:           "- %[1]s、%[2]s、%[3]s: %[4]s から %[5]s へ",
	LEnvRuntime:         "- 実行環境: %[1]s %[2]s (公式イメージ %[3]s)\n",
	LEnvRuntimeWhy:      "- 実行環境: %[1]s %[2]s (%[4]s。公式イメージ %[3]s)\n",
	LEnvWhySep:          "。",
	LEnvBasisFile:       "%s が指す主要な版",
	LEnvBasisRange:      "%s を満たす対応イメージの中で最小の主要な版",
	LEnvBasisDefault:    "Node.js の版の宣言がないため、対応イメージの中で長期サポート(LTS)中の最新の主要な版",
	LEnvExcludedEOL:     "Node.js %[1]s は %[2]s にサポート終了のため使わない",
	LEnvExcludedEngines: "%[2]s %[3]s が Node.js %[4]s を要求するため Node.js %[1]s は使わない",
	LEnvExcludedDecl:    "宣言が許さないため Node.js %s は使わない",
	LEnvFloor:           "- 更新で追加・変更したパッケージは、engines.node が宣言の許す最小の Node.js %s を許すことを確認した\n",
	LEnvPyBasisFile:     "%s が指す小版",
	LEnvPyBasisRange:    "%s を満たす対応イメージの中で最小の小版",
	LEnvPyExcludedEOL:   "Python %[1]s は %[2]s にサポート終了のため使わない",
	LEnvPyExcludedDecl:  "宣言がそのイメージの Python を許さないため Python %s は使わない",
	LEnvPip:             "- pip: %s (そのイメージに入っているもの)\n",
	LEnvTool:            "- パッケージマネージャー: %[1]s %[2]s (%[3]s)、アーカイブの sha256 %[4]s\n",
	LEnvToolDefault:     "プロジェクトの指定がないときにこのビルドが選ぶ版",
	LEnvToolSource:      "根拠 %s",
	LEnvToolDeclared:    "プロジェクトが正確に指定している版",
	LEnvToolInRange:     "プロジェクトが指定する範囲を満たす、このビルドの既定の版",
	LFollowedTitle:      "更新に伴って依存先が新しい版に寄ったエントリ",
	LFollowedLine:       "- %[1]s: %[2]s\n",
	LFollowedMove:       "%[1]s を %[2]s から %[3]s へ",
	LDeprecatedGained:   "- %s に非推奨の注記が付きました。npm で作者が非推奨にしたためで、今回の更新とは関係ありません\n",
	LDeprecatedChanged:  "- %s の非推奨の注記が変わりました。npm で作者が変更したためで、今回の更新とは関係ありません\n",
	LDeprecatedPresent:  "- %s は npm で非推奨になっています。更新後の版の注記で、npm の値と一致しています\n",
	LDeprecatedLost:     "- %s の非推奨の注記が外れました。npm で作者が解除したためで、今回の更新とは関係ありません\n",
	LEnvNone:            "- 実行した版: 記録なし (記録を残す前に作られた更新です)\n",
	LOps:                "**実行した操作**\n\n",
	LNoOps:              "- 記録なし\n",
	LStep:               "- %[1]s、終了コード %[2]d",
	LScratch:            " (作業用コピーで実行し、結果は比較だけに使いました)",
	LEntries:            "\n**lockfile のエントリ**: 追加 %[1]d 件、変更 %[2]d 件、削除 %[3]d 件",
	LTruncated:          " (一覧は途中で切ってあります)",
	LTitleChanged:       "変更",
	LTitleAdded:         "追加",
	LTitleRemoved:       "削除",
	LLookup:             "更新で追加または変更した版はすべて %[1]sに照会し、lockfile が指す配布物と照合しました。\n",
	LNote:               "\n- 実行時のメモ: %s\n",
	LSourceHead:         "\n**依存関係ファイルの更新前後のスキャン (Trivy、ファイルシステムモード)**\n\n",
	LBefore:             "- 更新前: %s\n",
	LAfter:              "- 更新後: %s\n",
	LSourceCounts:       "- 解消 %[1]d 件、残存 %[2]d 件、新規 %[3]d 件 (更新したパッケージだけでなく、ファイルの全パッケージが対象)\n",
	LListCut:            "- 以下の一覧は途中で切ってあります\n",
	LBothScans:          "\n両方のスキャンで Trivy %s を使用しました。",
	LDBBuilt:            "脆弱性データベースは、どちらも %s に作成されたものを使用しました。",
	LScanTail:           "重大度の範囲 (%s) と設定は、両方のスキャンで同じです。リポジトリ自身の Trivy 設定、ignore ファイル、VEX ドキュメントは読んでいません。\n",
	LInstallCheck:       "- マージ前に CI で lockfile からのインストール (例: %s) を実行してください\n",
	RegistryNpm:         "npm レジストリ",
	RegistryPyPI:        "PyPI",
	RelDirect:           "直接依存",
	RelTransitive:       "間接依存",
	RelMixed:            "直接依存かつ間接依存",
	RelUnknown:          "関係は不明",
}
