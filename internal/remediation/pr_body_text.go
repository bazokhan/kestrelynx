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
	HeadWhat, HeadChange, HeadWhyCandidate, HeadWhyVersions, HeadVerification, HeadNotVerified string
	HeadVulnTargets, HeadManifestEdits                                                         string

	// Shared pieces.
	ListSep      string // between items of a code list
	ListMore     string // after a cut list: %d
	LineMore     string // a list line: %d
	LineMoreFor  string // a list line: %d more for package %s
	LineMorePkgs string // a list line: %d
	None         string // a list line
	NoFiles      string
	CutNote      string
	Footer       string // %[1]s update key, %[2]s attempt key

	// Vulnerability lists.
	TitleResolved, TitleRemaining, TitleIntroduced string
	TitleRemainingTargeted, TitleOtherRemaining    string
	ListTitle                                      string // %[1]s title, %[2]d count
	VulnLine                                       string // %[1]s id, %[2]s package, %[3]s ecosystem, %[4]s class
	VulnSeverity, VulnKEV, VulnPriority            string
	VulnLineLang                                   string // %[1]s id, %[2]s package
	SourceVulnLine                                 string // %[1]s id, %[2]s package, %[3]s version
	SourceFixed                                    string

	// Scan sentences shared by the image bodies.
	Counts       string // %[1]d resolved, %[2]d remaining, %[3]d introduced
	VerRecord    string // %[1]s generated at, %[2]s baseline, %[3]s candidate
	DBBuilt      string
	SeverityEnd  string // %s
	ScopeEnd     string // %s
	ConfigDigest string
	PlatformPart string
	Locations    string
	DigestNote   string
	NVApp        string
	NVCI         string
	NVSeverity   string

	// Compose bodies.
	CWhat, CRunning, CServices, CWorkloads, CAlso, CChange, CWhy string
	CVerRunning, CCandidate, CScanned                            string
	CNVDeploy                                                    string

	// Dockerfile bodies.
	DWhat, DBaseNow, DEdited, DWorkloads, DChange, DWhy     string
	DIntro1, DIntro2, DIntro3                               string
	DRunning, DCurrentBase, DCandidateBase, DLayer, DVerRec string
	DTargets, DOther, DScanned, DAttribution, DNVRebuilt    string
	DNVApp, DNVDeploy                                       string

	// Language package bodies.
	LWhat, LDir, LManager, LWorkloads, LFiles               string
	LEntryOne, LEntryMany                                   string
	LMajorPkgs, LMajorEdits, LChangeIntro, LPkgLine, LMajor string
	LEditsIntro, LEditsMajor, LEditLine                     string
	LWhy, LVerification, LOps, LNoOps, LStep, LScratch      string
	LEnvRuntime, LEnvPip, LEnvTool, LEnvToolDefault         string
	LEnvToolSource, LEnvNone                                string
	LEnvToolDeclared, LEnvToolInRange, LDeprecated          string
	LFollowedTitle, LFollowedLine, LFollowedMove            string
	LEntries, LTruncated, LTitleChanged, LTitleAdded        string
	LTitleRemoved, LLookup, LNote                           string
	LSourceHead, LBefore, LAfter, LSourceCounts, LListCut   string
	LBothScans, LDBBuilt, LScanTail                         string
	LNVImage, LNVApp, LNVInstall, LNVDeploy                 string
	RegistryNpm, RegistryPyPI                               string
	RelDirect, RelTransitive, RelMixed, RelUnknown          string
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
	HeadWhat:          "What",
	HeadChange:        "Change",
	HeadWhyCandidate:  "Why this candidate",
	HeadWhyVersions:   "Why these versions",
	HeadVerification:  "Verification",
	HeadNotVerified:   "Not verified",
	HeadVulnTargets:   "Vulnerabilities this update targets",
	HeadManifestEdits: "Manifest edits",

	ListSep:      ", ",
	ListMore:     " and %d more",
	LineMore:     "- and %d more\n",
	LineMoreFor:  "- and %[1]d more for %[2]s\n",
	LineMorePkgs: "- and %d more packages\n",
	None:         "- none\n",
	NoFiles:      "no files",
	CutNote:      "\n_The rest of this description was cut to fit the length limit._\n",
	Footer:       "Opened by KestreLynx. Update key %[1]s, attempt key %[2]s.\n",

	TitleResolved:          "Resolved",
	TitleRemaining:         "Remaining",
	TitleIntroduced:        "Introduced",
	TitleRemainingTargeted: "Remaining among the targeted findings",
	TitleOtherRemaining:    "Other findings that remain in the candidate base image",
	ListTitle:              "\n**%[1]s (%[2]d)**\n\n",
	VulnLine:               "- %[1]s in %[2]s (%[3]s, %[4]s)",
	VulnSeverity:           ", severity %s",
	VulnKEV:                ", in the CISA KEV catalog",
	VulnPriority:           ", priority %s",
	VulnLineLang:           "- %[1]s in %[2]s",
	SourceVulnLine:         "- %[1]s in %[2]s %[3]s",
	SourceFixed:            ", fixed in %s",

	Counts:       "- Resolved %[1]d, remaining %[2]d, introduced %[3]d\n",
	VerRecord:    "- Verification record: plan generated at %[1]s, baseline scan %[2]s, candidate scan %[3]s\n",
	DBBuilt:      " with the vulnerability database built at %s",
	SeverityEnd:  ". Severity range: %s.",
	ScopeEnd:     " Scope: %s.",
	ConfigDigest: ", config digest %s",
	PlatformPart: ", platform %s",
	Locations:    "- Locations: %s\n",
	DigestNote:   "  - The running digest comes from the container runtime; whether it is the image config digest or an index or manifest digest is not confirmed.\n",
	NVApp:        "- Whether the application works with the new image\n",
	NVCI:         "- Continuous integration; opening this pull request may start the repository's CI\n",
	NVSeverity:   "- Vulnerabilities of severities outside the range above\n",

	CWhat:       "KestreLynx proposes a new image tag for %[1]d Compose service(s) in %[2]s of %[3]s, against base branch %[4]s at commit %[5]s.\n\n",
	CRunning:    "- Running image: %s\n",
	CServices:   "- Services edited: %s\n",
	CWorkloads:  "- Workloads running them: %s\n",
	CAlso:       "- Also running this image, not edited (no Compose mapping): %s\n",
	CChange:     "- %[1]s: %[2]s to %[3]s\n",
	CWhy:        "%s is the newest patch release in the complete tag listing that keeps the running tag's major and minor version, prefix and suffix.\n",
	CVerRunning: "- Running: %s",
	CCandidate:  "- Candidate: %[1]s, tag digest %[2]s, platform manifest %[3]s, config digest %[4]s, platform %[5]s\n",
	CScanned:    "Both images were scanned by Trivy %s",
	CNVDeploy:   "- Deployment after merge: merging changes the file only, and running containers keep the old image until they are recreated\n",

	DWhat:          "KestreLynx proposes a newer tag for the base image of %[1]s in %[2]s, against base branch %[3]s at commit %[4]s.\n\n",
	DBaseNow:       "- Base image now: %s\n",
	DEdited:        "- Edited: the FROM of stage %[1]d, line %[2]d\n",
	DWorkloads:     "- Workloads built from it: %s\n",
	DChange:        "- FROM on line %[1]d: %[2]s to %[3]s\n",
	DWhy:           "%s is the newest patch release in the complete tag listing that keeps the current tag's major and minor version, prefix and suffix.\n",
	DIntro1:        "Three images are involved and are kept apart below: the running image, which supplies the findings and the layers they were found in; the current base image, the content of the tag the FROM names today; and the candidate base image. ",
	DIntro2:        "The comparison is of the current base image with the candidate base image, on the findings the running image has in the base image's layers. ",
	DIntro3:        "The image rebuilt from the new Dockerfile was not built or scanned.\n",
	DRunning:       "- Running image: %s",
	DCurrentBase:   "- Current base image: %[1]s, tag digest %[2]s, platform manifest %[3]s, config digest %[4]s, platform %[5]s\n",
	DCandidateBase: "- Candidate base image: %[1]s, tag digest %[2]s, platform manifest %[3]s, config digest %[4]s, platform %[5]s\n",
	DLayer:         "- Layer check: %[1]s; the current base image has %[2]d layer(s) and the running image %[3]d. A match shows that the filesystem layers agree; it does not show how the image was built.\n",
	DVerRec:        "- Verification record: plan generated at %[1]s, scan of the current base %[2]s, scan of the candidate base %[3]s\n",
	DTargets:       "- Findings this update targets (fixed findings of the running image in the base image's layers): resolved %[1]d, remaining %[2]d\n",
	DOther:         "- Other findings of the compared base images that remain in the candidate base image: %[1]d; introduced by the candidate base image: %[2]d\n",
	DScanned:       "Both base images were scanned by Trivy %s",
	DAttribution:   "\nTrivy attributes a package to the lowest layer that holds that name and version, so a package installed again by a later instruction of the Dockerfile can still be attributed to a base image layer. A finding listed above is therefore matched to the base image, not proven to come from it.\n",
	DNVRebuilt:     "- The image rebuilt from this Dockerfile: it is not built or scanned, and instructions after the FROM can change which findings it has\n",
	DNVApp:         "- Whether the application works with the new base image\n",
	DNVDeploy:      "- Deployment after merge: merging changes the file only, and running containers keep the old image until it is built again and they are recreated\n",

	LWhat:            "KestreLynx proposes updating %[1]d package %[2]s in %[3]s of %[4]s with %[5]s, against base branch %[6]s at commit %[7]s.\n\n",
	LDir:             "- Dependency directory: %s\n",
	LManager:         "- Package manager: %s\n",
	LWorkloads:       "- Workloads running these packages: %s\n",
	LFiles:           "- Files changed: %s\n",
	LEntryOne:        "entry",
	LEntryMany:       "entries",
	LMajorPkgs:       "**%d package(s) move to another major version (for 0.x, another minor version). Review these first: the application may need changes.**\n",
	LMajorEdits:      "**%d manifest edit(s) allow a new major version and no longer allow the one before; see Manifest edits below.**\n",
	LChangeIntro:     "Running version to version after the update, with how the project requires the package:\n\n",
	LPkgLine:         "- %[1]s: %[2]s to %[3]s (%[4]s)",
	LMajor:           " — **major version change**",
	LEditsIntro:      "The version specifier of these direct dependencies did not allow a fixed version, so it was edited before the lockfile was updated.\n\n",
	LEditsMajor:      "**%d edit(s) below allow a new major version (for 0.x, a new minor version) and no longer allow the one before. Review these first: the application may need changes.**\n\n",
	LEditLine:        "- %[1]s, %[2]s, %[3]s: %[4]s to %[5]s",
	LWhy:             "For each package the target is the lowest version that the vulnerability data lists as fixed for every vulnerability found in the running image; the version in the updated file is the lowest version of the package it holds.\n",
	LVerification:    "The update ran in a throwaway container created from an official image pinned by digest, with fixed operations and no credentials. Its result was treated as untrusted and checked by KestreLynx itself.\n\n",
	LEnvRuntime:      "- Runtime: %[1]s %[2]s, from the official image %[3]s\n",
	LEnvPip:          "- pip: %s, the one in that image\n",
	LEnvTool:         "- Package manager: %[1]s %[2]s (%[3]s), archive sha256 %[4]s\n",
	LEnvToolDefault:  "the version this build selects when the project declares none",
	LEnvToolSource:   "source %s",
	LEnvToolDeclared: "the exact version the project declares",
	LEnvToolInRange:  "this build's default version, which the version ranges the project declares allow",
	LFollowedTitle:   "Entries whose dependencies moved to newer versions along with the update",
	LFollowedLine:    "- %[1]s: %[2]s\n",
	LFollowedMove:    "%[1]s %[2]s to %[3]s",
	LDeprecated:      "- Deprecation notes: %[1]d package version(s) gained, lost or changed one, and each equals what %[2]s publishes for that version\n",
	LEnvNone:         "- Versions that ran: no record of them (this update was made before they were recorded)\n",
	LOps:             "**Operations run**\n\n",
	LNoOps:           "- none recorded\n",
	LStep:            "- %[1]s, exit code %[2]d",
	LScratch:         " (run on a scratch copy; its result was only compared)",
	LEntries:         "\n**Lockfile entries**: %[1]d added, %[2]d changed, %[3]d removed",
	LTruncated:       " (the lists are cut)",
	LTitleChanged:    "Changed",
	LTitleAdded:      "Added",
	LTitleRemoved:    "Removed",
	LLookup:          "Every version the update added or changed was looked up in %[1]s and compared with the distribution the lockfile points at.\n",
	LNote:            "\n- Note from the run: %s\n",
	LSourceHead:      "\n**Scan of the dependency files before and after (Trivy, filesystem mode)**\n\n",
	LBefore:          "- Before: %s\n",
	LAfter:           "- After: %s\n",
	LSourceCounts:    "- Resolved %[1]d, remaining %[2]d, introduced %[3]d (over every package of the files, not only the updated ones)\n",
	LListCut:         "- The lists below are cut\n",
	LBothScans:       "\nBoth scans used Trivy %s",
	LDBBuilt:         ", the vulnerability database built at %s",
	LScanTail:        ", the same severity range (%s) and the same settings; the repository's own Trivy configuration, ignore files and VEX documents were not read. The scan shows that the target vulnerabilities are no longer detected in the lockfile; it is a check of the source files, not of an image.\n",
	LNVImage:         "- Whether the image built from these files has the vulnerabilities resolved: the image is not rebuilt or scanned, and what a build installs can differ from the lockfile\n",
	LNVApp:           "- Whether the application works with the updated packages, and its tests: compatibility and tests were not run\n",
	LNVInstall:       "- Whether the dependencies in the updated files agree exactly with what the registry declares for each version, and whether the installer accepts the format: both were checked only as far as possible, so run a CI job that installs from the lockfile (for example %s) before merging\n",
	LNVDeploy:        "- Deployment after merge: merging changes the files only, and running containers keep the old image until it is built again and they are recreated\n",
	RegistryNpm:      "the npm registry",
	RegistryPyPI:     "PyPI",
	RelDirect:        "direct dependency",
	RelTransitive:    "transitive dependency",
	RelMixed:         "direct and transitive dependency",
	RelUnknown:       "relation not known",
}

var jaPRText = prText{
	HeadWhat:          "概要",
	HeadChange:        "変更内容",
	HeadWhyCandidate:  "この候補を選んだ理由",
	HeadWhyVersions:   "これらの版を選んだ理由",
	HeadVerification:  "確認したこと",
	HeadNotVerified:   "確認していないこと",
	HeadVulnTargets:   "この更新が対象とする脆弱性",
	HeadManifestEdits: "manifest の編集",

	ListSep:      "、",
	ListMore:     "、ほか %d 件",
	LineMore:     "- ほか %d 件\n",
	LineMoreFor:  "- %[2]s について、ほか %[1]d 件\n",
	LineMorePkgs: "- ほか %d 個のパッケージ\n",
	None:         "- なし\n",
	NoFiles:      "ファイルなし",
	CutNote:      "\n_長さの上限に収めるため、この説明の残りを省略しました。_\n",
	Footer:       "KestreLynx が作成しました。更新キー %[1]s、試行キー %[2]s。\n",

	TitleResolved:          "解消",
	TitleRemaining:         "残存",
	TitleIntroduced:        "新規",
	TitleRemainingTargeted: "対象の検出結果のうち残存",
	TitleOtherRemaining:    "候補のベースイメージに残るその他の検出結果",
	ListTitle:              "\n**%[1]s (%[2]d)**\n\n",
	VulnLine:               "- %[2]s の %[1]s (%[3]s、%[4]s)",
	VulnSeverity:           "、重大度 %s",
	VulnKEV:                "、CISA KEV カタログに掲載",
	VulnPriority:           "、優先度 %s",
	VulnLineLang:           "- %[2]s の %[1]s",
	SourceVulnLine:         "- %[2]s %[3]s の %[1]s",
	SourceFixed:            "、修正版 %s",

	Counts:       "- 解消 %[1]d 件、残存 %[2]d 件、新規 %[3]d 件\n",
	VerRecord:    "- 確認の記録: 計画の生成時刻 %[1]s、変更前のスキャン %[2]s、候補のスキャン %[3]s\n",
	DBBuilt:      "。脆弱性データベースの作成時刻は %s です",
	SeverityEnd:  "。重大度の範囲は %s です。",
	ScopeEnd:     "対象範囲は %s です。",
	ConfigDigest: "、config digest %s",
	PlatformPart: "、プラットフォーム %s",
	Locations:    "- 場所: %s\n",
	DigestNote:   "  - 稼働中の digest はコンテナランタイムから得たもので、イメージの config digest か、index または manifest の digest かは確認していません。\n",
	NVApp:        "- アプリケーションが新しいイメージで動作するか\n",
	NVCI:         "- 継続的インテグレーション (このプルリクエストを開くと、リポジトリの CI が起動することがあります)\n",
	NVSeverity:   "- 上記の範囲外の重大度の脆弱性\n",

	CWhat:       "KestreLynx は、%[3]s の %[2]s にある %[1]d 件の Compose サービスについて、新しいイメージタグを提案します。ベースブランチは %[4]s、コミットは %[5]s です。\n\n",
	CRunning:    "- 稼働中のイメージ: %s\n",
	CServices:   "- 編集したサービス: %s\n",
	CWorkloads:  "- これらを実行しているワークロード: %s\n",
	CAlso:       "- 同じイメージを実行していますが編集していないもの (Compose の対応付けなし): %s\n",
	CChange:     "- %[1]s: %[2]s から %[3]s へ\n",
	CWhy:        "%s は、完全なタグ一覧のうち、稼働中のタグのメジャーバージョン、マイナーバージョン、接頭辞、接尾辞を保つ最新のパッチリリースです。\n",
	CVerRunning: "- 稼働中: %s",
	CCandidate:  "- 候補: %[1]s、タグの digest %[2]s、プラットフォームの manifest %[3]s、config digest %[4]s、プラットフォーム %[5]s\n",
	CScanned:    "両方のイメージを Trivy %s でスキャンしました",
	CNVDeploy:   "- マージ後のデプロイ: マージで変わるのはファイルだけで、稼働中のコンテナは再作成するまで古いイメージのままです\n",

	DWhat:          "KestreLynx は、%[2]s の %[1]s にあるベースイメージについて、新しいタグを提案します。ベースブランチは %[3]s、コミットは %[4]s です。\n\n",
	DBaseNow:       "- 現在のベースイメージ: %s\n",
	DEdited:        "- 編集した箇所: ステージ %[1]d の FROM (%[2]d 行目)\n",
	DWorkloads:     "- このイメージから作られるワークロード: %s\n",
	DChange:        "- %[1]d 行目の FROM: %[2]s から %[3]s へ\n",
	DWhy:           "%s は、完全なタグ一覧のうち、現在のタグのメジャーバージョン、マイナーバージョン、接頭辞、接尾辞を保つ最新のパッチリリースです。\n",
	DIntro1:        "ここでは 3 つのイメージを区別します。稼働中のイメージは、検出結果と、それが見つかったレイヤーの出どころです。現在のベースイメージは、今の FROM が指すタグの内容です。もう 1 つは候補のベースイメージです。",
	DIntro2:        "比較するのは現在のベースイメージと候補のベースイメージで、対象は稼働中のイメージがベースイメージのレイヤーに持つ検出結果です。",
	DIntro3:        "新しい Dockerfile から作り直したイメージは、ビルドもスキャンもしていません。\n",
	DRunning:       "- 稼働中のイメージ: %s",
	DCurrentBase:   "- 現在のベースイメージ: %[1]s、タグの digest %[2]s、プラットフォームの manifest %[3]s、config digest %[4]s、プラットフォーム %[5]s\n",
	DCandidateBase: "- 候補のベースイメージ: %[1]s、タグの digest %[2]s、プラットフォームの manifest %[3]s、config digest %[4]s、プラットフォーム %[5]s\n",
	DLayer:         "- レイヤーの確認: %[1]s。現在のベースイメージのレイヤーは %[2]d 層、稼働中のイメージは %[3]d 層です。一致が示すのはファイルシステムのレイヤーが揃っていることだけで、イメージの作られ方は示しません。\n",
	DVerRec:        "- 確認の記録: 計画の生成時刻 %[1]s、現在のベースのスキャン %[2]s、候補のベースのスキャン %[3]s\n",
	DTargets:       "- この更新が対象とする検出結果 (稼働中のイメージの修正可能な検出結果のうち、ベースイメージのレイヤーにあるもの): 解消 %[1]d 件、残存 %[2]d 件\n",
	DOther:         "- 比較した両ベースイメージのその他の検出結果のうち、候補のベースイメージに残るもの: %[1]d 件、候補のベースイメージで新たに入るもの: %[2]d 件\n",
	DScanned:       "両方のベースイメージを Trivy %s でスキャンしました",
	DAttribution:   "\nTrivy は、同じ名前と版のパッケージを、それを含む最も下のレイヤーに割り当てます。そのため、Dockerfile の後ろの命令で再びインストールされたパッケージも、ベースイメージのレイヤーに割り当てられることがあります。上に挙げた検出結果はベースイメージに対応付けたものであり、ベースイメージ由来であると証明したものではありません。\n",
	DNVRebuilt:     "- この Dockerfile から作り直したイメージ: ビルドもスキャンもしておらず、FROM より後の命令で検出結果が変わることがあります\n",
	DNVApp:         "- アプリケーションが新しいベースイメージで動作するか\n",
	DNVDeploy:      "- マージ後のデプロイ: マージで変わるのはファイルだけで、稼働中のコンテナはイメージをビルドし直して再作成するまで古いイメージのままです\n",

	LWhat:            "KestreLynx は、%[4]s の %[3]s にある %[1]d 件のパッケージ%[2]sを %[5]s で更新することを提案します。ベースブランチは %[6]s、コミットは %[7]s です。\n\n",
	LDir:             "- 依存関係のディレクトリ: %s\n",
	LManager:         "- パッケージマネージャー: %s\n",
	LWorkloads:       "- これらのパッケージを実行しているワークロード: %s\n",
	LFiles:           "- 変更したファイル: %s\n",
	LEntryOne:        "エントリ",
	LEntryMany:       "エントリ",
	LMajorPkgs:       "**%d 件のパッケージが別のメジャーバージョンに上がります (0.x では別のマイナーバージョン)。アプリケーションの変更が必要になることがあるため、最初に確認してください。**\n",
	LMajorEdits:      "**%d 件の manifest の編集で、新しいメジャーバージョンを許可し、それまで許可していたメジャーバージョンを許可しなくなります。下の「manifest の編集」を参照してください。**\n",
	LChangeIntro:     "更新前の稼働中の版から更新後の版へ、プロジェクトがそのパッケージをどう要求しているかとあわせて示します。\n\n",
	LPkgLine:         "- %[1]s: %[2]s から %[3]s へ (%[4]s)",
	LMajor:           " — **メジャーバージョンの変更**",
	LEditsIntro:      "これらの直接依存のバージョン指定は修正済みの版を許可していなかったため、lockfile の更新前に編集しました。\n\n",
	LEditsMajor:      "**以下の %d 件の編集は、新しいメジャーバージョン (0.x では新しいマイナーバージョン) を許可し、それまで許可していたメジャーバージョン (0.x ではマイナーバージョン) を許可しなくなります。アプリケーションの変更が必要になることがあるため、最初に確認してください。**\n\n",
	LEditLine:        "- %[1]s、%[2]s、%[3]s: %[4]s から %[5]s へ",
	LWhy:             "各パッケージの目標は、稼働中のイメージで見つかったすべての脆弱性について、脆弱性データが修正済みとして挙げている最も低い版です。更新後の版として示すのは、更新後のファイルに含まれる、そのパッケージの版のうち最も低いものです。\n",
	LVerification:    "更新は、digest で固定した公式イメージから作った使い捨てのコンテナで、固定の操作だけを認証情報なしで実行しました。その結果は信頼できないものとして扱い、KestreLynx 自身が確認しています。\n\n",
	LEnvRuntime:      "- 実行環境: %[1]s %[2]s (公式イメージ %[3]s)\n",
	LEnvPip:          "- pip: %s (そのイメージに入っているもの)\n",
	LEnvTool:         "- パッケージマネージャー: %[1]s %[2]s (%[3]s)、アーカイブの sha256 %[4]s\n",
	LEnvToolDefault:  "プロジェクトの指定がないときにこのビルドが選ぶ版",
	LEnvToolSource:   "根拠 %s",
	LEnvToolDeclared: "プロジェクトが正確に指定している版",
	LEnvToolInRange:  "プロジェクトが指定する範囲を満たす、このビルドの既定の版",
	LFollowedTitle:   "更新に伴って依存先が新しい版に寄ったエントリ",
	LFollowedLine:    "- %[1]s: %[2]s\n",
	LFollowedMove:    "%[1]s を %[2]s から %[3]s へ",
	LDeprecated:      "- 非推奨の注記: %[1]d 件のパッケージの版で注記が追加・変更・削除され、いずれも %[2]sが公開するその版の値と一致\n",
	LEnvNone:         "- 実行した版: 記録なし (記録を残す前に作られた更新です)\n",
	LOps:             "**実行した操作**\n\n",
	LNoOps:           "- 記録なし\n",
	LStep:            "- %[1]s、終了コード %[2]d",
	LScratch:         " (作業用コピーで実行し、結果は比較だけに使いました)",
	LEntries:         "\n**lockfile のエントリ**: 追加 %[1]d 件、変更 %[2]d 件、削除 %[3]d 件",
	LTruncated:       " (一覧は途中で切ってあります)",
	LTitleChanged:    "変更",
	LTitleAdded:      "追加",
	LTitleRemoved:    "削除",
	LLookup:          "更新で追加または変更した版はすべて %[1]sに照会し、lockfile が指す配布物と照合しました。\n",
	LNote:            "\n- 実行時のメモ: %s\n",
	LSourceHead:      "\n**依存関係ファイルの更新前後のスキャン (Trivy、ファイルシステムモード)**\n\n",
	LBefore:          "- 更新前: %s\n",
	LAfter:           "- 更新後: %s\n",
	LSourceCounts:    "- 解消 %[1]d 件、残存 %[2]d 件、新規 %[3]d 件 (更新したパッケージだけでなく、ファイルの全パッケージが対象)\n",
	LListCut:         "- 以下の一覧は途中で切ってあります\n",
	LBothScans:       "\n両方のスキャンで Trivy %s を使用しました。",
	LDBBuilt:         "脆弱性データベースは、どちらも %s に作成されたものを使用しました。",
	LScanTail:        "重大度の範囲 (%s) と設定は、両方のスキャンで同じです。リポジトリ自身の Trivy 設定、ignore ファイル、VEX ドキュメントは読んでいません。このスキャンが示すのは、対象の脆弱性が lockfile で検出されなくなったことです。イメージではなく、ソースファイルの確認です。\n",
	LNVImage:         "- このファイルから作ったイメージで脆弱性が解消しているか: イメージはビルドもスキャンもしておらず、ビルドが実際にインストールするものは lockfile と異なることがあります\n",
	LNVApp:           "- アプリケーションが更新後のパッケージで動作するか、およびそのテスト: 互換性の確認もテストも実施していません\n",
	LNVInstall:       "- 更新後のファイルの依存関係が各版についてレジストリの宣言と完全に一致するか、およびインストーラーがその形式を受け付けるか: どちらも可能な範囲でしか確認していないため、マージ前に lockfile からインストールする CI ジョブ (例: %s) を実行してください\n",
	LNVDeploy:        "- マージ後のデプロイ: マージで変わるのはファイルだけで、稼働中のコンテナはイメージをビルドし直して再作成するまで古いイメージのままです\n",
	RegistryNpm:      "npm レジストリ",
	RegistryPyPI:     "PyPI",
	RelDirect:        "直接依存",
	RelTransitive:    "間接依存",
	RelMixed:         "直接依存かつ間接依存",
	RelUnknown:       "関係は不明",
}
