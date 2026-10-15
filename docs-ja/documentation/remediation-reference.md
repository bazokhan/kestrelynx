# 対応形式と理由コード

修正計画と修正PRが扱う入力形式、実行環境、結果の値、理由コードをまとめます。
有効化は[有効化の手順](remediation-setup.md)を参照してください。

## 対応範囲 {#scope-and-requirements}

### 利用環境 {#supported-environments}

| 項目 | 対応範囲 |
| --- | --- |
| コンテナ環境 | Dockerモードに対応し、Kubernetesモードでは修正計画を有効にできない |
| ソースの対応付け | ComposeのWorkloadに対して、変更先のソースを指定 |
| ソースホスト | GitHub |
| 作業用コンテナ | Linuxの`amd64`・`arm64` |
| 言語更新の実行環境 | [対応する実行環境](#supported-runtimes)に記載した系列 |
| Sensor | 修正計画と修正PRの利用には不要 |

### 更新対象 {#supported-targets}

| 対象 | 取得元 | ソースの対応付け |
| --- | --- | --- |
| 配布イメージ | 公開レジストリ、認証を設定した非公開レジストリ | 比較結果の表示には不要で、Composeを変更するPRには必要 |
| Dockerfileのベースイメージ | 公開レジストリ、認証を設定した非公開レジストリ | 計画の作成からDockerfileまたはComposeの対応付けが必要 |
| npm・pnpmの依存パッケージ | 公開npmレジストリ | 計画の作成から依存ディレクトリの対応付けが必要 |
| pip・uvの依存パッケージ | 公開PyPI | 計画の作成から依存ディレクトリの対応付けが必要 |

非公開npmレジストリや非公開PyPIは更新対象にできません。
イメージレジストリの認証は、依存パッケージの取得には使いません。

## 対応する入力形式 {#supported-inputs}

### Composeの形式 {#compose-formats}

| 入力 | 対応範囲 |
| --- | --- |
| 編集箇所 | `services.<service>.image`に直接記述したイメージ参照 |
| イメージ参照 | 稼働中のリポジトリとタグに一致し、変更箇所を特定できる文字列 |
| 固定タグ | 完全な版を指定するタグを、同じ系列の新しいパッチへ変更可能 |
| 浮動タグ | 再pullの候補となり、同じタグの参照を書き換えるPRは作らない |
| 変数・digest | 編集対象のイメージ参照では未対応 |
| YAMLのアンカー・エイリアス・マージキー | 編集箇所に関わる場合は未対応 |
| ブロックスカラー・文字列以外の`image` | 未対応 |
| `include`・対象サービスの`extends` | 自動編集では未対応 |
| `build:`を持つサービス | 完成イメージを配布イメージの検索から除外 |

タグの選び方は[配布イメージのタグ](remediation-logic.md#published-image-tags)、ビルド対象の扱いは[ローカルビルドの除外](remediation-logic.md#local-builds)を参照してください。

### Dockerfileの形式 {#dockerfile-formats}

| 入力 | 対応範囲 |
| --- | --- |
| `FROM`の固定タグ | 変数やdigestを使わず、タグの位置を特定できる参照を編集可能 |
| `FROM`の浮動タグ | ベースの確認対象となるが、タグ更新PRの対象外 |
| ビルド`target` | ステージ名を指定可能で、省略時は最後のステージが対象 |
| 前のステージの継承 | 外部のベースイメージまでたどれる構成に対応 |
| `--platform` | 外部ベースを指定する`FROM`の静的な指定に対応し、継承途中の`FROM`での指定は未対応 |
| `FROM`内の変数・`scratch`・digest参照 | 自動編集では未対応 |
| 標準以外の構文フロントエンド・`escape`ディレクティブ | 自動編集では未対応 |
| 継承元ステージやベースイメージの`ONBUILD` | 自動更新では未対応 |
| Composeのbuild context | リポジトリ内の静的なパスに対応 |
| Composeの`dockerfile`・`target` | 対応する静的な指定からDockerfileの編集先を特定可能 |
| リモートbuild context・`dockerfile_inline`・`additional_contexts` | Composeからの編集先の特定では未対応 |

編集先の決め方と対応付けの照合は[ベースイメージの特定](remediation-logic.md#base-image-selection)を参照してください。

### npmの依存ファイル {#npm-inputs}

| 入力 | 対応範囲 |
| --- | --- |
| 必須ファイル | 単一プロジェクトの`package.json`と`package-lock.json` |
| lockfile形式 | `lockfileVersion`が2または3で、`packages`にルートの記録がある形式 |
| 取得元 | 公開npmレジストリの配布物 |
| workspace | 未対応 |
| Git・URL・ローカル参照・別名でのインストール | 対象パッケージの自動更新では未対応 |
| 同梱依存・独自のshrinkwrap | 対象パッケージの自動更新では未対応 |
| `overrides`による版の固定 | 該当するパッケージは手動対応 |
| `.npmrc`の非公開レジストリ指定 | 未対応 |

### pnpmの依存ファイル {#pnpm-inputs}

| 入力 | 対応範囲 |
| --- | --- |
| 必須ファイル | `package.json`と`pnpm-lock.yaml` |
| lockfile形式 | `lockfileVersion: '9.0'`で、importerが`.`だけの形式 |
| manifestとの整合 | 直接依存の宣言とimporterが一致する構成 |
| workspace・catalog・パッチ適用済み依存 | 未対応 |
| 公開npmレジストリ以外の取得元 | 対象パッケージの自動更新では未対応 |
| runtimeの自動取得を記録したlockfile | 未対応 |
| `resolutions`・`configDependencies`・`executionEnv`など | 解決方法や追加取得を変える未対応設定 |
| pnpm 12 | 現在のlockfile再生成方法では更新できないため手動対応 |

同じディレクトリの`pnpm-workspace.yaml`は、次の設定だけを持つ場合に読み取れます。
ファイルがあるだけでworkspaceとは判断しません。

| 設定 | 対応する形式 |
| --- | --- |
| `allowBuilds` | パッケージの指定をキーとし、真偽値または文字列を値とする対応表 |
| `onlyBuiltDependencies`・`ignoredBuiltDependencies`・`neverBuiltDependencies` | パッケージ名の文字列リスト |
| `supportedArchitectures` | `os`・`cpu`・`libc`ごとの文字列リスト |
| `packages` | workspace宣言として扱うため未対応 |
| 上記以外のキー | 未対応 |
| 依存ディレクトリより上にある`pnpm-workspace.yaml` | リポジトリのルートまで確認し、存在する場合は手動対応 |

`package.json`の`pnpm`設定も、上表のビルド許可とアーキテクチャの設定が対象です。
読み取れるビルド許可設定があっても、更新時のスクリプト実行は無効です。

### pipの依存ファイル {#pip-inputs}

| 入力 | 対応範囲 |
| --- | --- |
| 必須ファイル | UTF-8の`requirements.txt` |
| 厳密な固定版 | `name==1.2.3`形式を更新可能 |
| 範囲指定・版指定なし | 修正版を許す場合は再ビルドの見込みを示し、固定版への書き換えは行わない |
| extras | `name[extra]`形式を読み取り可能 |
| コメント・継続行 | 読み取り可能 |
| 既存の`--hash` | 固定版の更新時に、PyPIのwheel情報から更新 |
| 環境マーカー | 自動評価せず、対象パッケージを手動対応にする |
| `-r`・`-c`などの別ファイル参照 | 未対応 |
| 取得元を変更するオプション | 未対応 |
| Git・URL・ローカル参照 | 対象パッケージの自動更新では未対応 |
| ソース配布物しかない版 | 自動更新では未対応 |

稼働イメージに合わせた検証対象の条件は[pipの検証環境](remediation-logic.md#pip-target-environment)を参照してください。

### uvの依存ファイル {#uv-inputs}

| 入力 | 対応範囲 |
| --- | --- |
| 必須ファイル | 単一プロジェクトの静的な`pyproject.toml`と`uv.lock` |
| lockfile形式 | `version = 1`・`revision = 5` |
| プロジェクト | `[project]`があり、動的なメタデータを要求しない構成 |
| Pythonの要件 | 自動更新には`[project]`の`requires-python`が必要 |
| 取得元 | 公開PyPI |
| workspace | 未対応 |
| Git・URL・ローカル参照 | 対象パッケージの自動更新では未対応 |
| ソースのビルドが必要な依存 | 自動更新では未対応 |
| `[tool.uv]` | `required-version`・`dev-dependencies`・`sources`・`package`を読み取り可能 |
| 上記以外の`[tool.uv]`設定 | 未対応 |
| `uv.toml` | 依存ディレクトリからリポジトリのルートまでのいずれかに存在する場合は未対応 |

`[tool.uv]`のキーを読み取れる場合も、依存の取得元やプロジェクト構成が対応範囲内である必要があります。

### Node.jsの版宣言 {#node-declarations}

| 宣言 | 対応する形式 |
| --- | --- |
| `.nvmrc`・`.node-version` | 最初の空でない行にある`22`・`22.14`・`22.14.0`などの数値指定で、先頭の`v`も使用可能 |
| `.nvmrc`のLTS指定 | `lts/*`と、認識できるLTS系列名 |
| `package.json`の`engines.node` | 正確な版、比較演算子、`^`・`~`、ワイルドカードなどの解釈可能な範囲 |
| `devEngines.runtime`・`engines.runtime` | Node.jsを指定するオブジェクトまたは配列と、その版の範囲 |
| `system`・`current`などの指定 | 実行する系列を特定できないため未対応 |
| プレリリースを境界に含む範囲 | 未対応 |
| runtime宣言の`onFail: download` | 未対応 |

版ファイルはmajor系列の選択に使い、実際のminor・patch版は同梱の表に従います。
宣言の組み合わせ方は[Node.jsの選定](remediation-logic.md#node-selection)を参照してください。

### Pythonの版宣言 {#python-declarations}

| 宣言 | 対応する形式 |
| --- | --- |
| uvの`requires-python` | `>=3.12,<3.15`などの解釈可能なPython版の条件 |
| `.python-version` | 最初の空でない行にある`3.13`・`3.13.5`などの指定 |
| CPythonの接頭辞 | `cpython-3.13`・`cpython@3.13`など |
| `.python-versions` | 複数版の指定は未対応 |
| PyPy・GraalPy・Pyodide・`system` | 未対応 |
| free-threaded版 | 未対応 |

`.python-version`はPython X.Y系列の選択に使い、記載したpatch版と実行版の違いは許容します。
宣言の整合条件は[uv用Pythonの選定](remediation-logic.md#uv-python-selection)を参照してください。

### ツールの版宣言 {#tool-declarations}

| 宣言 | 対応する形式 |
| --- | --- |
| `packageManager` | `npm@11.21.0`・`pnpm@11.28.5`などのマネージャー名と正確な版 |
| `packageManager`のハッシュ | `name@version+<algorithm>.<hex>`形式 |
| ハッシュのアルゴリズム | `sha1`・`sha224`・`sha256`・`sha384`・`sha512` |
| `devEngines.packageManager` | マネージャー名と、正確な版または解釈可能な範囲 |
| `engines.npm`・`engines.pnpm` | 正確な版または解釈可能な範囲 |
| `tool.uv.required-version` | `==0.13.0`などの正確な版、または解釈可能な範囲 |
| プレリリース・ビルドメタデータ付きのツール版 | 未対応 |

| ツール | 扱える版 | 既定の版 |
| --- | --- | --- |
| npm | 9〜12系列で、選んだNode.jsと互換性がある版 | `11.21.0` |
| pnpm | 9〜11系列で、選んだNode.jsと互換性がある版 | `11.28.5` |
| uv | `0.12.22`以上の対応する安定版 | `0.13.0` |
| pip | 作業用の公式Pythonイメージに含まれる版 | Python 3.13の作業用イメージでは`26.2.1` |

宣言版と既定版の選び方は[ツール版の選定](remediation-logic.md#tool-version-selection)、公開後の利用条件は[ツール公開後の待機](remediation-logic.md#tool-release-age)を参照してください。

## 対応する実行環境 {#supported-runtimes}

対応する実行環境は、同梱の表にあるサポート中の系列(現時点で Node.js 22・24・26、Python 3.11〜3.15)です。
次の版と期限はKestreLynxが持つ情報であり、KestreLynxの更新に伴って変わります。

| 系列 | 同梱の表の実行版 | サポート終了日 |
| --- | --- | --- |
| Node.js 22 | `22.23.3` | 2027-04-30 |
| Node.js 24 | `24.21.0` | 2028-04-30 |
| Node.js 26 | `26.11.1` | 2029-04-30 |
| Python 3.11 | `3.11.17` | 2027-10-31 |
| Python 3.12 | `3.12.15` | 2028-10-31 |
| Python 3.13 | `3.13.16` | 2029-10-31 |
| Python 3.14 | `3.14.8` | 2030-10-31 |
| Python 3.15 | `3.15.0` | 2031-10-31 |

| 用途 | 既定の実行環境 |
| --- | --- |
| Node.jsの宣言がないnpm・pnpm更新 | 現時点ではNode.js 24で、同梱の表のLTS開始日に従い2026-10-28から26が候補になる |
| pip更新の作業用コンテナ | Python 3.13 |
| uv更新 | Pythonの宣言に従って選定 |

| 同梱の表にある終了済み系列 | サポート終了日 |
| --- | --- |
| Node.js 20 | 2026-04-30 |
| Python 3.9 | 2025-10-31 |
| Python 3.10 | 2026-10-01 |

サポート期限を過ぎた系列は更新に使いません。
選定条件は[実行環境の選定](remediation-logic.md#runtime-and-tool-versions)を参照してください。

## 結果の値 {#result-values}

### 計画の分類値 {#category-values}

`category`は、イメージや依存ディレクトリなどの計画項目全体の分類です。

| 値 | 意味 |
| --- | --- |
| `pr_candidate` | 検査を通り、PRでの変更を提案できる候補 |
| `dependency_update_candidate` | ソースと修正版情報から選んだ依存更新候補で、更新結果は未検証 |
| `pull_again` | 同じタグの内容を再取得することで改善が見込める、比較済みの候補 |
| `rebuild_expected` | 依存範囲から、再ビルドで修正版が入る見込み（Slackの「再ビルド」には、分類が`not_comparable`の浮動タグのベースの案内も表示される） |
| `manual` | 自動では進めず、利用者の判断や手動対応が必要 |
| `not_comparable` | 比較に必要な情報や条件がそろわない |
| `deferred` | 上限、待機、取得の問題などで処理を保留 |
| `no_candidate` | 新しい候補がない、内容が同じ、または候補で対象が解消しない |
| `excluded` | 自動で候補を探す対象外 |
| `failed` | 処理に失敗 |

### パッケージの処理値 {#action-values}

`action`は個々のパッケージの扱いです。
項目全体の`category`とは別に確認してください。

| 値 | 意味 |
| --- | --- |
| `update` | 依存ファイルを更新する対象 |
| `rebuild_expected` | 現在の依存範囲が修正版を許し、再ビルドによる解消を見込む対象 |
| `manual` | 手動対応が必要な対象 |

`update`だけでは更新の実行や検証の完了を表しません。
版の読み分けは[更新目標と採用版](remediation-results.md#target-and-adopted-version)を参照してください。

### PRの状態値 {#pr-status-values}

PR処理結果の`status`には、次の値があります。

| 値 | 意味 |
| --- | --- |
| `pr_created` | 今回の処理でPRを作成した |
| `pr_open` | 同じ更新を提案するPRが開いている |
| `pr_merged` | 同じ更新のPRがマージ済みで、配置済みかは未確認 |
| `pr_suppressed` | 未マージで閉じた更新のため、再作成を抑止した |
| `manual` | 自動編集できず、手動対応が必要 |
| `deferred` | 上限や候補の変化などにより、後の処理へ延期した |
| `failed` | GitHubへの書き込みなどに失敗した |
| `write_blocked` | 記録やGitHub上の状態などの問題により、書き込みを停止した |
| `write_disabled` | PR作成が無効であることを表す値で、通常のPR処理では生成しない |

PR記録の`state`には、次の値があります。

| 値 | 意味 |
| --- | --- |
| `open` | オープン中 |
| `closed` | 未マージでクローズ済み |
| `merged` | マージ済み |
| `replaced` | 新しいPRに置き換えるため、KestreLynxがクローズ済み |

## 理由コード {#reason-codes}

結果の`reason`には、候補を選んだ理由や処理を進められなかった理由が入ります。
コードの意味と、関連する判定・確認操作を次に示します。

### イメージ候補の理由 {#image-reasons}

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `scan_failed` | スキャンに失敗した | [比較条件](remediation-logic.md#comparison-conditions) |
| `entity_unverified` | 稼働イメージを確認できない、またはレジストリの内容と比較できない | [比較条件](remediation-logic.md#comparison-conditions) |
| `conditions_unknown` | スキャンの条件が分からない | [比較条件](remediation-logic.md#comparison-conditions) |
| `conditions_differ` | スキャンの条件がそろっていない | [比較条件](remediation-logic.md#comparison-conditions) |
| `platform_unknown` | イメージのプラットフォームが分からない | [比較条件](remediation-logic.md#comparison-conditions) |
| `platform_differ` | 比較するイメージのプラットフォームが異なる | [比較条件](remediation-logic.md#comparison-conditions) |
| `variant_unsupported` | 対応していない種類のイメージである | [比較条件](remediation-logic.md#comparison-conditions) |
| `packages_missing` | スキャン結果にパッケージ一覧がない | [比較条件](remediation-logic.md#comparison-conditions) |
| `packages_truncated` | スキャン結果のパッケージ一覧が途中で切れている | [比較条件](remediation-logic.md#comparison-conditions) |
| `unknown_package_type` | 対応していない種類のパッケージの所見がある | [比較条件](remediation-logic.md#comparison-conditions) |
| `type_not_analysed` | 候補のスキャンが対象の種類のパッケージを解析していない | [比較条件](remediation-logic.md#comparison-conditions) |
| `no_newer_tag` | より新しいタグがない | [配布イメージのタグ](remediation-logic.md#published-image-tags) |
| `same_content` | 新しいタグも内容が同じである | [配布イメージのタグ](remediation-logic.md#published-image-tags) |
| `candidate_does_not_resolve_targets` | 候補では対象の所見が解消しない | [比較条件](remediation-logic.md#comparison-conditions) |
| `auth_required` | レジストリへのログインが必要である | [非公開イメージの認証](remediation-setup.md#configure-registry-auth) |
| `platform_not_found` | 候補に同じプラットフォームのイメージがない | [比較条件](remediation-logic.md#comparison-conditions) |
| `platform_ambiguous` | 候補にプラットフォームが合うイメージが複数ある | [比較条件](remediation-logic.md#comparison-conditions) |
| `platform_mismatch` | 候補のプラットフォームが稼働イメージと異なる | [比較条件](remediation-logic.md#comparison-conditions) |
| `registry_error` | レジストリがエラーを返した | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `targets_not_detected_on_baseline` | 比較元のスキャンで対象の所見が検出されなかった | [比較条件](remediation-logic.md#comparison-conditions) |
| `analysis_incomplete` | イメージの解析が不完全だった | [比較条件](remediation-logic.md#comparison-conditions) |
| `tag_listing_incomplete` | タグ一覧を最後まで取得できなかった | [タグ一覧の探索](remediation-logic.md#tag-discovery) |
| `candidate_scan_limit` | 1回の実行でスキャンできる候補数の上限に達した | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `baseline_rescan_limit` | 比較元イメージを再スキャンできる数の上限に達した | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `tag_page_limit` | タグ一覧の取得回数の上限に達した | [タグ一覧の探索](remediation-logic.md#tag-discovery) |
| `registry_budget_exhausted` | レジストリへの要求数の上限に達した | [タグ一覧の探索](remediation-logic.md#tag-discovery) |
| `rate_limited` | レジストリのレート制限に掛かった | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `cycle_deadline` | 実行時間の上限に達した | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `registry_timeout` | レジストリへの要求がタイムアウトした | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `locally_built` | ホストでビルドしたイメージのため、配布イメージの検索対象外である | [ローカルビルドの除外](remediation-logic.md#local-builds) |
| `partial_improvement` | 候補では一部の所見だけが解消する | [比較条件](remediation-logic.md#comparison-conditions) |
| `introduced_findings` | 候補で新たな所見が入る | [比較条件](remediation-logic.md#comparison-conditions) |
| `introduced_kev` | 候補でKEV掲載の脆弱性が新たに入る | [比較条件](remediation-logic.md#comparison-conditions) |
| `adopted` | 候補を採用した | [比較条件](remediation-logic.md#comparison-conditions) |
| `digest_only` | タグがなくdigestだけで指定されている | [配布イメージのタグ](remediation-logic.md#published-image-tags) |
| `tag_and_digest` | タグとdigestの両方で指定されている | [配布イメージのタグ](remediation-logic.md#published-image-tags) |
| `prerelease` | タグがプレリリース版の形式である | [配布イメージのタグ](remediation-logic.md#published-image-tags) |
| `bare_digest` | digestだけの参照で、リポジトリが分からない | [配布イメージのタグ](remediation-logic.md#published-image-tags) |
| `unparsable` | イメージ参照を解釈できない | [配布イメージのタグ](remediation-logic.md#published-image-tags) |
| `unsupported_tag_format` | 対応していない形式のタグである | [配布イメージのタグ](remediation-logic.md#published-image-tags) |
| `base_layers_mismatch` | タグが指すベースのレイヤーが、稼働イメージの先頭部分と一致しない | [ベースレイヤーの照合](remediation-logic.md#base-layer-matching) |
| `base_layers_unusable` | 稼働イメージとベースイメージのレイヤーを比較できない | [ベースレイヤーの照合](remediation-logic.md#base-layer-matching) |
| `base_onbuild` | ベースイメージに`ONBUILD`トリガーがある | [ベースイメージの特定](remediation-logic.md#base-image-selection) |
| `no_base_derived_findings` | 修正可能な所見が、ベースイメージのレイヤーにない | [ベースレイヤーの照合](remediation-logic.md#base-layer-matching) |
| `base_unchanged` | タグが指す現在のベースのレイヤーが稼働イメージの先頭と一致し、ベースの更新を確認できない | [ベースレイヤーの照合](remediation-logic.md#base-layer-matching) |
| `floating_base_unconfirmed` | 稼働イメージの作成元のベースを確認できない | [ベースレイヤーの照合](remediation-logic.md#base-layer-matching) |
| `dockerfile_set_not_adopted` | 同じDockerfileを使うWorkloadのすべてで、同じ候補を採用できなかった（個々のWorkloadの理由も確認する） | [ベースイメージの特定](remediation-logic.md#base-image-selection) |
| `compose_set_not_adopted` | 同じイメージを使うサービスのすべてで、同じ候補を採用できなかった（個々のサービスの理由も確認する） | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |

### ソースの理由 {#source-reasons}

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `dockerfile_file_not_found` | 設定したパスにDockerfileがない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `dockerfile_file_unusable` | Dockerfileが編集できる種類のファイルではない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `dockerfile_invalid` | Dockerfileを解釈できない、または編集の検証に失敗した | |
| `dockerfile_target_missing` | 指定したビルドステージがない | [ベースイメージの特定](remediation-logic.md#base-image-selection) |
| `dockerfile_stage_cycle` | ステージの参照をたどっても外部イメージに行き着かない | [ベースイメージの特定](remediation-logic.md#base-image-selection) |
| `dockerfile_variable` | ベースイメージまたはプラットフォームに変数が含まれる | |
| `dockerfile_scratch` | ベースが`scratch`である | |
| `dockerfile_digest` | ベースがdigestで指定されている | |
| `dockerfile_tag_unsupported` | ベースのタグが候補を探せない形式である | [配布イメージのタグ](remediation-logic.md#published-image-tags) |
| `dockerfile_frontend` | 標準以外の構文フロントエンドを指定している | |
| `dockerfile_escape` | `escape`ディレクティブを設定している | |
| `dockerfile_ambiguous_range` | ファイル内でタグの位置を正確に特定できない | |
| `dockerfile_onbuild` | 継承元のステージに`ONBUILD`がある | |
| `dockerfile_stage_platform` | 継承途中の`FROM`に`--platform`がある | |
| `dockerfile_not_editable` | ベースが固定タグではない | [ベースイメージの特定](remediation-logic.md#base-image-selection) |
| `dockerfile_source_mismatch` | ファイルのベースイメージが想定と異なる | [ベースイメージの特定](remediation-logic.md#base-image-selection) |
| `dockerfile_mapping_differs` | 設定したDockerfileとComposeが指すDockerfileが一致しない | [ベースイメージの特定](remediation-logic.md#base-image-selection) |
| `compose_no_build` | 対象サービスに`build`の指定がない | [ベースイメージの特定](remediation-logic.md#base-image-selection) |
| `compose_build_remote_context` | build contextがURLまたはリポジトリである | |
| `compose_build_inline` | `dockerfile_inline`を使っている | |
| `compose_build_additional` | `additional_contexts`を使っている | |
| `compose_build_path` | ビルドのパスが絶対パス、リポジトリ外、または不正な形式である | |
| `compose_build_unsupported_form` | `build`の書き方に対応していない | |
| `compose_build_undetermined` | サービスのビルド方法を判断できない | [ローカルビルドの除外](remediation-logic.md#local-builds) |
| `compose_invalid` | Composeファイルを解釈できない、または編集の検証に失敗した | |
| `compose_service_missing` | Composeファイルに対象サービスまたは`image`キーがない | |
| `compose_build` | サービスがイメージをビルドしている | [ローカルビルドの除外](remediation-logic.md#local-builds) |
| `compose_include_or_extends` | Composeファイルが`include`または`extends`を使っている | |
| `compose_merge_key` | `image`への経路にマージキーがある | |
| `compose_anchor_or_alias` | `image`がYAMLのアンカーまたはエイリアスに関わっている | |
| `compose_not_string` | `image`の値が単純な文字列ではない | |
| `compose_block_scalar` | `image`の値がブロックスカラーである | |
| `compose_variable` | `image`の値に変数が含まれる | |
| `compose_digest` | `image`の値にdigestが付いている | |
| `compose_source_mismatch` | ファイルの`image`が稼働イメージと異なる | [ソースの確認](remediation-logic.md#source-verification) |
| `compose_file_not_found` | 設定したパスにComposeファイルがない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `compose_file_unusable` | Composeファイルが編集できる種類のファイルではない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `dependency_files_not_found` | 依存ファイルが見つからない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `ambiguous_dependency_files` | 依存ファイルの組み合わせが複数あり、一意に決められない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `dependency_file_unusable` | 依存ファイルを利用できない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `unsupported_lockfile` | lockfileの形式に対応していない | |
| `workspace_unsupported` | プロジェクトのworkspace構成に対応していない | |
| `workspace_settings_unsupported` | workspace設定ファイルの内容に対応していない | |
| `dynamic_metadata` | プロジェクトのメタデータが動的に決まる | |
| `unsupported_requirements` | requirementsの書き方に対応していない | |
| `unparsable_source` | 依存ファイルを解析できない | |
| `unsupported_source_settings` | 対応していないパッケージ取得元の設定がある | |
| `scan_not_pinned` | スキャン結果が特定のイメージに結び付いていない | [ソースの確認](remediation-logic.md#source-verification) |
| `not_found_in_source` | 依存ファイルに稼働版のパッケージが載っていない | [ソースの確認](remediation-logic.md#source-verification) |
| `non_registry_source` | 対応する公開レジストリ以外から取得されるパッケージである | |
| `sdist_only` | パッケージにソース配布物しかない | |
| `forced_by_override` | パッケージの版がoverrideで固定されている | |
| `marker_not_evaluated` | 依存指定の環境マーカーを評価していない | |
| `invalid_marker` | 依存指定の環境マーカーが不正である | |
| `multiple_versions` | 同名パッケージの複数の版や出現箇所を、1つの更新として扱えない | |
| `unparsable_version` | パッケージの版を解釈できない | |
| `source_not_found` | 取得元のリポジトリまたはブランチが見つからない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `source_access_denied` | 取得元のリポジトリにアクセスできない | [GitHubアクセスの準備](remediation-setup.md#prepare-github-access) |
| `source_too_large` | 取得元が大きすぎて読み込めない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `file_too_large` | 依存ファイルが大きすぎて読み込めない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `byte_budget_exhausted` | 取得元から読み込める容量の上限に達した | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `source_error` | 取得元の読み込みに失敗した | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `github_budget_exhausted` | GitHubへの要求数の上限に達した | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `source_read_failed` | 依存ファイルの再取得に失敗した | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |

### 実行環境の理由 {#runtime-reasons}

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `node_spec_invalid` | 宣言されたNode.jsの版を解釈できない | [Node.jsの選定](remediation-logic.md#node-selection) |
| `python_spec_invalid` | 宣言されたPythonの版を解釈できない | [uv用Pythonの選定](remediation-logic.md#uv-python-selection) |
| `manager_spec_invalid` | 宣言されたパッケージマネージャーの版を解釈できない | [ツール版の選定](remediation-logic.md#tool-version-selection) |
| `node_spec_conflict` | Node.jsの版宣言どうしが矛盾している | [Node.jsの選定](remediation-logic.md#node-selection) |
| `python_spec_conflict` | Pythonの版宣言どうしが矛盾している | [uv用Pythonの選定](remediation-logic.md#uv-python-selection) |
| `manager_spec_conflict` | パッケージマネージャーの宣言どうしが矛盾している | [ツール版の選定](remediation-logic.md#tool-version-selection) |
| `node_spec_unsupported` | 宣言されたNode.jsの版に対応していない | [Node.jsの選定](remediation-logic.md#node-selection) |
| `python_spec_unsupported` | 宣言されたPythonの版に対応していない | [uv用Pythonの選定](remediation-logic.md#uv-python-selection) |
| `manager_spec_unsupported` | 宣言されたパッケージマネージャーの版に対応していない | [ツール版の選定](remediation-logic.md#tool-version-selection) |
| `work_program_mismatch` | 作業用コンテナ内のプログラムが、実行中のKestreLynxに付属するものと異なる | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `work_environment_rejected` | 作業用コンテナがプログラムの実行要件を満たしていない | [実行時の制限](remediation-logic.md#worker-restrictions) |
| `runtime_eol` | 更新対象の実行環境がサポート終了している | [実行環境の選定](remediation-logic.md#runtime-and-tool-versions) |
| `runtime_engines_mismatch` | 更新した依存が、プロジェクトの宣言する最小Node.js版に対応していない | [Node.jsの互換条件](remediation-logic.md#node-compatibility) |
| `requires_python_unsupported` | 必要なPython版の条件を満たせない、または条件がない・解釈できない | [uv用Pythonの選定](remediation-logic.md#uv-python-selection) |
| `pip_target_undecidable` | パッケージが動く環境を判断できない | [pipの検証環境](remediation-logic.md#pip-target-environment) |
| `pip_target_mismatch` | pipの依存解決対象と、パッケージが動く環境が一致しない | [pipの検証環境](remediation-logic.md#pip-target-environment) |
| `work_image_not_configured` | 更新用の作業環境が用意されていない | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `work_image_unavailable` | 作業用イメージを用意できなかった | [公式イメージの固定](remediation-logic.md#worker-images) |

### ツール取得の理由 {#tool-reasons}

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `tool_fetch_config_unsupported` | マネージャー自身によるツール取得や、未対応の解決設定が指定されている | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `tool_version_unsupported` | パッケージマネージャーの版に対応していない | [ツール版の選定](remediation-logic.md#tool-version-selection) |
| `tool_version_not_found` | 指定したパッケージマネージャーの版が見つからない | [ツールの取得と照合](remediation-logic.md#tool-verification) |
| `tool_hash_mismatch` | ツールの配布物がチェックサムと一致しない | [ツールの取得と照合](remediation-logic.md#tool-verification) |
| `tool_hash_unsupported` | ツールの配布物のチェックサムを検証できない | [ツールの取得と照合](remediation-logic.md#tool-verification) |
| `tool_artifact_invalid` | ツールの配布物が不正である | [ツールの取得と照合](remediation-logic.md#tool-verification) |
| `tool_metadata_invalid` | ツールのリリース情報が不正である | [ツールの取得と照合](remediation-logic.md#tool-verification) |
| `tool_too_new` | ツールの公開後待機時間を満たしたと確認できない | [ツール公開後の待機](remediation-logic.md#tool-release-age) |
| `tool_fetch_failed` | ツールの取得に失敗した | [ツールの取得と照合](remediation-logic.md#tool-verification) |
| `tool_fetch_budget` | ツールの取得回数の上限に達した | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `tool_cache_full` | ツールキャッシュに空きを確保できない | [ツールキャッシュの再利用](remediation-logic.md#tool-cache) |
| `tool_file_mismatch` | キャッシュ内のツール配布物が記録と異なる | [ツールキャッシュの再利用](remediation-logic.md#tool-cache) |

### 更新結果の理由 {#update-reasons}

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `update_candidate_in_source` | ソース内のパッケージに対応する修正版の更新候補がある | [修正版の下限](remediation-logic.md#fix-lower-bound) |
| `range_allows_fix` | 依存範囲が修正版を許し、再ビルドで入る見込みがある | [直接依存の版指定](remediation-logic.md#direct-dependencies) |
| `no_fixed_version_above_installed` | 稼働版より新しい修正版がない、または修正対象がない | [修正版の下限](remediation-logic.md#fix-lower-bound) |
| `constraint_excludes_fix` | 候補または更新後の版が依存の制約を満たさない | [直接依存の版指定](remediation-logic.md#direct-dependencies)・[推移的依存の更新範囲](remediation-logic.md#transitive-dependencies) |
| `constraint_not_evaluable` | 版の制約を評価できない、または修正版がpipで選ばれないプレリリースである | [直接依存の版指定](remediation-logic.md#direct-dependencies) |
| `packages_need_manual_update` | 自動更新できるパッケージがない | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `update_job_limit` | 1回の実行で行える更新ジョブ数の上限に達した | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `update_input_limit` | 更新に使うファイルがサイズ上限を超えている | [コンテナへの入力](remediation-logic.md#worker-inputs) |
| `update_job_failed` | 更新の実行に失敗した | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `update_result_invalid` | 更新ジョブの結果が不正である | [結果の回収](remediation-logic.md#worker-results) |
| `update_job_timed_out` | 更新の実行がタイムアウトした | [実行時の制限](remediation-logic.md#worker-restrictions) |
| `distribution_lookup_failed` | レジストリでのパッケージ照会に失敗した | [付随変更の検査](remediation-logic.md#change-validation) |
| `source_scan_failed` | 依存ファイルのスキャンに失敗した | [比較条件](remediation-logic.md#comparison-conditions) |
| `update_input_invalid` | 更新の入力が不正である | [コンテナへの入力](remediation-logic.md#worker-inputs) |
| `update_job_input_rejected` | 更新ジョブが入力を受け付けなかった | [コンテナへの入力](remediation-logic.md#worker-inputs) |
| `manifest_edit_required` | 自動更新では行えないmanifestの変更が必要である | [直接依存の版指定](remediation-logic.md#direct-dependencies) |
| `input_modified` | 読み取り専用のはずの設定ファイルが変更された | [付随変更の検査](remediation-logic.md#change-validation) |
| `lockfile_inconsistent` | lockfileがプロジェクトと整合していない | [マネージャー別の更新処理](remediation-logic.md#manager-update-methods) |
| `no_wheel_for_version` | 対象の版に必要なプラットフォーム向けのwheelがない | [マネージャー別の更新処理](remediation-logic.md#manager-update-methods) |
| `release_yanked` | 対象のリリースが取り下げられている | [付随変更の検査](remediation-logic.md#change-validation) |
| `requirements_rewrite_unsupported` | 今回の更新方法ではrequirementsを書き換えられない | [マネージャー別の更新処理](remediation-logic.md#manager-update-methods) |
| `update_set_not_applied` | 同時に更新する別のパッケージを更新できなかった | [部分PRの成立条件](remediation-logic.md#partial-pr-selection) |
| `target_not_in_lockfile` | 更新対象のパッケージがlockfileに載っていない | [マネージャー別の更新処理](remediation-logic.md#manager-update-methods) |
| `no_reresolve_trigger` | 再解決のきっかけとして一時的に外せる依存がない | [マネージャー別の更新処理](remediation-logic.md#manager-update-methods) |
| `pnpm12_removal_unsupported` | pnpm 12では現在の更新方法を使えない | [マネージャー別の更新処理](remediation-logic.md#manager-update-methods) |
| `update_step_failed` | 更新中の処理に失敗した | [マネージャー別の更新処理](remediation-logic.md#manager-update-methods) |
| `post_update_check_failed` | 更新後の検査に失敗した | [付随変更の検査](remediation-logic.md#change-validation) |
| `unexpected_files` | 更新で想定外のファイルが変更された | [付随変更の検査](remediation-logic.md#change-validation) |
| `release_age_violation` | 依存のリリースが、プロジェクトの定める公開後の最低経過期間を満たさない | [付随変更の検査](remediation-logic.md#change-validation) |
| `manifest_changed` | 更新でmanifestに許可していない変更が入った | [付随変更の検査](remediation-logic.md#change-validation) |
| `output_files_invalid` | 出力ファイルが不正、または読み取れない | [結果の回収](remediation-logic.md#worker-results) |
| `lockfile_format_changed` | 更新でlockfileの形式が変わった | [付随変更の検査](remediation-logic.md#change-validation) |
| `target_not_updated` | 更新しても目標の版に上がらなかった | [部分PRの成立条件](remediation-logic.md#partial-pr-selection) |
| `target_removed` | 更新後に対象パッケージがなくなった、または依存関係から到達できなくなった | [部分PRの成立条件](remediation-logic.md#partial-pr-selection) |
| `fix_condition_not_met` | 更新後の版が脆弱性の修正条件を満たさない | [部分PRの成立条件](remediation-logic.md#partial-pr-selection) |
| `unexplained_dependency_diff` | 更新との関係を説明できない依存の変更がある | [付随変更の検査](remediation-logic.md#change-validation) |
| `distribution_mismatch` | パッケージがレジストリの公開内容やpipの解決結果と一致しない | [付随変更の検査](remediation-logic.md#change-validation) |
| `registry_check_limit` | 更新時のレジストリ照会数の上限に達した | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `update_package_limit` | 更新するパッケージ数が上限を超えている | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `resolved_source_changed` | パッケージの取得元が変わった | [付随変更の検査](remediation-logic.md#change-validation) |
| `post_update_lockfile_unstable` | lockfileを再生成すると、さらに内容が変わる | [マネージャー別の更新処理](remediation-logic.md#manager-update-methods) |
| `drop_side_effect` | 再解決のために一時的に外した依存が元の状態に戻らなかった | [マネージャー別の更新処理](remediation-logic.md#manager-update-methods) |
| `source_target_not_detected_before` | 更新前の依存ファイルで対象の脆弱性が検出されなかった | [比較条件](remediation-logic.md#comparison-conditions) |
| `source_target_not_analysed_after` | 更新後の依存ファイルで対象を解析できなかった | [比較条件](remediation-logic.md#comparison-conditions) |
| `source_target_still_detected` | 更新後も対象の脆弱性が検出される | [対象別の検証範囲](remediation-logic.md#verification-scope) |
| `source_introduced_findings` | 更新で依存ファイルに新たな所見が入る | [比較条件](remediation-logic.md#comparison-conditions) |
| `source_introduced_kev` | 更新で依存ファイルにKEV掲載の脆弱性が新たに入る | [比較条件](remediation-logic.md#comparison-conditions) |
| `source_scan_incomplete` | 依存ファイルのスキャンが不完全だった | [比較条件](remediation-logic.md#comparison-conditions) |
| `update_verified` | 更新結果の検証が完了した | [対象別の検証範囲](remediation-logic.md#verification-scope) |

### PR処理の理由 {#pr-reasons}

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `pr_limit` | 1回の実行で作成するPR数、またはオープン中のPR数の上限に達した（どちらかは`detail`で確認する） | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `candidate_changed` | PRの準備中に候補が変わった | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `base_moved` | PRの準備中にベースブランチが進んだ | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `github_rate_limited` | GitHubのレート制限に掛かった | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `write_outcome_unknown` | GitHubへの書き込み結果を確認できない | [書き込みの停止](remediation-logic.md#write-stops) |
| `reconciliation_failed` | 既存PRとの照合に失敗した | [既存PRとの照合](remediation-logic.md#existing-pr-matching) |
| `repository_mismatch` | リポジトリが記録と異なる | [書き込みの停止](remediation-logic.md#write-stops) |
| `attempt_unsettled` | 前回のPR作成結果がまだ確定していない | [既存PRとの照合](remediation-logic.md#existing-pr-matching) |
| `branch_not_ours` | 同名のブランチが存在し、KestreLynxが作成したものではない | [書き込みの停止](remediation-logic.md#write-stops) |
| `pull_request_not_as_created` | PRが作成時の状態と異なる | [書き込みの停止](remediation-logic.md#write-stops) |
| `github_refused` | GitHubが書き込みを拒否した | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `github_error` | GitHubがエラーを返した | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `candidate_recheck_failed` | PR作成前に候補を再確認できなかった | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `source_changed` | 計画の元にしたファイルが変更された | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `artifact_content_missing` | 更新したファイルの内容が保持されていない | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `artifacts_unusable` | 更新したファイルをそのままPRへ書き込めない | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `open_pr_not_inherited` | 同じファイルの既存PRに、今回の更新が引き継いでいない修正がある | [古いPRの置き換え](remediation-logic.md#pr-replacement) |
| `language_set_too_large` | 更新するパッケージが多すぎてPRの記録に収まらない | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `update_already_proposed` | この更新を提案するPRがすでにある | [既存PRとの照合](remediation-logic.md#existing-pr-matching) |

### 保存処理の理由 {#storage-reasons}

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `store_locked` | PRの記録が別のプロセスにロックされている | [記録を照合できない場合](remediation-troubleshooting.md#check-record-failure) |
| `storage_failed` | PRの記録を保存できなかった | [記録の保存順序](remediation-logic.md#record-order) |
| `storage_full` | PRの記録に空きを確保できない | [書き込みの停止](remediation-logic.md#write-stops) |
| `records_unverified` | 既存PRの記録を確認できない | [記録の復旧](remediation-logic.md#record-recovery) |
| `proposal_not_found` | この更新を提案していたPRの記録が見つからない | [既存PRとの照合](remediation-logic.md#existing-pr-matching) |

## 保存ファイル {#stored-records}

修正計画の記録は、`remediation.storage_dir`の下に保存します。

| ファイル・ディレクトリ | 内容 | 記録時点 |
| --- | --- | --- |
| `plan.json` | 最新の計画、ソースの場所、比較に使ったスキャン、実行した依存更新の検査結果 | 依存更新の処理後、PR処理前 |
| `delivered.json` | 配信した計画と、Slackに表示した内容をそれぞれ識別する情報 | 対応する通知の配信後 |
| `prs.json` | PRの識別情報、状態、作成試行、再作成の抑止、GitHub操作の記録 | PRの処理や照合、操作結果の記録時 |
| `tools` | 取得・照合したnpm・pnpm・uvのキャッシュ | ツールの取得時など |

`plan.json`は、PR処理後の結果を含めて再保存しません。
PR処理の今回の結果は通知で、継続して管理する記録は`prs.json`で確認できます。

保存とPR処理の関係は[記録の保存順序](remediation-logic.md#record-order)、保存先の設定は[保存先](configuration.md#remediation-storage)を参照してください。
