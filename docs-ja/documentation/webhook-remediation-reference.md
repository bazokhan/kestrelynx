# Webhookの修正計画フィールド

## 修正計画の共通フィールド {#remediation-fields}

修正計画が有効な場合、full・diffの両方のペイロードに`remediation`を含めます。
レポート全体の形式は、[Webhookのフィールド仕様](webhook-reference.md#top-level)を参照してください。

各表のフィールド名は、表で示すオブジェクトからの相対パスです。
省略条件を記載していないフィールドは、そのオブジェクトがある場合に出力します。

| `remediation`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `schema_version` | integer | このオブジェクトの形式の版で、現在は`1` |
| `status` | string | 計画を作成できた場合は`ok`、作成できなかった場合は`unavailable` |
| `unavailable_reason` | string | 計画を作成できなかった理由で、それ以外は省略 |
| `not_saved` | boolean | 計画を保存できなかった場合は`true`で、それ以外は省略 |
| `generated_at` | string | RFC 3339形式の計画生成時刻で、計画がない場合は省略 |
| `conditions` | object | 比較スキャンの条件で、Trivyの版と脆弱性データベースの識別情報の両方が不明なら省略 |
| `conditions.trivy_version` | string | Trivyの版 |
| `conditions.trivy_sha256` | string | TrivyのSHA-256で、不明なら省略 |
| `conditions.vulnerability_db_updated_at` / `conditions.java_db_updated_at` | string | 各データベースのRFC 3339形式の更新時刻で、不明なら省略 |
| `conditions.vulnerability_db_sha256` / `conditions.java_db_sha256` | string | 各データベースのSHA-256で、不明なら省略 |
| `conditions.severities` | stringの配列 | 比較対象の深刻度で、空なら省略 |
| `conditions.analysis_settings` | string | 解析設定の識別用ハッシュで、不明なら省略 |
| `limits` | object | 計画の上限で、計画がない場合は省略 |
| `limits.max_candidate_scans` | integer | 候補イメージのスキャン上限 |
| `limits.max_baseline_rescans` | integer | 比較元の再スキャン上限 |
| `limits.max_tag_pages` | integer | リポジトリごとのタグ一覧取得の上限 |
| `usage` | object | 計画作成時の処理件数で、計画がない場合は省略 |
| `usage.candidate_scans` / `usage.baseline_rescans` | integer | 候補スキャン・比較元の再スキャンの件数 |
| `usage.tag_pages` / `usage.registry_requests` | integer | タグ一覧取得・レジストリへの要求の件数 |

`unavailable_reason`には、`databases_not_prepared`または`planner_not_built`を使用します。
計画がない場合も、[配布イメージの`items`](#remediation-image-fields)は`[]`として出力します。

各項目の`category`は[計画の分類値](remediation-reference.md#category-values)、`reason`は[理由コード](remediation-reference.md#reason-codes)を参照してください。
項目の`reason`と補足の`detail`は、空なら省略します。

## 配布イメージのフィールド {#remediation-image-fields}

| `remediation`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `summary` | object | 分類値をキー、整数の件数を値とする配布イメージの集計で、計画がない場合は省略 |
| `items` | objectの配列 | 配布イメージの項目で、該当なしは`[]` |
| `items[].key` | string | 項目の識別子 |
| `items[].category` | string | 計画の分類値 |
| `items[].reason` / `items[].detail` | string | 理由と補足で、空なら省略 |
| `items[].tag_kind` | string | 現在のタグの分類で、不明なら省略 |
| `items[].priority` | string | 対象の優先度で、情報なしは省略 |
| `items[].services` | objectの配列 | 対応するサービスの情報で、空なら省略 |
| `items[].services[].workload` | string | Kubernetesのワークロードキーで、Kubernetesの`services[]`の各要素はこのフィールドだけを含む |
| `items[].declared` | objectの配列 | KubernetesのPodのspecにあるイメージ参照と取得方針で、空なら省略 |
| `items[].declared[].workload` | string | 対象のワークロードキー |
| `items[].declared[].ref` | string | specのイメージ参照で、読み取れない場合は省略 |
| `items[].declared[].pull_policy` | string | specの`imagePullPolicy`で、未指定なら省略 |
| `items[].pull` | objectの配列 | Kubernetesの`pull_again`項目に付く取得方針ごとの案内で、空なら省略 |
| `items[].pull[].guidance` | string | `restart_pulls`・`change_tag_or_digest`・`import_to_node`のいずれかで、意味は[再取得の案内](remediation-logic.md#kubernetes-image-references)を参照 |
| `items[].pull[].policy` | string | specの指定または未指定時の既定値に基づく取得方針 |
| `items[].pull[].workloads` | stringの配列 | この案内の対象となるワークロードキー |
| `items[].management` | objectの配列 | Kubernetesのワークロードごとの管理元のつながりで、空なら省略 |
| `items[].management[].workload` | string | 対象のワークロードキー |
| `items[].management[].chains` | objectの二重配列 | 管理元のつながりの一覧で、各配列はワークロードに近い管理元から順に並ぶ |
| `items[].management[].chains[][].kind` | string | 管理元の種類 |
| `items[].management[].chains[][].resource` / `resource_id` / `name` / `scope` | string | リソースの種類・識別子・名前・範囲で、それぞれ空なら省略 |
| `items[].management[].chains[][].confidence` | string | 管理元の判断の確かさで、空なら省略し、管理元の印による推定は`claimed` |
| `items[].management[].conflicting` | boolean | 複数の管理元のつながりがある場合は`true`で、それ以外は省略 |
| `items[].current` | object | 現在のイメージ情報 |
| `items[].candidate` | object | 候補のイメージ情報で、候補がなければ省略 |
| `items[].targets` | integer | 比較対象の所見数 |
| `items[].kev_targets` | integer | KEVに掲載された比較対象の所見数で、`0`なら省略 |
| `items[].comparison` | object | 比較結果で、結果がなければ省略 |
| `items[].scans` | objectの配列 | 比較に使ったスキャンの記録で、空なら省略 |

`current`と`candidate`のイメージ情報は、次の形式です。
ベースイメージの項目に含むイメージ情報も同じ形式を使用します。

| イメージ情報のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `ref` | string | イメージ参照 |
| `tag` | string | タグで、不明なら省略 |
| `content` | string | 稼働イメージの実体識別情報で、情報なしや候補イメージでは省略 |
| `config_digest` / `manifest_digest` / `top_digest` | string | 各digestで、不明なら省略 |
| `platform` | string | プラットフォームで、不明なら省略 |
| `digest_kind_unverified` | boolean | 稼働イメージのdigestの種類を確認できていない場合は`true`で、それ以外は省略 |

| `comparison`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `comparable` | boolean | 比較可能な場合は`true` |
| `reason` / `scope` / `decision` | string | 比較の理由・範囲・判定で、空なら省略 |
| `targets` / `resolved` / `remaining` | integer | 対象・解消・残存の件数 |
| `unknown` / `undetected` / `introduced` | integer | 判定不能・比較元で未検出・新規検出の件数 |
| `verdicts` | objectの配列 | 対象の脆弱性ごとの判定で、空なら省略 |
| `introduced_findings` | objectの配列 | 新規検出の脆弱性ごとの判定で、空なら省略 |
| `verdicts_truncated` / `introduced_findings_truncated` | boolean | 対応する一覧の一部を省略した場合は`true`で、それ以外は省略 |

| `scans[]`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `role` / `ref` | string | スキャンの役割とイメージ参照 |
| `requested` / `confirmed` | string | 要求した対象と確認できた対象 |
| `db` | string | 使用したデータベースの識別情報 |
| `scanned_at` | string | RFC 3339形式のスキャン時刻で、記録がなければ省略 |
| `failure` | string | スキャン失敗の情報で、空なら省略 |

比較の条件は[スキャンの比較条件](remediation-logic.md#comparison-conditions)、結果の解釈は[比較結果の解消](remediation-results.md#verification-results)を参照してください。

## ベースイメージのフィールド {#remediation-dockerfile-fields}

| `remediation`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `dockerfile_summary` | object | 分類値をキー、整数の件数を値とする集計で、該当項目がなければ省略 |
| `dockerfile_items` | objectの配列 | ベースイメージの項目で、該当なしは省略 |
| `dockerfile_items[].key` | string | 項目の識別子 |
| `dockerfile_items[].kind` | string | `dockerfile` |
| `dockerfile_items[].fix_class` | string | `base_image` |
| `dockerfile_items[].verification` | string | `base_image_comparison` |
| `dockerfile_items[].category` | string | 計画の分類値 |
| `dockerfile_items[].reason` / `dockerfile_items[].detail` | string | 理由と補足で、空なら省略 |
| `dockerfile_items[].priority` | string | 対象の優先度で、情報なしは省略 |
| `dockerfile_items[].workloads` | stringの配列 | 対象のWorkloadで、`container/<名前>`も含み、該当なしは`[]` |
| `dockerfile_items[].source` | object | Dockerfileのリポジトリ・ブランチ・パスと、取得できたコミット・ステージなどの情報 |
| `dockerfile_items[].base_ref` / `dockerfile_items[].base_kind` | string | 現在のベースイメージ参照とタグの分類で、空なら省略 |
| `dockerfile_items[].candidate` | object | 候補の[イメージ情報](#remediation-image-fields)で、候補がなければ省略 |
| `dockerfile_items[].counts` | object | 整数値の`targets`・`resolved`・`remaining`・`introduced`による集計 |
| `dockerfile_items[].rebuild_runtimes` | objectの配列 | 全稼働イメージが`floating_base_unconfirmed`の場合にまとめたランタイムの再ビルドの見込みで、空なら省略 |
| `dockerfile_items[].entities` | objectの配列 | 稼働イメージごとの照合・比較結果で、空なら省略 |
| `dockerfile_items[].final_image_verified` | boolean | 再ビルド後のアプリケーションイメージの検証有無で、常に`false` |
| `dockerfile_items[].pull_request` | object | 対応する[PR処理](#remediation-pr-fields)で、対応がなければ省略 |

| `dockerfile_items[].entities[]`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `running_image` | object | 稼働イメージの情報 |
| `current_base` / `candidate_base` | object | 現在・候補のベースイメージ情報で、情報なしは省略 |
| `layer_confirmation` / `findings_by_layer` | object | ベースレイヤーの照合結果とレイヤー別の所見件数 |
| `category` | string | 稼働イメージごとの分類値 |
| `reason` / `detail` | string | 理由と補足で、空なら省略 |
| `services` | objectの配列 | 対応するサービスで、空なら省略 |
| `targets` | integer | 比較対象の所見数 |
| `kev_targets` | integer | KEVに掲載された比較対象の所見数で、`0`なら省略 |
| `comparison` | object | [比較結果](#remediation-image-fields)で、結果がなければ省略 |
| `rebuild_runtimes` | objectの配列 | この稼働イメージが`floating_base_unconfirmed`の場合のランタイムの再ビルドの見込みで、空なら省略 |
| `scans` | objectの配列 | [スキャンの記録](#remediation-image-fields)で、空なら省略 |

両方の`rebuild_runtimes[]`は、現在のベースのランタイムの版から求めた見込みで、完成イメージの比較ではありません。

| `rebuild_runtimes[]`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `package` | string | ランタイム名で、`Node.js`または`Python runtime` |
| `installed` | string | 稼働イメージのランタイムの版 |
| `base_version` | string | 現在のベースのランタイムの版 |
| `disappearing` | stringの配列 | 検出中のCVEのうち、その版を引き継げば出なくなる見込みのIDで、空なら省略 |
| `remaining` | stringの配列 | 検出中のCVEのうち、その版でも残るIDで、空なら省略 |

- CVEの集計
  - 新しい版で増えるCVEは含めない
  - 項目全体では`package`・`installed`・`base_version`が同じ記録をまとめ、CVEのIDの重複を除いて並べ、どれかの稼働イメージで残るIDは`disappearing`に含めない
  - 稼働イメージごとの判定が混在する場合は項目全体の見込みを省略し、`entities[]`には個別の記録を残す

検査の範囲は、[対象別の検証範囲](remediation-logic.md#verification-scope)を参照してください。

## 言語パッケージのフィールド {#remediation-language-fields}

| `remediation`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `language_summary` | object | 分類値をキー、整数の件数を値とする集計で、該当項目がなければ省略 |
| `language_items` | objectの配列 | 言語パッケージの項目で、該当なしは省略 |
| `language_items[].key` | string | 項目の識別子 |
| `language_items[].category` | string | 計画の分類値 |
| `language_items[].reason` / `language_items[].detail` | string | 理由と補足で、空なら省略 |
| `language_items[].manager` / `language_items[].priority` | string | パッケージマネージャーと優先度で、空なら省略 |
| `language_items[].workloads` | stringの配列または`null` | 対象のWorkloadで、`container/<名前>`も含む |
| `language_items[].source` | object | 依存ファイルのリポジトリ・ブランチ・ディレクトリなどのソース情報 |
| `language_items[].pull_request` | object | 対応する[PR処理](#remediation-pr-fields)で、対応がなければ省略 |
| `language_items[].retry_after` | string | 公開後の待機が終わり、再試行できる日時（RFC 3339形式）で、日時がなければ省略 |

### パッケージの結果 {#language-package-fields}

| `language_items[]`からのフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `package_count` | integer | パッケージの総件数 |
| `packages` | objectの配列 | パッケージごとの結果で、空なら省略 |
| `packages_truncated` | boolean | 一覧の一部を省略した場合は`true`で、それ以外は省略 |
| `packages[].name` / `packages[].ecosystem` / `packages[].installed` | string | パッケージ名・エコシステム・稼働版 |
| `packages[].normalized` | string | 正規化したパッケージ名で、空なら省略 |
| `packages[].selection_lower_bound` / `packages[].adopted_version` | string | 更新目標の下限と採用版で、情報なしは省略 |
| `packages[].relation` | string | 依存関係の区分で、空なら省略 |
| `packages[].action` / `packages[].reason` / `packages[].detail` | string | 対応・理由・補足で、空なら省略 |
| `packages[].left_out` | boolean | 計画した更新から除外された場合は`true`で、それ以外は省略 |
| `packages[].through` | stringの配列 | 修正版に上げるために、あわせて更新した依存元の名前で、空なら省略 |
| `packages[].occurrence_count` / `packages[].cve_count` / `packages[].origin_count` | integer | 依存ファイル内の出現箇所・脆弱性・元の所見の件数 |
| `packages[].kev_count` | integer | KEVに掲載された脆弱性の件数で、`0`なら省略 |
| `packages[].occurrences` / `packages[].cves` / `packages[].origins` | objectの配列 | 出現箇所・脆弱性・元の所見の一覧で、空なら省略 |
| `packages[].occurrences_truncated` / `packages[].cves_truncated` / `packages[].origins_truncated` | boolean | 対応する一覧の一部を省略した場合は`true`で、それ以外は省略 |

`action`の定義は[パッケージの処理値](remediation-reference.md#action-values)、版の解釈は[更新目標と採用版](remediation-results.md#target-and-adopted-version)を参照してください。

`mkdirp`の更新で`minimist`を修正版に上げる例では、`minimist`の`through`は`["mkdirp"]`です。
直接依存の版が変わらない場合は、途中で更新した依存元のうち、プロジェクトに最も近いものを載せます。

`through`は既存PRから補う場合もあります。
今回の更新・検査の実行有無は、`update_executed`と`post_update_check_executed`で確認します。

### 実行環境 {#language-runtime-fields}

| `language_items[]`からのフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `runtime_eol` | object | サポート終了により手動対応となる実行環境で、該当なしは省略 |
| `runtime_eol.id` / `runtime_eol.name` | string | 実行環境の識別子と名前 |
| `runtime_eol.eol` | string | `YYYY-MM-DD`形式のサポート終了日で、不明なら省略 |
| `update.runtime` | object | 更新に使った実行環境で、記録がなければ省略 |
| `update.runtime.id` / `update.runtime.version` | string | 実行環境の識別子と版 |
| `update.runtime.pip` | string | Pythonイメージに含まれるpipの版で、情報なしは省略 |
| `update.runtime.image` / `update.runtime.platform` / `update.runtime.digest` | string | 作業用イメージ・プラットフォーム・digestで、情報なしは省略 |
| `update.runtime.support` / `update.runtime.eol` | string | サポート状態と終了日で、情報なしは省略 |
| `update.runtime.basis` | string | 実行環境の選定根拠で、情報なしは省略 |
| `update.runtime.declared` | objectの配列 | `source`・`value`を持つ版宣言で、空なら省略 |
| `update.runtime.excluded` | objectの配列 | 選ばなかった系列の`id`・`why`と補足情報で、空なら省略 |
| `update.runtime.engines_floor` | string | 依存の互換性を確認した最低Node.js版で、記録がなければ省略 |

選定方法は、[実行環境の選定](remediation-logic.md#runtime-and-tool-versions)を参照してください。

### ツール {#language-tool-fields}

`language_items[].update.tool`は、更新に使ったツールの記録がある場合に含めます。

| `update.tool`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `name` / `version` | string | ツール名と版 |
| `source` | string | 版の選定根拠で、`declared`、`default`、`default_in_range`のいずれか |
| `sha256` | string | 配布物のSHA-256 |
| `format` | string | 配布物の形式で、空なら省略 |
| `size` | integer | 配布物のバイト数で、`0`なら省略 |
| `sha512` | string | 配布物のSHA-512で、空なら省略 |
| `published_at` | string | RFC 3339形式の公開日時 |
| `registry_digest` | string | レジストリが示した配布物のdigestで、空なら省略 |
| `spec_hash` | string | プロジェクトが宣言し、照合したハッシュで、空なら省略 |

選定根拠の意味は、[ツール版の選定](remediation-logic.md#tool-version-selection)を参照してください。

### 更新の記録 {#language-update-fields}

| `language_items[]`からのフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `update_executed` | boolean | この回に依存更新を実行したかで、`false`でも出力 |
| `post_update_check_executed` | boolean | この回に更新後の検査を実行したかで、`false`でも出力 |
| `update` | object | 更新の記録で、記録がなければ省略 |
| `update.steps` | objectの配列 | 実行した操作の記録で、空なら省略 |
| `update.notes` | stringの配列 | 更新処理の補足で、空なら省略 |
| `update.manifest_edits` | objectの配列 | manifestの変更箇所で、空なら省略 |
| `update.manifest_edits[].file` / `section` / `name` / `from` / `to` | string | ファイル・節・依存名・変更前・変更後 |
| `update.manifest_edits[].major_change` | boolean | メジャー版の変更に該当する場合は`true`で、それ以外は省略 |
| `update.deprecated_changed` | integer | 非推奨注記が追加・削除・変更されたlockfile項目の件数で、`0`なら省略 |
| `update.diff` | object | lockfileの差分で、記録がなければ省略 |
| `update.diff.added` / `update.diff.changed` / `update.diff.removed` | stringの配列 | 追加・変更・削除された項目で、空なら省略 |
| `update.diff.truncated` | boolean | 差分一覧の一部を省略した場合は`true`で、それ以外は省略 |
| `update.diff.followed` | objectの配列 | 更新に伴って依存先の版が変わった項目で、空なら省略 |
| `update.diff.followed[].entry` | string | 変更された項目 |
| `update.diff.followed[].moves` | objectの配列 | stringの`name`・`from`・`to`を持つ依存先の変更 |
| `update.chain` | object | 依存元からの再解決の結果や見送りの理由で、情報がなければ省略 |
| `source_check` | object | 更新前後の依存ファイルのスキャン結果で、記録がなければ省略 |
| `source_check.counts` | integerの配列 | 解消・残存・新規検出の順に並ぶ3つの件数 |
| `source_check.resolved` / `source_check.remaining` / `source_check.introduced` | objectの配列 | 対応する脆弱性の一覧で、空なら省略 |
| `source_check.truncated` | boolean | 脆弱性一覧の一部を省略した場合は`true`で、それ以外は省略 |
| `source_check.passed` | boolean | 更新後の検査に合格したかで、`false`でも出力 |
| `source_check.basis` | string | [再解決のスキャン比較](#language-chain-scan-fields)の方法で、追加の比較がなければ省略 |
| `source_check.chain_new_findings` | objectの配列 | 更新後に新たに見つかった脆弱性（持ち越しを除く）で、空なら省略 |
| `source_check.chain_entry_growth` | objectの配列 | lockfile内で脆弱なパッケージの使用箇所が増えた結果で、空なら省略 |
| `source_check.chain_edge_growth` | objectの配列 | 脆弱なパッケージを使う依存関係が増えた結果で、空なら省略 |
| `source_check.chain_carried` | objectの配列 | 版が変わっても同じ依存関係に残る脆弱性で、空なら省略 |
| `source_check.chain_position_refusals` | objectの配列 | 依存関係の変化を検査して不合格とした理由で、空なら省略 |

非推奨注記の変更件数はWebhookに含めますが、対象名の一覧は含めません。
対象名と注記の追加・削除・変更はPR本文で確認します。

### 依存元からの再解決の結果 {#language-chain-fields}

`mkdirp 0.5.1`が`minimist 0.0.8`を指定する例では、`blocked`にこの指定、`tops`に選び直す`mkdirp`が入ります。
`language_items[].update.chain.outcome`で、再解決の結果を確認します。

| `outcome` | 意味 | 例 |
| --- | --- | --- |
| `adopted` | 採用 | `mkdirp`を`0.5.6`、`minimist`を`1.2.8`に更新し、検査に合格 |
| `not_fixed` | 修正版に届かない | 依存元を選び直しても、対象が修正版に上がらない |
| `rejected` | 不採用、または待機の繰り返しによる停止 | 更新によって別の脆弱性が新たに入る |
| `failed` | 処理に失敗 | パッケージマネージャーがエラーで終了 |
| `not_tried` | 見送り | 選び直す直接依存が5パッケージを超える |
| `deferred` | 保留 | 新たに入る版の公開から72時間が経過していない |

| `update.chain`からのフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `outcome` | string | 上表の結果 |
| `reason` / `detail` | string | 理由コードと補足で、空なら省略 |
| `source` | string | `chain_job`は追加の再解決、`first_run`はuvの最初の更新結果の再判定 |
| `blocked` | objectの配列 | 修正版への更新を妨げる版指定で、確認できなければ空配列 |
| `blocked[].package` / `blocked[].version` | string | 更新を妨げられているパッケージの名前と版（例: `minimist`・`0.0.8`） |
| `blocked[].parent` / `blocked[].parent_version` | string | 古い版を指定する依存元の名前と版（例: `mkdirp`・`0.5.1`） |
| `blocked[].range` | string | 依存元による版指定（例: `0.0.8`） |
| `blocked[].proof` | string | `exact`は古い版への固定、`upper_bound`は指定範囲の上限が修正版に届かない場合 |
| `blocked[].via` | stringの配列 | その依存元につながる直接依存の名前で、空なら省略 |
| `tops` | objectの配列 | 選び直す直接依存で、情報がなければ空配列 |
| `tops[].name` | string | 直接依存の名前（例: `mkdirp`） |
| `tops[].from` / `tops[].to` | string | 更新前後の版で、情報がなければ省略し、版が変わらない場合は同じ値 |
| `tops[].kind` | string | `top` |
| `moves` | objectの配列 | 更新対象と`tops`以外の変更で、空なら省略 |
| `moves[].name` | string | パッケージ名で、取得できなければlockfile内の識別子 |
| `moves[].from` / `moves[].to` | string | 変更前後の版で、追加前・削除後など、版がなければ省略 |
| `moves[].kind` | string | `ancestor`は依存元の変更、`followed`はその他の変更、`added`は追加、`removed`は削除 |
| `truncated` | boolean | 変更一覧の一部を省略する場合は`true`で、それ以外は省略 |
| `usage` | object | 通常更新・再実行を含む処理量の詳細 |
| `usage.containers` / `usage.lookups` / `usage.bytes` / `usage.elapsed_ms` | integer | 順に、作業用コンテナ数・レジストリ照会数・受信バイト数・処理開始からの経過ミリ秒 |

`update.chain`には見送りも含むため、このフィールドがあるだけでは実行済み・採用済みとは判断できません。
公開後の待機が終わる日時は、`language_items[].retry_after`で確認します。

待機中は、`retry_after`だけを含み、`update.chain`を含まない回もあります。
待機や停止の条件は[公開後の待機と再試行](remediation-reference.md#dependent-reresolution-waits)を参照してください。

### 再解決のスキャン比較 {#language-chain-scan-fields}

`language_items[].source_check`には、更新によって脆弱性やその使用箇所が増えないかを確認する結果が入ります。
`chain_carried`は、この更新では直らずに残る脆弱性です。

| `source_check.basis` | 比較方法 |
| --- | --- |
| `package_version_vuln_edges_positions` | パッケージ名・版・脆弱性ID、使用箇所と依存関係の数に加え、変化した依存関係も確認 |
| `package_version_vuln_edges` | パッケージ名・版・脆弱性ID、使用箇所と依存関係の数を比較 |

次のフィールドは、`source_check`内の各一覧に属します。

| 一覧内のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `chain_new_findings[].package` / `version` / `vuln_id` | string | 新たに見つかった脆弱性のパッケージ名・版・脆弱性ID |
| `chain_new_findings[].severity` / `fixed_ver` | string | 深刻度と修正版情報で、空なら省略 |
| `chain_new_findings[].kev` | boolean | KEV掲載の場合は`true`で、それ以外は省略 |
| `chain_entry_growth[].package` / `vuln_id` | string | 使用箇所が増えるパッケージ名・脆弱性ID |
| `chain_entry_growth[].version` | string | 版ごとの増加を示す場合の版で、複数の版をまとめる場合は省略 |
| `chain_entry_growth[].before` / `after` | integer | 更新前後のlockfile内の使用箇所数 |
| `chain_edge_growth[].package` / `vuln_id` | string | 依存関係が増えるパッケージ名・脆弱性ID |
| `chain_edge_growth[].before` / `after` | integer | その脆弱性がある版を使う、更新前後の依存関係の数 |
| `chain_carried[].package` | string | 脆弱性が残るパッケージ名 |
| `chain_carried[].from` / `to` | string | 変更前後の版で、変更前の版が複数ある場合の`from`は代表の1つ |
| `chain_carried[].vuln_id` | string | 残る脆弱性ID |
| `chain_carried[].positions` | integer | 同じ脆弱性が残る依存関係の箇所数で、プロジェクトからの経路総数とは異なる |
| `chain_carried[].kev` | boolean | KEV掲載の場合は`true`で、それ以外は省略 |
| `chain_position_refusals[].package` / `version` | string | 不合格の原因となるパッケージ名と版で、`split`の場合は分かれる前の名前と版 |
| `chain_position_refusals[].parent` | string | そのパッケージを使う依存元の名前で、値がなければ省略 |
| `chain_position_refusals[].check` | string | 下表の不合格理由 |
| `chain_position_refusals[].vuln_id` | string | `new_vuln`で新たに見つかった脆弱性IDの1つで、それ以外は省略 |

| `chain_position_refusals[].check` | 意味 |
| --- | --- |
| `no_position` | 更新前に同じ依存関係を確認できない |
| `merged` | 複数の依存経路が合流し、比較する旧版を一つに決められない |
| `name` | 依存先のパッケージ名が変わる |
| `new_vuln` | 旧版にはない脆弱性が新しい版にある |
| `split` | 1つの版が複数の脆弱な版に分かれる |

`chain_carried`は、パッケージ名・変更後の版・脆弱性IDごとにまとめます。
持ち越しがあっても合格とは限らず、検査の合否は`source_check.passed`、採否は`update.chain.outcome`で確認します。

各一覧は最大500件で、省略がある場合は`source_check.truncated`が`true`になります。
検査の合否は、省略前の全件で判定します。

`source_check.counts`は、パッケージ名と脆弱性IDで数える解消・残存・新規検出の件数です。
使用箇所や依存関係の数は含めません。

検査条件と持ち越しの例は、[再解決の検査条件](remediation-reference.md#dependent-reresolution-rules)と[脆弱性の持ち越し](remediation-logic.md#dependent-reresolution-carried-findings)を参照してください。

### 更新ファイル {#language-artifact-fields}

`language_items[].artifacts`は、更新ファイルの情報がある場合に含めます。
ファイルの内容は含めません。

| `artifacts[]`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `path` | string | リポジトリ内のファイルパス |
| `sha256` | string | ファイル内容のSHA-256 |
| `size` | integer | ファイルのバイト数 |
| `mode` | string | ファイルのモードで、情報なしは省略 |

## PR処理のフィールド {#remediation-pr-fields}

| `remediation`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `pull_request_summary` | object | 状態値をキー、整数の件数を値とする集計で、処理単位がなければ省略 |
| `pull_requests` | objectの配列 | PR処理の単位で、該当なしは省略 |
| `pull_requests[].key` | string | 処理単位の識別子 |
| `pull_requests[].kind` | string | Kubernetesマニフェストのタグ更新は`kubernetes`、Kustomizeの`newTag`更新は`kustomize`、Helmのvaluesのタグ更新は`helm_values`、ベースイメージ更新は`dockerfile`、言語パッケージ更新は`language`で、Composeのタグ更新では省略 |
| `pull_requests[].repo` / `pull_requests[].base_branch` / `pull_requests[].path` | string | 対象リポジトリ・ベースブランチ・ファイルパス |
| `pull_requests[].services` | stringの配列 | `kind: kubernetes`・`kind: kustomize`・`kind: helm_values`では`<kind>/<namespace>/<name>/<container>`形式のワークロードキーで、該当なしは`[]` |
| `pull_requests[].workloads` | stringの配列 | 対象ワークロードのキーで、`container/<名前>`も含み、空なら省略 |
| `pull_requests[].also_running[].workload` | string | 同じイメージで稼働していてマニフェストの対応付けがない、またはKustomize・Helmのvaluesの作用先として列挙した集合に含まれないKubernetesワークロードのキー |
| `pull_requests[].fix_targets[].location` | string | `kind: kubernetes`では`<Kind>/<namespace>/<name>/<container>`形式の編集位置で、`Kind`と`name`は対応付けたファイル内のオブジェクト、`namespace`はワークロードの名前空間であり、`kind: kustomize`では`images[<name>].newTag`、`kind: helm_values`では設定した`helm_values.key` |
| `pull_requests[].status` | string | PR処理の状態 |
| `pull_requests[].reason` / `pull_requests[].detail` | string | 理由と補足で、空なら省略 |
| `pull_requests[].number` | integer | PR番号で、`0`なら省略 |
| `pull_requests[].url` / `pull_requests[].state` | string | PRのURLとGitHub上の状態で、空なら省略 |
| `pull_requests[].item_key` | string | 対応する言語パッケージ項目の識別子で、情報なしは省略 |
| `pull_requests[].language` | object | 言語パッケージ更新の内容で、該当なしは省略 |
| `pull_requests[].language.remaining` | objectの配列 | PRに含めなかったパッケージで、空なら省略 |
| `pull_requests[].language.packages[].through` | stringの配列 | 修正版に上げるために、あわせて更新した依存元の名前で、空なら省略 |
| `pull_requests[].language.chain` | objectの配列 | PRに含む、再解決で版が変わる直接依存の一覧で、空なら省略 |

| `dockerfile_items[].pull_request` | object | 対応する処理の`status`と、任意の`reason`・`number`・`url`・`state`で、対応がなければ省略 |
| `language_items[].pull_request` | object | 対応する処理の`status`と、任意の理由・補足・PR情報・照合用識別子で、対応がなければ省略 |

| `pull_requests[].language.remaining[]`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `name` / `ecosystem` | string | パッケージ名とエコシステム |
| `from` / `target` | string | 稼働版と予定していた更新先 |
| `reason` | string | 更新から除外した理由 |
| `relation` / `detail` | string | 依存関係の区分と補足で、空なら省略 |

| `pull_requests[].language.chain[]`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `name` | string | あわせて更新する直接依存の名前（例: `mkdirp`） |
| `from` / `to` | string | 更新前後の版（例: `0.5.1`・`0.5.6`） |
| `held` | string | 古い版を指定されていたパッケージ名（例: `minimist`）で、空なら省略 |
| `held_range` | string | 更新を妨げていた版指定（例: `0.0.8`）で、空なら省略 |
| `held_by` | string | 間にあるパッケージが古い版を指定する場合の名前で、直接依存自身が指定する場合などは省略 |

KubernetesマニフェストのPR記録にある`locations`も、`<Kind>/<namespace>/<name>/<container>`形式を使います。
KustomizeのPR記録にある`locations`は`images[<name>].newTag`形式を使います。

HelmのvaluesのPR記録にある`locations`は、mapping形式・文字列形式ともに設定した`helm_values.key`を使います。
たとえば`key: image`では`image`になり、PR本文に示すmapping形式の変更箇所`image.tag`とは異なります。
Webhookの`pull_requests[]`には`locations`配列を出力せず、修正対象の位置は`fix_targets[].location`に出力します。
既存PRに対応付けた回は、PR側の`language.remaining`からパッケージの除外情報を補います。
その回の更新・検査の実行有無が`false`でも、`packages[]`に`left_out`・`action`・`reason`が付く場合があります。

状態の定義は[PRの状態値](remediation-reference.md#pr-status-values)、部分PRの解釈は[部分PR](remediation-results.md#partial-pull-requests)を参照してください。

## PR操作イベントのフィールド {#remediation-operation-fields}

| `remediation`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `operations` | objectの配列 | 未配信のPR操作イベントで、該当なしは省略 |
| `operations[].seq` | integer | イベントの連番 |
| `operations[].id` | string | 操作の識別子 |
| `operations[].at` | string | RFC 3339形式の時刻 |
| `operations[].phase` / `operations[].kind` / `operations[].repo` | string | 操作の段階・種類・対象リポジトリ |
| `operations[].attempt_key` | string | 試行の識別子で、空なら省略 |
| `operations[].number` | integer | PR番号で、`0`なら省略 |
| `operations[].result` / `operations[].error` | string | 操作結果とエラーで、空なら省略 |

配信と再送の扱いは、[修正計画の再送](notification-conditions.md#remediation-redelivery)を参照してください。

## 書き込み停止のフィールド {#remediation-problem-fields}

| `remediation`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `problems` | objectの配列 | PRの書き込みを止める問題で、該当なしは省略 |
| `problems[].code` | string | 問題の分類コード |
| `problems[].repo` / `problems[].target` | string | 対象リポジトリと更新対象の識別子で、空なら省略 |
| `problems[].reason` / `problems[].detail` | string | 理由と補足で、空なら省略 |

停止条件は[書き込みの停止](remediation-logic.md#write-stops)、理由は[理由コード](remediation-reference.md#reason-codes)を参照してください。

## 修正計画のJSON例 {#remediation-json-example}

部分PRを含むペイロードから、主要フィールドだけを抜粋した例です。
`example-b`は更新から除外され、パッケージの結果とPRの`remaining`の両方に記録されています。

```json
{
  "remediation": {
    "language_items": [
      {
        "category": "pr_candidate",
        "update_executed": true,
        "post_update_check_executed": true,
        "packages": [
          {
            "name": "example-a",
            "ecosystem": "node-pkg",
            "installed": "1.0.0",
            "adopted_version": "1.0.1",
            "action": "update",
            "reason": "update_verified"
          },
          {
            "name": "example-b",
            "ecosystem": "node-pkg",
            "installed": "2.0.0",
            "selection_lower_bound": "2.0.1",
            "action": "manual",
            "reason": "target_not_updated",
            "left_out": true
          }
        ]
      }
    ],
    "pull_requests": [
      {
        "kind": "language",
        "language": {
          "remaining": [
            {
              "name": "example-b",
              "ecosystem": "node-pkg",
              "from": "2.0.0",
              "target": "2.0.1",
              "reason": "target_not_updated"
            }
          ]
        }
      }
    ]
  }
}
```

採用条件は、[部分PRの成立条件](remediation-logic.md#partial-pr-selection)を参照してください。
