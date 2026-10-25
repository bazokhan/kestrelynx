# Webhookのフィールド仕様

## ペイロードの範囲 {#generic-webhook}

汎用Webhookは、現在のスキャン結果を構造化JSONで送信します。
diffモードでは、現在の結果に加えて前回からの差分を含めます。

Low、通知オフの所見、Slackで畳み込むEOLパッケージ、対象コンテナとWorkloadも含みます。
Slackと併用できますが、DiscordやTeams専用のメッセージ形式には変換しません。

送信先は[設定](configuration.md)、送信のタイミングは[通知の送信条件](notification-conditions.md#notification-conditions)を参照してください。
修正計画のJSONは[Webhookの修正計画フィールド](webhook-remediation-reference.md#remediation-fields)に記載しています。

## レポートのフィールド {#report-fields}

各表のフィールド名は、表で示すオブジェクトからの相対パスです。
省略条件を記載していないフィールドは、そのオブジェクトがある場合に出力します。

`MEDIUM`・`LOW`・`UNKNOWN`の件数は、`scan.severity`にそれぞれの深刻度を含めた場合だけ出力します。
既定の`[HIGH, CRITICAL]`では、Slack表示・Webhook・ログは変わりません。

### トップレベル {#top-level}

| フィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `generated_at` | string | RFC 3339形式のスキャン時刻 |
| `environment` | object | [環境](#environment) |
| `summary` | object | [サマリー](#summary) |
| `eosl_images` | stringの配列または`null` | EOLベースイメージの参照一覧で、該当なしは`null`になる場合がある |
| `actionable` | objectの配列 | `fixed`の[イメージ](#images)で、該当なしは`[]` |
| `watch` | objectの配列 | `affected`へ正規化したイメージで、該当なしは`[]` |
| `wont_fix` | objectの配列 | `will_not_fix`のイメージで、該当なしは`[]` |
| `eol_packages` | objectの配列 | 全`end_of_life`グループのイメージで、該当なしは`[]` |
| `scan_errors` | objectの配列 | [スキャン失敗](#scan-errors)で、該当なしは`[]` |

| `runtime_unchecked` | objectの配列 | セキュリティ情報を利用できなかった[未照合の言語ランタイム](#runtime-unchecked)で、該当なしは省略 |
| `diff` | object | [差分](#diff)で、fullモードでは省略 |
| `runtime` | object | [Sensorの情報と使用状況の件数](#runtime)で、稼働時の使用状況が無効なら省略 |
| `remediation` | object | [修正計画とPR処理の結果](webhook-remediation-reference.md#remediation-fields)で、修正計画が無効なら省略 |

`watch`は修正状態の区分で、優先度のWatchとは別です。
`not_affected`は、どの検出結果の配列にも含めません。

### 環境 {#environment}

| `environment`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `kind` | string | `docker`または`kubernetes` |
| `name` | string | 設定した環境名で、未設定なら省略 |

### サマリー {#summary}

| `summary`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `images_total` | integer | スキャン失敗を含む、一意なイメージ参照と実体の組み合わせ数 |
| `images_affected` | integer | 対象脆弱性またはEOLベースOSがあるイメージ数 |
| `priority_counts` | object | 優先度別のパッケージグループ件数で、トリアージ無効時は省略 |
| `priority_counts.act_now` | integer | Act nowの件数 |
| `priority_counts.watch` | integer | Watchの件数 |
| `priority_counts.low` | integer | Lowの件数 |
| `intel` | object | KEVとEPSSの利用可否と鮮度で、トリアージ無効時は省略 |
| `intel.degraded` | boolean | KEVとEPSSの両方を利用できない場合は`true` |
| `intel.kev_ok` | boolean | KEVを利用できる場合は`true` |
| `intel.epss_ok` | boolean | EPSSを利用できる場合は`true` |
| `intel.stale_days` | integer | 使用中の古い脅威情報の経過日数 |

`priority_counts`には、EOLパッケージをAct nowの場合だけ加算します。
`eol_packages`と集計対象が重なり、3値の合計は全パッケージグループ数とは限りません。

Node.jsまたはPython本体を照合できなかったイメージは、対応するパッケージ名とともにトップレベルの`runtime_unchecked`に含めます。
通知と履歴の扱いは、[言語ランタイムのセキュリティ情報の利用不能時の扱い](scan-logic.md#node-runtime-unavailable)に記載しています。

### 未照合の言語ランタイム {#runtime-unchecked}

| `runtime_unchecked[]`のフィールド名 | 型 | 意味 |
| --- | --- | --- |
| `image` | string | セキュリティ情報を利用できず本体を照合しなかったイメージ参照 |
| `package` | string | 未照合の本体のパッケージ名で、`Node.js`または`Python runtime` |

### スキャン失敗 {#scan-errors}

| `scan_errors[]`のフィールド名 | 型 | 意味 |
| --- | --- | --- |
| `image` | string | スキャンに失敗したイメージ参照 |
| `error` | string | エラー内容 |

失敗時の結果の扱いは、[スキャン失敗時の扱い](scan-logic.md#scan-failures)を参照してください。

## イメージのフィールド {#images}

`actionable`、`watch`、`wont_fix`、`eol_packages`の各要素は、修正状態ごとのイメージ参照と実体を表します。

### イメージの識別情報 {#image-identity}

| フィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `image` | string | 表示用のイメージ参照 |
| `severity_counts` | object | 深刻度別の整数件数で、`CRITICAL`・`HIGH`は常に出力し、`HIGH`はHIGHのみを数える |
| `findings` | objectの配列 | このイメージと修正状態に属する[パッケージグループ](#package-fields) |
| `containers` | objectの配列 | この実体に一致する[コンテナ](#containers)で、該当なしは`[]` |
| `content_id` | string | 実体を確認できたDockerのconfig digest指定スキャンの`sha256:<hex>`で、それ以外は省略 |
| `registry_digests` | stringの配列 | 成功して実体を確認できた結果のregistry digestを、同じ参照について集めた一覧で、情報なしは`[]` |
| `identity_resolved` | boolean | この要素のスキャンで稼働中イメージの実体を確認できた場合は`true` |
| `scan_target_kind` | string | `content_id`、`registry_digest`、`reference`のいずれか |
| `severity_counts.MEDIUM` | integer | MEDIUM件数で、`0`なら省略 |
| `severity_counts.LOW` | integer | LOW件数で、`0`なら省略 |
| `severity_counts.UNKNOWN` | integer | UNKNOWN件数（認識できない深刻度を含む）で、`0`なら省略 |

`registry_digests`は同じ参照全体の情報ですが、`identity_resolved`と`scan_target_kind`は各要素の情報です。
Slackの注釈との対応は、[スキャンの警告](slack-display.md#scan-warnings)を参照してください。

### コンテナ {#containers}

| `containers[]`のフィールド名 | 型 | 意味 |
| --- | --- | --- |
| `name` | string | Dockerでは先頭のスラッシュとリンク別名を除いた名前、Kubernetesでは`<namespace>/<pod>/<container>` |
| `workload` | object | [Workloadの対応情報](#workloads)で、所属が不明でも出力 |

同じ参照が複数の実体を指す場合も、各要素にはその実体に一致するコンテナだけを含めます。

### Workload {#workloads}

| `containers[].workload`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `kind` | string | `unknown`、`compose`、`deployment`、`statefulset`、`daemonset`、`job`、`cronjob`、`pod`のいずれか |
| `group` | string | Composeプロジェクトまたはnamespaceで、不明なら省略 |
| `name` | string | Composeサービス、解決したWorkload名、単独Pod名で、不明なら省略 |

## 検出結果のフィールド {#findings}

`findings[]`はパッケージグループを、その中の`vulns[]`は個々の脆弱性を表します。

### パッケージ {#package-fields}

| `findings[]`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `package` | string | パッケージ名 |
| `class` | string | `os`または`lang` |
| `ecosystem` | string | `debian`・`python-pkg`などの種類で、不明なら`""` |
| `installed` | string | インストール済みバージョン |
| `fixed` | string | 修正版バージョンで、なければ`""` |
| `status` | string | `fixed`、`affected`、`will_not_fix`、`end_of_life`のいずれか |
| `severity_counts` | object | 深刻度別の整数件数で、`CRITICAL`・`HIGH`は常に出力し、`HIGH`はHIGHのみを数える |
| `upgrade_risk` | string | `""`、`distro_update`、`safe`、`caution`、`unknown`のいずれか |
| `priority` | string | `act_now`、`watch`、`low`のいずれかで、トリアージ無効時は省略 |
| `vuln_ids` | stringの配列 | 並べ替え済みの脆弱性ID |
| `vulns` | objectの配列 | [脆弱性ごとの詳細](#vulnerability-fields) |
| `runtime` | object | [所見の使用状況](#finding-runtime)で、使用状況の判定が付いていない場合は省略 |
| `severity_counts.MEDIUM` | integer | MEDIUM件数で、`0`なら省略 |
| `severity_counts.LOW` | integer | LOW件数で、`0`なら省略 |
| `severity_counts.UNKNOWN` | integer | UNKNOWN件数（認識できない深刻度を含む）で、`0`なら省略 |

`class`と`ecosystem`は、稼働時の使用状況が無効でも出力します。
修正状態と優先度の判定は、[検出結果の分類](scan-logic.md#finding-classification)と[悪用情報による優先度](scan-logic.md#triage)を参照してください。

### 脆弱性 {#vulnerability-fields}

| `vulns[]`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `id` | string | Slackリンク表記を含まない脆弱性ID |
| `severity` | string | 脆弱性の深刻度 |
| `status` | string | 集約先と異なる元の脆弱性ステータスで、同じ場合は省略 |
| `url` | string | 主要アドバイザリーURLで、取得できなければ省略 |
| `title` | string | 脆弱性の短いタイトルで、取得できなければ省略 |
| `kev` | boolean | 利用可能なKEVカタログに掲載されている場合は`true` |
| `ransomware` | boolean | KEVのランサムウェアフラグで、`false`なら省略 |
| `epss` | numberまたは`null` | EPSS確率で、不明なら`null` |
| `priority` | string | `act_now`、`watch`、`low`のいずれかで、トリアージ無効時は省略 |
| `refs` | objectの配列 | [追加参照](#reference-fields)で、空なら省略 |

`status`が省略されている場合は、所属する`findings[]`の`status`と同じ値として読みます。
元の脆弱性ステータスがない場合は、`unknown`を出力します。

### 追加参照 {#reference-fields}

| `refs[]`のフィールド名 | 型 | 意味 |
| --- | --- | --- |
| `kind` | string | `vendor`または`discussion` |
| `label` | string | 表示ラベル |
| `url` | string | 参照URL |

## 稼働時のフィールド {#runtime}

稼働時のフィールドは、稼働時の使用状況が有効な場合に追加します。
Sensorの状態の意味と観測の限界は、[稼働時の使用状況](runtime-usage.md)を参照してください。

### Sensorの情報 {#sensor-fields}

| トップレベルの`runtime`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `sensor_status` | string | `ok`、`degraded`、`stale`、`not_reporting`、`permission_denied`、`evidence_invalid`、`isolation_failed`、`isolation_degraded`のいずれか |
| `heartbeat_at` | string | RFC 3339形式のSensorの報告時刻で、報告時刻がなければ省略 |
| `interval_seconds` | integer | 秒単位のサンプリング間隔で、`0`なら省略 |
| `rules` | object | 使用状況の判定方法 |
| `rules.os_packages` | string | `executed_or_loaded_by_running_process` |
| `rules.lang_packages_binary` | string | `in_running_binary` |
| `rules.lang_packages_runtime` | string | `runtime_process_running` |
| `events_status` | string | `ok`または`unavailable`で、Sensorの報告がなければ`""` |
| `events_reason` | string | イベント観測の状態に伴う理由で、空なら省略 |
| `counts` | object | [使用状況の件数](#runtime-counts) |

### 使用状況の件数 {#runtime-counts}

| `runtime.counts`のフィールド名 | 型 | 意味 |
| --- | --- | --- |
| `in_use` | integer | 使用中のパッケージグループ数 |
| `not_observed` | integer | 使用が確認されないパッケージグループ数 |
| `unavailable` | integer | 使用状況を判定できないパッケージグループ数 |
| `muted` | integer | 通知オフのパッケージグループ数 |

4つの検出結果の配列にある全グループを集計し、各件数は`0`でも出力します。
`muted`は使用状況の件数と重なるため、4値を合計して全件数として扱わないでください。

### 所見の使用状況 {#finding-runtime}

| `findings[].runtime`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `usage` | string | `in_use`、`not_observed`、`unavailable`のいずれか |
| `reason` | string | [判定できない理由](#runtime-reasons)で、空なら省略 |
| `evidence_kinds` | stringの配列 | 観測の種類で、空なら省略 |
| `events_coverage` | string | `since_start`、`partial`、`none`のいずれかで、情報なしは省略 |
| `exposure` | string | `host_published_all`、`host_published_loopback`、`container_listening`、`unknown`のいずれかで、情報なしは省略 |
| `high_privilege` | boolean | UID 0かつuser namespaceなし、危険なcapability、privilegedのいずれかに該当する場合は`true`で、それ以外は省略 |
| `containers` | objectの配列 | [コンテナの証拠](#container-evidence)で、空なら省略 |
| `muted` | boolean | 通知オフの場合は`true`で、それ以外は省略 |
| `muted_reason` | string | 通知オフの理由`no_fix_not_in_use_7d`で、理由がなければ省略 |

| `evidence_kinds[]`の値 | 意味 |
| --- | --- |
| `exe` | サンプリングで実行中を確認 |
| `mapped_library` | サンプリングでライブラリの読み込みを確認 |
| `exec_event` | eBPFで実行を観測 |
| `library_load_event` | eBPFでライブラリの読み込みを観測 |

| `events_coverage`の値 | 意味 |
| --- | --- |
| `since_start` | コンテナの起動前からeBPFで欠落なく観測 |
| `partial` | 一部の期間やイベントを観測 |
| `none` | eBPFによるイベント観測なし |

通知オフの条件は、[修正版がない所見の通知オフ](runtime-usage.md#muting-findings-without-a-fix)を参照してください。

### コンテナの証拠 {#container-evidence}

次の表は、`findings[].runtime.containers[]`のフィールドです。
使用中の場合は、公開範囲、権限の順に最も強い証拠を持つコンテナを先頭に配置します。

| フィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `name` | string | コンテナ名 |
| `container_id` | string | 64桁の16進数のコンテナID |
| `generation_started_at` | string | RFC 3339形式のコンテナの世代の起動時刻で、不明なら省略 |
| `usage` | string | `in_use`、`not_observed`、`unavailable`のいずれか |
| `reason` | string | 判定できない理由で、空なら省略 |
| `last_seen` | string | RFC 3339形式の最後に確認した時刻で、不明なら省略 |
| `ports` | stringの配列 | `0.0.0.0:443/tcp`などのポートの証拠で、空なら省略 |
| `kinds_ambiguous` | boolean | OSパッケージの複数の観測種類を個々のプロセスに対応付けられない場合は`true`で、それ以外は省略 |
| `process_exes` | stringの配列 | `kinds_ambiguous`の場合の、重複を除いた観測済み実行ファイルの一覧で、空なら省略 |
| `process` | object | プロセスの観測がある場合だけ出力 |
| `process.exe` | string | 実行ファイルのパスで、空なら省略 |
| `process.effective_uid` | integer | 実効UIDで、`0`でも出力 |
| `process.userns` | boolean | user namespaceの使用有無で、`false`でも出力 |
| `process.dangerous_caps` | stringの配列 | 危険なcapabilityの一覧で、空なら省略 |
| `process.privileged` | boolean | privilegedの使用有無で、`false`でも出力 |
| `instances` | objectの配列 | 言語パッケージのインスタンスで、空なら省略 |
| `instances[].type` | string | インスタンスの種類で、空なら省略 |
| `instances[].target` | string | 対象の実行ファイルなどで、空なら省略 |
| `instances[].pkg_path` | string | パッケージのパスで、空なら省略 |
| `instances[].usage` | string | `in_use`、`not_observed`、`unavailable`のいずれか |
| `instances[].reason` | string | 判定できない理由で、空なら省略 |

`kinds_ambiguous`が`true`の場合は、`evidence_kinds`の各種類を`process.exe`や`process_exes`の各要素に対応付けて解釈しないでください。

### 判定できない理由 {#runtime-reasons}

所見、コンテナ、インスタンスの`reason`には、次の理由コードを使用します。

| 理由コード | 意味 |
| --- | --- |
| `sensor_not_reporting` | Sensorからの報告なし |
| `sensor_stale` | Sensorの報告が古い |
| `evidence_invalid` | 証拠の検証に失敗 |
| `isolation_failed` | Sensorの分離に失敗 |
| `permission_denied` | 読み取り権限なし |
| `initializing` | パッケージの索引を準備中 |
| `stalled` | 観測処理が制限時間を超過 |
| `parse_failed` | パッケージデータベースの解析に失敗 |
| `truncated` | 読み取り上限により証拠が不足 |
| `incomplete` | 観測の一部が欠落 |
| `generation_unverified` | コンテナの世代とスキャン対象の対応を確認できない |
| `container_not_observed` | 対応するコンテナの観測なし |
| `db_absent` | パッケージデータベースなし |
| `db_error` | パッケージデータベースの読み取り・解析エラー |
| `db_unsupported` | 未対応のパッケージデータベース |
| `no_file_list` | パッケージのファイル一覧なし |
| `attribution_ambiguous` | 観測したパスの所有パッケージを一意に特定できない |
| `file_replaced` | 観測したファイルが置き換わっている |
| `version_mismatch` | パッケージの版が一致しない |
| `ecosystem_unmapped` | エコシステムに対応する実行環境を特定できない |
| `binary_path_unknown` | 実行ファイルのパスが不明 |

## 差分のフィールド {#diff}

`diff`は、前回からの変化を種類別に表します。
変化が成立する条件は、[差分と履歴の判定](diff-logic.md#comparison-baseline)を参照してください。

### 差分オブジェクト {#diff-fields}

| `diff`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `new` | objectの配列 | [通常のパッケージの変化](#new-fields)で、該当なしは`[]` |
| `resolved` | objectの配列 | [パッケージの解消](#resolved-fields)で、該当なしは`[]` |
| `replaced` | objectの配列 | [イメージの実体変更](#image-replacement-fields)で、該当なしは`[]` |
| `reference_changes` | objectの配列 | [イメージ参照の更新](#reference-change-fields)で、該当なしは省略 |
| `new_eosl` | stringの配列 | [新規EOLベースイメージ](#eol-base-fields)で、該当なしは`[]` |
| `resolved_eosl` | stringの配列 | [EOLとして記録されなくなった参照](#eol-base-fields)で、該当なしは`[]` |
| `new_eol_packages` | objectの配列 | [EOLパッケージの変化](#eol-change-fields)で、該当なしは`[]` |
| `resolved_eol_packages` | objectの配列 | [EOLパッケージの解除](#eol-resolved-fields)で、該当なしは`[]` |
| `oldest_open_days` | integer | [未解決の最長期間](#oldest-open-days)で、`0`でも出力 |

### 通常のパッケージの変化 {#new-fields}

| `diff.new[]`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `image` | string | イメージ参照 |
| `package` | string | パッケージ名 |
| `kind` | string | `new`、`escalated`、`new_cves`、`now_fixable`、`unmuted`のいずれか |
| `ecosystems` | stringの配列 | 変化にまとめたグループのエコシステムを重複なく並べ替えた一覧で、不明な種類は`""`として含む |
| `runtime_usage` | string | `in_use`、`not_observed`、`unavailable`のいずれかで、使用状況の判定がなければ省略 |
| `muted` | boolean | この変化の全グループが通知オフの場合は`true`で、それ以外は省略 |
| `new_cve_count` | integer | `new_cves`の場合の追加CVE件数で、`0`なら省略 |
| `new_cve_ids` | stringの配列 | `new_cves`の場合の追加IDで、空なら省略 |
| `critical` | integer | CRITICAL件数 |
| `high` | integer | HIGH件数（HIGHのみ） |
| `medium` | integer | MEDIUM件数で、`0`なら省略 |
| `low` | integer | LOW件数で、`0`なら省略 |
| `unknown` | integer | UNKNOWN件数（認識できない深刻度を含む）で、`0`なら省略 |
| `priority` | string | `act_now`、`watch`、`low`のいずれかで、優先度がなければ省略 |
| `reason` | string | `escalated`の判定根拠または`unmuted`の理由で、空なら省略 |

`new_cve_ids`はSlackリンク表記を含まず、その要素数は`new_cve_count`と一致します。
`reason`の説明文は、通知の言語設定にかかわらず英語です。

### パッケージの解消 {#resolved-fields}

| `diff.resolved[]`のフィールド名 | 型 | 意味 |
| --- | --- | --- |
| `image` | string | イメージ参照 |
| `package` | string | 通常側の検出結果からなくなったパッケージ名 |

解消の意味は、[解消の判定](diff-logic.md#resolved-findings)を参照してください。

### イメージの実体変更 {#image-replacement-fields}

| `diff.replaced[]`のフィールド名 | 型 | 意味 |
| --- | --- | --- |
| `ref` | string | イメージ参照 |
| `prev_content_ids` | stringの配列 | 並べ替え済みの前回の確認済みcontent-ID集合 |
| `content_ids` | stringの配列 | 並べ替え済みの今回の確認済みcontent-ID集合 |

配列は`null`にせず、空の場合は`[]`を出力します。

### イメージ参照の更新 {#reference-change-fields}

| `diff.reference_changes[]`のフィールド名 | 型 | 意味 |
| --- | --- | --- |
| `repository` | string | 新参照からタグとdigestを除いたリポジトリで、レジストリのポートは保持 |
| `previous_ref` | string | 省略していない旧イメージ参照 |
| `ref` | string | 省略していない新イメージ参照 |
| `workloads` | stringの配列 | 旧参照と新参照に共通するWorkloadキーの並べ替え済み一覧で、空なら`[]` |

| 対象 | Workloadキーの形式 |
| --- | --- |
| Compose | `compose/<project>/<service>` |
| Kubernetes | `<kind>/<namespace>/<name>/<container>` |
| 所属Workloadが不明な単独Dockerコンテナ | `container/<name>` |

履歴を引き継ぐ条件は、[イメージ参照の更新](diff-logic.md#reference-changes)を参照してください。

### ベースOSのEOL変化 {#eol-base-fields}

| フィールド名 | 要素の型 | 意味 |
| --- | --- | --- |
| `diff.new_eosl[]` | string | 新たにEOLとして記録されたベースイメージの参照 |
| `diff.resolved_eosl[]` | string | EOLとして記録されなくなったイメージ参照 |

### EOLパッケージの変化 {#eol-change-fields}

Slackで畳み込むEOLパッケージの変化も含めます。

| `diff.new_eol_packages[]`のフィールド名 | 型 | 意味・省略条件 |
| --- | --- | --- |
| `image` | string | イメージ参照 |
| `package` | string | パッケージ名 |
| `kind` | string | `eol_new`、`eol_new_cves`、`eol_escalated`のいずれか |
| `ecosystems` | stringの配列 | 変化にまとめたグループのエコシステムを重複なく並べ替えた一覧で、不明な種類は`""`として含む |
| `runtime_usage` | string | `in_use`、`not_observed`、`unavailable`のいずれかで、使用状況の判定がなければ省略 |
| `new_cve_ids` | stringの配列 | `eol_new_cves`の場合の並べ替え済み追加IDで、空なら省略 |
| `critical` | integer | 今回のEOLグループのCRITICAL件数 |
| `high` | integer | 今回のEOLグループのHIGH件数（HIGHのみ） |
| `medium` | integer | 今回のEOLグループのMEDIUM件数で、`0`なら省略 |
| `low` | integer | 今回のEOLグループのLOW件数で、`0`なら省略 |
| `unknown` | integer | 今回のEOLグループのUNKNOWN件数（認識できない深刻度を含む）で、`0`なら省略 |
| `priority` | string | `act_now`、`watch`、`low`のいずれかで、トリアージ無効時は省略 |
| `reason` | string | `eol_escalated`の場合の英語の判定根拠で、空なら省略 |

`new_cve_ids`はSlackリンク表記を含みません。
`new_cve_count`は出力しないため、追加件数は`new_cve_ids`の要素数で確認します。

### EOLパッケージの解除 {#eol-resolved-fields}

| `diff.resolved_eol_packages[]`のフィールド名 | 型 | 意味 |
| --- | --- | --- |
| `image` | string | イメージ参照 |
| `package` | string | EOL区分からなくなったパッケージ名 |
| `still_open` | boolean | 同じ参照とパッケージに通常側の検出結果が残る場合は`true`で、`false`でも出力 |

### 未解決の最長期間 {#oldest-open-days}

`diff.oldest_open_days`は、対象となる記録の最も古い初回検出日からの日数です。
1日未満は切り捨て、対象がない場合は`0`を出力します。

| 対象 | 集計する初回検出日 |
| --- | --- |
| 通常のパッケージ | 通常側の初回検出日で、Low・通知オフ・保持中の記録も含む |
| EOLベースOS | ベースOSの初回EOL検出日 |
| 畳み込まれていないEOLパッケージ | パッケージの初回EOL検出日 |
| 畳み込まれているAct nowのEOLパッケージ | パッケージの初回EOL検出日 |
| 畳み込まれているAct now以外のEOLパッケージ | 個別には加算せず、ベースOSの初回EOL検出日で集計 |

Slackのトリアージ有効時の経過日数とは対象が異なります。
Slack側の定義は、[未解決の経過日数](slack-display.md#unresolved-age)を参照してください。

## 互換性 {#compatibility}

エコシステム、稼働時の使用状況、EOL、参照更新の情報は、既存のフィールドと修正状態別の構造を維持して追加しています。

受信側では、未知の追加フィールドを許容し、各表の省略条件に従って処理してください。
省略、`null`、`[]`、`""`は、それぞれ別の値として扱います。
