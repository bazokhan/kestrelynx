# 設定

YAML設定ファイルについて説明します。コンテナイメージでは既定で
`/etc/kestrelynx/config.yml`を使用します。未知のYAMLフィールドはエラーになるようになってます。

コメント付きの完全な例は
[`config.example.yml`](https://github.com/kitsunetrail/kestrelynx/blob/main/config.example.yml)に
あります。

## スケジュール

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `schedule.daily_at` | 空 | `HH:MM`形式のローカル時刻。空の場合は起動時点から24時間ごとに実行します。 |
| `schedule.run_on_start` | `true` | KestreLynxの起動直後に1回スキャンします。 |

`daily_at`で使用するタイムゾーンは、コンテナの`TZ`環境変数で指定します。

## スキャン

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `scan.severity` | `[HIGH, CRITICAL]` | Node.js・Python本体の検出結果を含め、分析と通知の対象にする深刻度です。 |

指定できる値は`UNKNOWN`、`LOW`、`MEDIUM`、`HIGH`、`CRITICAL`です。

### 言語ランタイム本体の脆弱性照合 {#language-runtime}

対象は、KestreLynxが言語パッケージの更新に対応しているNode.jsとPythonのランタイム本体です。

#### Node.js本体の脆弱性照合 {#node-runtime}

KestreLynxは、`NODE_VERSION`に記録されたNode.jsの版をNode.jsのセキュリティ情報と照合します。
判定規則と制約は、[Node.js本体の検出結果](scan-logic.md#node-runtime)に記載しています。

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `scan.node_runtime.enabled` | `true` | セキュリティ情報の取得とNode.js本体の照合を有効にします。`false`では両方を停止します。 |
| `scan.node_runtime.security_wg_url` | 空 | security-wgのcore索引のミラーURLです。空の場合は`https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json`を使います。 |
| `scan.node_runtime.blog_feed_url` | 空 | セキュリティブログのRSSフィードのミラーURLです。空の場合は`https://nodejs.org/en/feed/vulnerability.xml`を使います。 |
| `scan.node_runtime.blog_post_base_url` | 空 | ブログ本文のMarkdownのミラーベースURLです。空の場合は`https://raw.githubusercontent.com/nodejs/nodejs.org/main/apps/site/pages/en/blog/vulnerability/`を使います。 |
| `scan.node_runtime.releases_url` | 空 | リリース日の一覧のミラーURLです。空の場合は`https://nodejs.org/dist/index.json`を使います。 |
| `scan.node_runtime.schedule_url` | 空 | 系列ごとのEOL日の一覧のミラーURLです。空の場合は`https://raw.githubusercontent.com/nodejs/Release/main/schedule.json`を使います。 |

キャッシュは、`state.path`と同じディレクトリの`nodejs/`配下に保存します。
取得先は、[Node.jsのセキュリティ情報の取得](outbound-communication.md#node-runtime-download)に記載しています。

#### Python本体の脆弱性照合 {#python-runtime}

KestreLynxは、`PYTHON_VERSION`に記録されたCPythonの版をPythonのセキュリティ情報と照合します。
判定規則と制約は、[Python本体の検出結果](scan-logic.md#python-runtime)に記載しています。

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `scan.python_runtime.enabled` | `true` | セキュリティ情報の取得とPython本体の照合を有効にします。`false`では両方を停止します。 |
| `scan.python_runtime.advisory_db_url` | 空 | PSFのアドバイザリーデータベースのアーカイブのミラーURLです。空の場合は`https://codeload.github.com/psf/advisory-database/tar.gz/refs/heads/main`を使います。 |
| `scan.python_runtime.cve_record_base_url` | 空 | CVEの公式レコードのミラーベースURLです。空の場合は`https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/`を使います。 |
| `scan.python_runtime.releases_url` | 空 | リリース一覧のミラーURLです。空の場合は`https://www.python.org/api/v2/downloads/release/?is_published=true`を使います。 |
| `scan.python_runtime.release_cycle_url` | 空 | リリースサイクルのミラーURLです。空の場合は`https://peps.python.org/api/release-cycle.json`を使います。 |

キャッシュは、`state.path`と同じディレクトリの`python/`配下に保存します。
取得先は、[Pythonのセキュリティ情報の取得](outbound-communication.md#python-runtime-download)に記載しています。

## 通知先

少なくとも1つの通知先が必要です。

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `notify.slack_webhook_url` | 空 | Slack Incoming WebhookのURLです。チャンネルへの通知に対応します。 |
| `notify.slack_bot_token` | 空 | `chat:write`権限を持つSlack Bot Tokenです。`slack_channel`と一緒に設定すると、スレッド投稿と前回レポートへのリンクを利用できます。 |
| `notify.slack_channel` | 空 | Botで通知するSlackチャンネルIDです。 |
| `notify.generic_webhook_url` | 空 | 構造化JSONを受け取るエンドポイントです。 |
| `notify.language` | `en` | Slack通知とPR本文の言語です。`en`か`ja`を指定し、それ以外は設定エラーです。汎用WebhookのJSONは英語のままです。 |
| `notify.notify_on_clean` | `false` | 脆弱性がない場合にも通知します。 |

`slack_webhook_url`とBot Tokenの組み合わせを同時には設定できません。
汎用Webhookは、どちらのSlack通知方式とも併用できます。

スレッドの位置とフッターの読み方は、[スレッドのレポート](slack-display.md#thread-display)を参照してください。

日本語のSlack通知は、次のように設定します。

```yaml
notify:
  language: ja
```

翻訳する定型文と英語のまま残る内容は、[通知の言語](slack-display.md#notification-language)を参照してください。

## 通知モード

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `notify.mode` | `diff` | `diff`は変化を通知し、`full`はスキャンごとに現在の全項目を通知します。 |
| `notify.full_report_day` | `monday` | diffモードで完全なレポートを送る曜日です。`never`で無効化します。 |

差分として扱う変化は[パッケージの変化](diff-logic.md#package-changes)、送信する条件は[スキャン通知の送信条件](notification-conditions.md#notification-conditions)を参照してください。

## 状態管理とDocker

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `docker.socket` | `/var/run/docker.sock` | Dockerソケットのパスです。 |
| `state.path` | `/var/lib/kestrelynx/state.json` | スキャン履歴と差分計算に使用するファイルです。 |

脅威情報フィードのキャッシュは、`state.path`と同じディレクトリ内の`intel`ディレクトリに保存します。
既定のパスは`/var/lib/kestrelynx/intel`です。

`state.path`を含むディレクトリの永続化は[セットアップ手順](getting-started.md)、履歴の扱いは[履歴の継続](diff-logic.md#state-lifecycle)を参照してください。

## 修正計画と修正PR {#remediation}

機能の入口は[修正計画の案内](remediation.md#contents)、有効化は[有効化の手順](remediation-setup.md)を参照してください。

### 有効化設定 {#remediation-enablement}

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `remediation.enabled` | `false` | Docker・Kubernetesモードで読み取り専用の修正計画を有効にします。 |
| `remediation.pull_requests.enabled` | `false` | 修正PRを有効にします。修正計画の有効化とGitHub tokenが必要です。 |

各設定で行う処理は[計画とPRの実行範囲](remediation-logic.md#plan-and-pr-execution)を参照してください。

### GitHubアクセス {#remediation-github}

| 設定項目 | 既定値 | 形式・必須条件 |
| --- | --- | --- |
| `remediation.github.token` | 空 | 空白・制御文字を含まないGitHub tokenで、PRを有効にする場合は必須です。 |

| 用途 | 必要な権限 |
| --- | --- |
| 公開リポジトリの計画 | tokenなしで匿名の読み取りが可能 |
| 非公開リポジトリの計画 | 対象リポジトリに限定したfine-grained tokenのContents: Read |
| PRの作成・管理 | 対象リポジトリに限定したfine-grained tokenのContentsとPull requests: Read and write |

設定ファイルは所有者だけが読めるようにしてください。
tokenの送付先は[認証情報の送付範囲](outbound-communication.md#credential-destinations)を参照してください。

### 保存先 {#remediation-storage}

| 設定項目 | 既定値 | 形式・説明 |
| --- | --- | --- |
| `remediation.storage_dir` | `/var/lib/kestrelynx/remediation` | 計画、配信記録、PR記録、ツールキャッシュを保存する絶対パスのディレクトリです。 |

`state.path`を変えても、この保存先は変わりません。
内容は[保存ファイル](remediation-reference.md#stored-records)を参照してください。

### イメージレジストリの認証 {#remediation-registries}

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `remediation.registries` | `[]` | 非公開イメージの候補選定と比較スキャンに使う、ホストごとの認証設定です。 |

| フィールド | 既定値・必須条件 | 形式・検証条件 |
| --- | --- | --- |
| `host` | 必須 | イメージ参照に書くホスト名またはIPv4アドレスと任意のポートで、scheme・パス・ユーザー情報は含めません。ポートは`1`〜`65535`です。 |
| `username` | 必須 | 空白・制御文字・`:`を含まない、空でない文字列です。 |
| `password` | 必須 | 空白・制御文字を含まない、空でないパスワードまたはアクセストークンです。 |
| `token_hosts` | `[]` | 認証情報を送ってよい追加のtoken serviceのホスト一覧で、各値の形式は`host`と同じです。 |

- ホスト名は大文字・小文字を区別せず、`docker.io`・`index.docker.io`・`registry-1.docker.io`は同じホストとして扱う
- 正規化後に同じ`host`となる認証設定は重複して指定できない
- Docker Hubの認証には`host: docker.io`と`token_hosts: [auth.docker.io]`を指定する

送付先とリダイレクトの制限は[認証情報の送付範囲](outbound-communication.md#credential-destinations)、設定手順は[非公開イメージの認証](remediation-setup.md#configure-registry-auth)を参照してください。

### ソースの対応付け {#remediation-mappings}

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `remediation.mappings` | `[]` | 稼働中のCompose・Kubernetesワークロード、Composeを使わないDockerコンテナとGitHub上のソースファイルを対応付けます。 |

各項目に`workload`、`repository`、`base_branch`と、ちょうど1種類のソースを設定します。

- `container/<名前>`はDockerモード専用で、`dockerfile`または`dependencies`の対応付けだけに使う
- 名前は`docker run --name`で指定した`docker ps`の`NAMES`の値で、`[a-zA-Z0-9][a-zA-Z0-9_.-]+`に一致する2〜253バイトとし、大文字・小文字を区別する
- `container/<名前>`と`compose`の対応付けを組み合わせると、`compose/<project>/<service>`を案内する設定エラーになる
- Kubernetesモードで`container/<名前>`を指定すると設定エラーになる

Kubernetesモードでは`manifest`・`kustomize`・`helm_values`・`dockerfile`・`dependencies`を指定できます。
`compose`はDockerモード専用で、`manifest`・`kustomize`・`helm_values`はKubernetesモード専用です。
修正計画が有効で、対応付けの名前空間が`kubernetes.namespaces`の対象外の場合は、起動時に警告し、その対応付けは計画に使われません。

| 対応付け内のフィールド | 必須条件・形式 |
| --- | --- |
| `workload` | 必須で、Dockerモードでは稼働中ワークロードのComposeラベルと一致する`compose/<project>/<service>`、またはComposeを使わないコンテナの`container/<名前>`、Kubernetesモードでは`<kind>/<namespace>/<name>/<container>`です。`kind`は`deployment`・`statefulset`・`daemonset`・`job`・`cronjob`・`pod`です。 |
| `repository` | 必須で、`owner/name`形式のGitHubリポジトリです。 |
| `base_branch` | 必須で、ソースの取得元とPRの宛先に使う有効なGitブランチ名です。 |
| `compose.path` / `compose.service` | Composeの対応付けで必須の、リポジトリ相対のComposeファイルとサービス名です。 |
| `manifest.path` | マニフェストの対応付けで必須の、リポジトリ相対のファイルパスです。 |
| `manifest.object.kind` | 任意で、省略時はワークロードの種類を使い、指定時も`Deployment`・`StatefulSet`・`DaemonSet`・`Job`・`CronJob`・`Pod`のうちワークロードと同じ種類に限ります。 |
| `manifest.object.name` | 任意で、省略時はワークロード名を使い、指定時はファイル内のオブジェクト名を使います。 |
| `kustomize.path` | Kustomizeの対応付けで必須のリポジトリ相対パスで、ファイル名は`kustomization.yaml`・`kustomization.yml`・`Kustomization`のいずれかです。 |
| `kustomize.image` | 必須で、対象の`images[].name`をタグ・digestなしで指定します。 |
| `kustomize.affects` | 任意で、この項目が効く、対応付けたコンテナ以外のワークロードキーの一覧です。通常のinit containerも含め、重複や`workload`自身の指定はできません。省略時は、対応付けたコンテナだけに効くことを利用者が確認した扱いになります。 |
| `helm_values.path` | Helmのvaluesの対応付けで必須のリポジトリ相対パスで、拡張子は`.yaml`または`.yml`です。 |
| `helm_values.key` | 必須で、`[A-Za-z0-9_-]`からなる空でない名前をドットでつないだ255バイト以内の経路です。`image`・`app.image`など、イメージのmappingまたは文字列を指し、ドットを含むキーは指定できません。 |
| `helm_values.affects` | 任意で、このキーが効く、対応付けたコンテナ以外のワークロードキーの一覧です。通常のinit containerも含め、重複や`workload`自身の指定はできません。省略時は、対応付けたコンテナだけに効くことを利用者が確認した扱いになります。 |
| `dockerfile.path` | Dockerfileの対応付けで必須の、リポジトリ相対のDockerfileです。 |
| `dockerfile.target` | 任意のビルド対象ステージで、省略すると最後のステージを使います。英字で始まる128バイト以内の英数字・`_`・`.`・`-`です。 |
| `dependencies.directory` | 依存ファイルの対応付けで必須のディレクトリで、`.`はリポジトリのルートです。 |

- パスはリポジトリ内の正規化したパスとし、先頭の`/`、`./`、`..`、バックスラッシュを使わない
- 同じワークロードには、ソースの種類ごとに1件ずつ、別の項目で対応付けるが、`manifest`・`kustomize`・`helm_values`は併用しない
- 共有する依存ディレクトリやDockerfileには同じbase branchを指定する
- 同じリポジトリの同じComposeファイルのサービスを複数のワークロードに対応付けない
- 同じリポジトリの同じマニフェスト内で、種類・名前空間・名前が同じオブジェクトの同じコンテナを複数のワークロードに対応付けない
- 同じKustomizeの項目または同じHelmのvaluesのキーを指す対応付けでは、`workload`と`affects`を合わせた集合をすべて同じにする
- `affects`に列挙するものを含め、1つのコンテナのイメージタグを決める箇所は、`manifest`を含めて1つだけにする
- 同じリポジトリの同じKustomizeファイルまたはHelmのvaluesファイルには、すべての対応付けで同じ`base_branch`を指定する
- リポジトリ名の重複判定では大文字・小文字を区別しない

Composeの`build`からの特定と明示したDockerfileとの照合は[ベースイメージの特定](remediation-logic.md#base-image-selection)、入力の対応範囲は[対応する入力形式](remediation-reference.md#supported-inputs)を参照してください。

KustomizeとHelmのvaluesの設定例と作用先の指定方法は[KustomizeのPR設定](remediation-setup.md#kustomize-pull-requests)・[HelmのvaluesのPR設定](remediation-setup.md#helm-values-pull-requests)を参照してください。
上記の対応付けの制約に違反する設定は、起動時にエラーになります。

### 処理の上限 {#remediation-limits}

次の設定は`remediation.limits`配下に指定します。

| 設定項目 | 既定値 | 単位・指定範囲 |
| --- | --- | --- |
| `candidate_scans_per_cycle` | `10` | 1サイクルの候補イメージのスキャン数で、正の整数です。 |
| `baseline_rescans_per_cycle` | `10` | 比較条件をそろえるための1サイクルの比較元の再スキャン数で、正の整数です。 |
| `registry_requests_per_cycle` | `200` | token交換を含む1サイクルのイメージレジストリへのHTTP要求数で、正の整数です。 |
| `tag_pages_per_repository` | `20` | イメージリポジトリごとのタグ一覧取得の要求数で、対象系列を探索する要求も含む正の整数です。 |
| `cycle_timeout` | `30m` | 計画、依存更新、PR処理の期限で、正の期間です。通常の稼働イメージのスキャンは含みません。 |
| `new_prs_per_cycle` | `3` | PR有効時の1サイクルの新規PR数で、正の整数です。 |
| `open_prs` | `10` | PR有効時の設定したリポジトリ全体で開いているKestreLynxのPR数で、正の整数です。 |
| `dependency_jobs_per_cycle` | `3` | 1サイクルで試みる依存更新の単位数で、正の整数です。パッケージ数やコンテナ数ではありません。 |
| `job_timeout` | `6m` | 各作業用コンテナの作成・実行・結果回収の期限で、`1m`〜`60m30s`です。 |

上限による結果は[理由コード](remediation-reference.md#reason-codes)、PRの扱いは[PRの管理](remediation-logic.md#pr-management)、実行期限と後処理は[作業用コンテナの実行](remediation-logic.md#worker-execution)を参照してください。

### 作業用Podの設定 {#remediation-worker-kubernetes}

Kubernetesモードの言語パッケージ更新に使います。
[導入手順](remediation-setup.md#kubernetes-language-updates)に従い、利用者が作業用namespaceと必要なリソースを適用します。

| 設定項目 | 既定値 | 形式・適用範囲 |
| --- | --- | --- |
| `remediation.worker.kubernetes.namespace` | 空 | 作業用Podを作るnamespace名で、未設定の場合は言語パッケージ更新が`work_namespace_not_configured`で手動対応になります。 |
| `remediation.worker.kubernetes.service_account` | `kestrelynx-work` | 作業用PodのServiceAccount名で、権限とトークンを持たないものを指定します。 |
| `remediation.worker.kubernetes.priority_class` | `kestrelynx-work` | 作業用PodのPriorityClass名で、`preemptionPolicy: Never`のものを指定します。 |
| `remediation.worker.kubernetes.receiver_image` | 空 | 入力ファイルを受け取るコンテナのKestreLynxイメージを`repository@sha256:...`で指定し、空の場合はKestreLynx自身のPodの状態からdigest付き参照を取得します。 |
| `remediation.worker.kubernetes.max_concurrent_pods` | `1` | 同じインスタンスが同時に保持する作業用Pod数の上限で、`1`〜`16`を指定し、未削除の終了済みPodは数え、削除中のPodは数えません。削除中のPodを含む総数は作業用namespaceのResourceQuotaで制限します。 |
| `remediation.worker.kubernetes.runtime_class` | 空 | 未対応のため空にし、指定した場合は`work_runtime_class_unsupported`で手動対応になります。 |

これらの設定には`kubernetes.enabled: true`が必要です。
`namespace`を省略してほかの項目だけを設定した場合や、名前・イメージ参照・数値の形式が不正な場合は、起動時にエラーになります。
### 作業用イメージの取得先 {#remediation-worker-registry}

| 設定項目 | 既定値 | 形式・検証条件 |
| --- | --- | --- |
| `remediation.worker.registry` | 空 | Docker Hubミラーの`host[:port][/path]`を小文字で指定します。空の場合はDocker Hubを使います。 |

- scheme・タグ・digest・`//`・`..`を含めない
- パスには小文字英数字と区切りの`.`・`_`・`-`を使う
- ミラーには指定したホストとパスの下に、公式イメージと同じ内容の`library/node`・`library/python`を配置する

固定と取得不能時の扱いは[公式イメージの固定](remediation-logic.md#worker-images)、系列は[対応する実行環境](remediation-reference.md#supported-runtimes)、通信先は[作業用イメージの取得](outbound-communication.md#worker-image-downloads)を参照してください。

### ツールの公開後待機時間 {#remediation-tool-release-age}

| 設定項目 | 既定値 | 形式・指定範囲 |
| --- | --- | --- |
| `remediation.worker.tool_versions.min_release_age` | `72h` | npm・pnpm・uvの公開から使用までの最小待機時間で、`72h`や`30m`のような正の期間です。`0`や負の値は指定できません。 |

判定は[ツール公開後の待機](remediation-logic.md#tool-release-age)、取得時の検査は[ツールの取得と照合](remediation-logic.md#tool-verification)を参照してください。

### ツールキャッシュの容量 {#remediation-tool-cache}

| 設定項目 | 既定値 | 形式・指定範囲 |
| --- | --- | --- |
| `remediation.worker.tool_versions.cache_max_size` | `1GiB` | npm・pnpm・uvのキャッシュ容量の上限です。整数のバイト数、または整数に`B`・`KiB`・`MiB`・`GiB`を付け、最低`128MiB`を指定します。 |

再利用時の検査と容量不足時の扱いは[ツールキャッシュの再利用](remediation-logic.md#tool-cache)を参照してください。

### 作業プログラムの配置先 {#remediation-worker-program}

| 設定項目 | 既定値 | 形式・適用範囲 |
| --- | --- | --- |
| `remediation.worker.program_dir` | 空 | 空または絶対パスで、開発用の作業プログラムを置くディレクトリです。通常の配布版では指定不要です。 |

作業用コンテナに渡す際の検査は[コンテナへの入力](remediation-logic.md#worker-inputs)を参照してください。

### 起動時の検証 {#remediation-validation}

次の組み合わせは起動時にエラーになります。

- `remediation.enabled`を有効にせず、PRだけを有効にした場合
- `remediation.github.token`なしでPRを有効にした場合
- Dockerモードで`manifest`・`kustomize`・`helm_values`の対応付けを指定した場合
- Kubernetesモードで`compose`の対応付けを指定した場合

機能が無効でも、tokenの形式、保存先、対応付け、処理上限、レジストリ認証、作業用コンテナの設定を検証します。
この設定の検証だけで、リモートのリポジトリやイメージにアクセスできることは確認しません。

## 稼働時の使用状況

[稼働時の使用状況](runtime-usage.md)は実験的な機能です。

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `runtime.enabled` | `false` | Sensorの証拠を読み、使用状況を通知に反映します。Sensorを置かない場合は無効のままにします。 |
| `runtime.mute_unfixable_not_in_use` | `false` | 修正版がなく7日以上使用が確認されない所見のうち、条件を満たすものをSlackで通知オフにします。`runtime.enabled: true`のときだけ有効です。優先度は変えず、汎用Webhookには全件残します。 |
| `runtime.evidence_dir` | `/var/lib/kestrelynx-runtime` | Sensorの証拠ボリュームをマウントした絶対パスです。Sensorの`--evidence-dir`と一致させます。 |

`runtime.enabled: false`では、証拠ディレクトリを開かず、通知に稼働時の情報を追加しません。
エコシステム名のラベルとWebhookのエコシステム関連フィールドは、この設定に関係なく適用されます。

`runtime.enabled: true`と`kubernetes.enabled: true`の併用は設定エラーです。
稼働時の使用状況はDockerだけで利用できます。

有効時は、本体がDocker APIの`GET /containers/json`に加えて
`GET /containers/{id}/json`も使用します。`io.kestrelynx.runtime.exclude=true`の
ラベルを持つコンテナは使用状況の判定から外します。値は小文字の`true`だけが該当します。

Sensorの導入手順、観測の判定方法、通知オフの条件と通知の再開、権限は[稼働時の使用状況](runtime-usage.md)に記載しています。

## Kubernetes

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `kubernetes.enabled` | `false` | Dockerホストの代わりにKubernetesクラスタをスキャンします。 |
| `kubernetes.api_server` | 空 | Kubernetes APIサーバのURLです。空の場合は`KUBERNETES_SERVICE_HOST`と`KUBERNETES_SERVICE_PORT`を使用します。空でない値は`https://`で始まる必要があります。 |
| `kubernetes.token_file` | 空 | ServiceAccountのトークンファイルです。空の場合は`/var/run/secrets/kubernetes.io/serviceaccount/token`を使用します。 |
| `kubernetes.ca_file` | 空 | PEM形式のクラスタCAバンドルです。空の場合は`/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`を使用します。 |
| `kubernetes.tls_server_name` | 空 | APIサーバのTLS証明書の検証に使用するサーバ名を上書きします。空の場合は上書きしません。 |
| `kubernetes.namespaces` | `[]` | スキャン対象のnamespaceです。空または省略した場合は、すべてのnamespaceを対象にします。 |

`docker.socket`に値（空文字列`""`を含みます）を設定した状態で`kubernetes.enabled: true`を設定すると、
起動に失敗します。キーを省略するか値を`null`にした場合は、この排他条件に該当しません。
空の`docker:`セクションは受け付けます。Kubernetesを有効にする場合は、`docker:`セクション全体を削除してください。

クラスタ内では、`api_server`、`token_file`、`ca_file`を空のままにすると、
Podに注入されたAPIサーバのアドレスと、マウントされたServiceAccountのトークンおよび
CAを使用できます。Kubernetesが有効な場合、`api_server`が空で、APIサーバの環境変数の
いずれかが欠けていると起動に失敗します。CAバンドルは実行時に読み取り可能で、
有効なPEM証明書を含む必要があります。安全でない接続へのフォールバックはありません。

各namespaceはDNS-1123ラベルである必要があります。使用できる文字は小文字の英数字と
ハイフンで、長さは1〜63バイト、先頭と末尾は英数字にします。namespaceを指定した場合、
Pod、ReplicaSet、Jobの一覧はnamespaceごとに個別に取得します。Nodeの一覧は
引き続きクラスタ全体から取得します。

## 環境

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `environment.name` | 空 | このインスタンスのスキャン履歴に付ける任意の名前です。空の場合は、名前のない既定の環境になります。 |

空でない名前はDNS-1123ラベルである必要があります。使用できる文字は小文字の英数字と
ハイフンで、長さは1〜63バイト、先頭と末尾は英数字にします。値は正規化しません。
大文字、ドット、アンダースコア、空白文字は受け付けません。

名前を設定すると、Slackのヘッダーには`[name]`として、汎用Webhookのペイロードでは
`environment`オブジェクトの`name`として表示します。このオブジェクトには、
有効なadapterに基づく`kind`が常に含まれ、値は`docker`または`kubernetes`です。
環境種別は設定できません。名前が空の場合、Webhookでは`name`を省略します。

この名前はスキャン履歴に付けるラベルであり、ホストを識別するものではありません。
ホスト名やIPアドレスから生成することもありません。状態ファイルを保持していれば、
ホストの再構築や移行の前後で同じ名前を使い続けても問題ありません。名前を追加、変更、
削除しても、履歴のリセット、初回検出日の変更、既存の検出項目の再通知は行いません。

## 悪用情報に基づく優先順位付け

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `triage.enabled` | `true` | CISA KEVとEPSSによる優先順位付けを有効にします。 |
| `triage.act_now_epss` | `0.10` | CVEをact nowに分類するEPSS確率の下限です。 |
| `triage.watch_epss` | `0.01` | CVEを少なくともwatchに分類するEPSS確率の下限です。 |
| `triage.kev_url` | 空 | CISA KEVフィードのURLを、ローカルミラーなどへ変更します。 |
| `triage.epss_url` | 空 | EPSSフィードのURLを、ローカルミラーなどへ変更します。 |
| `triage.discussion_links` | `true` | act-now CVEに関するHacker Newsの議論を検索します。 |

通信先と送信内容は[外向きの通信](outbound-communication.md#outbound-communication)を参照してください。

しきい値は次の条件を満たす必要があります。

```text
0 < watch_epss <= act_now_epss <= 1
```
