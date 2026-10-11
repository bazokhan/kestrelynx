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
| `scan.severity` | `[HIGH, CRITICAL]` | 分析と通知の対象にするTrivyの深刻度です。 |

指定できる値は`UNKNOWN`、`LOW`、`MEDIUM`、`HIGH`、`CRITICAL`です。

## 通知先

少なくとも1つの通知先が必要です。

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `notify.slack_webhook_url` | 空 | Slack Incoming WebhookのURLです。 |
| `notify.slack_bot_token` | 空 | `chat:write`権限を持つSlack Bot Tokenです。`slack_channel`と一緒に設定します。 |
| `notify.slack_channel` | 空 | Botで通知するSlackチャンネルIDです。 |
| `notify.generic_webhook_url` | 空 | 構造化JSONを受け取るエンドポイントです。 |
| `notify.language` | `en` | Slack通知の言語です。`en`か`ja`を指定し、それ以外は設定エラーです。汎用WebhookのJSONは英語のままです。 |
| `notify.notify_on_clean` | `false` | 脆弱性がない場合にも通知します。 |

`slack_webhook_url`とBot Tokenの組み合わせを同時には設定できません。
汎用Webhookは、どちらのSlack通知方式とも併用できます。

Botのスレッドの見出しは`Everything open now`（日本語では`未解決の所見の全体`）です。
本文を複数のメッセージに分ける場合も、スレッドは本文1通目に付けます。
スレッドを投稿した日は、その1通目の末尾にcontextのフッターとして
`📊 Everything open now is in this message's thread ↓`を表示します。
新しいスレッドがなく、有効な前回レポートへのリンクがある場合は
`🔗 Everything open as of the last report → thread`を表示し、
そのレポート時点の未解決の所見を示します。
どちらもない場合や、前回のパーマリンクが長すぎて表示できない場合はフッターを付けません。

日本語のSlack通知は、次のように設定します。

```yaml
notify:
  language: ja
```

翻訳する定型文と英語のまま残る内容は、[KestreLynxの仕組み](how-it-works.md#notification-language)に記載しています。

## 通知モード

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `notify.mode` | `diff` | `diff`は変化を通知し、`full`はスキャンごとに現在の全項目を通知します。 |
| `notify.full_report_day` | `monday` | diffモードで完全なレポートを送る曜日です。`never`で無効化します。 |

diffモードでは、新規検出、解消、修正可能化、優先度昇格、通知オフからの再開を通知します。未解決項目が
残っていても変化がない場合、完全なレポートを繰り返さず、短いハートビート通知を
送信します。

## 状態管理とDocker

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `docker.socket` | `/var/run/docker.sock` | Dockerソケットのパスです。 |
| `state.path` | `/var/lib/kestrelynx/state.json` | スキャン履歴と差分計算に使用するファイルです。 |

`state.path`を含むディレクトリをDockerボリューム、またはKubernetesの永続ボリュームで
永続化してください。脅威情報フィードのキャッシュは、`state.path`と同じディレクトリ内の
`intel`ディレクトリに保存します。既定のパスは`/var/lib/kestrelynx/intel`です。

## 修正計画と修正PR

[修正計画と修正PR（実験的）](remediation.md)はDocker向けの機能で、Composeのソースを
対応付けて利用できます。2つの有効化設定は、どちらも既定で`false`です。

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `remediation.enabled` | `false` | 候補の選定、スキャン結果の比較、読み取りだけの修正計画の通知を行い、GitHubへの書き込みや作業用コンテナは使いません。 |
| `remediation.pull_requests.enabled` | `false` | 検査した変更からGitHubにPRを作成し、言語パッケージの更新にはDockerの作業用コンテナを使います。 |
| `remediation.github.token` | 空 | 対応付けたリポジトリ用のGitHub tokenで、PRには必須です。 |
| `remediation.mappings` | `[]` | 稼働中のComposeワークロードとGitHub上のソースファイルを対応付けます。 |
| `remediation.storage_dir` | `/var/lib/kestrelynx/remediation` | 計画、配信記録、PR記録を保存する絶対パスのディレクトリです。 |
| `remediation.worker.image` | 空 | リリースに対応する作業用イメージを、digest付きの参照で上書きします。 |

tokenが空の場合、計画では公開リポジトリを匿名で読み取れます。
非公開リポジトリには、対象リポジトリに限定し、Contentsの読み取り権限を持つ
fine-grained tokenを使います。PRにはContentsとPull requestsのRead and write権限が
必要です。設定ファイルは所有者だけが読めるようにしてください。
tokenは作業用コンテナへ渡しません。PRの作成でリポジトリのCIが起動する場合があります。

コンテナを作り直しても`remediation.storage_dir`を保持してください。
既定では同梱の状態保存用ボリューム内にありますが、`state.path`を変えてもこの保存先は変わりません。

### ソースの対応付け

`remediation.mappings`の各項目に、`workload`、`repository`、`base_branch`と、
ちょうど1種類のソースを設定します。

| 対応付け内のフィールド | 説明 |
| --- | --- |
| `workload` | 稼働中ワークロードのComposeラベルと一致する`compose/<project>/<service>`です。 |
| `repository` | `owner/name`形式のGitHubリポジトリです。 |
| `base_branch` | ソースの取得元とPRの宛先に使うブランチです。 |
| `compose.path` / `compose.service` | リポジトリ相対のComposeファイルと、イメージ参照を編集するサービスです。 |
| `dockerfile.path` / `dockerfile.target` | リポジトリ相対のDockerfileと任意のビルド対象ステージで、targetを省略すると最後のステージを使います。 |
| `dependencies.directory` | npm・pnpm・pip・uvの依存ファイルを含むディレクトリで、`.`はリポジトリのルートです。 |

パスはリポジトリ内の正規化したパスとし、先頭の`/`、`./`、`..`、
バックスラッシュは使えません。同じワークロードには、ソースの種類ごとに1件ずつ、
別の項目で対応付けを設定できます。共有する依存ディレクトリやDockerfileは
同じbase branchを指定し、同じComposeファイルのサービスを複数のワークロードに対応付けることはできません。

Composeサービスの`build`が対応する静的な形式なら、別のDockerfileの対応付けなしで
パスとtargetを取得できます。両方を設定する場合は、一致している必要があります。

### 処理の上限

次の設定は`remediation.limits`配下に指定します。
上限を超えた処理は、候補なしではなく延期として通知します。

| 設定項目 | 既定値 | 説明 |
| --- | --- | --- |
| `candidate_scans_per_cycle` | `10` | 1サイクルの候補イメージのスキャン上限です。 |
| `baseline_rescans_per_cycle` | `10` | 比較条件をそろえるために行う、1サイクルの比較元の再スキャン上限です。 |
| `registry_requests_per_cycle` | `200` | token交換を含む、1サイクルのイメージレジストリへのHTTP要求の上限です。 |
| `tag_pages_per_repository` | `20` | イメージリポジトリごとのタグ一覧のページ上限です。 |
| `cycle_timeout` | `30m` | 計画、依存更新、PR処理の期限で、通常の稼働イメージのスキャンは含みません。 |
| `new_prs_per_cycle` | `3` | 1サイクルで新しく作成するPRの上限です。 |
| `open_prs` | `10` | 設定したリポジトリ全体で開いているKestreLynxのPRの上限です。 |
| `dependency_jobs_per_cycle` | `3` | 1サイクルで試みる依存更新の単位数の上限です（パッケージ数やコンテナ数ではありません）。pipの単位やmanifestを編集する単位など、1つの単位で複数のコンテナを使うことがあります。 |
| `job_timeout` | `6m` | 各作業用コンテナの作成・実行・結果回収の期限で、`1m`〜`60m30s`を指定でき、内部のジョブには30秒短い期限を渡します。後片付けには別途30秒の期限を使います。 |

PRの上限はPR有効時に適用します。`open_prs`の枠を空けるためだけに
既存PRを閉じることはありません。

### 作業用イメージと起動時の検証

本体のリリースごとに、`ghcr.io/kitsunetrail/kestrelynx-worker`のイメージをdigestで
固定しています。`worker.image`を空にするとそのイメージを使い、ミラーや検証用の
作業用イメージには`repository@sha256:<小文字の16進数64桁>`を指定できます。
初めて必要になったときに取得します。取得できない場合や、独自ビルドに既定イメージがなく
上書きも指定していない場合は、言語パッケージの更新を延期し、本体のコンテナ内で
パッケージマネージャーを代わりに実行することはありません。

`remediation.enabled`やtokenなしでPRだけを有効にした場合と、
`kubernetes.enabled: true`で修正計画を有効にした場合は起動時にエラーになります。
保存先、対応付け、上限が正の値であること、`job_timeout`の範囲、
作業用イメージの上書きの形式は、機能が無効でも検証します。
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

KEVとEPSSのフィードは一括でダウンロードされ、CVE IDとの照合はローカルで行われます。
ホストの完全なCVE一覧が外部サービスへアップロードされることはありません。
議論リンクを有効にしている場合、act-now CVEのIDは検索クエリとして
`hn.algolia.com`へ送信されます。この送信を防ぐには`discussion_links: false`、
追加の脅威情報フィードへの通信も止めるにはtriage自体を無効にしてください。

しきい値は次の条件を満たす必要があります。

```text
0 < watch_epss <= act_now_epss <= 1
```
