# 外向きの通信

## 通信先一覧 {#outbound-communication}

KestreLynxと、スキャン・依存更新に使用するツールの通信先を示します。
通信は、有効な機能とその回に必要な処理に応じて発生します。

### KEVの取得 {#kev-download}

| 通信主体 | 通信先 | 取得・送信する情報 | 発生条件 |
| --- | --- | --- | --- |
| KestreLynx | 既定は`www.cisa.gov` | KEVフィードを一括取得 | トリアージが有効で、フィードの取得・更新が必要な場合 |

検出したCVEとの照合はローカルで行い、検出したCVE一覧は取得先へ送信しません。

取得先は[設定](configuration.md)、更新と取得失敗時の扱いは[脅威情報の更新](scan-logic.md#intel-cache)と[脅威情報を利用できない場合](scan-logic.md#degraded-triage)を参照してください。

### EPSSの取得 {#epss-download}

| 通信主体 | 通信先 | 取得・送信する情報 | 発生条件 |
| --- | --- | --- | --- |
| KestreLynx | 既定は`epss.empiricalsecurity.com` | EPSSフィードを一括取得 | トリアージが有効で、フィードの取得・更新が必要な場合 |

検出したCVEとの照合はローカルで行い、検出したCVE一覧は取得先へ送信しません。

取得先は[設定](configuration.md)、更新と取得失敗時の扱いは[脅威情報の更新](scan-logic.md#intel-cache)と[脅威情報を利用できない場合](scan-logic.md#degraded-triage)を参照してください。

### Node.jsのセキュリティ情報の取得 {#node-runtime-download}

| 通信主体 | 通信先 | 取得・送信する情報 | 発生条件 |
| --- | --- | --- | --- |
| KestreLynx | 既定は`raw.githubusercontent.com` | CVE・深刻度・影響範囲・修正範囲を含む`nodejs/security-wg`のcore索引を一括取得 | Node.js本体の照合が有効で、データの取得・更新が必要な場合 |
| KestreLynx | 既定は`nodejs.org`・`raw.githubusercontent.com` | セキュリティブログの一覧をRSS、本文を`nodejs/nodejs.org`のMarkdownとして取得し、security-wgに未登録のCVEを補完 | Node.js本体の照合が有効で、データの取得・更新が必要な場合 |
| KestreLynx | 既定は`nodejs.org` | リリース日を含む`dist/index.json`を一括取得 | Node.js本体の照合が有効で、データの取得・更新が必要な場合 |
| KestreLynx | 既定は`raw.githubusercontent.com` | 系列ごとのEOL日を含む`nodejs/Release`の`schedule.json`を一括取得 | Node.js本体の照合が有効で、データの取得・更新が必要な場合 |

security-wgの索引更新はリリースから数週間以上遅れることがあるため、セキュリティブログで補います。
これらの公開データとの照合はローカルで行い、イメージの情報や検出したCVEは取得先へ送信しません。

取得先とミラーの設定は[Node.js本体の脆弱性照合](configuration.md#node-runtime)、更新規則は[脅威情報の更新](scan-logic.md#intel-cache)、取得失敗時の扱いは[Node.jsのセキュリティ情報の利用不能時の扱い](scan-logic.md#node-runtime-unavailable)に記載しています。

### Hacker Newsの検索 {#hacker-news-search}

| 通信主体 | 通信先 | 取得・送信する情報 | 発生条件 |
| --- | --- | --- | --- |
| KestreLynx | `hn.algolia.com` | 悪用情報によりAct nowとなるCVE IDを検索クエリとして送り、議論のリンクを取得 | トリアージと議論リンクが有効で、対象CVEの検索が必要な場合 |

検索の有効化は[設定](configuration.md)を参照してください。
検索を無効にしても、[通知先への送信](#notification-delivery)は継続します。

### Trivyの取得通信 {#trivy-downloads}

| 通信主体 | 通信先 | 取得・送信する情報 | 発生条件 |
| --- | --- | --- | --- |
| Trivy | 脆弱性データベースの配布レジストリ | スキャンに必要なデータベースを取得 | 通常のスキャンや比較スキャンでデータベースの準備が必要な場合 |
| Trivy | 対象イメージのレジストリと配布物の取得先 | スキャン対象または比較用のイメージを取得 | スキャンに必要なイメージをレジストリから取得する場合 |

比較に使う条件は、[スキャンの比較条件](remediation-logic.md#comparison-conditions)を参照してください。

### GitHubへの通信 {#github-communication}

| 通信主体 | 通信先 | 取得・送信する情報 | 発生条件 |
| --- | --- | --- | --- |
| KestreLynx | `api.github.com` | 対応付けたリポジトリ・ブランチ・ソースファイルを読み取り | 修正計画でソースを確認する場合 |
| KestreLynx | `api.github.com` | 既存PRと過去の操作結果を照合 | PR処理が有効な場合 |
| KestreLynx | `api.github.com` | コミット・ブランチ・PR・置き換えコメントを作成し、条件を満たした古いPRをクローズ | PR処理が有効で、書き込みの条件を満たした場合 |

PRには、イメージ参照とdigest、Workload名、リポジトリ名、ソースのパス、変更内容が含まれることがあります。
パッケージ名と版、脆弱性ID、比較結果、処理の理由なども含まれることがあります。

再解決のPRでは、`mkdirp`などをあわせて更新する理由を示すため、依存元の名前・変更前後の版・更新を妨げていた版指定をGitHubへ送信します。
途中のパッケージが古い版を指定する場合は、その名前も含みます。

管理の条件は[PRの管理](remediation-logic.md#pr-management)、PRによるワークフローの起動は[PR作成の有効化](remediation-setup.md#enable-pr-creation)を参照してください。

### イメージ候補の取得 {#candidate-registry-communication}

| 通信主体 | 通信先 | 取得・送信する情報 | 発生条件 |
| --- | --- | --- | --- |
| KestreLynx | 公開または認証設定済みのイメージレジストリ | タグ一覧、manifest、configなど、イメージの実体確認に使う情報を取得 | 配布イメージやベースイメージの候補を調べる場合 |

認証の設定は[イメージレジストリの認証](configuration.md#remediation-registries)、候補の探索は[イメージ候補の選定](remediation-logic.md#image-selection)を参照してください。

### 作業用イメージの取得 {#worker-image-downloads}

| 通信主体 | 通信先 | 取得・送信する情報 | 発生条件 |
| --- | --- | --- | --- |
| DockerまたはKubernetesノードのコンテナランタイム | Docker Hubまたは設定したミラー | 作業用の公式Node.js・Pythonイメージを取得 | 言語パッケージの更新に必要なイメージがローカルにない場合 |
| Kubernetesノードのコンテナランタイム | KestreLynxイメージのレジストリ | 入力ファイルを受け取るコンテナのイメージを取得 | 作業用Podに必要なイメージがローカルにない場合 |

ミラーの設定は[作業用イメージの取得先](configuration.md#remediation-worker-registry)、固定と取得不能時の扱いは[公式イメージの固定](remediation-logic.md#worker-images)を参照してください。

### ツールの取得 {#tool-downloads}

| 通信主体 | 通信先 | 取得・送信する情報 | 発生条件 |
| --- | --- | --- | --- |
| KestreLynx | `registry.npmjs.org` | npm・pnpmの版情報と配布物を取得 | ツールの版情報の確認や配布物の取得が必要な場合 |
| KestreLynx | `pypi.org`・`files.pythonhosted.org` | uvの版情報と配布物を取得 | ツールの版情報の確認や配布物の取得が必要な場合 |

ツール取得の要求とリダイレクトは、この表のホストへのHTTPS通信に制限します。

取得・照合は[ツールの取得と照合](remediation-logic.md#tool-verification)、再利用は[ツールキャッシュの再利用](remediation-logic.md#tool-cache)を参照してください。

### 依存パッケージの取得 {#dependency-downloads}

| 通信主体 | 通信先 | 取得・送信する情報 | 発生条件 |
| --- | --- | --- | --- |
| KestreLynx | `registry.npmjs.org` | 依存パッケージの版・依存関係などの情報を取得 | Node.jsの互換条件や更新結果を照合する場合 |
| KestreLynx | `pypi.org`・`files.pythonhosted.org` | Pythonパッケージの情報・配布物を取得 | Pythonの更新結果を照合する場合 |
| KestreLynx | `registry.npmjs.org` | パッケージ名・版を指定し、依存先の版指定と公開日時を取得 | npm・pnpmの再解決で、更新を妨げる指定や公開後72時間の経過を確認する場合 |
| KestreLynx | `pypi.org` | パッケージ名・版を指定し、依存先の版指定と配布物のアップロード日時を取得 | uvの再解決で、更新を妨げる指定や公開後72時間の経過を確認する場合 |

| 作業用コンテナ | 公開npmレジストリ・PyPIと配布物の取得先 | 依存解決、lockfile生成、検査に必要な情報・配布物を取得 | 言語パッケージの依存更新を実行する場合 |

更新処理は、[マネージャー別の更新処理](remediation-logic.md#manager-update-methods)を参照してください。

再解決では、更新対象の`minimist`だけでなく、依存元の`mkdirp`や新たに入る版の情報も取得します。
通信量などの上限は、[再解決の対応範囲と上限](remediation-reference.md#dependent-reresolution-limits)を参照してください。

### 通知先への送信 {#notification-delivery}

| 通信主体 | 通信先 | 取得・送信する情報 | 発生条件 |
| --- | --- | --- | --- |
| KestreLynx | 設定したSlack・汎用Webhook | 所見、計画、理由、PRのリンクや操作結果を送信 | 各通知の送信条件を満たした場合 |

通知には、イメージ参照とdigest、Workload名、リポジトリ名、ソースのパスが含まれることがあります。
パッケージ名と版、脆弱性ID、比較結果なども含まれるため、共有できる範囲に合わせて通知先を設定してください。

再解決の通知には、あわせて更新した依存元や、採用・見送り・待機などの結果と理由を含めます。
Webhookには、版指定・変更一覧・処理量・再試行可能な日時も含まれることがあります。

残る脆弱性や不採用の原因を確認できるよう、Webhookにはパッケージ名・版・依存元・脆弱性ID・使用箇所数・KEV掲載情報なども含まれることがあります。

送信条件は[通知の送信条件](notification-conditions.md#notification-conditions)、JSONの内容は[Webhookのフィールド仕様](webhook-reference.md#generic-webhook)を参照してください。

## 認証情報の送付範囲 {#credential-destinations}

| 認証情報・通信 | 送付先・制限 |
| --- | --- |
| GitHub token | HTTPSの`api.github.com`だけに送り、別ホストへのリダイレクトは拒否 |
| イメージレジストリの認証情報 | 設定したレジストリ自身と、同じホストまたは`token_hosts`で許可したtoken serviceにHTTPSで送付 |
| KestreLynxによるイメージレジストリへの要求 | リダイレクト先へ認証情報を引き継がない |
| Trivyによるイメージレジストリへの要求 | 同じホスト内のリダイレクトには認証情報が付く場合があるが、別ホストへは引き継がない |
| 作業用コンテナへの入力 | GitHub tokenとイメージレジストリの認証情報を渡さない |

認証を設定していないレジストリには匿名でアクセスします。

設定形式は、[GitHubアクセス](configuration.md#remediation-github)と[イメージレジストリの認証](configuration.md#remediation-registries)を参照してください。

## 作業用コンテナのネットワーク {#worker-network}

Dockerの作業用コンテナはbridgeネットワークを使います。
通信先をネットワークの許可リストで制限する構成ではありません。

Kubernetesの作業用Podには、利用者がNetworkPolicyを適用します。
`deploy/kubernetes/work/40-networkpolicy.yaml`の例は受信を拒否し、送信をDNSと除外範囲外のIPv4宛てTCP 443に限定します。

この例は公開HTTPSサイト全般への接続を許可し、npmやPyPIだけに限定しません。
NetworkPolicyを実施するCNIが必要で、標準のNetworkPolicyではPodとその実行ノードの通信は遮断しません。
CNIが新しいPodに制限を設定し終えるまでの数秒間は、送信が制限されない場合があります(K3sの既定のCNIで確認)。

導入時の調整は[Kubernetesの言語パッケージ更新](remediation-setup.md#kubernetes-language-updates)、ネットワーク以外の制限は[実行時の制限](remediation-logic.md#worker-restrictions)を参照してください。

