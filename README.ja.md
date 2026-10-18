# KestreLynx

[English](README.md) | **日本語**

[![CI](https://github.com/kitsunetrail/kestrelynx/actions/workflows/ci.yml/badge.svg)](https://github.com/kitsunetrail/kestrelynx/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

[ドキュメント](https://kestrelynx.dev/ja/) ·
[セットアップ手順](docs-ja/documentation/getting-started.md) ·
[設定リファレンス](docs-ja/documentation/configuration.md) ·
[動作報告](https://github.com/kitsunetrail/kestrelynx/discussions/categories/trying-kestrelynx)

> 稼働中のDocker・KubernetesコンテナのイメージをTrivyで定期的にスキャンし、**前回からの変化と、深刻度・CISA KEV・EPSSに基づく優先度**をSlackやWebhookへ通知するOSSです。Docker・Compose向けの**修正計画と修正PR（実験的）**で、更新候補の比較からGitHubへのPR作成まで修正を支援します（既定で無効）。

## 主な機能

- **イメージスキャン**：[Trivy](https://github.com/aquasecurity/trivy)のイメージスキャンで識別できるOSパッケージと言語パッケージのHIGH／CRITICALの検出（既定、言語パッケージの更新PRはnpm／pnpm／pip／uvのみ）
- **重複スキャンの抑制**：同一と確認できたイメージの結果共有
- **優先順位付け**：深刻度・CISA KEV・EPSSに基づく今すぐ対応／要監視／低優先度の分類
- **稼働時の使用状況（実験的）**：Docker向けの任意のSensorで使用中のパッケージの所見に印を付け、優先度を変えずに同じ区分内で先に表示（[稼働時の使用状況](docs-ja/documentation/runtime-usage.md)）
- **パッケージ単位の集約**：修正版の有無・バージョン・アップグレード時の注意度
- **未修正の脆弱性**：修正版がない項目も通知対象
- **ベースOS・パッケージのEOL**：サポート終了したベースOS（EOL base）と、ベンダーがこのリリースではサポート対象外と報告したCVEを持つパッケージ（EOL package）を、CVEの優先度とは別に最上部で強調して通知
- **差分通知**：新規検出・CVE追加・修正版公開・優先度昇格・解消
- **環境の識別**：Slack見出しへの任意の環境名の表示
- **対象コンテナの識別**：汎用Webhookへのコンテナ名・Composeプロジェクト／サービス・Kubernetes Workload情報の付加
- **稼働イメージの検証**：digestなどによるスキャン対象の固定と実体の一致確認
- **修正計画と修正PR（実験的）**：Docker向けの配布イメージ・Dockerfileのベース・npm／pnpm／pip／uv依存の更新候補と、任意のGitHubのPR作成

## 対応環境

| 対象 | 動作と範囲 |
| --- | --- |
| Docker | ホストごとに1インスタンス、全Composeプロジェクト・単独コンテナの稼働イメージ |
| Kubernetes | クラスタ内配置、読み取り専用ServiceAccount、全namespaceまたは指定namespace |

- **Kubernetesの所属取得**：Deployment・StatefulSet・DaemonSet・Job・CronJob（管理元不明は`unknown`）
- **スキャン対象**：取得時点で稼働中のコンテナ、Kubernetesのnative sidecar
- **対象外**：通常のinit container・ephemeral container
- **Kubernetesの検証済み構成**：Ubuntu／linux/amd64、単一ノードK3s 1.36＋containerd 2.3
- **Kubernetesの未検証構成**：複数ノード・混在アーキテクチャ・arm64・EKS／GKE／AKS・CRI-O・認証付き非公開レジストリ
- **詳細**：[検証記録と制約](docs-ja/development/kubernetes-support.md)

## 通知の例

以下は既定の`diff`モードで、`notify.language: ja`を設定したときの例です。SlackではBlock Kitのカードを使い、パッケージの見出しとラベル付きの行で表示します。

```text
🛡️ KestreLynx [prod-vps] — 2026-06-28 09:00のスキャン結果
イメージ12件をスキャン、3件に影響あり
前回のスキャンからの変化
───
🆕 前回のスキャンからの新規検出 (2件)
イメージ: nginx:1.25.3

◆ libnghttp2-14
現在: 1.52.0-1
修正版: 1.52.0-1+deb12u1
更新の注意度: 🟢 ディストリのセキュリティパッチ
検出件数: CRITICAL 0 / HIGH 2

代表CVE: CVE-2023-44487 · HIGH · EPSS >99% (このパッケージにほか +1件のCVE)
悪用情報: CISA KEV (実際の攻撃で悪用あり)
参照: アドバイザリ · ベンダーのアドバイザリ · 💬 HN (166 pts)
───
イメージ: myapp:latest
◆ webpack [npm-pkg]
現在: 4.46.0 · 修正版: 5.89.0 (🟠 メジャーバージョン更新 — 要注意)
検出件数: CRITICAL 0 / HIGH 1
代表CVE: CVE-2024-37890 · EPSS 0.1%
───
✅ 前回のスキャンからの解消 (1件)
• myapp:latest: postcss
───
📌 現在の未解決: 🚨 今すぐ対応1件 / 👀 要監視2件 / 🔕 低優先度4件
今すぐ対応/要監視の未解決の最長期間12日
```

長い通知は複数のメッセージに分け、続きには区分とイメージの見出しを繰り返します。各メッセージには、通知のプレビューと画面読み上げ用の短い要約も付けます。

- **変更あり**：変化した項目と未解決件数（KEV追加などによる優先度昇格も対象）
- **未解決項目あり・変更なし**：短い概要
- **問題なし・変更なし**：既定では通知なし（`notify.notify_on_clean`で変更可能）
- **週次レポート**：全体レポート（既定：月曜日、曜日変更・無効化も可能）
- **参考リンク**：アドバイザリ・KEVのベンダーガイダンス・関連するHacker Newsの議論

### 通知先の選択

| 通知先 | 内容 | 必要な設定 |
| --- | --- | --- |
| Slack Incoming Webhook | チャンネルに概要を投稿 | `notify.slack_webhook_url` |
| Slack Bot | 概要に加え、diffモードではスレッドに未解決項目の詳細を投稿 | `notify.slack_bot_token`と`notify.slack_channel` |
| 汎用Webhook | 現在のスキャン結果と、diffモードでの差分を構造化JSONとしてPOST | `notify.generic_webhook_url` |

- **Slack Botの詳細**：今すぐ対応／要監視の根拠・参照情報・未解決期間、低優先度の件数
- **詳細レポートの更新**：変更時・週次レポートの日
- **変更のない日のSlack Bot通知**：直近の詳細レポートへのリンク
- **Slack Botの必要条件**：`chat:write`スコープ、通知先チャンネルへの招待
- **併用可能**：Slack Incoming WebhookまたはSlack Botと、汎用Webhook
- **併用不可**：Slack Incoming WebhookとSlack Bot

## 修正計画と修正PR（実験的）

- Docker・Compose向けに、イメージと依存パッケージの更新を提案する
- 修正計画と任意のGitHub PR作成は、どちらも既定で無効
- 利用者が変更を確認し、マージ、配置、配置後の確認を行う

| 知りたいこと | 詳細ページ |
| --- | --- |
| 目的に合うページを探す | [修正計画の案内](docs-ja/documentation/remediation.md) |
| 修正計画と修正PRを有効にする | [有効化の手順](docs-ja/documentation/remediation-setup.md) |
| 候補やPRが出ない原因を切り分ける | [候補やPRが出ない場合](docs-ja/documentation/remediation-troubleshooting.md) |
| SlackやPRの内容を読む | [結果の読み方](docs-ja/documentation/remediation-results.md) |
| 候補の選定とPRの処理を確認する | [候補選定とPR処理の仕組み](docs-ja/documentation/remediation-logic.md) |
| 対応する入力と理由コードを調べる | [対応形式と理由コード](docs-ja/documentation/remediation-reference.md) |
| 設定値と必要な権限を調べる | [設定リファレンス](docs-ja/documentation/configuration.md) |
| 通知条件、Webhook仕様、外向きの通信を確認する | [KestreLynxの仕組み](docs-ja/documentation/how-it-works.md) |

## クイックスタート：Docker

Dockerが動作するホストと、少なくとも1つの通知先が必要です。配布イメージにはTrivyを同梱しています。

```sh
# 1. リポジトリを取得し、設定例をコピーして通知先を設定
git clone https://github.com/kitsunetrail/kestrelynx.git
cd kestrelynx
cp config.example.yml config.yml
${EDITOR:-vi} config.yml

# 2. 起動（TZは利用するタイムゾーンに合わせて変更）
docker run -d --name kestrelynx \
  --restart unless-stopped \
  -e TZ=Asia/Tokyo \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$PWD/config.yml:/etc/kestrelynx/config.yml:ro" \
  -v kestrelynx-state:/var/lib/kestrelynx \
  ghcr.io/kitsunetrail/kestrelynx:latest

# 3. 起動・スキャン結果を確認
docker logs -f kestrelynx
```

- **実行タイミング**：起動直後と毎日09:00（設定例）
- **タイムゾーン**：コンテナの`TZ`
- **永続化先**：`kestrelynx-state`ボリューム
- **保存内容**：差分通知の履歴・初回検出日・脅威情報キャッシュ
- **再作成・更新時**：既存ボリュームの引き継ぎ
- **配置単位**：ホストごとに1インスタンス（コンテナ・Composeプロジェクトごとの配置は不要）

動作報告は[Discussions](https://github.com/kitsunetrail/kestrelynx/discussions/categories/trying-kestrelynx)で受け付けています。

### Docker Composeでの実行

```sh
git clone https://github.com/kitsunetrail/kestrelynx.git
cd kestrelynx
cp config.example.yml config.yml
${EDITOR:-vi} config.yml
docker compose up -d
docker compose logs -f
```

- **使用ファイル**：同梱の[docker-compose.yml](docker-compose.yml)
- **`TZ`の既定値**：`UTC`（日本時間は`Asia/Tokyo`）

### Dockerソケットへのアクセス

- **対象取得**：`GET /containers/json`による稼働中コンテナの一覧取得、`runtime.enabled: true`では本体が`GET /containers/{id}/json`も使用
- **イメージ読み取り**：TrivyからDocker APIへのアクセス
- **コンテナ操作**：修正PR有効時に、言語パッケージ更新用の所有する作業用コンテナを作成・起動・削除し、監視対象のアプリケーションコンテナは変更しない
- **作業用コンテナの制限**：非root、全capabilityの削除、no-new-privileges、資源と時間の上限
- **作業用コンテナの書き込み先**：配布作業用イメージでは容量制限付きtmpfsに限定し、上書きイメージにも同じ所有者・権限の制約が必要で、イメージ内の全ファイルの権限は実行時には検査しない
- **作業用コンテナの認証情報**：GitHub token・本体の設定・Docker socketを渡さず、出力はKestreLynxが検査
- **`:ro`の制約**：Docker APIの操作権限は制限対象外で、PRのためにソケットを`:rw`へ変更する必要もない
- **マウント先**：信頼できるイメージのみ

## Kubernetesでの実行

1. [配置用マニフェスト](deploy/kubernetes/)の準備
2. [ConfigMap](deploy/kubernetes/configmap.yaml)の通知先設定、必要に応じた`kubernetes.namespaces`・`environment.name`の設定
3. [Deployment](deploy/kubernetes/deployment.yaml)の`TZ`と[PVC](deploy/kubernetes/pvc.yaml)のストレージ設定
4. namespaceの作成と編集済みマニフェストの適用

```sh
kubectl create namespace kestrelynx
kubectl apply -f deploy/kubernetes/
kubectl logs -n kestrelynx deployment/kestrelynx -f
```

- **有効化**：`kubernetes.enabled: true`
- **設定例からの切り替え**：`config.example.yml`の`docker`セクションを削除（`docker.socket`との同時設定は起動エラー）
- **不要な構成要素**：Dockerソケット・ノードごとのエージェント
- **接続要件**：スキャナPodから対象レジストリへのアクセス（Trivyによるイメージ取得）
- **非公開レジストリの認証**：Deployment内の認証情報マウント例を参照（実環境では未検証）
- **認証情報の引き継ぎ**：アプリ側の`imagePullSecrets`からの自動引き継ぎなし
- **対応範囲外**：ノード上にしか存在しないイメージ・削除済みdigest・K3sの`registries.yaml`によるミラー／書き換え・エアギャップ環境
- **履歴の保存先**：PVC（同じstateファイルへの複数インスタンスからの同時書き込み不可）
- **同梱Deploymentの構成**：1レプリカ・`Recreate`方式

## 主な設定

全設定の例は[config.example.yml](config.example.yml)、通知やスケジュールの詳細は[設定リファレンス](docs-ja/documentation/configuration.md)を参照してください。

| 設定 | 内容 |
| --- | --- |
| `schedule.daily_at` | 毎日の実行時刻（設定例：`09:00`、省略・空文字列：24時間間隔） |
| `schedule.run_on_start` | 起動直後のスキャン（既定：`true`） |
| `scan.severity` | 対象の深刻度（既定：`[HIGH, CRITICAL]`） |
| `notify.language` | Slack通知とPR本文の言語：`en`（既定）または`ja`、それ以外は設定エラーで、汎用Webhookは英語のまま |
| `notify.mode` | `diff`：差分通知（既定）、`full`：毎回全体レポート |
| `notify.full_report_day` | diffモードの週次レポートの曜日（既定：`monday`、無効化：`never`） |
| `notify.notify_on_clean` | 問題・変更のない場合の通知（既定：`false`） |
| `environment.name` | 通知元を見分ける任意の環境名（例：`prod-vps`） |
| `state.path` | 履歴ファイル（既定：`/var/lib/kestrelynx/state.json`） |
| `triage.enabled` | `true`：KEV／EPSSによる優先順位付け（既定）、`false`：深刻度に基づく通知 |
| `triage.act_now_epss` / `triage.watch_epss` | EPSSの判定しきい値（既定：`0.10`／`0.01`） |
| `triage.discussion_links` | Hacker Newsの議論リンク検索（既定：`true`） |

- **環境名の文字種**：小文字英数字・ハイフン、先頭と末尾は英数字
- **環境名の長さ**：1〜63文字、未設定も可
- **複数環境への配置**：インスタンスごとに異なる環境名・履歴保存先
- **再構築・移行時の履歴継続**：環境名とstateの引き継ぎ

## 開発

```sh
go test ./... -short   # 高速な単体テスト（Dockerやネットワークは不要）
go test ./...          # Trivyを利用する結合テストも実行（Trivyとネットワークが必要）
go build ./...
```

ドキュメントをローカルでビルドしてプレビューするには、次のコマンドを実行します。

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-docs.txt
mkdocs serve
```

日本語ドキュメントは別のプロセスでプレビューします。

```sh
mkdocs serve --config-file mkdocs.ja.yml
```

ビルド時に、英語・日本語の全ページで1200 × 630のOG画像とX向けのカード情報を自動生成します。
画像にはページタイトルを、メタタグにはタイトルと説明文を使用します。
サービス名の下のラベルは、日英共通で`development/`では「DEVELOPMENT LOG」、`articles/`では「TECHNICAL ARTICLES」、その他では「DOCUMENTATION」を表示します。
レイアウトは[`overrides/social/kestrelynx.yml`](overrides/social/kestrelynx.yml)にあり、ロゴなしで利用できます。
後からロゴを追加する場合は、画像を`overrides/social/`に配置し、`mkdocs.yml`の
`plugins.social.cards_layout_options.logo`にリポジトリ相対パス（例：`overrides/social/logo.png`）を指定します。
この設定は両言語で共通です。初回ビルドではGoogle FontsからNoto Sans JPを`.cache/`にダウンロードします。
画像生成にはCairoも必要です。Debian/Ubuntuではビルド前に`sudo apt-get install libcairo2`で導入してください。

`main` へプッシュされたドキュメントの変更は、[`docs.yml`](.github/workflows/docs.yml)によってビルドおよびデプロイされます。初回デプロイ前に、**Settings → Pages → Build and deployment → Source** で **GitHub Actions** を選択してください。

## ライセンス

[GNU AGPL-3.0](LICENSE)。Copyright (c) 2026 Kitsune Trail.
