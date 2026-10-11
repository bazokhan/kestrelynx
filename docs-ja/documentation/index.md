# ドキュメント

このセクションでは、KestreLynxのインストール、設定、運用方法について記載します。

## KestreLynxについて

- [セットアップ手順](getting-started.md) — Docker Compose、`docker run`、またはKubernetesで
  KestreLynxを導入します。
- [設定](configuration.md) — 実行スケジュール、通知先、Kubernetes、環境名、状態管理、
  脆弱性の優先順位付けを設定します。
- [修正計画と修正PR（実験的）](remediation.md) — 更新候補、任意のGitHubのPR、検証範囲を確認する
- [稼働時の使用状況（実験的）](runtime-usage.md) — 任意のDocker向けSensorを追加し、優先度を変えずに使用中のパッケージに印を付けます。
- [KestreLynxの仕組み](how-it-works.md) — スキャン、優先順位付け、差分検出、通知までの処理を説明します。

KestreLynxは現在も開発中です。特記がない限り、このドキュメントは最新の
コンテナイメージと`main`ブランチの内容を説明しています。

バグ、機能要望、ドキュメントの修正は
[GitHubリポジトリ](https://github.com/kitsunetrail/kestrelynx/issues)へIssueを
作成してください。
