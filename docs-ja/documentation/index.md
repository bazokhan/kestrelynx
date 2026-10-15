# ドキュメント

このセクションでは、KestreLynxのインストール、設定、運用方法について記載します。

## KestreLynxについて

- [セットアップ手順](getting-started.md) — Docker Compose、`docker run`、またはKubernetesで
  KestreLynxを導入します。
- [設定](configuration.md) — 実行スケジュール、通知先、Kubernetes、環境名、状態管理、
  脆弱性の優先順位付けを設定します。
- [KestreLynxの仕組み](how-it-works.md) — 機能の概要と、判定の仕組み・Slackの読み方・Webhookのフィールド仕様・外向きの通信の目次
- [修正計画と修正PR（実験的）](remediation.md#contents) — 導入、結果の読み方、判定の仕組み、対応形式の案内
- [稼働時の使用状況（実験的）](runtime-usage.md) — 任意のDocker向けSensorを追加し、優先度を変えずに使用中のパッケージに印を付けます。

KestreLynxは現在も開発中です。特記がない限り、このドキュメントは最新の
コンテナイメージと`main`ブランチの内容を説明しています。

バグ、機能要望、ドキュメントの修正は
[GitHubリポジトリ](https://github.com/kitsunetrail/kestrelynx/issues)へIssueを
作成してください。
