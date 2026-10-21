# 概要

## 機能の概要 {#overview}

KestreLynxは、稼働中のコンテナが使うイメージをTrivyでスキャンし、検出結果をパッケージ単位にまとめます。
悪用情報を使って対応の優先度を判定し、保存した履歴との比較から新規検出や解消などの変化を確認できます。

Slackでは変化や現在の検出結果を、汎用Webhookでは検出結果と差分の構造化データを確認できます。
通知を送る条件と、通知の表示・フィールドの説明は、それぞれ独立したページに記載しています。

Docker・Compose・Kubernetesでは、検出結果を直すための修正計画を通知し、Docker・ComposeではGitHubに修正PRを作成することもできます（実験的、既定で無効）。
修正計画はイメージや依存パッケージの更新候補を示し、マージ・ビルド・配置は利用者が行います。
詳細は[修正計画と修正PR](remediation.md)を参照してください。

導入方法は[セットアップ手順](getting-started.md)、設定値は[設定](configuration.md)を参照してください。

## 目次 {#contents}

- [スキャンと優先度の判定](scan-logic.md)
    - [処理の流れ](scan-logic.md#scan-cycle)
    - [スキャン対象](scan-logic.md#scan-targets)
    - [スキャン結果の確認](scan-logic.md#scan-verification)
    - [パッケージ単位の集約](scan-logic.md#package-grouping)
    - [検出結果の分類](scan-logic.md#finding-classification)
    - <span id="cve"></span><span id="cve-priority-rules"></span>[悪用情報による優先度](scan-logic.md#triage)
- [差分と履歴の判定](diff-logic.md)
    - [差分の比較単位](diff-logic.md#comparison-baseline)
    - [パッケージの変化](diff-logic.md#package-changes)
    - [ベースOSのEOL変化](diff-logic.md#eol-base-changes)
    - [イメージの実体変更](diff-logic.md#image-content-changes)
    - [イメージ参照の更新](diff-logic.md#reference-changes)
    - [履歴の継続](diff-logic.md#state-lifecycle)
- [通知の送信条件](notification-conditions.md)
    - <span id="notification-conditions"></span>[スキャン通知の送信条件](notification-conditions.md#notification-conditions)
    - [Slackスレッドの投稿条件](notification-conditions.md#slack-thread-delivery)
    - [スキャン通知の再送](notification-conditions.md#scan-redelivery)
    - <span id="remediation-slack-delivery"></span><span id="remediation-webhook-delivery"></span><span id="remediation-redelivery"></span>[修正計画の送信条件](notification-conditions.md#remediation-delivery)
- [Slackの読み方](slack-display.md)
    - <span id="slack-display"></span>[レポートの確認場所](slack-display.md#slack-display)
    - <span id="notification-language"></span>[通知の言語](slack-display.md#notification-language)
    - [区分の並び順](slack-display.md#section-order)
    - [件数の読み方](slack-display.md#counts)
    - [パッケージカードの読み方](slack-display.md#package-card)
    - [変化の表示](slack-display.md#change-labels)
    - [稼働時の使用状況の表示](slack-display.md#runtime-display)
    - [警告の読み方](slack-display.md#warnings)
- [Webhookのフィールド仕様](webhook-reference.md)
    - <span id="generic-webhook"></span>[ペイロードの範囲](webhook-reference.md#generic-webhook)
    - [レポートのフィールド](webhook-reference.md#report-fields)
    - [イメージのフィールド](webhook-reference.md#images)
    - [検出結果のフィールド](webhook-reference.md#findings)
    - [稼働時のフィールド](webhook-reference.md#runtime)
    - [差分のフィールド](webhook-reference.md#diff)
    - [互換性](webhook-reference.md#compatibility)
- [Webhookの修正計画フィールド](webhook-remediation-reference.md)
    - <span id="remediation-fields"></span>[修正計画の共通フィールド](webhook-remediation-reference.md#remediation-fields)
    - <span id="remediation-image-fields"></span>[配布イメージのフィールド](webhook-remediation-reference.md#remediation-image-fields)
    - <span id="remediation-dockerfile-fields"></span>[ベースイメージのフィールド](webhook-remediation-reference.md#remediation-dockerfile-fields)
    - <span id="remediation-language-fields"></span>[言語パッケージのフィールド](webhook-remediation-reference.md#remediation-language-fields)
    - <span id="remediation-pr-fields"></span>[PR処理のフィールド](webhook-remediation-reference.md#remediation-pr-fields)
    - <span id="remediation-operation-fields"></span>[PR操作イベントのフィールド](webhook-remediation-reference.md#remediation-operation-fields)
    - <span id="remediation-problem-fields"></span>[書き込み停止のフィールド](webhook-remediation-reference.md#remediation-problem-fields)
    - <span id="remediation-json-example"></span>[修正計画のJSON例](webhook-remediation-reference.md#remediation-json-example)
- [外向きの通信](outbound-communication.md)
    - <span id="outbound-communication"></span><span id="kev-download"></span><span id="epss-download"></span><span id="hacker-news-search"></span><span id="trivy-downloads"></span><span id="github-communication"></span><span id="candidate-registry-communication"></span><span id="worker-image-downloads"></span><span id="tool-downloads"></span><span id="dependency-downloads"></span><span id="notification-delivery"></span>[通信先一覧](outbound-communication.md#outbound-communication)
    - <span id="credential-destinations"></span>[認証情報の送付範囲](outbound-communication.md#credential-destinations)
    - <span id="worker-network"></span>[作業用コンテナのネットワーク](outbound-communication.md#worker-network)
