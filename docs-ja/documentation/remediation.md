# 修正計画と修正PR

!!! warning "実験的な機能"

    修正計画と修正PRは実験的な機能です。設定・通知・PRの形式は今後変わることがあります。

## 機能の概要 {#overview}

修正計画は、Docker・Composeで稼働するイメージの所見を基に、イメージや依存パッケージの更新を提案します。
修正PRを追加で有効にすると、条件を満たす更新をGitHubのPRとして作成します。

変更内容の確認、マージ、イメージの取得・ビルド、配置と配置後の確認は利用者が行います。
処理範囲の詳細は[計画とPRの実行範囲](remediation-logic.md#plan-and-pr-execution)を参照してください。

## 目次 {#contents}

- [有効化の手順](remediation-setup.md)
    - [修正計画の有効化](remediation-setup.md#enable-fix-plans)
    - [修正PRの有効化](remediation-setup.md#enable-pull-requests)
- [候補やPRが出ない場合](remediation-troubleshooting.md)
    - [診断情報の取得](remediation-troubleshooting.md#collect-diagnostics)
    - [計画が出ない場合の確認](remediation-troubleshooting.md#check-missing-plan)
    - [更新を実行できない場合の確認](remediation-troubleshooting.md#check-update-failure)
    - [PRを作れない場合の確認](remediation-troubleshooting.md#check-missing-pr)
    - [記録を照合できない場合の確認](remediation-troubleshooting.md#check-record-failure)
- [結果の読み方](remediation-results.md)
    - [Slackの修正計画](remediation-results.md#reading-results-in-slack-and-webhooks)
    - [更新結果の解釈](remediation-results.md#interpreting-updates)
    - [詳細な結果の確認先](remediation-results.md#detailed-results)
- [候補選定とPR処理の仕組み](remediation-logic.md)
    - [処理の流れ](remediation-logic.md#processing-flow)
    - [イメージ候補の選定](remediation-logic.md#image-selection)
    - [言語パッケージの候補選定](remediation-logic.md#package-selection)
    - [実行環境の選定](remediation-logic.md#runtime-and-tool-versions)
    - [作業用コンテナの実行](remediation-logic.md#worker-execution)
    - [更新結果の採用](remediation-logic.md#update-method-and-partial-pull-requests)
    - [PRの管理](remediation-logic.md#pr-management)
- [対応形式と理由コード](remediation-reference.md)
    - [対応範囲](remediation-reference.md#scope-and-requirements)
    - [対応する入力形式](remediation-reference.md#supported-inputs)
    - [対応する実行環境](remediation-reference.md#supported-runtimes)
    - [結果の値](remediation-reference.md#result-values)
    - [理由コード](remediation-reference.md#reason-codes)
    - [保存ファイル](remediation-reference.md#stored-records)

関連する設定と仕様は、次のページにあります。

- [設定：修正計画と修正PR](configuration.md#remediation)
- [仕組み：通知を送る条件](how-it-works.md#notification-conditions)
- [仕組み：汎用Webhookの修正計画のフィールド](how-it-works.md#remediation-fields)
- [仕組み：外向きの通信](how-it-works.md#outbound-communication)
