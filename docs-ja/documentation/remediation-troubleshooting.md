# 候補やPRが出ない場合

修正計画の候補やPRが出ないときに、原因を切り分ける手順を説明します。

## 診断情報の取得 {#collect-diagnostics}

1. 対象のWorkload、イメージ、スキャン時刻を控える
2. Slack、Webhook、保存された計画から、対象項目の分類・理由・詳細を確認する
3. PR処理の問題では、通知されたPRの状態・操作結果と、同じ実行時刻のKestreLynxのログを確認する

保存記録の確認先は[保存ファイル](remediation-reference.md#stored-records)、理由コードの定義は[理由コード](remediation-reference.md#reason-codes)を参照してください。

## 計画が出ない場合の確認 {#check-missing-plan}

| 症状 | 確認すること | 参照先 |
| --- | --- | --- |
| 設定の読み込みで停止する | ログに示された設定項目と、有効化設定の組み合わせを確認する | [起動時の検証](configuration.md#remediation-validation) |
| 計画に対象の項目がない | 稼働イメージのスキャン結果、対象の深刻度、修正版情報を確認する | [イメージ候補の選定](remediation-logic.md#image-selection)・[言語パッケージの候補選定](remediation-logic.md#package-selection) |
| 計画の記録はあるが通知がない | 通知先、送信条件、配信失敗のログを確認する | [通知を送る条件](notification-conditions.md#notification-conditions)・[修正計画の再送](notification-conditions.md#remediation-redelivery) |
| ソースを取得できない、対象ファイルが見つからない | ComposeラベルまたはKubernetesのワークロードキー、対応付け、ベースブランチ、パス、GitHubのアクセスを確認する | [ソースの対応付け](configuration.md#remediation-mappings)・[GitHubアクセス](configuration.md#remediation-github) |
| 非公開イメージへアクセスできない | レジストリのホスト、認証情報、取得権限、token serviceの許可を確認する | [イメージレジストリの認証](configuration.md#remediation-registries) |
| 新しいイメージ候補がない | 通知の理由から、新しいタグ・内容・改善の有無を確認する | [イメージ候補の理由](remediation-reference.md#image-reasons) |
| Kubernetesの項目が`declared_ref_mismatch`または`declared_ref_unavailable`になる | 同じ稼働イメージ参照を使う各コンテナのPodのspecと稼働中の参照を確認する | [Kubernetesのイメージ参照と再取得](remediation-logic.md#kubernetes-image-references) |
| タグ一覧の取得が途中で止まる | 取得失敗のログと、タグ取得・レジストリ要求・処理時間の上限を確認する | [タグ一覧の探索](remediation-logic.md#tag-discovery)・[処理の上限](configuration.md#remediation-limits) |
| ローカルビルドとして扱われる | Composeの`build`と、Dockerfile・依存ファイルの対応付けを確認する | [ローカルビルドの除外](remediation-logic.md#local-builds) |
| ベースイメージを確認できない | Dockerfileの対象ステージ、使用したベース、稼働イメージとの照合結果を確認する | [ベースレイヤーの照合](remediation-logic.md#base-layer-matching)・[イメージ候補の理由](remediation-reference.md#image-reasons) |

## 更新を実行できない場合の確認 {#check-update-failure}

| 症状 | 確認すること | 参照先 |
| --- | --- | --- |
| 言語パッケージが候補のままで更新されない | PR作成の有効化と、対象項目に付いた理由を確認する | [有効化設定](configuration.md#remediation-enablement)・[計画とPRの実行範囲](remediation-logic.md#plan-and-pr-execution) |
| 入力形式や取得元が未対応と表示される | 依存ファイル、workspace、追加設定、パッケージの取得元を確認する | [対応する入力形式](remediation-reference.md#supported-inputs)・[ソースの理由](remediation-reference.md#source-reasons) |
| 実行環境を選べない、互換条件を満たさない | 版ファイルとmanifestの宣言、依存パッケージの要件、系列のサポート状態を確認する | [実行環境の選定](remediation-logic.md#runtime-and-tool-versions)・[実行環境の理由](remediation-reference.md#runtime-reasons) |
| pipの検証環境を決められない、または一致しない | 稼働イメージのPython版・OS・platformと、同じ依存ファイルを共有するイメージを確認する | [pipの検証環境](remediation-logic.md#pip-target-environment) |
| ツールの公開後待機で保留になる | 公開時刻、設定した待機時間、詳細に示された使用可能時刻を確認する | [ツールの公開後待機時間](configuration.md#remediation-tool-release-age)・[ツール取得の理由](remediation-reference.md#tool-reasons) |
| ツールを取得できない | 取得先への通信、取得枠、通知の詳細を確認する | [ツールの取得](outbound-communication.md#tool-downloads)・[ツール取得の理由](remediation-reference.md#tool-reasons) |
| ツールのハッシュが一致しない | 宣言したハッシュと、取得・照合の詳細を確認する | [ツールの版宣言](remediation-reference.md#tool-declarations)・[ツールの取得と照合](remediation-logic.md#tool-verification) |
| ツールキャッシュを利用できない | 保存先の書き込み権限、空き容量、キャッシュ容量の設定を確認する | [ツールキャッシュの容量](configuration.md#remediation-tool-cache)・[ツール取得の理由](remediation-reference.md#tool-reasons) |
| Dockerの作業用コンテナを実行できない | Docker API、作業用イメージの取得先、作業環境の検査ログを確認する | [修正PRの有効化](remediation-setup.md#enable-pull-requests)・[作業用コンテナの実行](remediation-logic.md#worker-execution) |
| Kubernetesの言語パッケージ更新が手動対応または延期になる | 理由コードに従い、作業用namespace、Kubernetesの版、RuntimeClassの未指定、RBAC、Pod作成規則とパラメータ、PriorityClass、Pod数・クォータ、Podのイベントを確認する | [導入手順](remediation-setup.md#kubernetes-language-updates)・[理由コード](remediation-reference.md#reason-codes) |
| Kubernetesで`update_result_invalid`になり、結果ログの欠落が示される | 実行ノードの`containerLogMaxSize`が`144Mi`以上か、ログが切り詰められたりローテーションされたりしていないかを確認する | [導入条件](remediation-setup.md#kubernetes-language-updates) |
| 作業プログラムを利用できない | 利用中の配布物とログを確認し、独自ビルドでは作業プログラムの配置も確認する | [作業プログラムの配置先](configuration.md#remediation-worker-program) |
| 処理の上限や期限で止まる | 通知に示された上限、設定値、次の実行予定を確認する | [処理の上限](configuration.md#remediation-limits)・[更新結果の理由](remediation-reference.md#update-reasons) |
| 修正版に届かない、一部だけPRに入る | 除外されたパッケージ、残った版、親パッケージの依存範囲を確認する | [部分PR](remediation-results.md#partial-pull-requests)・[更新結果の理由](remediation-reference.md#update-reasons) |
| 更新後のファイルや付随変更の検査に失敗する | 変更ファイル、lockfile形式、依存範囲、配布物との照合結果を確認する | [付随変更の検査](remediation-logic.md#change-validation)・[更新結果の理由](remediation-reference.md#update-reasons) |
| 比較できない、所見が残る、新しい所見が入る | スキャンのログと比較条件、更新後の残存・新規所見を確認する | [スキャンの比較条件](remediation-logic.md#comparison-conditions)・[比較結果の解消](remediation-results.md#verification-results) |

## PRを作れない場合の確認 {#check-missing-pr}

| 症状 | 確認すること | 参照先 |
| --- | --- | --- |
| 候補はあるがPRがない | PR作成の有効化、ソースの対応付け、対象の編集可能な形式を確認する | [有効化設定](configuration.md#remediation-enablement)・[ソースの対応付け](configuration.md#remediation-mappings)・[対応する入力形式](remediation-reference.md#supported-inputs) |
| GitHubへの書き込みを拒否される | tokenの対象リポジトリと権限、リポジトリの規則を確認する | [GitHubアクセス](configuration.md#remediation-github)・[PR処理の理由](remediation-reference.md#pr-reasons) |
| 新規PR数やオープン中のPR数の上限に達する | 現在のPRと設定した上限を確認する | [処理の上限](configuration.md#remediation-limits) |
| 既存PRに対応付けられる、新しいPRが作られない | 通知された既存PRと、同じ更新を未マージで閉じた履歴を確認する | [既存PRとの照合](remediation-logic.md#existing-pr-matching)・[閉じたPRの扱い](remediation-logic.md#closed-prs) |
| PR準備中にソースや候補が変わる | 通知の詳細と現在のソース・候補を確認し、次のサイクルの結果を確認する | [PR処理の理由](remediation-reference.md#pr-reasons) |
| GitHub操作が失敗する、結果が不明になる | アクセス、通信、操作結果を確認し、結果不明の操作はKestreLynxによる照合を待つ | [PR操作イベントのフィールド](webhook-remediation-reference.md#remediation-operation-fields)・[PR処理の理由](remediation-reference.md#pr-reasons) |

## 記録を照合できない場合の確認 {#check-record-failure}

| 症状 | 確認すること | 参照先 |
| --- | --- | --- |
| 計画やPRの記録を保存できない | 永続ボリュームのマウント、保存先の権限、空き容量、ログを確認する | [保存先](configuration.md#remediation-storage)・[保存処理の理由](remediation-reference.md#storage-reasons) |
| 記録がロックされている | 同じ保存先を使用する別のKestreLynxが動いていないか確認する | [保存処理の理由](remediation-reference.md#storage-reasons) |
| 既存PRと記録を照合できない | GitHubへのアクセス、PR本文の識別マーカー、PRやリポジトリの変更履歴を確認する | [記録の復旧](remediation-logic.md#record-recovery)・[PR処理の理由](remediation-reference.md#pr-reasons) |
| 記録の破損・形式・操作履歴の問題で書き込みが止まる | ログと通知の詳細を確認し、停止の原因を特定する | [書き込みの停止](remediation-logic.md#write-stops)・[保存処理の理由](remediation-reference.md#storage-reasons) |

!!! warning "記録を保持する"

    再試行を強制するためにPRの記録を削除しないでください。閉じた更新の再作成を抑止し、過去の操作を照合するために必要です。
