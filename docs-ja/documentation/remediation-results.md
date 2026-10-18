# 結果の読み方

修正計画には、更新候補、PRの状態、手動対応が必要な項目などが表示されます。
候補の提示やPRのマージは、稼働中のコンテナで脆弱性が解消したことを意味しません。

## Slackの修正計画 {#reading-results-in-slack-and-webhooks}

### 表示例 {#slack-example}

次は表示例です。Slackではイメージ参照が太字になり、PR番号はリンクになります。

```text
🔧 修正計画
Pull Request: 作成 1件 · オープン中 1件

イメージ: example/app:latest
修正するファイル: example/application の pnpm-lock.yaml
Pull Request: #12 (今回作成)
更新: package-a 1.2.3 → 1.2.4
要判断: package-b は脆弱性が直る 2.3.0 に上げられず、pnpm-lock.yaml では 2.1.1 のまま（上げられない原因は KestreLynx では調べていないため、package-b に依存しているパッケージの版の指定を確認してください）

イメージ: example/service:latest
修正するファイル: example/application の docker/Dockerfile
Pull Request: #13 (オープン中)
更新: ベースイメージ python 3.12.3-slim → 3.12.4-slim
```

### 表示項目 {#slack-fields}

| 表示 | 意味 |
| --- | --- |
| イメージ | 所見の元になった稼働イメージ |
| サービス | イメージ参照で見出しを作れない場合などに示す対象サービス |
| 修正するファイル | 対応付けたリポジトリと変更対象のファイル |
| Pull Request | PRへのリンクと、今回作成・オープン中・マージ済み・未マージでクローズの状態 |
| 更新 | PRが提案するイメージタグやパッケージの変更 |
| 更新候補 | 提案された変更であり、PR作成済みとは限らない |
| 再pull | 同じタグの新しい内容への更新を、比較結果が支持している |
| 再ビルド | 依存の版指定による解消見込み、またはベースを再取得してビルドする案内 |
| 要判断 | ソース、版の条件、更新方法、比較結果などについて手動対応が必要 |
| 保留 | 上限、待機時間、取得の問題などで処理を進められなかった |
| 比較不能 | 比較に必要な情報や条件がそろわなかった |
| 失敗 | スキャン、取得、更新などの処理に失敗した |
| ⚠️ メジャーバージョンの変更 | majorが変わる更新や、0.xでminorが変わる更新 |
| ⚠️ Pull Requestの作成を停止中 | 記録やGitHub上の状態などに問題があり、PRへの書き込みを止めている |

更新目標があるパッケージの要判断は、パッケージごとの行で表示します。
目標がないパッケージは理由ごとにまとめ、その下にパッケージの一覧を表示します。

理由の定義は[理由コード](remediation-reference.md#reason-codes)、対応の進め方は[候補やPRが出ない場合](remediation-troubleshooting.md)を参照してください。

### 件数の読み方 {#reading-counts}

| 集計 | 数える単位 |
| --- | --- |
| `Pull Request: 作成 …件 · オープン中 …件`など | PR処理の対象となった更新単位ごとの状態 |
| `更新候補 …件 · 要判断 …件`など | 変更対象のファイルや再pull対象などの項目ごとの表示の種類 |
| `所見…件が解消` | 比較で検出されなくなった所見 |
| `KEV …件` | 表示対象に含まれるCISA KEV掲載の脆弱性に関する件数 |

PR番号がある結果を含む場合、冒頭はPR処理の状態別集計になります。
この集計には、まだPRがない更新単位の「要判断」「延期」「停止・失敗」も含まれます。

- PRの件数は、更新するパッケージ数や脆弱性数とは異なる
- 候補と要判断が同じ項目にある場合、それぞれの種類に1件ずつ数える
- 同じ項目に要判断のパッケージが複数あっても、要判断の件数がパッケージ数と一致するとは限らない
- PRが作られていても、含まれなかったパッケージは要判断として残る

### 省略された情報の確認先 {#omitted-details}

Slackでは、長いパッケージ一覧などを「ほか…件」として省略することがあります。

| 確認したい内容 | 確認先 |
| --- | --- |
| パッケージごとの版、理由、除外情報 | [Webhookの確認先](#webhook-details) |
| 実際に提案されたファイル差分 | PRの変更内容 |
| 計画時点のソースや検査結果 | [保存記録の確認先](#saved-details) |
| 取得や実行に失敗した際の詳細 | [診断情報の取得](remediation-troubleshooting.md#collect-diagnostics) |

## 更新結果の解釈 {#interpreting-updates}

### 更新目標と採用版 {#target-and-adopted-version}

| 表示する版 | 読み方 |
| --- | --- |
| 稼働版 | スキャンしたイメージで検出された版 |
| 更新目標の下限 | 報告された修正版情報から求めた、更新先を選ぶ際の下限 |
| 採用版 | 更新後の依存ファイルで確認した版であり、複数の版が残る場合はその最小版 |

更新目標は、パッケージマネージャーが実際に選んだ版とは限りません。
計画だけの場合は依存更新を実行しないため、更新目標を検証済みの採用版として読まないでください。

下限の求め方は[修正版の下限](remediation-logic.md#fix-lower-bound)、実行する処理の違いは[計画とPRの実行範囲](remediation-logic.md#plan-and-pr-execution)を参照してください。

### 部分PR {#partial-pull-requests}

npm・pnpm・uvでは、計画したパッケージのうち、検査を通った更新だけがPRに含まれる場合があります。

| 結果 | 読み方 |
| --- | --- |
| PRの「更新」にあるパッケージ | 今回のPRに含まれる変更 |
| 「要判断」「ため除外」と表示されたパッケージ | 今回の更新から外れ、別の対応が必要な対象 |
| 目標の版に上げられず、元の版のままと表示されたパッケージ | 修正版に届かなかった対象であり、上がらない原因まで特定できたとは限らない |
| PRがオープン中で、除外情報も表示される結果 | 既存PRに対応付けた更新にも、対応が残るパッケージがある |

「除外」は、パッケージをイメージから削除したという意味ではありません。
また、項目全体がPR候補でも、すべてのパッケージが更新されたとは限りません。

pipの固定版更新は部分PRに分けません。
成立条件は[部分PRの成立条件](remediation-logic.md#partial-pr-selection)、確認操作は[更新を実行できない場合の確認](remediation-troubleshooting.md#check-update-failure)を参照してください。

### 依存元からの再解決の結果 {#dependent-reresolution-results}

npm・pnpm・uvでは、対象パッケージを修正版へ更新するために、プロジェクトが宣言する範囲内で依存元も更新する場合があります。
Slackでは、更新するパッケージに添えて、あわせて動かした依存元を表示します。

| 表示の例 | 読み方 |
| --- | --- |
| `対象 旧版 → 採用版（依存元 旧版 → 新版 も更新）` | 対象の更新とともに、その依存元の版も変更 |
| `今回の再解決では修正版に届かなかった` | 依存元を再解決したが、今回の結果では対象を修正版にできなかった |
| `更新も必要だが、…ため採用しない` | 再解決の結果が検査を通らなかった場合などの不採用 |
| `…ため … の更新を試していない` | 対応形式や上限などによる見送り |
| `公開から72時間経っていないため … 以降に再試行する` | 新たに入る版が公開後の待機条件を満たしていない状態 |

- 修正版に届かなかった表示は、ほかの更新方法でも解消できないことまでは示さない
- 直接依存の版が変わらず途中の依存元だけが変わる場合は、その依存元の名前を表示する
- Slackの依存元一覧は3件まで表示し、残りは件数で示す
- 再解決を採用しなくても、検査を通った通常更新のPRが作られる場合がある

版が変わった直接依存がある場合、PR本文の「あわせて更新したパッケージ」に変更前後の版を載せます。
古い版を要求されていた対象と要求範囲も載せ、途中のパッケージが要求していた場合はその名前を示します。

PR本文のスキャン比較の行は、`source_check.basis`に応じて表示します。
持ち越しがある場合は、記録件数と先頭の例を1行で示し、この更新では直らないことを明記します。

| 記録 | PR本文の表示 |
| --- | --- |
| `package_version_vuln_edges_positions` | パッケージ名・版・脆弱性ID、エントリ数・要求数に加え、変更された要求を位置ごとに照合する比較 |
| `package_version_vuln_edges` | パッケージ名・版・脆弱性IDとエントリ数・要求数による比較 |
| 持ち越しの表示例 | 更新で版が変わった位置に、同じ脆弱性が 2 件残っています(例: `rc` `1.2.8` から `1.2.9` の `CVE-2026-0001`)。この更新では直りません。 |

- 持ち越しの表示件数は、記録された`chain_carried`の要素数であり、位置の総数ではない
- 一覧が上限で省略された場合は、PR本文にも省略の案内を表示する
- Slackの表示は変わらず、持ち越しや位置の検査の専用一覧は追加しない

| 確認したい内容 | Webhookの確認先 |
| --- | --- |
| 更新に伴って動かした依存元 | `language_items[].packages[].through` |
| 古い版を要求していたパッケージと要求範囲 | `language_items[].update.chain.blocked` |
| 再解決の起点と結果 | `language_items[].update.chain.tops`・`outcome` |
| 不採用や見送りの詳しい理由 | `language_items[].update.chain.reason`・`detail` |
| 最初の更新結果の再判定か、追加の再解決か | `language_items[].update.chain.source` |
| スキャン比較の単位 | `language_items[].source_check.basis` |
| 同じ位置に残る脆弱性 | `language_items[].source_check.chain_carried` |
| 位置の検査による拒否 | `language_items[].source_check.chain_position_refusals` |
| 再試行可能な時刻 | `language_items[].retry_after` |
| PRに含む直接依存の変更 | `pull_requests[].language.chain` |

処理の条件は[依存元からの再解決](remediation-logic.md#dependent-reresolution)、フィールドの仕様は[依存元からの再解決の記録](webhook-remediation-reference.md#language-chain-fields)を参照してください。

### 再取得の案内 {#repull-guidance}

「再pull」は、同じタグが現在指す内容との比較で改善を確認した結果です。
タグの文字列を変更しないため、この案内だけでComposeのタグ更新PRは作りません。

`所見4件中3件が解消`なら、比較対象の4件のうち3件が候補では検出されなくなったことを示します。
稼働中のコンテナがその内容へ置き換わったことは示しません。

### 再ビルドの案内 {#rebuild-guidance}

| 表示の内容 | 読み方 |
| --- | --- |
| `再ビルドで … 以上が入る見込み` | pipの依存範囲が修正版を許すため、再ビルドによる解消を見込んでいる |
| `稼働中のイメージの作成元のベースを確認できない` | 浮動タグのベースを確認できず、現在のベースを再取得してビルドする案内 |
| `docker compose build --pull`の案内 | ベースを再取得するための案内であり、脆弱性の改善を確認した結果ではない |

どちらも、再ビルド後に実際に入る版や、配置後の稼働イメージでの解消を確認した結果ではありません。
判定の詳細は[直接依存の版指定](remediation-logic.md#direct-dependencies)と[ベースレイヤーの照合](remediation-logic.md#base-layer-matching)を参照してください。

### 比較結果の解消 {#verification-results}

| 表示 | 意味 |
| --- | --- |
| 解消・`Resolved` | 更新前の比較対象にはあり、更新後の比較対象では検出されなかった所見 |
| 残存 | 更新後の比較対象にも残っている所見 |
| 新規 | 更新前の比較対象にはなく、更新後の比較対象で検出された所見 |

比較対象は更新の種類によって異なります。

| 更新の種類 | 比較結果が表す対象 |
| --- | --- |
| 配布イメージ | 比較元のイメージと候補イメージ |
| Dockerfileのベースイメージ | 現在のベースイメージと候補のベースイメージ |
| 言語パッケージ | 更新前後の依存ファイル |

!!! note "解消の表示と稼働状態"

    PRやSlackの「解消」は比較結果です。再ビルドした完成イメージや、配置後の稼働中のコンテナで解消したことを示すものではありません。

検査の境界は[対象別の検証範囲](remediation-logic.md#verification-scope)、比較条件は[スキャンの比較条件](remediation-logic.md#comparison-conditions)を参照してください。
依存のインストールやアプリケーションの動作は確認していません。

## 詳細な結果の確認先 {#detailed-results}

### Webhookの確認先 {#webhook-details}

| 確認したい内容 | フィールド仕様 |
| --- | --- |
| 計画の状態、比較条件、処理上限と使用量 | [修正計画の共通フィールド](webhook-remediation-reference.md#remediation-fields) |
| 配布イメージの候補と比較結果 | [配布イメージのフィールド](webhook-remediation-reference.md#remediation-image-fields) |
| ベースイメージの候補とレイヤーの確認結果 | [ベースイメージのフィールド](webhook-remediation-reference.md#remediation-dockerfile-fields) |
| パッケージごとの版・処理・除外理由、実行環境、ツール、更新検査 | [言語パッケージのフィールド](webhook-remediation-reference.md#remediation-language-fields) |
| PRの状態と、PRに含まれず対応が残るパッケージ | [PR処理のフィールド](webhook-remediation-reference.md#remediation-pr-fields) |
| PRの作成・照合などの操作結果 | [PR操作イベントのフィールド](webhook-remediation-reference.md#remediation-operation-fields) |
| PRへの書き込みを止めた問題 | [書き込み停止のフィールド](webhook-remediation-reference.md#remediation-problem-fields) |
| 部分PRを含む通知データの例 | [修正計画のJSON例](webhook-remediation-reference.md#remediation-json-example) |

### 保存記録の確認先 {#saved-details}

計画時点の情報は`plan.json`、継続して管理するPRの記録は`prs.json`で確認できます。
PR処理後の今回の結果は通知で確認してください。

保存内容と記録時点の一覧は[保存ファイル](remediation-reference.md#stored-records)、取得の操作は[診断情報の取得](remediation-troubleshooting.md#collect-diagnostics)を参照してください。
