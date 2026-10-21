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
| pullポリシー | Kubernetesの再pull項目に表示する、イメージ取得の方針と対象ワークロードごとの再取得方法 |
| 管理元(目印による推定) | Kubernetesのリソースに管理元の印がある場合に表示する管理元のつながりで、印からの推定 |
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

### KubernetesのPR表示 {#kubernetes-pr-results}

Slackでは、マニフェスト・Kustomize・Helmのvaluesのタグ更新を変更先ファイルとPRへのリンク付きで表示します。
管理元の印がある場合は、マニフェスト・Kustomize・Helmのvalues・DockerfileのPRにも管理元のつながりを表示します。

Kubernetes向けのPR本文には、次の情報を載せます。

- マージ後に外部の自動同期やCIで変更が反映されうる注意を、管理元の検出有無にかかわらず載せる
- Argo CD・Flux・Helmなどの管理元は、オブジェクトの印が示す主張として載せ、実際の管理関係を確認済みとは扱わない
- CronJob・Jobを含むマニフェスト・Kustomize・HelmのvaluesのPRには、既存のJobには反映されない注意を載せる
- マニフェストPRには、同じイメージで稼働していてマニフェストの対応付けがないワークロードと、同じPodテンプレート内で変更しないコンテナを載せる
- KustomizeとHelmのvaluesのPRには、作用先として列挙したコンテナの一覧と、そのうち通常のinit containerとして確認したものの一覧を載せる
- KustomizeのPRには、列挙した集合が作用先のすべてであることを利用者が確認した前提と、Kustomizeを展開せずに確認した範囲を載せる
- HelmのvaluesのPRには、指定したキーが最終的な値であり、列挙した集合が作用先のすべてであることを利用者が確認した前提と、Helmを描画せずに確認した範囲を載せる
- HelmのvaluesのPRには、ほかのvaluesファイル・CIの`--set`・Argo CDの`parameters`・`valuesObject`・`valuesFrom`による上書きと、ほかのツールによるタグの管理を確認していない旨を載せる
- Flux HelmReleaseの印を検出したワークロードを列挙し、HelmReleaseの`spec.values`を読み取っておらず、valuesファイルより優先される可能性を載せる
- HelmリリースもFlux HelmReleaseも検出できない場合は、このvaluesファイルが配備に使われるか分からない旨を載せる
- Helmで文字列として読まれるよう新しいタグに二重引用符を追加する場合は、その理由を載せる

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

`mkdirp 0.5.1`が`minimist 0.0.8`を指定している場合、`mkdirp`を`0.5.6`に上げることで`minimist`も修正版に更新できます。
`minimist 1.2.8`を採用する例では、Slackに次のように表示します。

```text
minimist 0.0.8 → 1.2.8（mkdirp 0.5.1 → 0.5.6 も更新）
```

一方、`rc 1.2.8`の指定は`minimist ^1.2.0`で、通常の更新で修正版を選べるため、`rc`の版は変えません。

| Slackの表示の一部 | 意味 |
| --- | --- |
| `mkdirp 0.5.1 → 0.5.6 も更新` | `minimist`を直すために、依存元の`mkdirp`も更新 |
| `今回の再解決では修正版に届かなかった` | 依存元を選び直しても、今回は修正版に上がらない |
| `更新も必要だが、…ため採用しない` | 検査に通らないなどの理由で不採用 |
| `…の更新を試していない` | 対応形式や処理上限などの理由で見送り |
| `公開から72時間経っていないため … 以降に再試行する` | 表示された日時まで待機 |

PR本文の「あわせて更新したパッケージ」には、版が変わった直接依存を載せます。
この例では、変更前後の版と、更新を妨げていた指定を次のように表示します。

> - `mkdirp`: `0.5.1` から `0.5.6` へ（`minimist` `0.0.8` を要求していた）

ほかのパッケージに同じ脆弱性が残る場合、PR本文に持ち越しの件数と例を表示します。
持ち越した脆弱性は、この更新では直りません。

再解決を採用しない場合でも、検査を通る通常更新はPRに含めることがあります。
「修正版に届かなかった」は、ほかの方法でも直せないという意味ではありません。

| 確認したい内容 | Webhookの`language_items[]`からの確認先 |
| --- | --- |
| あわせて更新した依存元 | `packages[].through` |
| 採用・見送りなどの結果と理由 | `update.chain.outcome`・`update.chain.reason`・`update.chain.detail` |
| 持ち越した脆弱性 | `source_check.chain_carried` |
| 再試行可能な日時 | `retry_after` |

npm・pnpm・uvでの処理の流れは[依存元からの再解決](remediation-logic.md#dependent-reresolution)を参照してください。
そのほかのフィールドは、[再解決の結果](webhook-remediation-reference.md#language-chain-fields)と[スキャン比較](webhook-remediation-reference.md#language-chain-scan-fields)にまとめています。

### 再取得の案内 {#repull-guidance}

「再pull」は、同じタグが現在指す内容との比較で改善を確認した結果です。
タグの文字列を変更しないため、この案内だけでCompose・Kubernetesマニフェスト・Kustomize・Helmのvaluesのタグ更新PRは作りません。

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

Compose・Kubernetesマニフェスト・Kustomize・Helmのvaluesのイメージタグ更新とDockerfileのベースイメージ更新では、PR本文で対象の所見とその他の所見を分けて表示します。

- 対象は修正版が報告されている所見で、Dockerfile更新ではベースイメージのレイヤーにあるものに限り、Slack・Webhookの修正計画でもこの対象の解消・残存だけを数える
- 候補に残るその他の所見と、新規の所見は、対象の解消・残存とは分けて表示する
- その他の所見は、修正版の報告がない所見など、更新の対象に含まれない所見
- Compose・Kubernetesマニフェスト・Kustomize・HelmのvaluesのPRでは、その他の所見のうち候補で検出されなくなった件数も表示し、該当する所見がある場合だけ一覧を載せる

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
