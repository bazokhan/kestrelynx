# 対応形式と理由コード

修正計画と修正PRが扱う入力形式、実行環境、結果の値、理由コードをまとめます。
有効化は[有効化の手順](remediation-setup.md)を参照してください。

## 対応範囲 {#scope-and-requirements}

### 利用環境 {#supported-environments}

| 項目 | 対応範囲 |
| --- | --- |
| コンテナ環境 | Docker・Kubernetesモードで修正計画とPR作成に対応 |
| ソースの対応付け | ComposeのWorkloadに対して変更先のソースを指定し、KubernetesのWorkloadにはマニフェスト・Kustomizeの`images`の項目・Helmのvaluesのキー・Dockerfile・依存ディレクトリを指定 |
| ソースホスト | GitHub |
| 作業用コンテナ | Linuxの`amd64`・`arm64` |
| 言語更新の実行環境 | [対応する実行環境](#supported-runtimes)に記載した系列 |
| Sensor | 修正計画と修正PRの利用には不要 |
| Kubernetesの計画 | 配布イメージ・Dockerfileのベースイメージの更新候補、浮動タグの再取得の案内、言語パッケージの更新候補の提示 |
| KubernetesのPR | プレーンなマニフェストのイメージタグ、Kustomizeの`images[].newTag`、Helmのvaluesのイメージタグ、Dockerfileのベースイメージの更新に加え、[作業用Podの設定](remediation-setup.md#kubernetes-language-updates)によりnpm・pnpm・pip・uvの更新に対応 |

### 更新対象 {#supported-targets}

| 対象 | 取得元 | ソースの対応付け |
| --- | --- | --- |
| 配布イメージ | 公開レジストリ、認証を設定した非公開レジストリ | 比較結果の表示には不要で、Compose・Kubernetesマニフェスト・Kustomize・Helmのvaluesを変更するPRには必要 |
| Dockerfileのベースイメージ | 公開レジストリ、認証を設定した非公開レジストリ | 計画の作成からDockerfileまたはComposeの対応付けが必要 |
| npm・pnpmの依存パッケージ | 公開npmレジストリ | 計画の作成から依存ディレクトリの対応付けが必要 |
| pip・uvの依存パッケージ | 公開PyPI | 計画の作成から依存ディレクトリの対応付けが必要 |

非公開npmレジストリや非公開PyPIは更新対象にできません。
イメージレジストリの認証は、依存パッケージの取得には使いません。

## 対応する入力形式 {#supported-inputs}

### Composeの形式 {#compose-formats}

| 入力 | 対応範囲 |
| --- | --- |
| 編集箇所 | `services.<service>.image`に直接記述したイメージ参照 |
| イメージ参照 | 稼働中のリポジトリとタグに一致し、変更箇所を特定できる文字列 |
| 固定タグ | 完全な版を指定するタグを、同じ系列の新しいパッチへ変更可能 |
| 浮動タグ | 再pullの候補となり、同じタグの参照を書き換えるPRは作らない |
| 変数・digest | 編集対象のイメージ参照では未対応 |
| YAMLのアンカー・エイリアス・マージキー | 編集箇所に関わる場合は未対応 |
| ブロックスカラー・文字列以外の`image` | 未対応 |
| `include`・対象サービスの`extends` | 自動編集では未対応 |
| `build:`を持つサービス | 完成イメージを配布イメージの検索から除外 |

タグの選び方は[配布イメージのタグ](remediation-logic.md#published-image-tags)、ビルド対象の扱いは[ローカルビルドの除外](remediation-logic.md#local-builds)を参照してください。

### マニフェストの形式 {#manifest-formats}

| 入力 | 対応範囲 |
| --- | --- |
| YAML文書 | 1ファイルに複数の文書を含むプレーンなマニフェストに対応 |
| オブジェクト | `apps/v1`の`Deployment`・`StatefulSet`・`DaemonSet`、`batch/v1`の`Job`・`CronJob`、`v1`の`Pod` |
| 対象の選択 | `apiVersion`・`kind`・`metadata.name`と、ファイルに値がある場合は`metadata.namespace`で文書を一意に選び、コンテナ名で編集箇所を選ぶ |
| 編集箇所 | 通常のコンテナと、`restartPolicy: Always`を持つネイティブsidecarの`image` |
| 編集する文字列 | 宣言と稼働中のイメージに一致する明示的なタグの部分だけを書き換え、書式とコメントを保つ |
| 重複キー | 編集の前後で全YAML文書を検査し、重複があれば拒否 |
| digest・`$`変数・タグなし | 編集対象のイメージ参照では手動対応 |
| ブロックスカラー・単純な文字列以外の`image` | 手動対応 |
| YAMLのアンカー・エイリアス・マージキー | 編集箇所への経路や、文書の識別に使う`metadata`などに関わる場合は手動対応 |
| Fluxの`$imagepolicy` | 編集対象の`image`の行に印がある場合は手動対応 |
| `{{` | ファイル内のどこかに含まれる場合は手動対応 |
| `List`内のオブジェクト・通常のinit container | 編集対象外 |
| `.argocd-source-*.yaml` | 同じディレクトリにArgo CD Image Updaterの書き戻しファイルがある場合は手動対応 |

対象の名前空間をファイルで省略していても、同じ文書への対応付けが重なる場合はPRを作成しません。
作成条件は[KubernetesのマニフェストPR](remediation-logic.md#kubernetes-manifest-prs)を参照してください。

### Kustomizeの形式 {#kustomize-formats}

`kustomization.yaml`の`images`と`affects`の[設定例](remediation-setup.md#kustomize-pull-requests)を基に、名前で指定した項目の`newTag`だけを編集します。

| 入力 | 対応範囲 |
| --- | --- |
| ファイル | `kustomization.yaml`・`kustomization.yml`・`Kustomization`で、1つのYAML文書だけを含むファイル |
| 対象の選択 | `kustomize.image`と`images[].name`が一致する項目を一意に選択 |
| 編集する文字列 | 既存の文字列の`newTag`だけを書き換え、引用符・コメント・改行を保持 |
| `newName` | 既存の値を維持し、得られるイメージ参照を宣言・稼働中の参照と照合するが、`newName`自体の変更は手動対応 |
| `newTag`の未設定・空文字列 | `kustomize_tag_not_set`で手動対応 |
| 数値・文字列以外・明示的なYAMLタグ付きの値 | `kustomize_not_string`で手動対応し、数値として解釈されるタグは引用符で囲む |
| ブロックスカラー・`$`を含む値 | `kustomize_block_scalar`・`kustomize_variable`で手動対応 |
| digest | 対象項目に`digest`がある場合や、イメージ名にdigestを含む場合は`kustomize_digest`で手動対応 |
| YAMLのアンカー・エイリアス・マージキー | 文書のルート、`images`、その項目や読み取る値に関わる場合は手動対応 |
| `{{` | ファイル内のどこかに含まれる場合は`kustomize_template`で手動対応 |
| フィールド名の綴り・重複 | `Newtag`など既知のフィールド名と大小文字が異なる綴りや、大小文字だけが異なる重複キーは`kustomize_invalid`で手動対応 |
| `imageTags`・`patches`・`replacements`・`components`・`helmCharts`・`helmGlobals` | 使用するファイルは`kustomize_unsupported_feature`で手動対応 |
| `generators`・`transformers`・`vars`・`patchesStrategicMerge`・`patchesJson6902` | 使用するファイルは`kustomize_unsupported_feature`で手動対応 |
| リモートの`resources`・`bases` | `kustomize_unsupported_feature`で手動対応 |
| 別の`images`の項目による影響 | Kustomizeが`name`を正規表現として照合することを踏まえ、別の項目が対象の名前や変更前後の参照に作用する場合などは`kustomize_image_chained`で手動対応 |
| 正規表現として不正な`name` | 対象以外も含む`images`の項目を検査し、`kustomize_invalid`で手動対応 |
| Fluxの`$imagepolicy` | `newTag`の行に印がある場合は`kustomize_image_automation`で手動対応 |
| `.argocd-source-*.yaml` | 同じディレクトリにArgo CD Image Updaterの書き戻しファイルがある場合は`image_updater_file`で手動対応 |

ファイルが見つからない場合は`manifest_file_not_found`、編集できる種類のファイルでない場合は`manifest_file_unusable`を使います。
ファイルから得る参照が宣言または稼働中の参照と異なる場合は`source_mismatch`になります。

集合全体の確認条件と通常のinit containerの扱いは[KustomizeのPR](remediation-logic.md#kustomize-prs)を参照してください。

### Helmのvaluesの形式 {#helm-values-formats}

[設定例](remediation-setup.md#helm-values-pull-requests)の`helm_values.key`で指定したイメージのタグ部分だけを編集します。
registryを含むリポジトリとタグが、宣言したイメージと稼働中のイメージの両方に一致することが必要です。

| 入力 | 対応範囲 |
| --- | --- |
| ファイル | `.yaml`・`.yml`のvaluesファイルで、重複キーのない1つのYAML文書に対応 |
| mapping形式 | `repository`と文字列の`tag`を持つmappingに対応し、`registry`は任意 |
| 文字列形式 | `"repo:tag"`形式のイメージ参照に対応 |
| 対象の選択 | `helm_values.key`の経路で選び、値がない場合は`helm_key_missing`で手動対応 |
| 編集内容 | タグ部分だけを書き換え、既存の引用符とコメントを保つ |
| 新しいタグの引用符 | mapping形式の元のタグが引用符なしで、新しいタグが`1.10`・`on`などHelmで文字列にならない値の場合は、二重引用符で囲み、PR本文に記載 |
| タグの未設定・空文字列 | チャートの既定値を使うため、`helm_tag_from_chart`で手動対応 |
| 数値・真偽値・null・明示的なYAMLタグ付きの値 | `helm_not_string`で手動対応し、引用符なしの既存タグがHelmで文字列にならない場合も対象 |
| ブロックスカラー・`$`を含む値 | 読み取る値に含まれる場合は`helm_block_scalar`・`helm_variable`で手動対応 |
| digest | mappingの非空の`digest`や文字列形式のdigestは`helm_digest`で手動対応 |
| `repository`の形式 | タグやdigestを含む場合は`helm_values_shape`で手動対応 |
| `repository`と同じmapping内の`name`・`image` | 存在する場合は`helm_values_shape`で手動対応 |
| YAMLのアンカー・エイリアス | 対象キーまでの経路や読み取る値に関わる場合は`helm_anchor_or_alias`で手動対応 |
| キー側のアンカー・エイリアス | 経路上のmappingや対象のmappingのキーにアンカーがある場合は`helm_invalid`、ファイル内のどこかのキーがエイリアスの場合は`helm_anchor_or_alias`で手動対応 |
| マージキー | 文書のルート、対象キーまでの経路、対象のmappingにある場合は`helm_merge_key`で手動対応 |
| Helmで文字列にならない引用符なしのキー・同じキーに解釈される組 | 経路上のmappingや対象のmappingにある場合は`helm_invalid`で手動対応し、`"true"`と`on`の組なども対象 |
| 複数文書・重複キー・不正なYAML | `helm_invalid`で手動対応し、重複キーはファイル全体を検査 |
| `{{` | ファイル内のどこかに含まれる場合は`helm_template`で手動対応 |
| Fluxの`$imagepolicy` | `repository`・`registry`・`tag`または文字列形式のイメージの行に印がある場合は`helm_image_automation`で手動対応 |
| `.argocd-source-*.yaml` | 同じディレクトリにArgo CD Image Updaterの書き戻しファイルがある場合は`image_updater_file`で手動対応 |

ファイルが見つからない場合は`manifest_file_not_found`、編集できる種類のファイルでない場合は`manifest_file_unusable`を使います。
ファイルから得る参照が宣言または稼働中の参照と異なる場合は`source_mismatch`になります。

集合全体の確認条件、通常のinit containerの扱い、最終的な値についての前提は[HelmのvaluesのPR](remediation-logic.md#helm-values-prs)を参照してください。
### Dockerfileの形式 {#dockerfile-formats}

| 入力 | 対応範囲 |
| --- | --- |
| `FROM`の固定タグ | 変数やdigestを使わず、タグの位置を特定できる参照を編集可能 |
| `FROM`の浮動タグ | ベースの確認対象となるが、タグ更新PRの対象外 |
| ビルド`target` | ステージ名を指定可能で、省略時は最後のステージが対象 |
| 前のステージの継承 | 外部のベースイメージまでたどれる構成に対応 |
| `--platform` | 外部ベースを指定する`FROM`の静的な指定に対応し、継承途中の`FROM`での指定は未対応 |
| `FROM`内の変数・`scratch`・digest参照 | 自動編集では未対応 |
| 標準以外の構文フロントエンド・`escape`ディレクティブ | 自動編集では未対応 |
| 継承元ステージやベースイメージの`ONBUILD` | 自動更新では未対応 |
| Composeのbuild context | リポジトリ内の静的なパスに対応 |
| Composeの`dockerfile`・`target` | 対応する静的な指定からDockerfileの編集先を特定可能 |
| リモートbuild context・`dockerfile_inline`・`additional_contexts` | Composeからの編集先の特定では未対応 |

編集先の決め方と対応付けの照合は[ベースイメージの特定](remediation-logic.md#base-image-selection)を参照してください。

### npmの依存ファイル {#npm-inputs}

| 入力 | 対応範囲 |
| --- | --- |
| 必須ファイル | 単一プロジェクトの`package.json`と`package-lock.json` |
| lockfile形式 | `lockfileVersion`が2または3で、`packages`にルートの記録がある形式 |
| 取得元 | 公開npmレジストリの配布物 |
| workspace | 未対応 |
| Git・URL・ローカル参照・別名でのインストール | 対象パッケージの自動更新では未対応 |
| 同梱依存・独自のshrinkwrap | 対象パッケージの自動更新では未対応 |
| `overrides`による版の固定 | 該当するパッケージは手動対応 |
| `.npmrc`の非公開レジストリ指定 | 未対応 |
| 依存元からの再解決 | 通常更新で修正版に届かず、依存元が古い版を要求していると確認できる推移的依存に限定 |

#### 再解決の対応範囲と上限 {#dependent-reresolution-limits}

依存元の版指定が修正版への更新を妨げる推移的依存に使います。
次の例では、最小の修正版をnpm・pnpmでは`1.2.8`、uvでは`2.0.0`と仮定します。

| 依存元の指定の例 | 使われるか | 補足 |
| --- | --- | --- |
| npm・pnpmの`0.0.8` | 使われる | 修正前の版への完全一致 |
| npm・pnpmの`<1.0` | 使われる | 上限が修正版に届かない |
| uvの`==1.2.3`・`<1.0` | 使われる | 完全一致または上限により修正版に届かない |
| uvの`~=1.4` | 使われる | 1.4以上2.0未満の指定で、修正版が2.0以上の場合 |
| npm・pnpmの`^1.2.0` | 使われない | 指定範囲内で修正版を選べる |
| npm・pnpmの`\|\|`を含む範囲・`latest`などのタグ | 使われない | 再解決を始める根拠にしない |
| uvの`!=1.2.3`・`===1.2.3`・`==1.2.*` | 使われない | 除外指定・厳密一致・ワイルドカードは再解決を始める根拠にしない |

次の場合は対象外です。

- 直したいパッケージをプロジェクト自身が直接依存として宣言している
- 対象や必要な依存元が別名・ローカル・Git・URL参照、または`overrides`で固定されている
- 同じ依存先への宣言が食い違い、版指定を一つに決められない
- pipを使っている、またはpnpmが9・10・11・12.10.0以上の12.xのいずれでもない

| 上限の対象 | 上限と対処 |
| --- | --- |
| 再解決の起点となる直接依存 | 5パッケージまで、超える場合は`dependents_update_limit`で手動対応 |
| 更新対象以外に追加・変更・削除するパッケージ | 合計64まで、超える結果は`chain_move_limit`で不合格 |
| 1項目の処理量 | 実行回数・通信量・作業時間などに上限があり、保留を繰り返すと`dependents_update_limit`で手動対応 |

#### 再解決の検査条件 {#dependent-reresolution-rules}

次の変化がある結果は採用しません。
Webhookでは、パッケージごとの`packages[].reason`と、詳しい理由を示す`update.chain.reason`を併せて確認します。

| 変化の例 | 記録される理由コード |
| --- | --- |
| どこかの経路で版が下がる、または更新前後の版を対応付けられない | `chain_downgrade` |
| 通常更新の対象でも再解決の起点でもない直接依存の版や参照先が変わる | `unexplained_dependency_diff` |
| 更新対象以外に動くパッケージが上限を超える | `chain_move_limit` |
| 直したい脆弱性が更新後のスキャンでも検出される | `source_target_still_detected` |
| 脆弱な新しいパッケージが入る | `source_introduced_findings` |
| 脆弱なパッケージを使う依存元が増える | `source_introduced_findings` |
| 新しい版に、対応する旧版にはない脆弱性がある | `source_introduced_findings` |
| 1つの版が複数の脆弱な版に分かれる、または複数の経路が合流して脆弱なパッケージの旧版を一つに決められない | `source_introduced_findings` |
| KEV掲載の脆弱性が新たに入る、または上記の増加・分岐・合流などにKEV掲載の脆弱性が関わる | `source_introduced_kev` |

依存関係上の同じ位置で版だけが変わり、旧版にもある脆弱性が増えずに残る場合は、持ち越しとして認めることがあります。
例は[脆弱性の持ち越し](remediation-logic.md#dependent-reresolution-carried-findings)を参照してください。

この検査には次の限界があります。

- スキャンで検出されない脆弱性や、深刻度設定の範囲外の脆弱性は確認できない
- 持ち越した脆弱性は直らず、今回直したい脆弱性を持ち越して合格にはできない
- プロジェクトから脆弱なパッケージまでの経路の総数は比較しない

#### 公開後の待機と再試行 {#dependent-reresolution-waits}

新たに入る版は公開から72時間待ちます。
元のlockfileに同じパッケージの同じ版がある場合は待機の対象外で、公開日時を確認できない版は採用しません。

- 公開後の待機による再試行時刻はWebhookの`retry_after`で確認する
- 公開後の待機、または同じ種類の処理上限で3回連続して保留になると、同じ入力での再解決を停止する
- 再試行時刻より前に処理を見送る回は、3回に含めない
- 停止後も検査に合格する通常更新の結果は採用し、残る対象は次の理由コードで手動対応にする

| 停止の原因 | 残る対象の理由コード |
| --- | --- |
| 公開後の待機が3回連続する | `dependents_update_rejected` |
| 同じ種類の処理上限による保留が3回連続する | `dependents_update_limit` |

### pnpmの依存ファイル {#pnpm-inputs}

| 入力 | 対応範囲 |
| --- | --- |
| 必須ファイル | `package.json`と`pnpm-lock.yaml` |
| lockfile形式 | `lockfileVersion: '9.0'`で、importerが`.`だけの形式 |
| manifestとの整合 | 直接依存の宣言とimporterが一致する構成 |
| workspace・catalog・パッチ適用済み依存 | 未対応 |
| 公開npmレジストリ以外の取得元 | 対象パッケージの自動更新では未対応 |
| runtimeの自動取得を記録したlockfile | 未対応 |
| `resolutions`・`configDependencies`・`executionEnv`など | 解決方法や追加取得を変える未対応設定 |
| pnpm 12 | 12.10.0以上に対応。12.10.0より前の12.xは手動対応 |
| 依存元からの再解決 | 通常更新で修正版に届かず、依存元が古い版を要求していると確認できる推移的依存に限定 |

同じディレクトリの`pnpm-workspace.yaml`は、次の設定だけを持つ場合に読み取れます。
ファイルがあるだけでworkspaceとは判断しません。

| 設定 | 対応する形式 |
| --- | --- |
| `allowBuilds` | パッケージの指定をキーとし、真偽値または文字列を値とする対応表 |
| `onlyBuiltDependencies`・`ignoredBuiltDependencies`・`neverBuiltDependencies` | パッケージ名の文字列リスト |
| `supportedArchitectures` | `os`・`cpu`・`libc`ごとの文字列リスト |
| `packages` | workspace宣言として扱うため未対応 |
| 上記以外のキー | 未対応 |
| 依存ディレクトリより上にある`pnpm-workspace.yaml` | リポジトリのルートまで確認し、存在する場合は手動対応 |

`package.json`の`pnpm`設定も、上表のビルド許可とアーキテクチャの設定が対象です。
読み取れるビルド許可設定があっても、更新時のスクリプト実行は無効です。

### pipの依存ファイル {#pip-inputs}

| 入力 | 対応範囲 |
| --- | --- |
| 必須ファイル | UTF-8の`requirements.txt` |
| 厳密な固定版 | `name==1.2.3`形式を更新可能 |
| 範囲指定・版指定なし | 修正版を許す場合は再ビルドの見込みを示し、固定版への書き換えは行わない |
| extras | `name[extra]`形式を読み取り可能 |
| コメント・継続行 | 読み取り可能 |
| 既存の`--hash` | 固定版の更新時に、PyPIのwheel情報から更新 |
| 環境マーカー | 自動評価せず、対象パッケージを手動対応にする |
| `-r`・`-c`などの別ファイル参照 | 未対応 |
| 取得元を変更するオプション | 未対応 |
| Git・URL・ローカル参照 | 対象パッケージの自動更新では未対応 |
| ソース配布物しかない版 | 自動更新では未対応 |

稼働イメージに合わせた検証対象の条件は[pipの検証環境](remediation-logic.md#pip-target-environment)を参照してください。

### uvの依存ファイル {#uv-inputs}

| 入力 | 対応範囲 |
| --- | --- |
| 必須ファイル | 単一プロジェクトの静的な`pyproject.toml`と`uv.lock` |
| lockfile形式 | `version = 1`・`revision = 5` |
| プロジェクト | `[project]`があり、動的なメタデータを要求しない構成 |
| Pythonの要件 | 自動更新には`[project]`の`requires-python`が必要 |
| 取得元 | 公開PyPI |
| workspace | 未対応 |
| Git・URL・ローカル参照 | 対象パッケージの自動更新では未対応 |
| ソースのビルドが必要な依存 | 自動更新では未対応 |
| `[tool.uv]` | `required-version`・`dev-dependencies`・`sources`・`package`を読み取り可能 |
| 上記以外の`[tool.uv]`設定 | 未対応 |
| `uv.toml` | 依存ディレクトリからリポジトリのルートまでのいずれかに存在する場合は未対応 |
| 依存元からの再解決 | 依存元が古い版を要求していると確認できる推移的依存に限定し、最初の更新結果が依存の差分検査で拒否された場合の再判定も含む |

`[tool.uv]`のキーを読み取れる場合も、依存の取得元やプロジェクト構成が対応範囲内である必要があります。

### Node.jsの版宣言 {#node-declarations}

| 宣言 | 対応する形式 |
| --- | --- |
| `.nvmrc`・`.node-version` | 最初の空でない行にある`22`・`22.14`・`22.14.0`などの数値指定で、先頭の`v`も使用可能 |
| `.nvmrc`のLTS指定 | `lts/*`と、認識できるLTS系列名 |
| `package.json`の`engines.node` | 正確な版、比較演算子、`^`・`~`、ワイルドカードなどの解釈可能な範囲 |
| `devEngines.runtime`・`engines.runtime` | Node.jsを指定するオブジェクトまたは配列と、その版の範囲 |
| `system`・`current`などの指定 | 実行する系列を特定できないため未対応 |
| プレリリースを境界に含む範囲 | 未対応 |
| runtime宣言の`onFail: download` | 未対応 |

版ファイルはmajor系列の選択に使い、実際のminor・patch版は同梱の表に従います。
宣言の組み合わせ方は[Node.jsの選定](remediation-logic.md#node-selection)を参照してください。

### Pythonの版宣言 {#python-declarations}

| 宣言 | 対応する形式 |
| --- | --- |
| uvの`requires-python` | `>=3.12,<3.15`などの解釈可能なPython版の条件 |
| `.python-version` | 最初の空でない行にある`3.13`・`3.13.5`などの指定 |
| CPythonの接頭辞 | `cpython-3.13`・`cpython@3.13`など |
| `.python-versions` | 複数版の指定は未対応 |
| PyPy・GraalPy・Pyodide・`system` | 未対応 |
| free-threaded版 | 未対応 |

`.python-version`はPython X.Y系列の選択に使い、記載したpatch版と実行版の違いは許容します。
宣言の整合条件は[uv用Pythonの選定](remediation-logic.md#uv-python-selection)を参照してください。

### ツールの版宣言 {#tool-declarations}

| 宣言 | 対応する形式 |
| --- | --- |
| `packageManager` | `npm@11.21.0`・`pnpm@11.28.5`などのマネージャー名と正確な版 |
| `packageManager`のハッシュ | `name@version+<algorithm>.<hex>`形式 |
| ハッシュのアルゴリズム | `sha1`・`sha224`・`sha256`・`sha384`・`sha512` |
| `devEngines.packageManager` | マネージャー名と、正確な版または解釈可能な範囲 |
| `engines.npm`・`engines.pnpm` | 正確な版または解釈可能な範囲 |
| `tool.uv.required-version` | `==0.13.0`などの正確な版、または解釈可能な範囲 |
| プレリリース・ビルドメタデータ付きのツール版 | 未対応 |

| ツール | 扱える版 | 既定の版 |
| --- | --- | --- |
| npm | 9〜12系列で、選んだNode.jsと互換性がある版 | `11.21.0` |
| pnpm | 9〜12系列で、選んだNode.jsと互換性がある版（12系列は12.10.0以上） | `11.28.5` |
| uv | `0.12.22`以上の対応する安定版 | `0.13.0` |
| pip | 作業用の公式Pythonイメージに含まれる版 | Python 3.13の作業用イメージでは`26.2.1` |

宣言版と既定版の選び方は[ツール版の選定](remediation-logic.md#tool-version-selection)、公開後の利用条件は[ツール公開後の待機](remediation-logic.md#tool-release-age)を参照してください。

## 対応する実行環境 {#supported-runtimes}

対応する実行環境は、同梱の表にあるサポート中の系列(現時点で Node.js 22・24・26、Python 3.11〜3.15)です。
次の版と期限はKestreLynxが持つ情報であり、KestreLynxの更新に伴って変わります。

| 系列 | 同梱の表の実行版 | サポート終了日 |
| --- | --- | --- |
| Node.js 22 | `22.23.3` | 2027-04-30 |
| Node.js 24 | `24.21.0` | 2028-04-30 |
| Node.js 26 | `26.11.1` | 2029-04-30 |
| Python 3.11 | `3.11.17` | 2027-10-31 |
| Python 3.12 | `3.12.15` | 2028-10-31 |
| Python 3.13 | `3.13.16` | 2029-10-31 |
| Python 3.14 | `3.14.8` | 2030-10-31 |
| Python 3.15 | `3.15.0` | 2031-10-31 |

| 用途 | 既定の実行環境 |
| --- | --- |
| Node.jsの宣言がないnpm・pnpm更新 | 現時点ではNode.js 24で、同梱の表のLTS開始日に従い2026-10-28から26が候補になる |
| pip更新の作業用コンテナ | Python 3.13 |
| uv更新 | Pythonの宣言に従って選定 |

| 同梱の表にある終了済み系列 | サポート終了日 |
| --- | --- |
| Node.js 20 | 2026-04-30 |
| Python 3.9 | 2025-10-31 |
| Python 3.10 | 2026-10-01 |

サポート期限を過ぎた系列は更新に使いません。
選定条件は[実行環境の選定](remediation-logic.md#runtime-and-tool-versions)を参照してください。

## 結果の値 {#result-values}

### 計画の分類値 {#category-values}

`category`は、イメージや依存ディレクトリなどの計画項目全体の分類です。

| 値 | 意味 |
| --- | --- |
| `pr_candidate` | 検査を通り、PRでの変更を提案できる候補 |
| `dependency_update_candidate` | ソースと修正版情報から選んだ依存更新候補で、更新結果は未検証 |
| `pull_again` | 同じタグの内容を再取得することで改善が見込める、比較済みの候補 |
| `rebuild_expected` | 依存範囲から、再ビルドで修正版が入る見込み（Slackの「再ビルド」には、分類が`not_comparable`の浮動タグのベースの案内も表示される） |
| `manual` | 自動では進めず、利用者の判断や手動対応が必要 |
| `not_comparable` | 比較に必要な情報や条件がそろわない |
| `deferred` | 上限、待機、取得の問題などで処理を保留 |
| `no_candidate` | 新しい候補がない、内容が同じ、または候補で対象が解消しない |
| `excluded` | 自動で候補を探す対象外 |
| `failed` | 処理に失敗 |

### パッケージの処理値 {#action-values}

`action`は個々のパッケージの扱いです。
項目全体の`category`とは別に確認してください。

| 値 | 意味 |
| --- | --- |
| `update` | 依存ファイルを更新する対象 |
| `rebuild_expected` | 現在の依存範囲が修正版を許し、再ビルドによる解消を見込む対象 |
| `manual` | 手動対応が必要な対象 |

`update`だけでは更新の実行や検証の完了を表しません。
版の読み分けは[更新目標と採用版](remediation-results.md#target-and-adopted-version)を参照してください。

### PRの状態値 {#pr-status-values}

PR処理結果の`status`には、次の値があります。

| 値 | 意味 |
| --- | --- |
| `pr_created` | 今回の処理でPRを作成した |
| `pr_open` | 同じ更新を提案するPRが開いている |
| `pr_merged` | 同じ更新のPRがマージ済みで、配置済みかは未確認 |
| `pr_suppressed` | 未マージで閉じた更新のため、再作成を抑止した |
| `manual` | 自動編集できず、手動対応が必要 |
| `deferred` | 上限や候補の変化などにより、後の処理へ延期した |
| `failed` | GitHubへの書き込みなどに失敗した |
| `write_blocked` | 記録やGitHub上の状態などの問題により、書き込みを停止した |
| `write_disabled` | PR作成が無効であることを表す値で、通常のPR処理では生成しない |

PR記録の`state`には、次の値があります。

| 値 | 意味 |
| --- | --- |
| `open` | オープン中 |
| `closed` | 未マージでクローズ済み |
| `merged` | マージ済み |
| `replaced` | 新しいPRに置き換えるため、KestreLynxがクローズ済み |

## 理由コード {#reason-codes}

結果の`reason`には、候補を選んだ理由や処理を進められなかった理由が入ります。
コードの意味と、関連する判定・確認操作を次に示します。

### イメージ候補の理由 {#image-reasons}

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `scan_failed` | スキャンに失敗した | [比較条件](remediation-logic.md#comparison-conditions) |
| `entity_unverified` | 稼働イメージを確認できない、またはレジストリの内容と比較できない | [比較条件](remediation-logic.md#comparison-conditions) |
| `conditions_unknown` | スキャンの条件が分からない | [比較条件](remediation-logic.md#comparison-conditions) |
| `conditions_differ` | スキャンの条件がそろっていない | [比較条件](remediation-logic.md#comparison-conditions) |
| `platform_unknown` | イメージのプラットフォームが分からない | [比較条件](remediation-logic.md#comparison-conditions) |
| `platform_differ` | 比較するイメージのプラットフォームが異なる | [比較条件](remediation-logic.md#comparison-conditions) |
| `variant_unsupported` | 対応していない種類のイメージである | [比較条件](remediation-logic.md#comparison-conditions) |
| `packages_missing` | スキャン結果にパッケージ一覧がない | [比較条件](remediation-logic.md#comparison-conditions) |
| `packages_truncated` | スキャン結果のパッケージ一覧が途中で切れている | [比較条件](remediation-logic.md#comparison-conditions) |
| `unknown_package_type` | 対応していない種類のパッケージの所見がある | [比較条件](remediation-logic.md#comparison-conditions) |
| `type_not_analysed` | 候補のスキャンが対象の種類のパッケージを解析していない | [比較条件](remediation-logic.md#comparison-conditions) |
| `no_newer_tag` | より新しいタグがない | [配布イメージのタグ](remediation-logic.md#published-image-tags) |
| `same_content` | 新しいタグも内容が同じである | [配布イメージのタグ](remediation-logic.md#published-image-tags) |
| `candidate_does_not_resolve_targets` | 候補では対象の所見が解消しない | [比較条件](remediation-logic.md#comparison-conditions) |
| `auth_required` | レジストリへのログインが必要である | [非公開イメージの認証](remediation-setup.md#configure-registry-auth) |
| `platform_not_found` | 候補に同じプラットフォームのイメージがない | [比較条件](remediation-logic.md#comparison-conditions) |
| `platform_ambiguous` | 候補にプラットフォームが合うイメージが複数ある | [比較条件](remediation-logic.md#comparison-conditions) |
| `platform_mismatch` | 候補のプラットフォームが稼働イメージと異なる | [比較条件](remediation-logic.md#comparison-conditions) |
| `registry_error` | レジストリがエラーを返した | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `targets_not_detected_on_baseline` | 比較元のスキャンで対象の所見が検出されなかった | [比較条件](remediation-logic.md#comparison-conditions) |
| `analysis_incomplete` | イメージの解析が不完全だった | [比較条件](remediation-logic.md#comparison-conditions) |
| `tag_listing_incomplete` | タグ一覧を最後まで取得できなかった | [タグ一覧の探索](remediation-logic.md#tag-discovery) |
| `candidate_scan_limit` | 1回の実行でスキャンできる候補数の上限に達した | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `baseline_rescan_limit` | 比較元イメージを再スキャンできる数の上限に達した | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `tag_page_limit` | タグ一覧の取得回数の上限に達した | [タグ一覧の探索](remediation-logic.md#tag-discovery) |
| `registry_budget_exhausted` | レジストリへの要求数の上限に達した | [タグ一覧の探索](remediation-logic.md#tag-discovery) |
| `rate_limited` | レジストリのレート制限に掛かった | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `cycle_deadline` | 実行時間の上限に達した | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `registry_timeout` | レジストリへの要求がタイムアウトした | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `locally_built` | ホストでビルドしたイメージのため、配布イメージの検索対象外である | [ローカルビルドの除外](remediation-logic.md#local-builds) |
| `partial_improvement` | 候補では一部の所見だけが解消する | [比較条件](remediation-logic.md#comparison-conditions) |
| `introduced_findings` | 候補で新たな所見が入る | [比較条件](remediation-logic.md#comparison-conditions) |
| `introduced_kev` | 候補でKEV掲載の脆弱性が新たに入る | [比較条件](remediation-logic.md#comparison-conditions) |
| `adopted` | 候補を採用した | [比較条件](remediation-logic.md#comparison-conditions) |
| `declared_ref_mismatch` | 同じ稼働イメージ参照を使うコンテナのいずれかで、Podのspecのイメージ参照と稼働中の参照が一致しないため`not_comparable`になる | [Kubernetesのイメージ参照と再取得](remediation-logic.md#kubernetes-image-references) |
| `declared_ref_unavailable` | 同じ稼働イメージ参照を使うコンテナのいずれかで、Podのspecのイメージ参照を読み取れないため`not_comparable`になる | [Kubernetesのイメージ参照と再取得](remediation-logic.md#kubernetes-image-references) |
| `digest_only` | タグがなくdigestだけで指定されている | [配布イメージのタグ](remediation-logic.md#published-image-tags) |
| `tag_and_digest` | タグとdigestの両方で指定されている | [配布イメージのタグ](remediation-logic.md#published-image-tags) |
| `prerelease` | タグがプレリリース版の形式である | [配布イメージのタグ](remediation-logic.md#published-image-tags) |
| `bare_digest` | digestだけの参照で、リポジトリが分からない | [配布イメージのタグ](remediation-logic.md#published-image-tags) |
| `unparsable` | イメージ参照を解釈できない | [配布イメージのタグ](remediation-logic.md#published-image-tags) |
| `unsupported_tag_format` | 対応していない形式のタグである | [配布イメージのタグ](remediation-logic.md#published-image-tags) |
| `base_layers_mismatch` | タグが指すベースのレイヤーが、稼働イメージの先頭部分と一致しない | [ベースレイヤーの照合](remediation-logic.md#base-layer-matching) |
| `base_layers_unusable` | 稼働イメージとベースイメージのレイヤーを比較できない | [ベースレイヤーの照合](remediation-logic.md#base-layer-matching) |
| `base_onbuild` | ベースイメージに`ONBUILD`トリガーがある | [ベースイメージの特定](remediation-logic.md#base-image-selection) |
| `no_base_derived_findings` | 修正可能な所見が、ベースイメージのレイヤーにない | [ベースレイヤーの照合](remediation-logic.md#base-layer-matching) |
| `base_unchanged` | タグが指す現在のベースのレイヤーが稼働イメージの先頭と一致し、ベースの更新を確認できない | [ベースレイヤーの照合](remediation-logic.md#base-layer-matching) |
| `floating_base_unconfirmed` | 稼働イメージの作成元のベースを確認できない | [ベースレイヤーの照合](remediation-logic.md#base-layer-matching) |
| `dockerfile_set_not_adopted` | 同じDockerfileを使うWorkloadのすべてで、同じ候補を採用できなかった（個々のWorkloadの理由も確認する） | [ベースイメージの特定](remediation-logic.md#base-image-selection) |
| `compose_set_not_adopted` | 同じイメージを使うサービスのすべてで、同じ候補を採用できなかった（個々のサービスの理由も確認する） | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `instances_missing` | 対応付けたコンテナの稼働インスタンスがない、稼働中の参照を取得できない、または更新対象に計画の項目がないインスタンスがある | [KubernetesのマニフェストPR](remediation-logic.md#kubernetes-manifest-prs) |
| `mixed_references` | 稼働インスタンスの間で、宣言または稼働中の参照が一致しない | [KubernetesのマニフェストPR](remediation-logic.md#kubernetes-manifest-prs) |
| `kubernetes_set_not_adopted` | 同じファイルで同じイメージを更新するコンテナの間で、採用した候補が一致しない | [KubernetesのマニフェストPR](remediation-logic.md#kubernetes-manifest-prs) |

### ソースの理由 {#source-reasons}

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `dockerfile_file_not_found` | 設定したパスにDockerfileがない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `dockerfile_file_unusable` | Dockerfileが編集できる種類のファイルではない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `dockerfile_invalid` | Dockerfileを解釈できない、または編集の検証に失敗した | |
| `dockerfile_target_missing` | 指定したビルドステージがない | [ベースイメージの特定](remediation-logic.md#base-image-selection) |
| `dockerfile_stage_cycle` | ステージの参照をたどっても外部イメージに行き着かない | [ベースイメージの特定](remediation-logic.md#base-image-selection) |
| `dockerfile_variable` | ベースイメージまたはプラットフォームに変数が含まれる | |
| `dockerfile_scratch` | ベースが`scratch`である | |
| `dockerfile_digest` | ベースがdigestで指定されている | |
| `dockerfile_tag_unsupported` | ベースのタグが候補を探せない形式である | [配布イメージのタグ](remediation-logic.md#published-image-tags) |
| `dockerfile_frontend` | 標準以外の構文フロントエンドを指定している | |
| `dockerfile_escape` | `escape`ディレクティブを設定している | |
| `dockerfile_ambiguous_range` | ファイル内でタグの位置を正確に特定できない | |
| `dockerfile_onbuild` | 継承元のステージに`ONBUILD`がある | |
| `dockerfile_stage_platform` | 継承途中の`FROM`に`--platform`がある | |
| `dockerfile_not_editable` | ベースが固定タグではない | [ベースイメージの特定](remediation-logic.md#base-image-selection) |
| `dockerfile_source_mismatch` | ファイルのベースイメージが想定と異なる | [ベースイメージの特定](remediation-logic.md#base-image-selection) |
| `dockerfile_mapping_differs` | 設定したDockerfileとComposeが指すDockerfileが一致しない | [ベースイメージの特定](remediation-logic.md#base-image-selection) |
| `compose_no_build` | 対象サービスに`build`の指定がない | [ベースイメージの特定](remediation-logic.md#base-image-selection) |
| `compose_build_remote_context` | build contextがURLまたはリポジトリである | |
| `compose_build_inline` | `dockerfile_inline`を使っている | |
| `compose_build_additional` | `additional_contexts`を使っている | |
| `compose_build_path` | ビルドのパスが絶対パス、リポジトリ外、または不正な形式である | |
| `compose_build_unsupported_form` | `build`の書き方に対応していない | |
| `compose_build_undetermined` | サービスのビルド方法を判断できない | [ローカルビルドの除外](remediation-logic.md#local-builds) |
| `compose_invalid` | Composeファイルを解釈できない、または編集の検証に失敗した | |
| `compose_service_missing` | Composeファイルに対象サービスまたは`image`キーがない | |
| `compose_build` | サービスがイメージをビルドしている | [ローカルビルドの除外](remediation-logic.md#local-builds) |
| `compose_include_or_extends` | Composeファイルが`include`または`extends`を使っている | |
| `compose_merge_key` | `image`への経路にマージキーがある | |
| `compose_anchor_or_alias` | `image`がYAMLのアンカーまたはエイリアスに関わっている | |
| `compose_not_string` | `image`の値が単純な文字列ではない | |
| `compose_block_scalar` | `image`の値がブロックスカラーである | |
| `compose_variable` | `image`の値に変数が含まれる | |
| `compose_digest` | `image`の値にdigestが付いている | |
| `compose_source_mismatch` | ファイルの`image`が稼働イメージと異なる | [ソースの確認](remediation-logic.md#source-verification) |
| `compose_file_not_found` | 設定したパスにComposeファイルがない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `compose_file_unusable` | Composeファイルが編集できる種類のファイルではない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `manifest_file_not_found` | 設定したパスにマニフェストがない | [マニフェストの形式](#manifest-formats) |
| `manifest_file_unusable` | マニフェストが編集できる形のファイルではない | [マニフェストの形式](#manifest-formats) |
| `manifest_invalid` | マニフェストを解釈できない、キーが重複している、または編集の検証に失敗した | [マニフェストの形式](#manifest-formats) |
| `manifest_anchor_or_alias` | コンテナへの経路または文書の識別情報がYAMLのアンカー・エイリアスに関わっている | [マニフェストの形式](#manifest-formats) |
| `manifest_merge_key` | コンテナへの経路または文書の識別情報にマージキーがある | [マニフェストの形式](#manifest-formats) |
| `manifest_not_string` | `image`の値が単純な文字列ではない | [マニフェストの形式](#manifest-formats) |
| `manifest_block_scalar` | `image`の値がブロックスカラーである | [マニフェストの形式](#manifest-formats) |
| `manifest_variable` | `image`の値に変数が含まれる | [マニフェストの形式](#manifest-formats) |
| `manifest_digest` | `image`の値にdigestが付いている | [マニフェストの形式](#manifest-formats) |
| `manifest_tag_missing` | `image`の値にタグがない | [マニフェストの形式](#manifest-formats) |
| `manifest_image_automation` | `image`の行にFlux image automationの印がある | [マニフェストの形式](#manifest-formats) |
| `manifest_template` | マニフェストにテンプレートの式がある | [マニフェストの形式](#manifest-formats) |
| `image_updater_file` | 同じディレクトリにArgo CD Image Updaterの書き戻しファイルがある | [マニフェストの形式](#manifest-formats) |
| `source_object_missing` | マニフェストにワークロードのオブジェクトの文書がない | [マニフェストの形式](#manifest-formats) |
| `source_object_ambiguous` | マニフェストにワークロードのオブジェクトの文書が複数ある | [マニフェストの形式](#manifest-formats) |
| `source_container_missing` | オブジェクトに、その名前の編集できるコンテナがない | [マニフェストの形式](#manifest-formats) |
| `source_mismatch` | ファイルから得るイメージ参照が宣言または稼働中のイメージと異なる | [KubernetesのマニフェストPR](remediation-logic.md#kubernetes-manifest-prs)・[HelmのvaluesのPR](remediation-logic.md#helm-values-prs) |
| `mapping_conflict` | ファイルの2つ以上の対応付けが、同じ文書の同じコンテナを指している | [KubernetesのマニフェストPR](remediation-logic.md#kubernetes-manifest-prs) |
| `kustomize_invalid` | kustomizationが1つの正しいYAML文書でない、キーが重複している、または編集後の検査に通らない | [Kustomizeの形式](#kustomize-formats) |
| `kustomize_image_missing` | kustomizationに対応付けた名前の`images`の項目がない | [Kustomizeの形式](#kustomize-formats) |
| `kustomize_image_ambiguous` | 対応付けた名前の`images`の項目が複数ある | [Kustomizeの形式](#kustomize-formats) |
| `kustomize_tag_not_set` | `images`の項目に`newTag`がない、または空である | [Kustomizeの形式](#kustomize-formats) |
| `kustomize_unsupported_feature` | kustomizationが、`images`の項目の作用先を変えうる機能を使っている | [Kustomizeの形式](#kustomize-formats) |
| `kustomize_image_chained` | 別の`images`の項目が、この項目の名前または結果に作用する | [Kustomizeの形式](#kustomize-formats) |
| `kustomize_digest` | `images`の項目がdigestを固定している | [Kustomizeの形式](#kustomize-formats) |
| `kustomize_anchor_or_alias` | `images`の項目に関わるアンカーまたはエイリアスがある | [Kustomizeの形式](#kustomize-formats) |
| `kustomize_merge_key` | `images`の項目に関わるマージキーがある | [Kustomizeの形式](#kustomize-formats) |
| `kustomize_not_string` | `images`の項目の値が単純な文字列ではない | [Kustomizeの形式](#kustomize-formats) |
| `kustomize_block_scalar` | `images`の項目の値がブロックスカラーである | [Kustomizeの形式](#kustomize-formats) |
| `kustomize_variable` | `images`の項目の値に変数がある | [Kustomizeの形式](#kustomize-formats) |
| `kustomize_template` | kustomizationにテンプレートの式がある | [Kustomizeの形式](#kustomize-formats) |
| `kustomize_image_automation` | `newTag`の行にFlux image automationの印がある | [Kustomizeの形式](#kustomize-formats) |
| `helm_invalid` | valuesファイルが1つの正しいYAML文書でない、キーが重複している、または編集後の検査に通らない | [Helmのvaluesの形式](#helm-values-formats) |
| `helm_key_missing` | valuesファイルに対応付けたキーの値がない | [Helmのvaluesの形式](#helm-values-formats) |
| `helm_tag_from_chart` | キーにタグがなく、チャート自身の既定値が使われる | [Helmのvaluesの形式](#helm-values-formats) |
| `helm_digest` | キーのイメージがdigestで固定されている | [Helmのvaluesの形式](#helm-values-formats) |
| `helm_values_shape` | キーが`repository`と`tag`の組でも`repository:tag`の文字列でもない | [Helmのvaluesの形式](#helm-values-formats) |
| `helm_not_string` | キーの値が文字列でない（数値など） | [Helmのvaluesの形式](#helm-values-formats) |
| `helm_block_scalar` | キーの値がブロックスカラー | [Helmのvaluesの形式](#helm-values-formats) |
| `helm_variable` | キーの値に変数がある | [Helmのvaluesの形式](#helm-values-formats) |
| `helm_template` | valuesファイルにテンプレートの式がある | [Helmのvaluesの形式](#helm-values-formats) |
| `helm_anchor_or_alias` | キーまでの経路のノードにアンカーまたはエイリアスがある | [Helmのvaluesの形式](#helm-values-formats) |
| `helm_merge_key` | キーまでの経路のマッピングにマージキーがある | [Helmのvaluesの形式](#helm-values-formats) |
| `helm_image_automation` | イメージの行にFlux image automationの目印がある | [Helmのvaluesの形式](#helm-values-formats) |
| `undeclared_affected_workload` | 列挙されていないコンテナがKustomizeの`images`の項目またはHelmのvaluesのキーと同じイメージ参照を宣言しており、編集の影響を受けうる | [KustomizeのPR](remediation-logic.md#kustomize-prs)・[HelmのvaluesのPR](remediation-logic.md#helm-values-prs) |
| `init_container_unverified` | 列挙したinit containerが、稼働コンテナと同じイメージを動かしたことを確認できない | [KustomizeのPR](remediation-logic.md#kustomize-prs) |
| `dependency_files_not_found` | 依存ファイルが見つからない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `ambiguous_dependency_files` | 依存ファイルの組み合わせが複数あり、一意に決められない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `dependency_file_unusable` | 依存ファイルを利用できない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `unsupported_lockfile` | lockfileの形式に対応していない | |
| `workspace_unsupported` | プロジェクトのworkspace構成に対応していない | |
| `workspace_settings_unsupported` | workspace設定ファイルの内容に対応していない | |
| `dynamic_metadata` | プロジェクトのメタデータが動的に決まる | |
| `unsupported_requirements` | requirementsの書き方に対応していない | |
| `unparsable_source` | 依存ファイルを解析できない | |
| `unsupported_source_settings` | 対応していないパッケージ取得元の設定がある | |
| `scan_not_pinned` | スキャン結果が特定のイメージに結び付いていない | [ソースの確認](remediation-logic.md#source-verification) |
| `not_found_in_source` | 依存ファイルに稼働版のパッケージが載っていない | [ソースの確認](remediation-logic.md#source-verification) |
| `non_registry_source` | 対応する公開レジストリ以外から取得されるパッケージである | |
| `sdist_only` | パッケージにソース配布物しかない | |
| `forced_by_override` | パッケージの版がoverrideで固定されている | |
| `marker_not_evaluated` | 依存指定の環境マーカーを評価していない | |
| `invalid_marker` | 依存指定の環境マーカーが不正である | |
| `multiple_versions` | 同名パッケージの複数の版や出現箇所を、1つの更新として扱えない | |
| `unparsable_version` | パッケージの版を解釈できない | |
| `source_not_found` | 取得元のリポジトリまたはブランチが見つからない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `source_access_denied` | 取得元のリポジトリにアクセスできない | [GitHubアクセスの準備](remediation-setup.md#prepare-github-access) |
| `source_too_large` | 取得元が大きすぎて読み込めない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `file_too_large` | 依存ファイルが大きすぎて読み込めない | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `byte_budget_exhausted` | 取得元から読み込める容量の上限に達した | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `source_error` | 取得元の読み込みに失敗した | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `github_budget_exhausted` | GitHubへの要求数の上限に達した | [計画が出ない場合](remediation-troubleshooting.md#check-missing-plan) |
| `source_read_failed` | 依存ファイルの再取得に失敗した | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |

### 実行環境の理由 {#runtime-reasons}

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `node_spec_invalid` | 宣言されたNode.jsの版を解釈できない | [Node.jsの選定](remediation-logic.md#node-selection) |
| `python_spec_invalid` | 宣言されたPythonの版を解釈できない | [uv用Pythonの選定](remediation-logic.md#uv-python-selection) |
| `manager_spec_invalid` | 宣言されたパッケージマネージャーの版を解釈できない | [ツール版の選定](remediation-logic.md#tool-version-selection) |
| `node_spec_conflict` | Node.jsの版宣言どうしが矛盾している | [Node.jsの選定](remediation-logic.md#node-selection) |
| `python_spec_conflict` | Pythonの版宣言どうしが矛盾している | [uv用Pythonの選定](remediation-logic.md#uv-python-selection) |
| `manager_spec_conflict` | パッケージマネージャーの宣言どうしが矛盾している | [ツール版の選定](remediation-logic.md#tool-version-selection) |
| `node_spec_unsupported` | 宣言されたNode.jsの版に対応していない | [Node.jsの選定](remediation-logic.md#node-selection) |
| `python_spec_unsupported` | 宣言されたPythonの版に対応していない | [uv用Pythonの選定](remediation-logic.md#uv-python-selection) |
| `manager_spec_unsupported` | 宣言されたパッケージマネージャーの版に対応していない | [ツール版の選定](remediation-logic.md#tool-version-selection) |
| `work_program_mismatch` | 作業用コンテナ内のプログラムが、実行中のKestreLynxに付属するものと異なる | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `work_environment_rejected` | 作業用コンテナがプログラムの実行要件を満たしていない | [実行時の制限](remediation-logic.md#worker-restrictions) |
| `runtime_eol` | 更新対象の実行環境がサポート終了している | [実行環境の選定](remediation-logic.md#runtime-and-tool-versions) |
| `runtime_engines_mismatch` | 更新した依存が、プロジェクトの宣言する最小Node.js版に対応していない | [Node.jsの互換条件](remediation-logic.md#node-compatibility) |
| `requires_python_unsupported` | 必要なPython版の条件を満たせない、または条件がない・解釈できない | [uv用Pythonの選定](remediation-logic.md#uv-python-selection) |
| `pip_target_undecidable` | パッケージが動く環境を判断できない | [pipの検証環境](remediation-logic.md#pip-target-environment) |
| `pip_target_mismatch` | pipの依存解決対象と、パッケージが動く環境が一致しない | [pipの検証環境](remediation-logic.md#pip-target-environment) |
| `work_image_not_configured` | 更新用の作業環境が用意されていない | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `work_namespace_not_configured` | Kubernetesでの更新に必要な作業用namespaceが設定されていないため手動対応 | [作業用Podの設定](configuration.md#remediation-worker-kubernetes) |
| `work_runtime_class_unsupported` | 作業用Podに未対応のRuntimeClassが設定されているため手動対応 | [作業用Podの設定](configuration.md#remediation-worker-kubernetes) |
| `work_cluster_too_old` | クラスタが作業用Podのポリシーに必要なKubernetes 1.30より古いため手動対応 | [導入条件](remediation-setup.md#kubernetes-language-updates) |
| `work_pod_limit` | 作業用Pod数またはnamespaceのクォータが上限で、更新を次回に持ち越す | [作業用Podの設定](configuration.md#remediation-worker-kubernetes) |
| `work_admission_unverified` | 作業用namespaceのPod作成規則が有効と確認できず、作業用Podを起動しない | [作業用Podの実行](remediation-logic.md#kubernetes-work-pods) |
| `work_priority_class_missing` | 作業用Podに設定したPriorityClassが存在しない、または必要な設定と一致しないため手動対応 | [導入手順](remediation-setup.md#kubernetes-language-updates) |
| `work_pod_not_started` | 作業用Podが時間内に起動せず、更新を次回に持ち越す | [作業用Podの確認](remediation-troubleshooting.md#check-update-failure) |
| `work_image_unavailable` | 作業用イメージを用意できなかった | [公式イメージの固定](remediation-logic.md#worker-images) |

### ツール取得の理由 {#tool-reasons}

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `tool_fetch_config_unsupported` | マネージャー自身によるツール取得や、未対応の解決設定が指定されている | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `tool_version_unsupported` | パッケージマネージャーの版に対応していない | [ツール版の選定](remediation-logic.md#tool-version-selection) |
| `tool_version_not_found` | 指定したパッケージマネージャーの版が見つからない | [ツールの取得と照合](remediation-logic.md#tool-verification) |
| `tool_hash_mismatch` | ツールの配布物がチェックサムと一致しない | [ツールの取得と照合](remediation-logic.md#tool-verification) |
| `tool_hash_unsupported` | ツールの配布物のチェックサムを検証できない | [ツールの取得と照合](remediation-logic.md#tool-verification) |
| `tool_artifact_invalid` | ツールの配布物が不正である | [ツールの取得と照合](remediation-logic.md#tool-verification) |
| `tool_metadata_invalid` | ツールのリリース情報が不正である | [ツールの取得と照合](remediation-logic.md#tool-verification) |
| `tool_too_new` | ツールの公開後待機時間を満たしたと確認できない | [ツール公開後の待機](remediation-logic.md#tool-release-age) |
| `tool_fetch_failed` | ツールの取得に失敗した | [ツールの取得と照合](remediation-logic.md#tool-verification) |
| `tool_fetch_budget` | ツールの取得回数の上限に達した | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `tool_cache_full` | ツールキャッシュに空きを確保できない | [ツールキャッシュの再利用](remediation-logic.md#tool-cache) |
| `tool_file_mismatch` | キャッシュ内のツール配布物が記録と異なる | [ツールキャッシュの再利用](remediation-logic.md#tool-cache) |

### 更新結果の理由 {#update-reasons}

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `update_candidate_in_source` | ソース内のパッケージに対応する修正版の更新候補がある | [修正版の下限](remediation-logic.md#fix-lower-bound) |
| `range_allows_fix` | 依存範囲が修正版を許し、再ビルドで入る見込みがある | [直接依存の版指定](remediation-logic.md#direct-dependencies) |
| `no_fixed_version_above_installed` | 稼働版より新しい修正版がない、または修正対象がない | [修正版の下限](remediation-logic.md#fix-lower-bound) |
| `constraint_excludes_fix` | 候補または更新後の版が依存の制約を満たさない | [直接依存の版指定](remediation-logic.md#direct-dependencies)・[推移的依存の更新範囲](remediation-logic.md#transitive-dependencies) |
| `constraint_not_evaluable` | 版の制約を評価できない、または修正版がpipで選ばれないプレリリースである | [直接依存の版指定](remediation-logic.md#direct-dependencies) |
| `packages_need_manual_update` | 自動更新できるパッケージがない | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `update_job_limit` | 1回の実行で行える更新ジョブ数の上限に達した | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `update_input_limit` | 更新に使うファイルがサイズ上限を超えている | [コンテナへの入力](remediation-logic.md#worker-inputs) |
| `update_job_failed` | 更新の実行に失敗した | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `update_result_invalid` | 更新ジョブの結果が不正である | [結果の回収](remediation-logic.md#worker-results) |
| `update_job_timed_out` | 更新の実行がタイムアウトした | [実行時の制限](remediation-logic.md#worker-restrictions) |
| `distribution_lookup_failed` | レジストリでのパッケージ照会に失敗した | [付随変更の検査](remediation-logic.md#change-validation) |
| `source_scan_failed` | 依存ファイルのスキャンに失敗した | [比較条件](remediation-logic.md#comparison-conditions) |
| `update_input_invalid` | 更新の入力が不正である | [コンテナへの入力](remediation-logic.md#worker-inputs) |
| `update_job_input_rejected` | 更新ジョブが入力を受け付けなかった | [コンテナへの入力](remediation-logic.md#worker-inputs) |
| `manifest_edit_required` | 自動更新では行えないmanifestの変更が必要である | [直接依存の版指定](remediation-logic.md#direct-dependencies) |
| `input_modified` | 読み取り専用のはずの設定ファイルが変更された | [付随変更の検査](remediation-logic.md#change-validation) |
| `lockfile_inconsistent` | lockfileがプロジェクトと整合していない | [マネージャー別の更新処理](remediation-logic.md#manager-update-methods) |
| `no_wheel_for_version` | 対象の版に必要なプラットフォーム向けのwheelがない | [マネージャー別の更新処理](remediation-logic.md#manager-update-methods) |
| `release_yanked` | 対象のリリースが取り下げられている | [付随変更の検査](remediation-logic.md#change-validation) |
| `requirements_rewrite_unsupported` | 今回の更新方法ではrequirementsを書き換えられない | [マネージャー別の更新処理](remediation-logic.md#manager-update-methods) |
| `update_set_not_applied` | 同時に更新する別のパッケージを更新できなかった | [部分PRの成立条件](remediation-logic.md#partial-pr-selection) |
| `target_not_in_lockfile` | 更新対象のパッケージがlockfileに載っていない | [マネージャー別の更新処理](remediation-logic.md#manager-update-methods) |
| `no_reresolve_trigger` | 再解決のきっかけとして一時的に外せる依存がない | [マネージャー別の更新処理](remediation-logic.md#manager-update-methods) |
| `pnpm12_removal_unsupported` | 12.10.0より前のpnpm 12では、現在の更新方法を使えない | [マネージャー別の更新処理](remediation-logic.md#manager-update-methods) |
| `update_step_failed` | 更新中の処理に失敗した | [マネージャー別の更新処理](remediation-logic.md#manager-update-methods) |
| `post_update_check_failed` | 更新後の検査に失敗した | [付随変更の検査](remediation-logic.md#change-validation) |
| `unexpected_files` | 更新で想定外のファイルが変更された | [付随変更の検査](remediation-logic.md#change-validation) |
| `release_age_violation` | 依存のリリースが、プロジェクトの定める公開後の最低経過期間を満たさない | [付随変更の検査](remediation-logic.md#change-validation) |
| `manifest_changed` | 更新でmanifestに許可していない変更が入った | [付随変更の検査](remediation-logic.md#change-validation) |
| `output_files_invalid` | 出力ファイルが不正、または読み取れない | [結果の回収](remediation-logic.md#worker-results) |
| `lockfile_format_changed` | 更新でlockfileの形式が変わった | [付随変更の検査](remediation-logic.md#change-validation) |
| `target_not_updated` | 更新しても目標の版に上がらなかった | [部分PRの成立条件](remediation-logic.md#partial-pr-selection) |
| `target_removed` | 更新後に対象パッケージがなくなった、または依存関係から到達できなくなった | [部分PRの成立条件](remediation-logic.md#partial-pr-selection) |
| `fix_condition_not_met` | 更新後の版が脆弱性の修正条件を満たさない | [部分PRの成立条件](remediation-logic.md#partial-pr-selection) |
| `unexplained_dependency_diff` | 更新との関係を説明できない依存の変更がある | [付随変更の検査](remediation-logic.md#change-validation) |
| `distribution_mismatch` | パッケージがレジストリの公開内容やpipの解決結果と一致しない | [付随変更の検査](remediation-logic.md#change-validation) |
| `registry_check_limit` | 更新時のレジストリ照会数の上限に達した | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `update_package_limit` | 更新するパッケージ数が上限を超えている | [更新を実行できない場合](remediation-troubleshooting.md#check-update-failure) |
| `resolved_source_changed` | パッケージの取得元が変わった | [付随変更の検査](remediation-logic.md#change-validation) |
| `post_update_lockfile_unstable` | lockfileを再生成すると、さらに内容が変わる | [マネージャー別の更新処理](remediation-logic.md#manager-update-methods) |
| `drop_side_effect` | 再解決のために一時的に外した依存が元の状態に戻らなかった | [マネージャー別の更新処理](remediation-logic.md#manager-update-methods) |
| `source_target_not_detected_before` | 更新前の依存ファイルで対象の脆弱性が検出されなかった | [比較条件](remediation-logic.md#comparison-conditions) |
| `source_target_not_analysed_after` | 更新後の依存ファイルで対象を解析できなかった | [比較条件](remediation-logic.md#comparison-conditions) |
| `source_target_still_detected` | 更新後も対象の脆弱性が検出される | [対象別の検証範囲](remediation-logic.md#verification-scope) |
| `source_introduced_findings` | 更新で依存ファイルに新たな所見が入る | [比較条件](remediation-logic.md#comparison-conditions) |
| `source_introduced_kev` | 更新で依存ファイルにKEV掲載の脆弱性が新たに入る | [比較条件](remediation-logic.md#comparison-conditions) |
| `source_scan_incomplete` | 依存ファイルのスキャンが不完全だった | [比較条件](remediation-logic.md#comparison-conditions) |
| `update_verified` | 更新結果の検証が完了した | [対象別の検証範囲](remediation-logic.md#verification-scope) |
| `dependents_update_not_fixed` | 依存元を解決し直したが、今回の再解決では修正版に届かなかった | [依存元からの再解決](remediation-logic.md#dependent-reresolution) |
| `dependents_update_rejected` | 依存元の更新が検査を通らなかった | [再解決の検査条件](#dependent-reresolution-rules) |
| `dependents_update_unsupported` | 依存元をこのツールでは更新できない | [再解決の対応範囲と上限](#dependent-reresolution-limits) |
| `dependents_update_limit` | 依存元の更新が上限を超える | [再解決の対応範囲と上限](#dependent-reresolution-limits) |
| `release_too_new` | 更新で入る版の公開から72時間経っていない | [公開後の待機と再試行](#dependent-reresolution-waits) |
| `chain_downgrade` | 更新でパッケージが古い版に下がる、または版の対応を確定できない | [再解決の検査条件](#dependent-reresolution-rules) |
| `chain_move_limit` | 更新で動くパッケージ数が上限を超える | [再解決の対応範囲と上限](#dependent-reresolution-limits) |
| `chain_item_budget` | 更新に必要な作業が1項目の上限を超える | [公開後の待機と再試行](#dependent-reresolution-waits) |

依存元からの再解決では、パッケージごとの理由と、再解決全体の詳しい理由を分けて記録します。
Webhookでは、`packages[].reason`と`update.chain.reason`を併せて確認します。

- `dependents_update_rejected`には、公開後の待機が3回続いて再解決を停止した場合も含む
- `dependents_update_limit`には、同じ種類の作業上限による停止や、待機記録を保存できない場合も含む
- `source_introduced_findings`と`source_introduced_kev`には、脆弱なエントリ数・要求数の増加や、依存関係上の位置の検査による拒否も含む
- 実行や取得に失敗した場合は、通常更新と共通の失敗コードも使う

### PR処理の理由 {#pr-reasons}

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `pr_limit` | 1回の実行で作成するPR数、またはオープン中のPR数の上限に達した（どちらかは`detail`で確認する） | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `candidate_changed` | PRの準備中に候補が変わった | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `base_moved` | PRの準備中にベースブランチが進んだ | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `github_rate_limited` | GitHubのレート制限に掛かった | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `write_outcome_unknown` | GitHubへの書き込み結果を確認できない | [書き込みの停止](remediation-logic.md#write-stops) |
| `reconciliation_failed` | 既存PRとの照合に失敗した | [既存PRとの照合](remediation-logic.md#existing-pr-matching) |
| `repository_mismatch` | リポジトリが記録と異なる | [書き込みの停止](remediation-logic.md#write-stops) |
| `attempt_unsettled` | 前回のPR作成結果がまだ確定していない | [既存PRとの照合](remediation-logic.md#existing-pr-matching) |
| `branch_not_ours` | 同名のブランチが存在し、KestreLynxが作成したものではない | [書き込みの停止](remediation-logic.md#write-stops) |
| `pull_request_not_as_created` | PRが作成時の状態と異なる | [書き込みの停止](remediation-logic.md#write-stops) |
| `github_refused` | GitHubが書き込みを拒否した | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `github_error` | GitHubがエラーを返した | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `candidate_recheck_failed` | PR作成前に候補を再確認できなかった | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `source_changed` | 計画の元にしたファイルが変更された | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `artifact_content_missing` | 更新したファイルの内容が保持されていない | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `artifacts_unusable` | 更新したファイルをそのままPRへ書き込めない | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `open_pr_not_inherited` | 同じファイルの既存PRに、今回の更新が引き継いでいない修正がある | [古いPRの置き換え](remediation-logic.md#pr-replacement) |
| `language_set_too_large` | 更新するパッケージが多すぎてPRの記録に収まらない | [PRを作れない場合](remediation-troubleshooting.md#check-missing-pr) |
| `update_already_proposed` | この更新を提案するPRがすでにある | [既存PRとの照合](remediation-logic.md#existing-pr-matching) |

### 保存処理の理由 {#storage-reasons}

| コード | 意味 | 詳しい説明 |
| --- | --- | --- |
| `store_locked` | PRの記録が別のプロセスにロックされている | [記録を照合できない場合](remediation-troubleshooting.md#check-record-failure) |
| `storage_failed` | PRの記録を保存できなかった | [記録の保存順序](remediation-logic.md#record-order) |
| `storage_full` | PRの記録に空きを確保できない | [書き込みの停止](remediation-logic.md#write-stops) |
| `records_unverified` | 既存PRの記録を確認できない | [記録の復旧](remediation-logic.md#record-recovery) |
| `proposal_not_found` | この更新を提案していたPRの記録が見つからない | [既存PRとの照合](remediation-logic.md#existing-pr-matching) |

## 保存ファイル {#stored-records}

修正計画の記録は、`remediation.storage_dir`の下に保存します。

| ファイル・ディレクトリ | 内容 | 記録時点 |
| --- | --- | --- |
| `plan.json` | 最新の計画、ソースの場所、比較に使ったスキャン、実行した依存更新の検査結果 | 依存更新の処理後、PR処理前 |
| `delivered.json` | 配信した計画と、Slackに表示した内容をそれぞれ識別する情報 | 対応する通知の配信後 |
| `prs.json` | PRの識別情報、状態、作成試行、再作成の抑止、GitHub操作の記録 | PRの処理や照合、操作結果の記録時 |
| `tools` | 取得・照合したnpm・pnpm・uvのキャッシュ | ツールの取得時など |

`prs.json`には、依存元からの再解決の待機時刻、同じ種類の保留が続いた回数、入力ごとの停止記録も保存します。
この記録は依存更新の処理後にも更新します。

`plan.json`は、PR処理後の結果を含めて再保存しません。
PR処理の今回の結果は通知で、継続して管理する記録は`prs.json`で確認できます。

保存とPR処理の関係は[記録の保存順序](remediation-logic.md#record-order)、保存先の設定は[保存先](configuration.md#remediation-storage)を参照してください。
