---
description: "TrivyがPython・Node.js・Java・Goの言語パッケージを検出する仕組みと、実行時に観測したファイルへの紐づけ方を記載する。RECORD、package.json、JAR、Goバイナリの情報を使った計測結果と、確認できる範囲を扱います。"
---

# Trivyで検出した言語パッケージを実行時のファイル情報に紐づける

公開日：2026年9月20日

## はじめに

コンテナイメージの脆弱性スキャンでは、OSパッケージのほかに、pipでインストールしたPythonパッケージや、npmの依存パッケージ、JARに含まれるライブラリ、Goバイナリに組み込まれたモジュールが検出されます。
これらのパッケージが稼働中のコンテナで使われているかを調べるには、スキャン結果と実行時に観測したファイルを対応付ける必要があります。

この対応付けを検証するため、既知の依存パッケージを読み込むコンテナを用意し、procfsから取得したファイル情報と、bpftraceによる実行・ファイルオープンの記録を比較しました。
Python・Java・Goの対象ケースでは、ファイル情報の収集と対応付けを広げることでスキャン結果に証拠を付けられました。
Node.jsのケースでは読み込み時のイベントが必要で、読み込み後に観測を始めると確認できませんでした。

この記事では、Trivyがパッケージを特定する情報と、実行時のファイルからそのパッケージへ辿る方法を説明します。
イベント自体の取得方法は、[bpftraceでコンテナの実行とファイルオープンを観測する](bpftrace-container-exec-open-events-ja.md)を参照してください。

## 検証内容

次の4ケースを取り上げます。
コンテナ内のプログラムが残す利用ログと、パッケージの所有者情報を使って比較対象を決め、観測したファイルをそのパッケージのスキャン結果に紐づけられるかを調べました。[^measurements]

| 対象 | コンテナの動作 | 比較対象のパッケージ |
| --- | --- | --- |
| Python | cryptographyをimportし、プロセスを維持する | cryptography 41.0.0 |
| Node.js | npmで配置したlodashをrequireする | lodash 4.17.15 |
| Java | 通常のJARからlog4j-coreのクラスを読み込む | org.apache.logging.log4j:log4j-core 2.14.1 |
| Go | モジュールを組み込んだ静的バイナリを実行する | golang.org/x/text v0.3.0 |

計測条件は次のとおりです。

- OS・カーネル：WSL2上のLinux 6.6
- アーキテクチャ：amd64
- コンテナ環境：ネイティブのDocker Engine、cgroup v2
- スキャナ：Trivy 0.71.2
- イベント収集：bpftrace 0.25.0、root権限、`perf_rb_pages=256`
- 観測期間：各300秒、procfsの読み取りは30秒間隔

## Trivyが言語パッケージを検出する情報

Trivyは、スキャン対象にあるパッケージのメタデータやバイナリから名前・バージョンを取り出し、脆弱性情報と照合します。
ソースリポジトリの依存定義を読む場合と、コンテナイメージに配置されたパッケージを読む場合では、使うファイルが異なります。[^trivy-language]

| 対象 | ソースや依存定義を調べる場合の例 | インストール済みファイルを調べる場合の例 |
| --- | --- | --- |
| Python | `requirements.txt`や`poetry.lock` | `.dist-info/METADATA`や`.egg-info`の情報[^trivy-python] |
| Node.js | `package-lock.json`や`pnpm-lock.yaml` | 配置されたパッケージ自身の`package.json`[^trivy-node] |
| Java | `pom.xml`やGradleのロックファイル | JAR内の`pom.properties`・`MANIFEST.MF`。情報が足りない場合はTrivy Java DBによる識別[^trivy-java] |
| Go | `go.mod` | ビルド時にバイナリへ埋め込まれた依存モジュールとGoのバージョン情報[^trivy-go] |

依存関係が検出されたことから分かるのは、そのスキャン対象に対応するパッケージ情報があることです。
その時点では、稼働中のプロセスがどのファイルを開いたかは分かりません。

### JSONにあるパスの意味

今回のスキャン結果では、言語パッケージの`Class`は`lang-pkgs`でした。
対応付けに使うパスは、対象によって`Vulnerabilities[].PkgPath`または`Results[].Target`にあります。
保存済みJSONから抜き出した例は次のとおりです。[^runs]

| 対象 | `Type` | パスを持つ項目 | 記録された値 |
| --- | --- | --- | --- |
| Python | `python-pkg` | `PkgPath` | `usr/local/lib/python3.12/site-packages/cryptography-41.0.0.dist-info/METADATA` |
| Node.js | `node-pkg` | `PkgPath` | `app/node_modules/lodash/package.json` |
| Java | `jar` | `PkgPath` | `app/log4j-core-2.14.1.jar` |
| Go | `gobinary` | `Target` | `server` |

PythonとNode.jsのパスは、実行されたコードそのものではなく、パッケージを識別するメタデータを指しています。
そのため、観測した`.so`や`.js`のパスをそのまま比較しても一致しません。
JavaではJAR、Goではバイナリ自体が対応付けの入口になります。

## 計測に使用したプログラム

収集と照合には、次の公開プログラムを使用しました。

| プログラム | 役割 |
| --- | --- |
| [collect.go](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-discovery/collect.go)・[aux.go](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-discovery/aux.go) | procfsの実行ファイル・maps・fdと、パッケージの対応付けに使うファイル一覧やリンク情報を収集する |
| [mapping.go](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-discovery/mapping.go) | 観測パスからスキャン側のファイルとパッケージを特定する |
| [series.go](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-discovery/series.go) | 収集情報とイベント証拠を段階的に追加して確認数を比較する |
| [gtb_case.py](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-discovery/tools/gtb_case.py) | コンテナ内の利用ログと所有者情報から比較用の正解データを作る |

計測全体の実行には[case-run.sh](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-discovery/tools/case-run.sh)を使いました。
ビルド方法と実行手順は[実験用ツールのREADME](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-discovery/README.ja.md)にあります。

## 観測したファイルからパッケージへ辿る

観測したファイルがどのパッケージに属するかを調べ、同じイメージのスキャン結果と照合します。
使う情報は言語ごとに異なります。

### Python：インストール済みファイルの一覧を使う

- `RECORD`のインストール済みファイル一覧から、観測ファイルの所属パッケージを特定[^python-record]
- 所属パッケージの`METADATA`にある名前・バージョンを、Trivyの検出結果と照合
- 検証では、読み込まれたネイティブ拡張の`.so`ファイルをcryptographyに対応付け

### Node.js：ファイルの配置先を調べる

- 読み込まれたファイルの配置先から、`node_modules`内の所属パッケージを特定
- そのパッケージの`package.json`にある名前・バージョンを、Trivyの検出結果と照合
- 検証では、`node_modules/lodash`内のファイルを開いた記録をlodashの検出結果に対応付け

### Java：開かれているJARを照合する

- JVMが開いたまま保持しているJARを、プロセスのファイル情報から確認
- JARのパスを使い、そのJARに含まれるライブラリの検出結果と照合
- 検証では、開かれた`log4j-core-2.14.1.jar`をlog4j-coreの検出結果に対応付け

### Go：実行中のバイナリを照合する

- 静的なGoバイナリでは、依存モジュールも同じ実行ファイルに組み込まれる
- 実行中のバイナリを特定し、Trivyがそのバイナリの埋め込み情報から検出したモジュールに対応付け[^trivy-go]
- 検証では、`server`の実行記録を、組み込まれたgolang.org/x/textの検出結果に対応付け

## 方法ごとの確認結果

同じ計測記録に対して、次の3段階で確認数を比較しました。

1. **従来のルール**：procfsの実行ファイルやmapsを、主にOSパッケージへ対応付け
2. **追加手法まで**：従来のルールに加えて、fdなどの収集情報と、前節の言語パッケージ向けの対応付けを使用
3. **イベント証拠まで**：追加手法までの情報に加えて、対象コンテナの観測期間内に成功した実行・ファイルオープンの記録を使用

表は、対象操作より前に観測を始めた場合の結果です。
比較対象は、各ケースで指定したパッケージのHIGH/CRITICALの脆弱性検出結果です。
各方法の列には、そのうち利用の証拠を紐づけられた件数を示します。[^runs]

| 比較対象 | 対象パッケージの検出結果 | 従来のルール | 追加手法まで | イベント証拠まで |
| --- | --- | --- | --- | --- |
| cryptography | 5件 | 0件 | 5件 | 5件 |
| lodash（npm） | 4件 | 0件 | 0件 | 4件 |
| log4j-core（通常のJAR） | 3件 | 0件 | 3件 | 3件 |
| golang.org/x/text（静的Goバイナリ） | 4件 | 0件 | 4件 | 4件 |

### 読み込み後に観測を始めた場合

同じNode.jsのケースで、最初の`require`が終わってから観測を始めると、イベント証拠まで追加してもlodashの確認数は0件でした。
Python・Java・Goの対象ケースでは、対応付けられるファイルの情報がサンプリング時にも残っていたため、追加手法までの確認数は変わりませんでした。[^runs]

この違いは、スキャンの検出能力ではなく、実行時に証拠が残る時間の違いによるものです。
Node.jsの`require`は読み込んだモジュールをキャッシュするため、最初の読み込みを取り逃した後に長く観測しても、そのファイルが再び開かれるとは限りません。[^node-cache]

## 結果を解釈するときの注意点

この方法が確認するのは、パッケージに属するファイルの観測や、そのパッケージを含むバイナリの実行です。
ファイルオープンの成功だけでは、内容を読んだか、脆弱な関数へ到達したか、攻撃が成立するかまでは分かりません。
Goではバイナリの実行を確認しても、個々のモジュールの関数が実行されたかは分かりません。
複数のライブラリを含むJARでも、外側のファイルを開いた事実だけで、各ライブラリが読み込まれたとは判断できません。

一方、確認できなかったものも「未使用」とは限りません。
観測開始前の読み込み、短時間のファイル利用、イベントの欠落、所有者メタデータの不足、収集範囲外の配置を区別して扱います。

今回の比較は、単一環境の少数の検証用パッケージによるものです。
実運用のアプリケーション全体に対する網羅性や、方式別の見逃し率は示していません。
ファイルの利用証拠は修正の優先順位を検討する追加情報として扱い、証拠がないことだけで修正対象から外さないようにします。

## まとめ

言語パッケージの対応付けでは、Pythonはインストール済みファイルの一覧、Node.jsはファイルの配置先、JavaはJAR、Goは実行バイナリを使います。
スキャンが示すメタデータのパスと、実行時に観測するファイルのパスの関係を辿ることで、検出結果へ証拠を付けられます。

今回の計測では、サンプリングで残る情報を使えるケースと、読み込み時のイベントが必要なケースがありました。
対応付けの結果には、観測したファイル、確認できた単位、観測期間を残すことで、何を根拠に利用を確認したかを説明できます。

## 参考資料

///Footnotes Go Here///

[^trivy-language]: [Trivy：言語パッケージのスキャン対象](https://trivy.dev/docs/latest/coverage/language/)

[^trivy-python]: [Trivy：Python](https://trivy.dev/docs/latest/coverage/language/python/)

[^trivy-node]: [Trivy：Node.js](https://trivy.dev/docs/latest/coverage/language/nodejs/)

[^trivy-java]: [Trivy：Java](https://trivy.dev/docs/latest/coverage/language/java/)

[^trivy-go]: [Trivy：Go](https://trivy.dev/docs/latest/coverage/language/golang/)

[^python-record]: [Python Packaging User Guide：インストール済みパッケージの記録](https://packaging.python.org/en/latest/specifications/recording-installed-packages/)

[^node-cache]: [Node.js：CommonJSモジュールのキャッシュ](https://nodejs.org/api/modules.html#caching)

[^measurements]: [eBPFによる実行時証拠の観測調査：計測結果](../development/runtime-event-evidence.md#2026-09-16)

[^runs]: 保存済み計測のケース15・17・19・22、run名`<ケース番号>-root-30-300-p0-r1-startup-nofilter256p`と`<ケース番号>-root-30-300-p0-r1-attach_running-nofilter256p`の`trivy_hc.json`と`csv_hc/series.csv`。Pythonは`.pyc`キャッシュあり、Javaは通常のJARを対象とする。計測手順は本文の`case-run.sh`、結果の概要は[公開開発ログ](../development/runtime-event-evidence.md#2026-09-16)を参照。

---

KestreLynxは、稼働中のDocker・KubernetesコンテナのイメージをTrivyで定期的にスキャンし、前回からの変化と、深刻度・CISA KEV・EPSSに基づく優先度をSlackやWebhookへ通知するOSSです。

Docker・Compose・Kubernetes向けの修正計画と修正PR（実験的）で、更新候補の比較からGitHubへのPR作成まで修正を支援します（既定で無効）。マージ・再ビルド・デプロイは利用者が行います。

[KestreLynxについて](../index.md) · [GitHubでソースコードを見る](https://github.com/kitsunetrail/kestrelynx)
