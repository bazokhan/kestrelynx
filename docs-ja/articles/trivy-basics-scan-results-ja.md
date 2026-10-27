---
description: "Trivyのスキャン対象とJSON出力を、nginxイメージの実例で解説。検出件数、修正版の有無、深刻度の情報源を読み取り、検査範囲の限界とKEV・EPSSを使う優先順位付けを理解できます。"
---

# Trivyの基礎とスキャン結果の読み方

公開日：2026年9月10日

## はじめに

コンテナイメージの脆弱性を確認するツールとして、Trivyがあります。スキャン結果を利用するには、検出件数や深刻度に加えて、何を検査した結果なのか、各項目が何を表しているのかを確認する必要があります。

この記事では、Trivyの基本、スキャン対象、JSON出力を使った結果の読み方、脆弱性管理で利用する際の注意点について記載します。

## Trivyとは

Trivyは、Aqua Securityが開発するオープンソースのセキュリティスキャナーです。既知の脆弱性だけでなく、設定ミスや、ファイルに含まれる認証情報などの検出にも対応しています。

| 機能 | 調べる内容 |
| --- | --- |
| 脆弱性スキャン | OSパッケージや依存ライブラリに関する既知の脆弱性 |
| 設定ミスの検査 | Dockerfile、Kubernetes、Terraformなどの設定上の問題 |
| シークレット検出 | APIキーなどの機密情報らしき記述 |
| ライセンス確認 | パッケージのライセンス情報 |
| SBOM生成 | 検出したソフトウェア構成の一覧 |

すべての機能が、すべての対象に対して常に有効になるわけではありません。対象とスキャナーの組み合わせ、オプションによって検査範囲が変わります。[^trivy]

脆弱性検出の基本は、対象に含まれるソフトウェアとバージョンを特定し、対応する脆弱性情報と照合することです。アプリケーションに攻撃を送って、実際に悪用できるかを試験する仕組みではありません。

そのため、「脆弱性が検出された」と「この環境で攻撃が成立する」は区別して考える必要があります。

## Trivyのスキャン対象

代表的なスキャン対象とコマンドは次のとおりです。

| 対象 | コマンド例 | 主に確認するもの |
| --- | --- | --- |
| コンテナイメージ | `trivy image nginx:1.20` | イメージ内のOSパッケージ、ライブラリ、ファイルなど |
| ローカルディレクトリ | `trivy fs ./my-project` | 指定範囲内の依存関係ファイルや設定ファイルなど |
| Gitリポジトリ | `trivy repo https://github.com/owner/repo` | リポジトリ内の依存関係ファイルや設定ファイルなど |

最後のURLは説明用です。実行時には調べたいリポジトリのURLに置き換えます。

`trivy fs`は単一のファイルも指定できます。例えば、対応するロックファイルを直接指定して依存パッケージの脆弱性を調べられます。[^filesystem]

`trivy repo`はソースリポジトリ向けの検査です。公式説明では、ロックファイルなどを対象とし、JARやバイナリなどのビルド成果物は対象にしないとされています。[^repository]

### ファイルとイメージで結果が異なる理由

例えば、Node.jsアプリのリポジトリに、`package-lock.json`とDockerfileがある場合を考えます。

- リポジトリ側では、ロックファイルなどに記録された依存パッケージを調べる。
- イメージ側では、ビルド後のイメージに実際に含まれるOSパッケージやライブラリを調べる。
- Dockerfileの`FROM`にベースイメージ名が書いてあっても、リポジトリのスキャンだけで、そのベースイメージ内部まで自動的に検査するわけではない。

つまり、「開発用のファイル」と「配布・実行する成果物」では、読み取れる情報が違います。どちらの検出件数が多いかは一概には決まりません。

開発用依存関係についても、ロックファイルに存在するだけで必ず検出対象になるとは限りません。言語ごとの対応や、開発用依存関係を含める設定を確認する必要があります。

### 共通の出力形式

`fs`、`repo`、`image`は、表形式やJSON形式などの共通した出力形式を利用できます。

```bash
trivy fs --format json ./my-project
trivy image --format json nginx:1.20
```

JSONの基本構造や脆弱性の主要項目は共通ですが、イメージIDやレイヤー情報など、対象固有の情報もあります。すべての項目が常に存在するわけではありません。[^reporting]

## Trivyのインストール

Trivyのインストール方法は、[公式のインストール手順](https://trivy.dev/docs/latest/getting-started/installation/)を参照してください。導入後、次のコマンドでバージョンを確認できます。

```bash
trivy --version
```

## イメージのスキャンとJSON出力

イメージをスキャンする基本コマンドは次のとおりです。

```bash
trivy image nginx:1.20
```

初回など、必要な場合は脆弱性データベースが自動取得されます。本体のインストールと脆弱性情報の更新は別であり、同じTrivyでも、使用するデータベースによって結果が変わることがあります。[^database]

結果をJSONに保存するには、出力形式とファイル名を指定します。

```bash
trivy image --format json --output trivy_nginx.json nginx:1.20
```

パッケージ一覧も含める意図を明示する場合は、次のように指定できます。

```bash
trivy image --format json --list-all-pkgs \
  --output trivy_nginx.json nginx:1.20
```

同名の出力ファイルがある場合は上書きされるため、過去の結果を残すならファイル名を変えます。[^reporting]

## スキャン結果の読み方

ここでは、2026年9月9日にTrivy 0.71.2で取得した`nginx:1.20`のスキャン結果を例に、集計値とJSON出力の抜粋を使って説明します。

導入されるTrivyのバージョンや、再実行時の検出結果は、実例と異なる場合があります。

### 検査対象と件数

| 項目 | 記録内容 |
| --- | --- |
| Trivy | 0.71.2 |
| レポート作成日時 | 2026年9月9日10:45、日本時間 |
| 対象 | `nginx:1.20` |
| 検出されたOS | Debian 11.3 |
| nginxパッケージのバージョン | 1.20.2 |
| パッケージ一覧の件数 | 142 |
| 脆弱性の検出レコード数 | 866 |
| 重複を除いた脆弱性ID数 | 548 |

深刻度別の検出レコード数は次のとおりです。

| 深刻度 | 検出レコード数 |
| --- | ---: |
| CRITICAL | 32 |
| HIGH | 217 |
| MEDIUM | 348 |
| LOW | 238 |
| UNKNOWN | 31 |

866件は「異なるCVEが866個ある」という意味ではありません。同じCVEが複数のパッケージに対応すると、複数の検出レコードになります。また、これらはnginx本体だけの件数ではなく、イメージに含まれるパッケージの検出結果です。

これらの数値は上記の日時に取得したスキャン結果の集計値です。同じコマンドで再実行しても、同じ結果になるとは限りません。

### JSON全体の構造

主要な項目に絞ると、JSON出力は次のような構造になります。

```json
{
  "Trivy": {
    "Version": "0.71.2"
  },
  "ArtifactName": "nginx:1.20",
  "ArtifactType": "container_image",
  "Metadata": {
    "OS": {
      "Family": "debian",
      "Name": "11.3"
    }
  },
  "Results": [
    {
      "Target": "nginx:1.20 (debian 11.3)",
      "Class": "os-pkgs",
      "Type": "debian",
      "Packages": [],
      "Vulnerabilities": []
    }
  ]
}
```

これは全体の構造を示すための例であり、一部の項目を省略しています。`Packages`と`Vulnerabilities`も説明のため空配列にしていますが、実際のスキャン結果では、検出したパッケージや脆弱性のレコードが入ります。

`Metadata`にはスキャン対象の情報が入り、`Results`には対象ごとの検査結果が配列として格納されます。上の例では`Results`の要素を1つだけ示しています。その要素の中に、パッケージ一覧の`Packages`と脆弱性一覧の`Vulnerabilities`があります。

JSON出力は、主に次の3つに分けて確認できます。

| まとまり | 内容 |
| --- | --- |
| レポート情報 | 使用したTrivy、作成日時、対象名、識別ID |
| `Metadata` | OS、イメージ、レイヤー、ビルド履歴、起動設定 |
| `Results` | 検出したパッケージと脆弱性 |

脆弱性を確認したい場合は、まず`Results`内の`Vulnerabilities`を読み、必要に応じて`Packages`や`Metadata`を参照します。

## 脆弱性レコードの主要項目

脆弱性の検出レコードは、`Results`配列の各要素にある`Vulnerabilities`配列（`Results[].Vulnerabilities[]`）に格納されます。このスキャン結果から、`PkgName`が`apt`のレコードの主要項目を抜粋すると、次のようになります。

```json
{
  "VulnerabilityID": "CVE-2011-3374",
  "PkgName": "apt",
  "InstalledVersion": "2.2.4",
  "Status": "affected",
  "Severity": "LOW",
  "SeveritySource": "debian"
}
```

| 項目 | 読み方 |
| --- | --- |
| `VulnerabilityID` | どの脆弱性か |
| `PkgName` | どのパッケージに該当するか |
| `InstalledVersion` | イメージに入っているバージョン |
| `FixedVersion` | 修正が提供されているバージョン。情報がない場合は省略される |
| `Status` | 脆弱性情報源が示す対応状況 |
| `Severity` | Trivyが採用した深刻度 |
| `SeveritySource` | その深刻度を採用した情報源 |

この例では、「apt 2.2.4がCVE-2011-3374に該当し、深刻度にはDebian由来のLOWが使われている」と読めます。ここから、稼働中のアプリがその脆弱性のある処理を呼び出しているかまでは分かりません。

### Statusと修正バージョンの関係

同じスキャン結果の`Results[].Vulnerabilities[]`には、`PkgName`が`bsdutils`のレコードも含まれています。その主要項目を抜粋すると、次のようになります。

```json
{
  "VulnerabilityID": "CVE-2024-28085",
  "PkgName": "bsdutils",
  "InstalledVersion": "1:2.36.1-8+deb11u1",
  "FixedVersion": "2.36.1-8+deb11u2",
  "Status": "fixed"
}
```

`Status: fixed`は、このイメージが修正済みという意味ではなく、修正版が提供されていることを表します。この例では、インストール済みは`deb11u1`で、修正版として`deb11u2`が示されています。

このJSONに含まれるステータスと検出レコード数は、次のとおりです。

| Status | 意味 | 検出レコード数 |
| --- | --- | ---: |
| `fixed` | 修正版が提供されている | 437 |
| `affected` | 影響ありとして登録されている | 305 |
| `fix_deferred` | 修正が先送りされている | 90 |
| `will_not_fix` | 修正しない方針となっている | 34 |

`FixedVersion`がないことも、安全や影響なしを意味しません。修正版が未提供の場合や、情報が登録されていない場合があります。[^filtering]

## 深刻度の選択とCVSSの関係

`Severity`は、Trivyが外部の脆弱性情報から採用した深刻度です。Trivyが独自に算出したCVSSスコアではありません。

Trivyは外部の評価を選び、必要に応じて深刻度に分類します。既定の選択では、対象のベンダーの深刻度を優先し、それがなければ提供されたCVSSスコアから分類し、さらに情報がなければNVDなどを参照します。

そのため、同じCVEについてNVDとDebianの評価が異なる場合、NVDで見た深刻度とTrivyの`Severity`が一致しないことがあります。ビルド方法や標準設定など、配布形態の違いをベンダーが考慮できるためです。[^severity]

先ほどの`apt`のレコードには、次の評価情報が含まれています。

```json
{
  "Severity": "LOW",
  "SeveritySource": "debian",
  "VendorSeverity": {
    "debian": 1,
    "nvd": 1
  },
  "CVSS": {
    "nvd": {
      "V2Score": 4.3,
      "V3Score": 3.7
    }
  }
}
```

この抜粋では、`CVSS`にNVDのスコアがある一方、`SeveritySource`は`debian`です。つまり、`CVSS.nvd`が出ているからといって、表示上の深刻度もNVDのスコアだけで決まったとは限りません。

`VendorSeverity`の数値は、0がUNKNOWN、1がLOW、2がMEDIUM、3がHIGH、4がCRITICALを表す列挙値です。CVSSの点数ではありません。

また、`CVSS`には情報源ごとに異なるバージョンの評価が入ることがあります。`V3Vector`の先頭が`CVSS:3.1`ならv3.1の評価であり、すべてのCVEにv4.0のスコアがあるわけではありません。

## KEV・EPSSとの組み合わせ

このスキャン結果のJSONにはCVSSの評価情報が含まれていますが、KEVへの掲載情報やEPSSスコアの専用項目はありません。

| 情報 | 分かること | この結果への補い方 |
| --- | --- | --- |
| CVSS | 技術的な深刻さ | JSON内の`CVSS`を参照 |
| KEV | CISAが実際の悪用を確認し、カタログに掲載しているか | CVE IDをKEVカタログと照合 |
| EPSS | 今後30日以内に実環境で悪用される確率の推定 | CVE IDを使ってスコアを取得 |

KEVは、CISAがJSONやCSVで公開しています。未掲載であることは、悪用されていない証明ではありません。[^kev]

EPSSはFIRSTがAPIやCSVなどで提供しています。少数のCVEの照会にはAPI、大量のスコア取得には日次CSVなどを使い分けます。EPSSは、特定の自分のサーバーが侵害される確率そのものではありません。[^epss][^epss-data]

Trivyの検出結果にこれらを組み合わせる場合は、`VulnerabilityID`を共通のキーとして補足情報を付ける形になります。

## スキャン結果を利用する際の注意点

### 脆弱性の報告がなくても、安全とは限らない

今回のスキャンでは、イメージ内にnginxがあることは確認できましたが、nginxの脆弱性は報告されませんでした。

イメージのスキャンが完了しても、中にあるすべてのパッケージが脆弱性の検査対象になるとは限りません。nginxが検査対象から外れていた場合、nginxに脆弱性があっても検出されません。

例えば、Debian上のパッケージを調べるとき、TrivyはDebianが公開する脆弱性情報を使います。しかし、その情報が対象とするのはDebianが配布するパッケージです。nginxの開発元など、別の配布元から入れたパッケージは、検査の対象外になることがあります。[^third-party]

今回のnginxも、Debian以外の配布元のパッケージとして記録されていました。この結果だけでは検査されたかどうかを確認できないため、「脆弱性の報告がないので安全」とは判断できません。

### OSのサポート終了情報を確認する

このスキャン結果の`Metadata.OS`には、次の値が記録されています。

```json
{
  "Family": "debian",
  "Name": "11.3",
  "EOSL": true
}
```

これは、そのスキャン時点でTrivyがOSをサポート終了と判定した記録です。現在のサポート契約や、すべての延長サポート制度まで判定した結果とは限らないため、運用判断ではOS提供元の情報も確認します。

### 同じイメージでも結果は変わる

イメージを変更していなくても、新しい脆弱性の公開や既存情報の訂正によって検出結果は変わります。継続利用するイメージを、ビルド時だけでなく後日再スキャンする意味はここにあります。

比較のためには、イメージのダイジェスト、Trivyのバージョン、実行日時、オプション、使用した脆弱性データベースの情報を記録しておくと、差分の原因を調べやすくなります。

### フィルターで除外された脆弱性も存在する

例えば、`--ignore-unfixed`は修正版がない脆弱性などを結果から除外します。修正可能なものに絞る用途はありますが、全体像の確認とは区別が必要です。

深刻度フィルターや除外設定も同様です。検出件数を比較するときには、検査条件がそろっているかを先に確認します。[^filtering]

## JSON出力の項目一覧

ここでは、本文で扱った項目以外も含め、このスキャン結果のJSON出力に含まれる項目を整理します。Trivyの全スキャン対象に共通する完全なスキーマ一覧ではありません。

まず、各項目の位置関係を示します。`Metadata`と`Results`は、どちらもJSONの最上位の項目です。`Packages`と`Vulnerabilities`は、`Results`配列の各要素に属する項目です。

以下は説明用のコメントを付けたJSONC形式の例です。一部の項目を省略し、ハッシュ値は`"..."`で置き換えています。実際のTrivyのJSON出力にはコメントは含まれません。

```jsonc
{
  "SchemaVersion": 2, // レポート全体のJSON構造のバージョン
  "Trivy": {
    "Version": "0.71.2" // 使用したTrivyのバージョン
  },
  "ArtifactName": "nginx:1.20", // スキャン対象の名前
  "Metadata": { // スキャン対象のイメージ情報
    "OS": {
      "Family": "debian", // イメージ内のOSの種類
      "Name": "11.3" // OSのバージョン
    },
    "Layers": [ // イメージのレイヤー一覧
      {
        "Digest": "..." // このレイヤーのハッシュ
      }
    ],
    "ImageConfig": {
      "architecture": "amd64" // イメージのCPUアーキテクチャ
    }
  },
  "Results": [ // 対象ごとの検査結果
    {
      "Class": "os-pkgs", // この要素はOSパッケージの検査結果
      "Packages": [ // イメージ内で見つかったパッケージの一覧
        {
          "Name": "apt", // パッケージ名
          "Version": "2.2.4" // パッケージのバージョン
        }
      ],
      "Vulnerabilities": [ // 検出した脆弱性の一覧
        {
          "VulnerabilityID": "CVE-2011-3374", // 脆弱性のID
          "PkgName": "apt", // この脆弱性に該当するパッケージ名
          "InstalledVersion": "2.2.4" // そのパッケージのバージョン
        }
      ]
    }
  ]
}
```

以下の表では、見出しごとに格納位置を示します。`.`は項目の階層を区切り、`[]`は配列の各要素を表します。

### レポート情報（JSONの最上位）

以下はJSONの最上位の項目です。ただし、`Trivy.Version`は、最上位の`Trivy`に属する`Version`項目です。

| 項目 | 意味 |
| --- | --- |
| `SchemaVersion` | JSON構造のバージョン。今回の値は2 |
| `Trivy.Version` | 使用したTrivyのバージョン |
| `ReportID` | レポートの識別ID |
| `CreatedAt` | レポート作成日時 |
| `ArtifactID` | Trivyがスキャン対象を識別するID |
| `ArtifactName` | 対象名 |
| `ArtifactType` | 対象の種類。今回は`container_image` |

### Metadata（対象イメージの情報）

以下は、JSONの最上位にある`Metadata`に属する項目です。

| 項目（`Metadata`内） | 意味 |
| --- | --- |
| `Size` | イメージのレイヤーサイズ合計、バイト単位 |
| `OS.Family` | ディストリビューションの種類 |
| `OS.Name` | 検出したOSバージョン |
| `OS.EOSL` | Trivyによるサポート終了判定 |
| `ImageID` | イメージの識別ID |
| `Reference` | 対象イメージの参照文字列 |
| `RepoTags` | タグの一覧 |
| `RepoDigests` | リポジトリ名とダイジェストを組み合わせた参照一覧 |
| `DiffIDs` | 非圧縮レイヤーのハッシュ一覧 |
| `Layers` | レイヤーごとの情報 |
| `Layers[].Size` | 各レイヤーのサイズ、バイト単位 |
| `Layers[].Digest` | 配布されるレイヤーデータのハッシュ |
| `Layers[].DiffID` | 非圧縮レイヤーデータのハッシュ |
| `ImageConfig` | イメージの構成情報。内部の項目は次の表で説明 |

IDやハッシュは用途が異なるため、名前が似ているからといって同じものとして扱わないようにします。[^report-types][^layer-size]

### ImageConfig（Metadata内の構成情報）

以下は、`Metadata.ImageConfig`に属する項目です。イメージに記録されている構成情報を表します。

| 項目（`Metadata.ImageConfig`内） | 意味 |
| --- | --- |
| `architecture` | CPUアーキテクチャ。今回は`amd64` |
| `os` | OSの種類。今回は`linux` |
| `created` | イメージ作成日時 |
| `history` | ビルド履歴 |
| `history[].created` | 各工程の作成日時 |
| `history[].created_by` | 各工程を生成したコマンドなど |
| `history[].empty_layer` | `true`ならファイルシステム変更のレイヤーを追加しない工程 |
| `rootfs.type` | ファイルシステムの構成方式。今回は`layers` |
| `rootfs.diff_ids` | 構成レイヤーの非圧縮ハッシュ一覧 |
| `config.Entrypoint` | 起動時に実行するプログラム |
| `config.Cmd` | デフォルトのコマンド・引数 |
| `config.Env` | 環境変数 |
| `config.Labels` | 管理者情報などの付加情報 |
| `config.Labels.maintainer` | 管理者を表すラベル |
| `config.ExposedPorts` | 使用を想定するポート。今回は`80/tcp` |
| `config.StopSignal` | 停止時に送るシグナル。今回は`SIGQUIT` |

`ExposedPorts`があるだけで、ホストへのポート公開が行われるわけではありません。また、`Env`や起動コマンドは実行時に上書きできるため、この情報は稼働中コンテナの実測結果ではありません。[^image-config]

### Results（対象ごとの検査結果）

以下は、JSONの最上位にある`Results`配列の各要素に属する項目です。

| 項目（`Results[]`内） | 意味 |
| --- | --- |
| `Target` | この結果の対象名 |
| `Class` | 検査結果の分類。今回はOSパッケージを表す`os-pkgs` |
| `Type` | 解析対象の種類。今回は`debian` |
| `Packages` | 検出したパッケージの一覧 |
| `Vulnerabilities` | 脆弱性の検出レコード一覧 |

### Packages（Results内のパッケージ一覧）

以下は、`Results[].Packages[]`の各要素に属する項目です。

| 項目（`Results[].Packages[]`内） | 意味 |
| --- | --- |
| `ID` | パッケージID。例：`adduser@3.118` |
| `Name` | パッケージ名 |
| `Identifier.PURL` | 種類・名前・バージョンなどを表す標準形式のPackage URL |
| `Identifier.UID` | パッケージを区別するための識別子 |
| `Version` | パッケージのバージョン |
| `Release` | 配布パッケージの改訂番号 |
| `Epoch` | バージョン比較の順序を調整する数値 |
| `Arch` | 対応アーキテクチャ。`all`はアーキテクチャ非依存 |
| `SrcName` | 元となるソースパッケージ名 |
| `SrcVersion`／`SrcRelease`／`SrcEpoch` | ソースパッケージ側のバージョン情報 |
| `Licenses` | ライセンス一覧 |
| `Maintainer` | パッケージ管理者 |
| `Repository.Class` | 配布元の分類。`official`はOS公式、`third-party`はOS提供元以外の配布元を表す |
| `DependsOn` | 依存するパッケージのID一覧 |
| `Layer.Digest`／`Layer.DiffID` | パッケージに対応するレイヤーのハッシュ |
| `InstalledFiles` | パッケージに属するインストールファイルのパス一覧 |
| `AnalyzedBy` | 解析に使ったアナライザー。今回は`dpkg` |

ライセンス情報やファイル一覧が含まれていても、それ自体が問題の検出を意味するわけではありません。[^package-types]

### Vulnerabilities（Results内の脆弱性一覧）

以下は、`Results[].Vulnerabilities[]`の各要素に属する項目です。

| 項目（`Results[].Vulnerabilities[]`内） | 意味 |
| --- | --- |
| `VulnerabilityID` | CVEなどの脆弱性識別子 |
| `PkgID`／`PkgName` | 対象パッケージのID／名前 |
| `PkgIdentifier.PURL`／`PkgIdentifier.UID` | 対象パッケージの識別情報 |
| `InstalledVersion` | インストール済みバージョン |
| `FixedVersion` | 修正が提供されたバージョン |
| `Status` | 情報源が示す脆弱性の対応状況 |
| `Layer.Digest`／`Layer.DiffID` | 対象パッケージのレイヤー情報 |
| `Severity` | 採用された深刻度 |
| `SeveritySource` | 深刻度の採用元 |
| `VendorSeverity` | 情報源ごとの深刻度を表す列挙値 |
| `CVSS` | 情報源ごとのCVSS評価 |
| `CVSS.*.V2Score` | CVSS v2のスコア。`*`は`nvd`などの情報源の名前 |
| `CVSS.*.V3Score` | CVSS v3のスコア |
| `CVSS.*.V40Score` | CVSS v4.0のスコア |
| `CVSS.*.V2Vector` | CVSS v2の評価条件を表すベクター文字列 |
| `CVSS.*.V3Vector` | CVSS v3の評価条件を表すベクター文字列 |
| `CVSS.*.V40Vector` | CVSS v4.0の評価条件を表すベクター文字列 |
| `CweIDs` | 弱点の種類を分類するCWE ID |
| `Title`／`Description` | 見出し／詳細説明 |
| `PrimaryURL` | 代表的な詳細ページ |
| `References` | 関連資料のURL一覧 |
| `DataSource.ID`／`DataSource.Name`／`DataSource.URL` | 検出に使うアドバイザリの情報源のID／名前／URL |
| `VendorIDs` | ベンダーのアドバイザリIDなど |
| `Fingerprint` | 対象・パッケージ・脆弱性などの組み合わせの識別用ハッシュ |
| `PublishedDate` | 脆弱性情報の公開日時 |
| `LastModifiedDate` | 脆弱性情報の最終更新日時 |

`PublishedDate`や`LastModifiedDate`は、このイメージで初めて脆弱性を検出した日時ではありません。`DataSource`と`SeveritySource`も、それぞれ検出根拠と深刻度の採用元を表す別の項目です。[^vulnerability-types]

## まとめ

Trivyは、コンテナイメージやローカルファイル、Gitリポジトリなどを対象に、既知の脆弱性や設定上の問題を検出するセキュリティスキャナーです。

- スキャン対象やオプションによって、検査できる範囲が異なる
- JSON出力では、パッケージ一覧、脆弱性レコード、イメージの構成情報を確認できる
- 検出レコード数は、重複を除いた脆弱性ID数とは異なる
- `Status: fixed`は修正版の提供を表し、対象イメージの修正完了を意味しない
- `Severity`と併せて、評価元を示す`SeveritySource`や`CVSS`を確認する必要がある
- パッケージが検出されていても、脆弱性情報と照合できているとは限らない
- KEVやEPSSをCVE IDで照合することで、対応の優先順位を判断する材料を補える

スキャン結果を読む際は、どのパッケージが含まれているか、脆弱性情報との照合で何が検出されたか、自分の環境で何を優先して対応するかを分けて考える必要があります。

検出件数や深刻度だけでは、利用環境での影響や対応優先度は決まりません。検査範囲と評価の前提を確認したうえで、修正版の有無、実際の悪用状況、パッケージの利用状況などを組み合わせて判断する必要があります。

## 参考資料

文書の確認日：2026年9月10日。記事中の集計値とJSON出力の抜粋は、2026年9月9日にTrivy 0.71.2で取得したスキャン結果に基づいています。

///Footnotes Go Here///

[^trivy]: [Trivy公式リポジトリ](https://github.com/aquasecurity/trivy)

[^filesystem]: [Filesystemの公式説明](https://trivy.dev/docs/latest/guide/target/filesystem/)

[^repository]: [Code Repositoryの公式説明](https://trivy.dev/docs/latest/target/repository/)

[^reporting]: [出力形式の公式説明](https://trivy.dev/docs/latest/configuration/reporting/)

[^database]: [データベースの公式説明](https://trivy.dev/docs/latest/configuration/db/)

[^filtering]: [ステータスとフィルタリングの公式説明](https://trivy.dev/docs/latest/configuration/filtering/)

[^severity]: [深刻度の選択ルール](https://trivy.dev/docs/latest/guide/scanner/vulnerability/#severity-selection)

[^kev]: [CISA KEVカタログ](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

[^epss]: [EPSSの説明](https://www.first.org/epss/faq)

[^epss-data]: [データの取得方法](https://www.first.org/epss/data)

[^third-party]: [第三者パッケージの扱い](https://trivy.dev/docs/latest/guide/scanner/vulnerability/#third-party-packages)

[^report-types]: [Trivyのレポート型](https://pkg.go.dev/github.com/aquasecurity/trivy/pkg/types)

[^layer-size]: [レイヤーサイズ情報の仕様](https://github.com/aquasecurity/trivy/issues/8767)

[^image-config]: [OCIイメージ設定の仕様](https://github.com/opencontainers/image-spec/blob/main/config.md)

[^package-types]: [Trivy 0.71.2のパッケージ型](https://pkg.go.dev/github.com/aquasecurity/trivy@v0.71.2/pkg/fanal/types#Package)

[^vulnerability-types]: [検出脆弱性の型定義](https://pkg.go.dev/github.com/aquasecurity/trivy/pkg/types#DetectedVulnerability)

---

KestreLynxは、稼働中のDocker・KubernetesコンテナのイメージをTrivyで定期的にスキャンし、前回からの変化と、深刻度・CISA KEV・EPSSに基づく優先度をSlack、メール、またはWebhookへ通知するOSSです。

Docker・Compose・Kubernetes向けの修正計画と修正PR（実験的）で、更新候補の比較からGitHubへのPR作成まで修正を支援します（既定で無効）。マージ・再ビルド・デプロイは利用者が行います。

[KestreLynxについて](../index.md) · [GitHubでソースコードを見る](https://github.com/kitsunetrail/kestrelynx)
