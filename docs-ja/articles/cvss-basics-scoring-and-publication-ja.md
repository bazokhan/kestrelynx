---
description: "CVSSの深刻度と評価・公開の流れ、v4.0の評価グループを解説。NVDでスコアの評価元やベクター文字列を確認し、数値の前提となる攻撃条件と影響、バージョンによる違いを読み取れます。"
---

# CVSSの基礎と評価・公開の流れ

公開日：2026年9月8日

## はじめに

脆弱性情報には、「CVSS 8.8」「Critical」といったスコアや深刻度が記載されています。これらの情報を利用するには、数値の意味に加えて、誰がどの基準で評価し、どこで公開しているかを確認する必要があります。

この記事では、CVSSの意味、スコアの読み方、FIRST・CNA・NVDの役割、評価から公開までの流れ、NVDでの確認方法について記載します。CVSS v4.0を中心に説明し、v3.1との違いも扱います。

## CVSSとは

CVSSは **Common Vulnerability Scoring System** の略で、日本語では「共通脆弱性評価システム」と呼ばれます。攻撃のしやすさや、悪用に成功した場合の影響などを共通の基準で評価し、技術的な深刻度を0.0〜10.0のスコアで表します。

v3.xとv4.0では、スコアに対応する深刻度の区分は次のとおりです。

| スコア | 深刻度 |
| --- | --- |
| 0.0 | None |
| 0.1〜3.9 | Low |
| 4.0〜6.9 | Medium |
| 7.0〜8.9 | High |
| 9.0〜10.0 | Critical |

CVSSは、実際に悪用される確率を直接表す指標ではありません。また、一般に公開されている基本評価だけでは、自分の環境での対応優先度は決まりません。利用環境や悪用状況を反映する仕組みはありますが、事業上の損失なども含めたリスク評価全体をCVSSだけで置き換えることはできません。[FIRST：CVSS v4.0仕様](https://www.first.org/cvss/v4.0/specification-document)

## FIRST・CNA・NVDの役割

CVSSの仕様を管理する組織と、個々の脆弱性を評価・公開する組織の役割は次のとおりです。

| 組織・仕組み | CVSSに関係する役割 |
| --- | --- |
| FIRST | CVSSの仕様を管理する。内部のCVSS SIGが改訂や改善を担当する |
| CNA（CVE Numbering Authority） | 担当範囲のCVE番号を割り当て、CVE Recordを公開する。レコードにCVSS評価を含める場合がある |
| NVD（National Vulnerability Database） | 米国NISTが運営する脆弱性データベース。CVE情報を基にCVSSなどの追加情報を提供する |

FIRSTは、世界のインシデント対応チームなどが参加する国際的な非営利組織です。NVDを運営するNISTとは別組織で、NVDがFIRSTの下部組織という関係ではありません。

CVSSについては、FIRSTが評価ルールを管理し、ベンダー、CNA、NVDなどがそのルールを利用して評価する、という関係になります。FIRSTがすべてのCVEを採点しているわけではありません。[FIRST：CVSS SIG](https://www.first.org/cvss/)、[NVD：Vulnerability Metrics](https://nvd.nist.gov/vuln-metrics/cvss)

## CVSSの評価と公開の流れ

CVSSの評価結果は、CNAがCVE Recordに含める場合や、NVDなどが独自の評価として公開する場合があります。

### CNAがCVE Recordに含める場合

代表的な流れは次のとおりです。

1. ベンダーや評価担当者が、脆弱性の攻撃条件と影響を調べる。
2. 使用するCVSSバージョンの評価項目に値を設定し、スコアを算出する。
3. CNAがスコアとベクター文字列（CVSSのバージョンと各評価項目の値をまとめた文字列）をCVE Recordに含め、CVE Programの指定する仕組みで提出・公開する。

この提出を扱うシステムが「CVE Services」です。公式リポジトリで案内されている本番APIのホストは `cveawg.mitre.org` です。スコアやベクター文字列は、CVE情報の一項目として扱われます。[CVE Services公式説明](https://github.com/CVEProject/cve-services#api-documentation)

公開されたCVE Recordは、GitHubの [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) でもJSON形式で確認できます。このリポジトリは公開データの配布先であり、CNAの通常の登録窓口とは区別されます。

CNA Operational Rulesの4.5.1.2と4.5.5.1には、指定された手順・形式でレコードを提出して公開することが定められています。一方、このルール本文ではCVSSは必須項目として列挙されていません。CVE番号が割り当てられても、必ずCVSSスコアが公開されるとは限りません。[CNA Operational Rules](https://www.cve.org/ResourcesSupport/AllResources/CNARules)

### NVDが評価する場合

NVDは公開されたCVEや関連する公開情報を基に、独自のCVSS評価を行います。評価結果はNVDで公開され、他の組織から提供された評価と併記される場合があります。

NVDの説明によると、NVDが行うのは基本評価（Base）で、現状評価・脅威評価・環境評価・補足評価は提供対象ではありません。利用者が追加の評価を行うための計算機は提供されています。[NVD：Vulnerability Metrics](https://nvd.nist.gov/vuln-metrics/cvss)

したがって、NVDのページで見かけるスコアが、すべてNVD自身の採点結果とは限りません。数値と併せて評価元を見る必要があります。

## CVSSの計算方法と過去の仕様

CVSSの評価項目と計算方法は公開されています。v3.1では評価値に対応する重みや計算式、丸め処理を確認できます。v4.0では方式が変わり、評価の組み合わせをまとめた「MacroVector」に対応するスコア表と、補間による計算手順が使われます。[v3.1公式仕様](https://www.first.org/cvss/v3.1/specification-document)、[v4.0公式仕様](https://www.first.org/cvss/v4.0/specification-document)

過去の仕様もFIRSTの公式サイトに残っています。

| バージョン | 公式資料 |
| --- | --- |
| v1 | [Complete CVSS v1 Guide](https://www.first.org/cvss/v1/guide) |
| v2 | [CVSS v2 Complete Documentation](https://www.first.org/cvss/v2/guide) |
| v3.0 | [CVSS v3.0 Specification Document](https://www.first.org/cvss/v3.0/specification-document) |
| v3.1 | [CVSS v3.1 Specification Document](https://www.first.org/cvss/v3.1/specification-document) |
| v4.0 | [CVSS v4.0 Specification Document](https://www.first.org/cvss/v4.0/specification-document) |

同じバージョンで同じ評価値を入力すれば、同じスコアを再現できます。ただし、「攻撃にはどの権限が必要か」「影響はどの範囲まで及ぶか」といった評価には判断が伴います。計算ルールが共通でも、評価元によって入力値や結果が異なる場合があります。

## CVSS v4.0の評価グループ

CVSS v3.1には、基本評価・現状評価・環境評価の3つの評価グループがあります。v4.0では次の4つの評価グループで構成されます。

| 評価グループ | 評価する内容 |
| --- | --- |
| 基本評価（Base） | 攻撃経路、必要な権限、利用者の操作の必要性、悪用による影響など、脆弱性固有の性質 |
| 脅威評価（Threat） | 実証コード（PoC）の公開や実際の悪用など、時間とともに変わる状況 |
| 環境評価（Environmental） | 利用環境の防御策や、機密性・完全性・可用性の重要度など |
| 補足評価（Supplemental） | 攻撃の自動化や復旧のしやすさなど、判断を補う情報。数値スコアには影響しない |

これは、4種類の独立した点数を足し合わせるという意味ではありません。基本評価を土台に、脅威評価や環境評価を反映してスコアを算出します。[FIRST：CVSS v4.0仕様](https://www.first.org/cvss/v4.0/specification-document)

### スコアの表記と評価グループの関係

スコアに反映した評価グループは、次の表記で区別します。

| 表記 | 明示的に評価したグループ |
| --- | --- |
| CVSS-B | 基本評価 |
| CVSS-BT | 基本評価＋脅威評価 |
| CVSS-BE | 基本評価＋環境評価 |
| CVSS-BTE | 基本評価＋脅威評価＋環境評価 |

脅威評価や環境評価を指定しない場合も、計算では仕様上の既定値が使われます。「未指定だから脅威がない」と解釈するものではありません。公開される基本評価に、利用者が自分の環境や悪用状況を反映することで、対応判断の材料を具体化できます。[FIRST：CVSS v4.0 User Guide](https://www.first.org/cvss/v4.0/user-guide)、[仕様のNomenclature節](https://www.first.org/cvss/v4.0/specification-document#Nomenclature)

## NVDでのスコアの確認方法

個別のCVSS評価は、[NVD](https://nvd.nist.gov/vuln/search)や[JVN iPedia](https://jvndb.jvn.jp/)、製品ベンダーのセキュリティ情報などで確認できます。

ここでは、[CVE-2026-9999のNVD詳細ページ](https://nvd.nist.gov/vuln/detail/CVE-2026-9999)を例に、スコアと評価内容を確認する流れを説明します。以下のスクリーンショットは取得時点の表示であり、掲載内容はその後更新される可能性があります。

### CVSSのバージョンと評価元、スコアの確認

CVE詳細ページを開き、「Metrics」欄の「CVSS Version 3.x」タブを選択します。

![NVDのCVE-2026-9999詳細ページでCVSS Version 3.xタブを選択し、CISA-ADPの基本スコア8.8 HIGHとベクター文字列を表示した画面](../assets/articles/cvss/nvd-cvss-v3-score-and-vector.png)

この画面では、上段に「NIST: NVD」、下段に「ADP: CISA-ADP」と表示されています。それぞれの行で、評価元と「Base Score」を確認します。

| 評価元 | Base Scoreの表示 | 読み取れること |
| --- | --- | --- |
| NIST: NVD | N/A | NVD自身の評価は未掲載 |
| ADP: CISA-ADP | 8.8 HIGH | CISA-ADPによる基本スコアは8.8で、深刻度はHigh |

「NIST: NVD」がN/Aでも、この例のように他の評価元のスコアが掲載されている場合があります。N/Aは0点や安全という意味ではなく、その欄に評価値がないことを示します。

### スコアの横にあるベクター文字列の確認

同じ画面のCISA-ADPの行には、「8.8 HIGH」の右側に「Vector」が表示されています。ここに記載されているのが、CVSSのバージョンと各評価項目の値をまとめたベクター文字列です。

スコアが深刻度を数値で示すのに対し、ベクター文字列からは、そのスコアの前提となる攻撃条件や影響を確認できます。上のスクリーンショットでは、次の文字列が表示されています。

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
```

先頭の`CVSS:3.1`は、v3.1で評価したことを示します。その後は`/`で区切られ、それぞれが「評価項目:値」の形式になっています。この例の各項目は、次のように読み取れます。

| 表記 | この例での意味 |
| --- | --- |
| `CVSS:3.1` | v3.1で評価 |
| `AV:N` | ネットワーク経由で攻撃可能 |
| `AC:L` | 攻撃の複雑さが低い |
| `PR:N` | 攻撃前に権限を持つ必要がない |
| `UI:R` | 攻撃者以外の利用者による操作が必要 |
| `S:U` | 影響が同じセキュリティ権限の管理範囲内に収まる |
| `C:H` | 機密性への影響が高い |
| `I:H` | 完全性への影響が高い |
| `A:H` | 可用性への影響が高い |

例えば、`AV:N`、`PR:N`、`UI:R`からは、ネットワーク経由で攻撃でき、攻撃前の権限は不要ですが、攻撃者以外の利用者による操作が必要な評価であると分かります。このように、数値だけでは分からない攻撃条件を確認できます。

ここでは項目の意味を簡略化しています。詳細な判定条件は[v3.1の公式仕様](https://www.first.org/cvss/v3.1/specification-document)で確認できます。v4.0では項目が異なるため、この文字列の先頭を`4.0`に書き換えて使うことはできません。

### 別のバージョンの評価の確認

同じ「Metrics」欄で「CVSS Version 4.0」タブを選択します。

![NVDのCVE-2026-9999詳細ページでCVSS Version 4.0タブを選択し、NIST: NVDの評価がN/Aと表示された画面](../assets/articles/cvss/nvd-cvss-v4-assessment-not-provided.png)

この画面では、「NIST: NVD」の行に「N/A」と「NVD assessment not yet provided.」が表示され、v4.0のスコアは掲載されていません。

CVSSはバージョンごとに評価項目と計算方法が異なります。v3.1のスコアが公開されていても、v4.0のスコアが自動的に付与されるわけではありません。

v4.0で評価するには、その仕様で必要な情報を確認して採点する必要があります。すべてのCVEに、すべてのバージョンのスコアがそろうわけではありません。[FIRST：CVSS v4.0 User Guide](https://www.first.org/cvss/v4.0/user-guide)

スコアを比較する際は、バージョン、評価元、基本評価か追加の評価を反映したものかを併せて確認する必要があります。

## CVSSとKEV Catalogの関係

CVSSの算出とKEV Catalogへの登録は別の処理です。KEV CatalogはCISAが公開する、実際に悪用された脆弱性のカタログであり、計算して得るスコアではありません。[CISA公式：KEVデータ](https://github.com/cisagov/kev-data)

CVSSが高いというだけでKEV Catalogに登録されるわけではありません。また、KEV Catalogに登録されていないことだけで、悪用されていないと断定することもできません。

v4.0の脅威評価にも悪用状況を反映しますが、それはCVSSの評価項目です。CISAが管理するKEV Catalogへの登録とは区別します。[FIRST：CVSS v4.0仕様](https://www.first.org/cvss/v4.0/specification-document)

## まとめ

CVSSは、脆弱性の技術的な深刻度を共通の基準で評価する仕組みです。

- FIRSTが仕様を管理し、ベンダー、CNA、NVDなどが個々の脆弱性を評価する
- 評価結果はCVE RecordやNVDなどで公開される
- 評価項目と計算方法は公開されており、過去の仕様も確認できる
- v4.0は基本評価・脅威評価・環境評価・補足評価の4グループで構成される
- スコアと併せて、バージョン、評価元、ベクター文字列を確認する必要がある
- NVDでN/Aと表示されていても、0点や安全であることを意味しない
- CVSSの算出とKEV Catalogへの登録は別の処理である

CVSSの数値だけでは、自分の環境での対応優先度は決まりません。脆弱性管理では、評価の前提を確認したうえで、利用環境への影響や実際の悪用状況などと組み合わせて判断する必要があります。

## 参考資料

以下の情報は2026年9月7日に確認しました。CNA Operational RulesとNVDのVulnerability Metricsは、公式ページから取得された本文に基づいています。

- [FIRST: CVSS SIG](https://www.first.org/cvss/)
- [FIRST: CVSS v4.0 Specification Document](https://www.first.org/cvss/v4.0/specification-document)
- [FIRST: CVSS v4.0 User Guide](https://www.first.org/cvss/v4.0/user-guide)
- [FIRST: CVSS v3.1 Specification Document](https://www.first.org/cvss/v3.1/specification-document)
- [NVD: Vulnerability Metrics](https://nvd.nist.gov/vuln-metrics/cvss)
- [NVD: CVE-2026-9999](https://nvd.nist.gov/vuln/detail/CVE-2026-9999)
- [JVN iPedia](https://jvndb.jvn.jp/)
- [CVE Services: API Documentation](https://github.com/CVEProject/cve-services#api-documentation)
- [CVE Program: CNA Operational Rules](https://www.cve.org/ResourcesSupport/AllResources/CNARules)
- [公式CVE List（GitHub）](https://github.com/CVEProject/cvelistV5)
- [CISA: KEV Data](https://github.com/cisagov/kev-data)

CVSSはFIRST.Org, Inc.が所有・管理しており、本記事ではFIRSTの利用条件に基づいて使用しています。

---

KestreLynxは、稼働中のDocker・KubernetesコンテナのイメージをTrivyで定期的にスキャンし、前回からの変化と、深刻度・CISA KEV・EPSSに基づく優先度をSlackやWebhookへ通知するOSSです。Docker・Compose向けの修正計画と修正PR（実験的）で、更新候補の比較からGitHubへのPR作成まで修正を支援します（既定で無効）。マージ・再ビルド・デプロイは利用者が行います。

[KestreLynxについて](../index.md) · [GitHubでソースコードを見る](https://github.com/kitsunetrail/kestrelynx)
