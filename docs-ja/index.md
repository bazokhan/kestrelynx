---
template: home.html
hide:
  - navigation
  - toc
  - footer
---

<div class="kl-hero" markdown>
<div class="kl-hero__text" markdown>

Docker · Kubernetes · Trivy · CISA KEV · EPSS
{ .kl-eyebrow }

# コンテナイメージの脆弱性スキャン・通知・修正

KestreLynxは、Docker・Kubernetesで稼働中のコンテナが使うイメージを[Trivy](https://trivy.dev/)で定期的にスキャンするOSSです。前回からの変化と、深刻度・[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)・[EPSS](https://www.first.org/epss/)に基づく優先度をSlackやWebhookへ通知します。

Docker・Compose・Kubernetes向けの[修正計画と修正PR（実験的）](documentation/remediation.md)を備え、同じ条件での再スキャン結果の比較とGitHubへのPR作成を通じて修正を支援します（既定で無効）。

[セットアップ](documentation/getting-started.md){ .md-button .md-button--primary }
[GitHub](https://github.com/kitsunetrail/kestrelynx){ .md-button }
{ .kl-actions }

オープンソース · AGPL-3.0
{ .kl-license }

</div>
<figure class="kl-notification">
<div class="kl-slack">
<div class="kl-slack__channel"># security-alerts</div>
<div class="kl-slack__message">
<div class="kl-slack__avatar" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z"/></svg></div>
<div class="kl-slack__body">
<p class="kl-slack__meta"><strong>KestreLynx</strong> <span class="kl-slack__badge">アプリ</span> <span class="kl-slack__time">9:00</span></p>
<p>🛡️ <strong>KestreLynx</strong> [prod-vps] — 2026-06-28 09:00のスキャン結果<br>イメージ12件をスキャン、1件に影響あり<br><em>前回のスキャンからの変化</em></p>
<hr>
<p><strong>🆕 前回のスキャンからの新規検出 (1件)</strong><br>イメージ: <code>nginx:1.25.3</code></p>
<p><strong>◆ libnghttp2-14</strong><br><strong>現在:</strong> 1.52.0-1<br><strong>修正版:</strong> 1.52.0-1+deb12u1<br><strong>更新の注意度:</strong> 🟢 ディストリのセキュリティパッチ<br><strong>検出件数:</strong> CRITICAL 0 / HIGH 2</p>
<p><strong>代表CVE:</strong> <span class="kl-slack__link">CVE-2023-44487</span> · HIGH · EPSS &gt;99% (このパッケージにほか +1件のCVE)<br><strong>悪用情報:</strong> CISA KEV (実際の攻撃で悪用あり)<br><strong>参照:</strong> <span class="kl-slack__link">アドバイザリ</span> · <span class="kl-slack__link">ベンダーのアドバイザリ</span> · 💬 <span class="kl-slack__link">HN (166 pts)</span></p>
<hr>
<p>📌 <strong>現在の未解決:</strong> 🚨 今すぐ対応1件</p>
</div>
</div>
</div>
<figcaption>既定の<code>diff</code>モード、<code>notify.language: ja</code>での通知のサンプルです。値は説明用で、実環境のスキャン結果ではありません。</figcaption>
</figure>
</div>

<div class="kl-callouts" markdown>

- **新規検出** 「前回のスキャンからの新規検出」でイメージとパッケージを確認
- **修正版の有無** 「現在」と「修正版」で使用中のバージョンと修正版を確認
- **優先度** 「現在の未解決」で優先度別の件数、KEVとEPSSで判断材料を確認

</div>

<div class="kl-section kl-features" markdown>
<div markdown>

:material-history:

## 前回からの変化を追う

差分通知で、新規検出、CVEの追加、修正版の提供開始、優先度の上昇、監視範囲から消えた検出を確認できます。未解消の検出があれば変化のない日も短い通知が届き、既定では月曜の通知に全件レポートが加わります。

</div>
<div markdown>

:material-sort-variant:

## KEVとEPSSを確認の優先順位に

深刻度にCISA KEVとEPSSの情報を組み合わせ、「今すぐ対応」「要監視」「低優先度」に分類します。確認する順番の判断材料であり、その環境で悪用できるかを確定するものではありません。

</div>
<div markdown>

:material-magnify-scan:

## Trivyの結果に修正版と更新の注記を添える

Trivyでスキャンし、既定では修正版のないものも含めてHIGH・CRITICALの脆弱性を報告します。パッケージごとに修正版があればそのバージョンと更新リスクの目安を示しますが、互換性は保証しません。

</div>
</div>

<div class="kl-section" markdown>

## 修正計画と修正PR（実験的）

Kubernetesの修正計画は、配布イメージの更新候補、浮動タグの再取得の案内、言語パッケージの更新候補を提示します。
KubernetesのPRは、プレーンなマニフェストのイメージタグ、[Kustomizeの`images[].newTag`](documentation/remediation-setup.md#kustomize-pull-requests)、[Helmのvaluesのイメージタグ](documentation/remediation-setup.md#helm-values-pull-requests)、Dockerfileのベースイメージに加え、[作業用Podを設定](documentation/remediation-setup.md#kubernetes-language-updates)するとnpm・pnpm・pip・uvの更新にも対応します。
npm・pnpm・uvでは、対応する条件の下で依存元からの再解決も行います。
Docker・Compose向けに、次の3種類のソースの変更を提案できます。

- Composeファイルの配布イメージのタグ
- Dockerfileのベースイメージのタグ
- npm・pnpm・pip・uvで管理する言語パッケージの依存

修正計画と修正PRは、どちらも既定で無効です。計画は候補の選定、スキャン結果の比較、
通知を行い、GitHubへの書き込みや作業用コンテナの起動は行いません。
PRを別途有効にすると、GitHubへの変更と、言語パッケージ更新用のDockerの作業用コンテナ、または利用者が設定したKubernetesの作業用Podを使います。

以下は古いイメージと依存を意図的に固定した[デモ用リポジトリ](https://github.com/kitsunetrail/kestrelynx-demo)での実際の出力（英語UI）で、[作成されたPR](https://github.com/kitsunetrail/kestrelynx-demo/pulls)も公開しています。

Slackの修正計画には作成された3件のPRと、新たな所見が入るため「Needs a decision」となったDockerfileのベース更新候補が表示されています。

![Compose・pip・npmの更新PRと、判断が必要なDockerfileのベース更新候補を示すSlackの修正計画](assets/screenshots/slack-fix-plan.png)

[PR #1](https://github.com/kitsunetrail/kestrelynx-demo/pull/1)はnginx 1.27.0から1.27.5への更新を提案し、候補のスキャン比較結果として、更新対象の所見のうち17件が解消、86件が残ることを記載しています。

![What・Change・Verificationを記載したGitHubのPR本文で、対象外の所見は94件残り、新たな所見は0件](assets/screenshots/pr-compose-body.png)

PR #1をマージして稼働中の`proxy`コンテナをnginx 1.27.5に入れ替えた後、次のスキャンでは履歴を引き継ぎ、4パッケージの所見の解消が通知されています。

![nginxのイメージ更新と、libabsl20220623・libavif15・libfreetype6・liblzma5の所見の解消を示すSlackのスキャン通知](assets/screenshots/slack-resolved.png)

候補やPRがあることは、稼働イメージが修正済みであることを意味しません。
比較した範囲を確認し、マージ前にCIを実行してください。再ビルドとデプロイは別途必要です。

設定、通知、権限は[修正計画と修正PR（実験的）](documentation/remediation.md)に記載しています。

</div>

<div class="kl-section" markdown>

## 用途・対応範囲・必要な権限

セルフホストしているサービスについて、稼働中のコンテナが使うイメージの脆弱性を継続して確認する用途に向いています。

<dl class="kl-scope" markdown>
<dt>Docker</dt>
<dd markdown="span">ホストごとに1インスタンスを配置し、複数のComposeプロジェクトと単独コンテナをまとめて対象にする</dd>
<dt>Kubernetes</dt>
<dd markdown="span">クラスタ内のDeploymentから、読み取り専用のAPI操作で全namespaceまたは指定namespaceの稼働中コンテナを発見し、言語パッケージ更新を設定した場合だけ作業用namespaceに限定した追加権限を使う</dd>
<dt>Kubernetesの検証範囲</dt>
<dd markdown="span">linux/amd64の単一ノードK3s＋containerdのみ検証済みで、複数ノード、arm64、マネージドKubernetes、認証付きプライベートレジストリは未検証 [検証の記録](development/kubernetes-support.md)</dd>
<dt>発見の範囲</dt>
<dd markdown="span">発見時に稼働中のコンテナが対象で、Kubernetesのネイティブsidecarを含み、通常のinit containerとephemeral containerは対象外</dd>
<dt>Docker socketの権限</dt>
<dd markdown="span">コンテナ情報やイメージの読み取りに加え、修正PR有効時は言語パッケージ更新用の作業用コンテナの作成・起動・削除にも使い、`:ro`はDocker APIの権限を制限せず`:rw`への変更も不要なため、接続先のイメージを信頼できることが前提</dd>
</dl>

</div>

<div class="kl-section kl-steps" markdown>

## セットアップ

Docker Composeでの手順です。Docker Composeが使えるDockerホストと、通知先が1つ以上必要です。通知先はSlack Incoming Webhook、Slack Botとチャンネル、汎用Webhookから選べます。Kubernetesでの手順は[セットアップ](documentation/getting-started.md#kubernetes)を参照してください。

1. リポジトリを取得してディレクトリへ移動する

    ```sh
    git clone https://github.com/kitsunetrail/kestrelynx.git
    cd kestrelynx
    ```

2. 設定ファイルを作る

    設定例を`config.yml`にコピーし、通知先と`notify.language: ja`を設定する
    { .kl-step-note }

    ```sh
    cp config.example.yml config.yml
    ${EDITOR:-vi} config.yml
    ```

3. タイムゾーンを確認して起動する

    スキャン時刻は`docker-compose.yml`の`TZ`に従うため、既定の`UTC`を確認し、日本時間なら`Asia/Tokyo`に変更する
    { .kl-step-note }

    ```sh
    ${EDITOR:-vi} docker-compose.yml
    docker compose up -d
    ```

4. ログで起動とスキャンを確認する

    設定例では起動時に1回スキャンし、以後は毎日09:00に実行する
    { .kl-step-note }

    ```sh
    docker compose logs -f
    ```

:material-information-outline: 差分通知や初回検出日の履歴を保つため、コンテナを作り直すときも`kestrelynx-state`ボリュームは削除しない
{ .kl-note }

:material-information-outline: 動作報告は[Discussions](https://github.com/kitsunetrail/kestrelynx/discussions/categories/trying-kestrelynx)で受け付けています。
{ .kl-note }

</div>

<div class="kl-section" markdown>

## ドキュメント・開発ログ・技術記事

<div class="kl-links" markdown>
<div markdown>

### ドキュメント

- [セットアップ](documentation/getting-started.md)
- [設定](documentation/configuration.md)
- [修正計画と修正PR（実験的）](documentation/remediation.md)
- [稼働時の使用状況（実験的）](documentation/runtime-usage.md)
- [仕組み](documentation/how-it-works.md)

</div>
<div markdown>

### 開発ログ

- [Kubernetes対応の開発](development/kubernetes-support.md)
- [eBPFによる実行時証拠の観測調査](development/runtime-event-evidence.md)
- [開発ログの一覧 →](development/index.md){ .kl-more }

</div>
<div markdown>

### 技術記事

- [Trivyの基礎とスキャン結果の読み方](articles/trivy-basics-scan-results-ja.md)
- [EPSSの基礎とスコアの確認方法](articles/epss-exploit-prediction-scoring-system-ja.md)
- [コンテナの脆弱性スキャンで検出されたパッケージの実行時利用状況を確認する方法](articles/which-container-scan-findings-are-actually-running-ja.md)
- [技術記事の一覧 →](articles/index.md){ .kl-more }

</div>
</div>

不具合の報告や改善の提案は[GitHub Issues](https://github.com/kitsunetrail/kestrelynx/issues)へ。
{ .kl-issues }

</div>
