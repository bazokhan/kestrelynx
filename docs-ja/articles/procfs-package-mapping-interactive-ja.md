---
description: "nginxワーカーが読み込んだlibssl.so.3を、procfsとコンテナ内のdpkgの記録からlibssl3に紐づけ、Trivyの結果との照合で読み込みを確認するまでを8ステップで追う動く図解です。2026年9月12日に計測した実データを使います。"
template: explainer.html
explainer: procfs-packages
hide:
  - navigation
  - toc
---

# procfsのパッケージ紐づけの流れを追う動く図解

公開日：2026年10月5日

## 概要

- 稼働中の`nginx`コンテナのワーカーが読み込んだ`libssl.so.3`を、`/proc`の読み取りとコンテナ内のdpkgの記録から、Trivyが報告した`libssl3` `3.0.16-1~deb12u1`に紐づけ、「読み込みを確認（confirmed）」と記録するまでを8ステップで追う図解
- [procfsで稼働中コンテナのプロセスをOSパッケージに紐づける方法](procfs-process-to-package-mapping-ja.md)で説明した、プロセスからパッケージを特定し、スキャン結果と照合する流れを示す
- 値は2026年9月12日に計測した実データの例で、`nginx:1.27`のイメージから起動したコンテナ`nginx`のワーカー1つを抜粋

## 図解

<div class="klx-explainer" data-klx-explainer="procfs-packages" tabindex="-1">
  <p class="klx-fallback">この図解の操作にはJavaScriptが必要です。</p>
</div>

計測結果と例外・限界は、[procfsで稼働中コンテナのプロセスをOSパッケージに紐づける方法](procfs-process-to-package-mapping-ja.md)で説明しています。
定期読み取りでは捉えにくい短命な動作を、発生時点のイベントとして観測する流れは、[bpftraceの計測プログラムの流れを追う動く図解](bpftrace-event-observation-interactive-ja.md)で説明しています。

---

KestreLynxは、稼働中のDocker・KubernetesコンテナのイメージをTrivyで定期的にスキャンし、前回からの変化と、深刻度・CISA KEV・EPSSに基づく優先度をSlack、メール、またはWebhookへ通知するOSSです。

Docker・Compose・Kubernetes向けの修正計画と修正PR（実験的）で、更新候補の比較からGitHubへのPR作成まで修正を支援します（既定で無効）。マージ・再ビルド・デプロイは利用者が行います。

[KestreLynxについて](../index.md) · [GitHubでソースコードを見る](https://github.com/kitsunetrail/kestrelynx)
