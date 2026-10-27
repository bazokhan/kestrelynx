---
description: "コンテナ内のcurl 1回分の実行とファイルオープンが、bpftraceの出力行を経てコンテナID付きのイベントになるまでを9ステップで追う動く図解です。開始と結果の対応付け、時刻・パス・コンテナの補完、JSONLへの書き出しを確認できます。"
template: explainer.html
explainer: bpftrace-events
hide:
  - navigation
  - toc
---

# bpftraceの計測プログラムの流れを追う動く図解

公開日：2026年10月5日

## 概要

- コンテナ内の`curl` 1回分の実行とファイルオープンが、bpftraceの出力行を経てコンテナID付きのイベントになるまでを、9ステップで追う図解
    - `node`など他のプログラムの実行とファイルオープンも、同じ流れで記録される
- [bpftraceでコンテナの実行とファイルオープンを観測する](bpftrace-container-exec-open-events-ja.md)で使った計測プログラムの流れを示す
- 値は説明用の例で、E・O・Xの行の書式は実際のスクリプトの出力書式どおり

## 図解

<div class="klx-explainer" data-klx-explainer="bpftrace-events" tabindex="-1">
  <p class="klx-fallback">この図解の操作にはJavaScriptが必要です。</p>
</div>

計測結果と実装の詳細は、[bpftraceでコンテナの実行とファイルオープンを観測する](bpftrace-container-exec-open-events-ja.md)で説明しています。
定期読み取りの方法とサンプリングの限界は、[procfsで稼働中コンテナのプロセスをOSパッケージに紐づける方法](procfs-process-to-package-mapping-ja.md)を参照してください。

---

KestreLynxは、稼働中のDocker・KubernetesコンテナのイメージをTrivyで定期的にスキャンし、前回からの変化と、深刻度・CISA KEV・EPSSに基づく優先度をSlack、メール、またはWebhookへ通知するOSSです。

Docker・Compose・Kubernetes向けの修正計画と修正PR（実験的）で、更新候補の比較からGitHubへのPR作成まで修正を支援します（既定で無効）。マージ・再ビルド・デプロイは利用者が行います。

[KestreLynxについて](../index.md) · [GitHubでソースコードを見る](https://github.com/kitsunetrail/kestrelynx)
