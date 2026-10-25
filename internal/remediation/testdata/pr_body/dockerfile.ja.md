## 概要

KestreLynx は、`example/app` の `build/Dockerfile` にあるベースイメージについて、新しいタグを提案します。

- 現在のベースイメージ: `app:2.0`
- 編集した箇所: ステージ 1 の FROM (3 行目)
- このイメージから作られるワークロード: `compose/app/web`

## 変更内容

- 3 行目の FROM: `debian:12.5` から `debian:12.6` へ

## 確認したこと

- 稼働中のイメージ: `nginx:1.25.3`、config digest `sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`、プラットフォーム `linux/amd64`
  - 稼働中の digest はコンテナランタイムから得たもので、イメージの config digest か、index または manifest の digest かは確認していません。
- 現在のベースイメージ: `debian:12.5`、タグの digest `sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`、プラットフォームの manifest `sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc`、config digest `sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd`、プラットフォーム `linux/amd64`
- 候補のベースイメージ: `nginx:1.25.4`、タグの digest `sha256:1111111111111111111111111111111111111111111111111111111111111111`、プラットフォームの manifest `sha256:2222222222222222222222222222222222222222222222222222222222222222`、config digest `sha256:3333333333333333333333333333333333333333333333333333333333333333`、プラットフォーム `linux/amd64`
- レイヤーの確認: `confirmed`。現在のベースイメージのレイヤーは 3 層、稼働中のイメージは 7 層です。一致が示すのはファイルシステムのレイヤーが揃っていることだけで、イメージの作られ方は示しません。
- 確認の記録: 計画の生成時刻 2026-10-09T04:00:00Z、現在のベースのスキャン `scan-base-1`、候補のベースのスキャン `scan-cand-1`
- この更新が対象とする検出結果 (稼働中のイメージの修正可能な検出結果のうち、ベースイメージのレイヤーにあるもの): 解消 2 件、残存 1 件
- 比較した両ベースイメージのその他の検出結果のうち、候補のベースイメージに残るもの: 1 件、候補のベースイメージで新たに入るもの: 0 件

**解消 (2)**

- `libc6` の `CVE-2026-0001` (`debian`、`os`)、重大度 `CRITICAL`、CISA KEV カタログに掲載、優先度 `act_now`
- `openssl` の `CVE-2026-0002` (`debian`、`os`)、重大度 `HIGH`

**対象の検出結果のうち残存 (1)**

- `zlib1g` の `CVE-2026-0003` (`debian`、`os`)、重大度 `HIGH`

**候補のベースイメージに残るその他の検出結果 (1)**

- `tar` の `CVE-2026-0004` (`debian`、`os`)

**新規 (0)**

- なし

両方のベースイメージを Trivy `0.71.2` でスキャンしました。脆弱性データベースの作成時刻は 2026-10-09T01:02:03Z です。重大度の範囲は `CRITICAL`、`HIGH` です。対象範囲は `os packages` です。

<!-- kestrelynx:{"v":1,"repo_id":7,"base_branch":"main","path":"compose.yml","locations":["services.web.image"],"current_ref":"nginx:1.25.3","candidate_tag":"1.25.4","candidate_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","input_blob_sha":"3333333333333333333333333333333333333333","changes":[{"path":"compose.yml","mode":"100644","blob_sha":"4444444444444444444444444444444444444444"}],"target_key":"d596a66a37dc307e942721c34ab9e199f77f040025dd35c89eca19f67f63a6ca","update_key":"e513bca69279da9566db0a06ac85a0a173b88d9bf1a0a76acc455a31016fe979","attempt_key":"e17763c925cde9702bea370d076aec40d211b1d0658f6a78f56fbf450df9d39d","fix_targets":[{"location":"services.web.image","vuln_id":"CVE-1","package":{"ecosystem":"debian","class":"os","name":"libc"}}]} -->