## 概要

KestreLynx は、`example/app` の `compose.yml` にある 2 件の Compose サービスについて、新しいイメージタグを提案します。

- 稼働中のイメージ: `nginx:1.25.3`
- 編集したサービス: `web`、`worker`
- これらを実行しているワークロード: `compose/app/web`、`compose/app/worker`
- 同じイメージを実行していますが編集していないもの (Compose の対応付けなし): `app/extra (app-extra-1)`、`loose`

## 変更内容

- `services.web.image`: `nginx:1.25.3` から `nginx:1.25.4` へ
- `services.worker.image`: `nginx:1.25.3` から `nginx:1.25.4` へ

## 確認したこと

- 稼働中: `nginx:1.25.3`、config digest `sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`、プラットフォーム `linux/amd64`
  - 稼働中の digest はコンテナランタイムから得たもので、イメージの config digest か、index または manifest の digest かは確認していません。
- 候補: `nginx:1.25.4`、タグの digest `sha256:1111111111111111111111111111111111111111111111111111111111111111`、プラットフォームの manifest `sha256:2222222222222222222222222222222222222222222222222222222222222222`、config digest `sha256:3333333333333333333333333333333333333333333333333333333333333333`、プラットフォーム `linux/amd64`
- 場所: `services.web.image`、`services.worker.image`
- 確認の記録: 計画の生成時刻 2026-10-09T04:00:00Z、変更前のスキャン `scan-base-1`、候補のスキャン `scan-cand-1`
- この更新が対象とする検出結果 (稼働中のイメージの修正可能な検出結果): 解消 2 件、残存 1 件
- 稼働中のイメージのその他の検出結果 (この更新の対象外。修正版の報告がないものなど) のうち、候補のイメージで検出されなくなるもの: 1 件、候補のイメージに残るもの: 1 件。候補のイメージで新たに入る検出結果: 0 件

**解消 (2)**

- `libc6` の `CVE-2026-0001` (`debian`、`os`)、重大度 `CRITICAL`、CISA KEV カタログに掲載、優先度 `act_now`
- `openssl` の `CVE-2026-0002` (`debian`、`os`)、重大度 `HIGH`

**対象の検出結果のうち残存 (1)**

- `zlib1g` の `CVE-2026-0003` (`debian`、`os`)、重大度 `HIGH`

**候補のイメージで検出されなくなるその他の検出結果 (1)**

- `libheif1` の `CVE-2026-0005` (`debian`、`os`)、重大度 `HIGH`

**候補のイメージに残るその他の検出結果 (1)**

- `tar` の `CVE-2026-0004` (`debian`、`os`)

**新規 (0)**

- なし

両方のイメージを Trivy `0.71.2` でスキャンしました。脆弱性データベースの作成時刻は 2026-10-09T01:02:03Z です。重大度の範囲は `CRITICAL`、`HIGH` です。対象範囲は `os packages` です。

<!-- kestrelynx:{"v":1,"repo_id":7,"base_branch":"main","path":"compose.yml","locations":["services.web.image"],"current_ref":"nginx:1.25.3","candidate_tag":"1.25.4","candidate_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","input_blob_sha":"3333333333333333333333333333333333333333","changes":[{"path":"compose.yml","mode":"100644","blob_sha":"4444444444444444444444444444444444444444"}],"target_key":"d596a66a37dc307e942721c34ab9e199f77f040025dd35c89eca19f67f63a6ca","update_key":"e513bca69279da9566db0a06ac85a0a173b88d9bf1a0a76acc455a31016fe979","attempt_key":"e17763c925cde9702bea370d076aec40d211b1d0658f6a78f56fbf450df9d39d","fix_targets":[{"location":"services.web.image","vuln_id":"CVE-1","package":{"ecosystem":"debian","class":"os","name":"libc"}}]} -->