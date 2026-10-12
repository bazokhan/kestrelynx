## 概要

KestreLynx は、`example/app` の `compose.yml` にある 2 件の Compose サービスについて、新しいイメージタグを提案します。ベースブランチは `main`、コミットは `1111111111111111111111111111111111111111` です。

- 稼働中のイメージ: `nginx:1.25.3`
- 編集したサービス: `web`、`worker`
- これらを実行しているワークロード: `compose/app/web`、`compose/app/worker`
- 同じイメージを実行していますが編集していないもの (Compose の対応付けなし): `app/extra (app-extra-1)`、`loose`

## 変更内容

- `services.web.image`: `nginx:1.25.3` から `nginx:1.25.4` へ
- `services.worker.image`: `nginx:1.25.3` から `nginx:1.25.4` へ

## この候補を選んだ理由

`1.25.4` は、完全なタグ一覧のうち、稼働中のタグのメジャーバージョン、マイナーバージョン、接頭辞、接尾辞を保つ最新のパッチリリースです。

## 確認したこと

- 稼働中: `nginx:1.25.3`、config digest `sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`、プラットフォーム `linux/amd64`
  - 稼働中の digest はコンテナランタイムから得たもので、イメージの config digest か、index または manifest の digest かは確認していません。
- 候補: `nginx:1.25.4`、タグの digest `sha256:1111111111111111111111111111111111111111111111111111111111111111`、プラットフォームの manifest `sha256:2222222222222222222222222222222222222222222222222222222222222222`、config digest `sha256:3333333333333333333333333333333333333333333333333333333333333333`、プラットフォーム `linux/amd64`
- 場所: `services.web.image`、`services.worker.image`
- 確認の記録: 計画の生成時刻 2026-10-09T04:00:00Z、変更前のスキャン `scan-base-1`、候補のスキャン `scan-cand-1`
- 解消 2 件、残存 1 件、新規 0 件

**解消 (2)**

- `libc6` の `CVE-2026-0001` (`debian`、`os`)、重大度 `CRITICAL`、CISA KEV カタログに掲載、優先度 `act_now`
- `openssl` の `CVE-2026-0002` (`debian`、`os`)、重大度 `HIGH`

**残存 (1)**

- `zlib1g` の `CVE-2026-0003` (`debian`、`os`)、重大度 `HIGH`

**新規 (0)**

- なし

両方のイメージを Trivy `0.71.2` でスキャンしました。脆弱性データベースの作成時刻は 2026-10-09T01:02:03Z です。重大度の範囲は `CRITICAL`、`HIGH` です。対象範囲は `os packages` です。

## 確認していないこと

- アプリケーションが新しいイメージで動作するか
- 継続的インテグレーション (このプルリクエストを開くと、リポジトリの CI が起動することがあります)
- マージ後のデプロイ: マージで変わるのはファイルだけで、稼働中のコンテナは再作成するまで古いイメージのままです
- 上記の範囲外の重大度の脆弱性

---

KestreLynx が作成しました。更新キー `uk1`、試行キー `ak1`。

<!-- kestrelynx:{"v":1,"repo_id":7,"base_branch":"main","path":"compose.yml","locations":["services.web.image"],"current_ref":"nginx:1.25.3","candidate_tag":"1.25.4","candidate_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","input_blob_sha":"3333333333333333333333333333333333333333","changes":[{"path":"compose.yml","mode":"100644","blob_sha":"4444444444444444444444444444444444444444"}],"target_key":"d596a66a37dc307e942721c34ab9e199f77f040025dd35c89eca19f67f63a6ca","update_key":"e513bca69279da9566db0a06ac85a0a173b88d9bf1a0a76acc455a31016fe979","attempt_key":"e17763c925cde9702bea370d076aec40d211b1d0658f6a78f56fbf450df9d39d","fix_targets":[{"location":"services.web.image","vuln_id":"CVE-1","package":{"ecosystem":"debian","class":"os","name":"libc"}}]} -->