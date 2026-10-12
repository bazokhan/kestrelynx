## 概要

KestreLynx は、`example/app` の `svc/pnpm-lock.yaml` にある 1 件のパッケージエントリを `uv` で更新することを提案します。

- 依存関係のディレクトリ: `svc`
- パッケージマネージャー: `uv`
- これらのパッケージを実行しているワークロード: `compose/app/web`
- 変更したファイル: `svc/pnpm-lock.yaml`

## 変更内容

更新前の稼働中の版から更新後の版へ、プロジェクトがそのパッケージをどう要求しているかとあわせて示します。

- `lodash`: `4.17.20` から `4.17.21` へ (直接依存)

### この更新が対象とする脆弱性

- `lodash` の `CVE-2026-1111`、重大度 `CRITICAL`、CISA KEV カタログに掲載、優先度 `act_now`

## 確認したこと

- 実行した版: 記録なし (記録を残す前に作られた更新です)

- マージ前に CI で lockfile からのインストール (例: `uv sync --locked`) を実行してください

<!-- kestrelynx:{"v":1,"repo_id":7,"base_branch":"main","path":"compose.yml","locations":["services.web.image"],"current_ref":"nginx:1.25.3","candidate_tag":"1.25.4","candidate_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","input_blob_sha":"3333333333333333333333333333333333333333","changes":[{"path":"compose.yml","mode":"100644","blob_sha":"4444444444444444444444444444444444444444"}],"target_key":"d596a66a37dc307e942721c34ab9e199f77f040025dd35c89eca19f67f63a6ca","update_key":"e513bca69279da9566db0a06ac85a0a173b88d9bf1a0a76acc455a31016fe979","attempt_key":"e17763c925cde9702bea370d076aec40d211b1d0658f6a78f56fbf450df9d39d","fix_targets":[{"location":"services.web.image","vuln_id":"CVE-1","package":{"ecosystem":"debian","class":"os","name":"libc"}}]} -->