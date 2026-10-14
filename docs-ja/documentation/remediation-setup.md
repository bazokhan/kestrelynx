# 有効化の手順

修正計画と修正PRを有効にする手順と、設定が効いていることの確認方法を説明します。
機能の概要は[修正計画と修正PR](remediation.md#overview)を参照してください。

対応する環境と入力は[対応範囲](remediation-reference.md#scope-and-requirements)、通信先は[外向きの通信](how-it-works.md#outbound-communication)を参照してください。

## 修正計画の有効化 {#enable-fix-plans}

以下の設定例は、既存の`config.yml`の該当箇所へ統合してください。
同じファイルに`remediation`セクションを重複して追加しないでください。

### GitHubアクセスの準備 {#prepare-github-access}

1. 対応付けるGitHubリポジトリと、ソースの取得元・PRの宛先にするブランチを決める
2. [GitHubアクセス](configuration.md#remediation-github)で、ソースの読み取りとPR作成に必要な権限を確認する
3. tokenが必要な用途では、対象リポジトリに限定したtokenを用意し、`remediation.github.token`に設定する
4. tokenを含む設定ファイルは所有者だけが読めるようにし、リポジトリへのコミット対象から外す

### Workloadの確認 {#identify-workload}

1. 対象の稼働コンテナを`docker inspect`で確認する
2. `com.docker.compose.project`と`com.docker.compose.service`のラベル値を控える
3. ラベル値から、対応付けに使う`compose/<project>/<service>`形式のWorkloadキーを組み立てる

projectが`example`、serviceが`web`なら、Workloadキーは`compose/example/web`です。
形式の詳細は[ソースの対応付け](configuration.md#remediation-mappings)を参照してください。

!!! note "Composeプロジェクト名"

    実際の配置で使っているComposeプロジェクト名を確認してください。リポジトリ名やディレクトリ名とは異なることがあります。

### ソースの対応付け {#map-source}

1. 更新対象に合わせて、[ソースの対応付け](configuration.md#remediation-mappings)から設定する種類を選ぶ
2. Workload、リポジトリ、ベースブランチ、対象ファイルの場所を実際の値に置き換える
3. 修正計画を有効にし、最初はPR作成を無効にした状態で設定する

配布イメージの参照をComposeファイルへ対応付ける最小限の例です。

```yaml
remediation:
  enabled: true
  pull_requests:
    enabled: false
  mappings:
    - workload: compose/example/web
      repository: example/deployment
      base_branch: main
      compose:
        path: compose.yml
        service: web
```

依存ファイルやDockerfileの指定方法、複数の対応付けを使う場合の制約は[ソースの対応付け](configuration.md#remediation-mappings)を参照してください。
有効化キーの詳細は[有効化設定](configuration.md#remediation-enablement)に記載しています。

### 非公開イメージの認証 {#configure-registry-auth}

公開イメージだけを扱う場合、この設定は不要です。

1. 対象イメージを読み取れる認証情報を用意する
2. [イメージレジストリの認証](configuration.md#remediation-registries)に従い、対象ホストと認証情報を追加する
3. 別ホストのtoken serviceを使う場合は、認証情報の送付先を確認して`token_hosts`を設定する

```yaml
remediation:
  registries:
    - host: registry.example.com
      username: example-puller
      password: "REPLACE_WITH_REGISTRY_READ_TOKEN"
```

各キーの形式と設定条件は[イメージレジストリの認証](configuration.md#remediation-registries)を参照してください。
認証情報が送られる範囲は[認証情報の送付範囲](how-it-works.md#credential-destinations)に記載しています。

!!! note "記録の保存先"

    配布のCompose構成では、記録は状態保存用のボリュームに保存されます。`remediation.storage_dir`を変える場合は、コンテナを作り直しても残る場所を指定してください。詳細は[保存先](configuration.md#remediation-storage)を参照してください。

### 修正計画の起動確認 {#verify-fix-plans}

1. 配布のCompose構成では、KestreLynxの配置ディレクトリで`docker compose up -d --force-recreate kestrelynx`を実行する
2. `docker compose logs -f kestrelynx`で、設定の読み込みと修正計画の有効化を確認する
3. 起動後または次の予定時刻のスキャンで、対象イメージのスキャンと修正計画の処理結果を確認する
4. 通知に表示されたWorkload、ソース、更新対象が意図したものか確認する

表示の意味は[結果の表示項目](remediation-results.md#slack-fields)を参照してください。
起動に失敗した場合は[起動時の検証](configuration.md#remediation-validation)、計画が見つからない場合は[計画が出ない場合の確認](remediation-troubleshooting.md#check-missing-plan)へ進んでください。

## 修正PRの有効化 {#enable-pull-requests}

[修正計画の起動確認](#verify-fix-plans)を終えてから、PR作成を有効にしてください。

!!! note "Docker API"

    言語パッケージの更新では、KestreLynxがDocker APIで作業用コンテナを作成・起動・削除します。Docker socketの`:ro`はAPI操作を制限しないため、配布のCompose構成では`:rw`へ変更する必要はありません。Docker APIのプロキシを使う場合は、これらの操作を許可してください。

### PR作成の有効化 {#enable-pr-creation}

1. [GitHubアクセスの準備](#prepare-github-access)で設定したtokenに、PR作成に必要なアクセスがあることを確認する
2. 既存の対応付け、認証情報、保存先を保持したまま、PR作成を有効にする
3. KestreLynxのコンテナを再作成し、ログでPR作成が有効になったことを確認する

```yaml
remediation:
  enabled: true
  pull_requests:
    enabled: true
```

キーの詳細は[有効化設定](configuration.md#remediation-enablement)を参照してください。
PR数や依存更新の処理量を調整する場合は[処理の上限](configuration.md#remediation-limits)を確認してください。

!!! note "リポジトリのワークフロー"

    PRを作ると、対象リポジトリの`pull_request`を契機とするワークフローが起動することがあります。

PR本文のHTMLコメントには、記録の照合と復旧に使う識別マーカーがあるため、本文を編集する場合も残してください。
PRが作られない場合は[PRを作れない場合の確認](remediation-troubleshooting.md#check-missing-pr)を参照してください。
