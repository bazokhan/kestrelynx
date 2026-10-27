# 有効化の手順

修正計画と修正PRを有効にする手順と、設定が効いていることの確認方法を説明します。
機能の概要は[修正計画と修正PR](remediation.md#overview)を参照してください。

対応する環境と入力は[対応範囲](remediation-reference.md#scope-and-requirements)、通信先は[外向きの通信](outbound-communication.md#outbound-communication)を参照してください。

## 修正計画の有効化 {#enable-fix-plans}

以下の設定例は、既存の`config.yml`の該当箇所へ統合してください。
同じファイルに`remediation`セクションを重複して追加しないでください。

### Kubernetesの設定 {#kubernetes-plans}

Kubernetesの既存設定に`remediation.enabled: true`を追加します。
配布イメージの比較には対応付けが不要で、言語パッケージの候補を調べる場合は次のように依存ディレクトリを指定します。

```yaml
remediation:
  enabled: true
  pull_requests:
    enabled: false
  mappings:
    - workload: deployment/example/web/app
      repository: example/application
      base_branch: main
      dependencies:
        directory: .
```

`workload`は通知のワークロードキーに合わせます。
形式と名前空間の制約は[ソースの対応付け](configuration.md#remediation-mappings)を参照してください。

設定したConfigMapを適用してKestreLynxのPodを再起動し、ログで設定の読み込みと計画の処理結果を確認します。
配布構成では`kubectl logs -n kestrelynx deployment/kestrelynx -f`でログを確認できます。

### GitHubアクセスの準備 {#prepare-github-access}

1. 対応付けるGitHubリポジトリと、ソースの取得元・PRの宛先にするブランチを決める
2. [GitHubアクセス](configuration.md#remediation-github)で、ソースの読み取りとPR作成に必要な権限を確認する
3. tokenが必要な用途では、対象リポジトリに限定したtokenを用意し、`remediation.github.token`に設定する
4. tokenを含む設定ファイルは所有者だけが読めるようにし、リポジトリへのコミット対象から外す

### Workloadの確認 {#identify-workload}

次の手順はCompose向けです。
Kubernetesでは[対応付けの形式](configuration.md#remediation-mappings)に従い、通知のワークロードキーを使います。

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

### docker runのコンテナの対応付け {#docker-run-mappings}

Composeを使わずに起動したコンテナは、Dockerモードで名前から対応付けます。

1. `docker ps --format '{{.Names}}'`で、`docker run --name`で付けた稼働コンテナの名前を確認する
2. `remediation.mappings`の`workload`に`container/<名前>`を指定し、リポジトリとベースブランチを設定する
3. ベースイメージの更新には`dockerfile`、言語パッケージの更新には`dependencies`を指定する
4. 修正計画を有効にし、最初はPR作成を無効にした状態で設定する

`example-api`のDockerfileと依存ディレクトリを、別々の項目で対応付ける例です。

```yaml
remediation:
  enabled: true
  pull_requests:
    enabled: false
  mappings:
    - workload: container/example-api
      repository: example/application
      base_branch: main
      dockerfile:
        path: Dockerfile
    - workload: container/example-api
      repository: example/application
      base_branch: main
      dependencies:
        directory: .
```

- 同じアプリケーションのコンテナを作り直すときは、`docker run --name`で同じ名前を指定する
- KestreLynxはコンテナが指定したリポジトリから作られたことを確かめないため、名前を別のアプリケーションに使い回さない
- 名前を使い回すと、別のアプリケーションの所見に基づくPRが、設定に残ったリポジトリに作られることがある

名前と設定の制約は[ソースの対応付け](configuration.md#remediation-mappings)、対象となる時点とイメージストアの制限は[docker runのコンテナ](remediation-reference.md#docker-run-containers)を参照してください。

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
認証情報が送られる範囲は[認証情報の送付範囲](outbound-communication.md#credential-destinations)に記載しています。

!!! note "記録の保存先"

    配布のCompose構成では、記録は状態保存用のボリュームに保存されます。`remediation.storage_dir`を変える場合は、コンテナを作り直しても残る場所を指定してください。詳細は[保存先](configuration.md#remediation-storage)を参照してください。

### 修正計画の起動確認 {#verify-fix-plans}

次の手順はCompose向けで、Kubernetesの起動確認は[Kubernetesの設定](#kubernetes-plans)を参照してください。

1. 配布のCompose構成では、KestreLynxの配置ディレクトリで`docker compose up -d --force-recreate kestrelynx`を実行する
2. `docker compose logs -f kestrelynx`で、設定の読み込みと修正計画の有効化を確認する
3. 起動後または次の予定時刻のスキャンで、対象イメージのスキャンと修正計画の処理結果を確認する
4. 通知に表示されたWorkload、ソース、更新対象が意図したものか確認する

表示の意味は[結果の表示項目](remediation-results.md#slack-fields)を参照してください。
起動に失敗した場合は[起動時の検証](configuration.md#remediation-validation)、計画が見つからない場合は[計画が出ない場合の確認](remediation-troubleshooting.md#check-missing-plan)へ進んでください。

## 修正PRの有効化 {#enable-pull-requests}

[修正計画の起動確認](#verify-fix-plans)を終えてから、PR作成を有効にしてください。

!!! note "Docker API"

    Dockerモードの言語パッケージ更新では、KestreLynxがDocker APIで作業用コンテナを作成・起動・削除します。Docker socketの`:ro`はAPI操作を制限しないため、配布のCompose構成では`:rw`へ変更する必要はありません。Docker APIのプロキシを使う場合は、これらの操作を許可してください。

### KubernetesのPR設定 {#kubernetes-pull-requests}

`deployment/example/web/app`のイメージタグを`apps/web.yaml`で更新し、`deployment/example/api/app`のベースイメージを`docker/Dockerfile`で更新する例です。
既存のKubernetes設定で、GitHub tokenと対応付けを設定し、`remediation.pull_requests.enabled`を有効にします。

```yaml
remediation:
  enabled: true
  github:
    token: "REPLACE_WITH_GITHUB_TOKEN"
  pull_requests:
    enabled: true
  mappings:
    - workload: deployment/example/web/app
      repository: example/deployment
      base_branch: main
      manifest:
        path: apps/web.yaml
    - workload: deployment/example/api/app
      repository: example/application
      base_branch: main
      dockerfile:
        path: docker/Dockerfile
        target: runtime
```

設定を反映してKestreLynxのPodを再起動します。
このマニフェスト・Dockerfileの更新には、スキャン用の読み取り専用RBACだけを使います。
言語パッケージの更新には、次の作業用Podの設定を追加します。

編集できる形式は[マニフェストの形式](remediation-reference.md#manifest-formats)、作成条件は[KubernetesのマニフェストPR](remediation-logic.md#kubernetes-manifest-prs)を参照してください。

### KustomizeのPR設定 {#kustomize-pull-requests}

`apps/kustomization.yaml`の例です。

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - web.yaml
  - worker.yaml
images:
  - name: nginx
    newTag: "1.27.2" # 使用するタグ
```

この`images`の項目が`web`と`worker`の`app`、および`web`の通常のinit containerである`prepare`に効く場合、既存の`remediation.mappings`へ次の対応付けを追加します。

```yaml
remediation:
  mappings:
    - workload: deployment/example/web/app
      repository: example/deployment
      base_branch: main
      kustomize:
        path: apps/kustomization.yaml
        image: nginx
        affects:
          - deployment/example/worker/app
          - deployment/example/web/prepare
```

`image`には`images[].name`を指定し、`affects`にはこの項目が効く、対応付けたコンテナ以外のワークロードキーをすべて列挙します。
通常のinit containerも、同じ形式のキーで列挙します。

KestreLynxはKustomizeを展開せず、この一覧が作用先のすべてであることを利用者が確認した前提で扱います。
`affects`を省略すると、対応付けたコンテナだけに効くことを確認した扱いになります。

既存のGitHub tokenとPRの有効化設定を保持し、設定を反映してKestreLynxのPodを再起動します。
この更新にはスキャン用の読み取り専用RBACだけを使います。

全コンテナの確認条件は[KustomizeのPR](remediation-logic.md#kustomize-prs)、設定の制約は[ソースの対応付け](configuration.md#remediation-mappings)、編集できる形式は[Kustomizeの形式](remediation-reference.md#kustomize-formats)を参照してください。

### HelmのvaluesのPR設定 {#helm-values-pull-requests}

`apps/values.yaml`の例です。

```yaml
image:
  registry: docker.io
  repository: library/nginx
  tag: "1.27.2" # 使用するタグ
```

この`image`キーが`web`と`worker`の`app`、および`web`の通常のinit containerである`prepare`に効く場合、次の対応付けを使います。
同じワークロードに`manifest`または`kustomize`の対応付けがある場合は置き換えます。

```yaml
remediation:
  mappings:
    - workload: deployment/example/web/app
      repository: example/deployment
      base_branch: main
      helm_values:
        path: apps/values.yaml
        key: image
        affects:
          - deployment/example/worker/app
          - deployment/example/web/prepare
```

`key`には`tag`自体ではなく、`repository`と`tag`を持つmappingの経路を指定し、`registry`は省略できます。
`image: "nginx:1.27.2"`のような文字列形式にも、同じ`key: image`を指定できます。

`affects`には、このキーが効く、対応付けたコンテナ以外のワークロードキーを通常のinit containerも含めてすべて列挙します。
省略すると、対応付けたコンテナだけに効くことを利用者が確認した扱いになります。

KestreLynxはHelmを描画しないため、このキーがイメージの最終的な値であり、列挙した集合が作用先のすべてであることを利用者が確認します。
次の設定で上書きされていないことも確認します。

- Flux HelmReleaseの`spec.values`で上書きされていないことを確認する
- Argo CDの`parameters`・`valuesObject`・`valuesFrom`で上書きされていないことを確認する
- CIの`--set`やほかのvaluesファイルで上書きされていないことを確認する

既存のGitHub tokenとPRの有効化設定を保持し、設定を反映してKestreLynxのPodを再起動します。
この更新にはスキャン用の読み取り専用RBACだけを使います。

全コンテナの確認条件は[HelmのvaluesのPR](remediation-logic.md#helm-values-prs)、設定の制約は[ソースの対応付け](configuration.md#remediation-mappings)、編集できる形式は[Helmのvaluesの形式](remediation-reference.md#helm-values-formats)を参照してください。
### Kubernetesの言語パッケージ更新 {#kubernetes-language-updates}

npm・pnpm・pip・uvの更新は、利用者が用意した作業用namespaceにKestreLynxが作る使い捨てのPodで実行します。
npm・pnpm・uvの[依存元からの再解決](remediation-reference.md#dependent-reresolution-limits)にも同じPodを使います。

#### 導入条件

- Kubernetes 1.30以上で、`kubernetes.enabled: true`を設定する
- 作業用Podを実行する各ノードの`containerLogMaxSize`を、大きな結果を保持できるように`144Mi`以上に設定する
- 作業用Podを実行する各ノードで、Podのプロセス数を制限するPID上限を設定する
- NetworkPolicyを実施するCNIを使う

最大の結果ログはAPI経由で約94.56 MiB、ノード上の保存形式では約143.69 MiBです。
ログの切り詰めやローテーションで結果が欠けると、その結果は採用しません。

#### マニフェストの準備と適用

`deploy/kubernetes/work/`の次の箇所を配置先に合わせます。

- `00-namespace.yaml`・`10-rbac.yaml`・`51-validatingadmissionpolicybinding.yaml`・`52-policy-params.yaml`などの作業用namespace名とServiceAccount名をそろえる
- `10-rbac.yaml`のRoleBindingの`subjects`を、KestreLynxが使うServiceAccount名とnamespaceに合わせる
- `20-priorityclass.yaml`は`preemptionPolicy: Never`を維持し、名前を変える場合は設定と`52-policy-params.yaml`の`priorityClass`もそろえる
- `52-policy-params.yaml`の`receiverRepository`をKestreLynxイメージのリポジトリ名、`workRepositories`を公式イメージまたは設定したミラーのリポジトリ名、`arch`をKestreLynxのPodと実行ノードのアーキテクチャに合わせる
- `40-networkpolicy.yaml`のDNSの選択条件と除外するアドレス範囲を、クラスタのDNS・Pod・Service・ノードのネットワークに合わせる
- ValidatingAdmissionPolicyとそのbindingの`metadata.name`は、確認処理で使う`kestrelynx-work`のままにする

リポジトリのルートで次を実行し、namespace、制限、ポリシーのパラメータ、ポリシーとbinding、操作権限の順に適用します。

```sh
kubectl apply -f deploy/kubernetes/work/00-namespace.yaml
kubectl apply -f deploy/kubernetes/work/20-priorityclass.yaml
kubectl apply -f deploy/kubernetes/work/30-resourcequota.yaml
kubectl apply -f deploy/kubernetes/work/40-networkpolicy.yaml
kubectl apply -f deploy/kubernetes/work/52-policy-params.yaml
kubectl apply -f deploy/kubernetes/work/50-validatingadmissionpolicy.yaml
kubectl apply -f deploy/kubernetes/work/51-validatingadmissionpolicybinding.yaml
kubectl apply -f deploy/kubernetes/work/10-rbac.yaml
```

作業用namespaceにはPod Securityの`restricted`を適用し、作業用ServiceAccountには権限やトークンを持たせません。
ResourceQuotaの例はPod数を8に制限し、CPU・メモリ・一時ストレージにも上限を設けます。

追加権限は、利用者がRoleとRoleBindingを適用した場合だけ、作業用namespaceに限ってKestreLynxへ与えます。
スキャン用ClusterRoleは読み取り専用のままで、Secretなどの操作権限は追加しません。

| 対象 | 追加する操作 |
| --- | --- |
| `pods` | `create`・`get`・`list`・`delete` |
| `pods/attach` | 入力ファイルを受信用コンテナの標準入力へ送る接続の`create`・`get` |
| `pods/log` | 暗号化した結果を回収するための`get` |

#### 設定と起動確認

既存のGitHub tokenと対応付けを保持し、`deploy/kubernetes/configmap.yaml`の`config.yml`に次を統合します。
`namespace`は適用した作業用namespace名、`workload`とリポジトリは更新対象に合わせます。

```yaml
kubernetes:
  enabled: true
remediation:
  enabled: true
  pull_requests:
    enabled: true
  worker:
    kubernetes:
      namespace: kestrelynx-work
  mappings:
    - workload: deployment/example/api/app
      repository: example/application
      base_branch: main
      dependencies:
        directory: .
```

配布構成では次を実行し、ログと次回の通知で言語パッケージ更新の有効化と処理結果を確認します。

```sh
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl rollout restart -n kestrelynx deployment/kestrelynx
kubectl logs -n kestrelynx deployment/kestrelynx -f
```

設定の既定値は[作業用Podの設定](configuration.md#remediation-worker-kubernetes)、安全策と実行条件は[作業用Podの実行](remediation-logic.md#kubernetes-work-pods)を参照してください。
### PR作成の有効化 {#enable-pr-creation}

1. [GitHubアクセスの準備](#prepare-github-access)で設定したtokenに、PR作成に必要なアクセスがあることを確認する
2. 既存の対応付け、認証情報、保存先を保持したまま、PR作成を有効にする
3. DockerではKestreLynxのコンテナを再作成し、KubernetesではPodを再起動し、ログでPR作成が有効になったことを確認する

```yaml
remediation:
  enabled: true
  pull_requests:
    enabled: true
```

キーの詳細は[有効化設定](configuration.md#remediation-enablement)を参照してください。
PR数や依存更新の処理量を調整する場合は[処理の上限](configuration.md#remediation-limits)を確認してください。

!!! note "複数ホストでのPR作成"

    - PRの重複を防ぐ仕組みはホストごとのため、同じ修正先である同じリポジトリの同じDockerfile・lockfileのPR作成は1つのインスタンスに任せる
    - 他のホストではその対応付けを設定しないか、`remediation.pull_requests.enabled: false`で計画だけを有効にする

!!! note "リポジトリのワークフロー"

    PRを作ると、対象リポジトリの`pull_request`を契機とするワークフローが起動することがあります。

PR本文のHTMLコメントには、記録の照合と復旧に使う識別マーカーがあるため、本文を編集する場合も残してください。
PRが作られない場合は[PRを作れない場合の確認](remediation-troubleshooting.md#check-missing-pr)を参照してください。
