# セットアップ手順

KestreLynxはDockerホストごとに1つのコンテナとして、またはKubernetesクラスタ内で
レプリカ数1のDeploymentとして動作します。  
実行中のコンテナが使用しているイメージを特定してスキャンし、その結果をSlack、メール、または
Webhookへ送信します。

## 必要なもの

- Docker ComposeまたはDocker CLIを利用できるDockerホスト、または`kubectl`で
  アクセスでき、永続ストレージを利用できるKubernetesクラスタ
- 次のうち1つ以上の通知先
    - Slack Incoming Webhook
    - Slack Bot Tokenとチャンネル
    - Webhook URL
    - TLS必須のSMTPメール

## Docker Composeで実行

リポジトリをダウンロードまたはcloneし、ローカル設定ファイルを作成します。

```bash
git clone https://github.com/kitsunetrail/kestrelynx.git
cd kestrelynx
cp config.example.yml config.yml
```

以下のように少なくとも1つの通知先を設定してください。

```yaml
notify:
  slack_webhook_url: "https://hooks.slack.com/services/..."
```

KestreLynxを起動します。

```bash
docker compose up -d
docker compose logs -f
```

同梱のComposeファイルは、`kestrelynx-state`ボリュームを`/var/lib/kestrelynx`にマウントします。
スキャン履歴と脅威情報フィードのキャッシュを保持するため、このボリュームを永続化してください。

保存先の設定は[設定](configuration.md)、履歴が差分判定に与える影響は[履歴の継続](diff-logic.md#state-lifecycle)を参照してください。

## Dockerで実行

```bash
docker run -d --name kestrelynx \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$PWD/config.yml:/etc/kestrelynx/config.yml:ro" \
  -v kestrelynx-state:/var/lib/kestrelynx \
  ghcr.io/kitsunetrail/kestrelynx:latest
```

修正PRを有効にする場合のDockerソケットの権限は、[修正PRの有効化](remediation-setup.md#enable-pull-requests)を参照してください。

Dockerでは、任意のSensor（実験的）を追加すると使用中のパッケージの所見に印が付き、
優先度を変えずに同じ区分内で先に並びます。導入手順と観測の限界は
[稼働時の使用状況](runtime-usage.md)に記載しています。

### 修正計画と修正PR {#remediation}

Docker・Kubernetes向けの機能の概要は[修正計画の案内](remediation.md#overview)を参照してください。

| 操作 | 手順 |
| --- | --- |
| 更新候補の計画を有効にする | [修正計画の有効化](remediation-setup.md#enable-fix-plans) |
| GitHubへのPR作成を有効にする | [修正PRの有効化](remediation-setup.md#enable-pull-requests) |

## Kubernetesで実行

リポジトリをダウンロードまたはcloneしてください。`deploy/kubernetes/`ディレクトリには、
次のマニフェストが含まれています。

| ファイル | リソース |
| --- | --- |
| `serviceaccount.yaml` | `kestrelynx`名前空間のServiceAccount `kestrelynx`です。 |
| `clusterrole.yaml` | Pod、Node、ReplicaSet、Deployment、StatefulSet、DaemonSet、Job、CronJobへの読み取り専用の`get`と`list`アクセスを許可するClusterRoleです。 |
| `clusterrolebinding.yaml` | そのロールをServiceAccountに割り当てるClusterRoleBindingです。 |
| `configmap.yaml` | `config.yml`を含むConfigMap `kestrelynx-config`です。 |
| `pvc.yaml` | アクセスモード`ReadWriteOnce`で1 GiBを要求するPersistentVolumeClaim `kestrelynx-state`です。 |
| `deployment.yaml` | `Recreate`戦略を使用するレプリカ数1のDeploymentです。設定を`/etc/kestrelynx`に、状態データを`/var/lib/kestrelynx`にマウントします。 |
| `work/` | 言語パッケージ更新用の任意の追加マニフェストで、[作業用Podの設定](remediation-setup.md#kubernetes-language-updates)に従って別途適用します。 |

修正計画を有効にすると、通常の取得対象に加えて`deployments`・`statefulsets`・`daemonsets`・`cronjobs`をLISTします。
配布の読み取り専用ClusterRoleは、そのまま使用できます。
`deploy/kubernetes/configmap.yaml`に少なくとも1つの通知先を設定してください。
その中の`config.yml`には`kubernetes.enabled: true`を設定し、`docker.socket`には
空文字列`""`を含む値を設定しないでください。キーの省略または値の`null`指定は受け付けます。
空の`docker:`セクションは受け付けます。`config.example.yml`を基に設定する場合は、
`docker:`セクション全体を削除してください。

1つのインスタンスが1つのクラスタを対象とします。既定ではすべての名前空間を
スキャンします。`kubernetes.namespaces`を設定すると、スキャン対象を指定した
名前空間に制限できます。複数のインスタンスから1つのSlackチャンネルへ投稿する場合は、
インスタンスを区別するために`environment.name`を設定してください。
設定項目については[設定項目](configuration.md)を参照してください。

Trivyはレジストリからイメージを取得するため、スキャナPodからレジストリへ
アクセスできる必要があります。非公開レジストリのイメージを使用する場合は、
`kestrelynx`名前空間に、型が`kubernetes.io/dockerconfigjson`の
`kestrelynx-registry-auth`という名前のSecretを作成してください。
`deploy/kubernetes/deployment.yaml`内の`DOCKER_CONFIG`環境変数、
`registry-auth`ボリュームマウント、Secretボリュームのコメントを解除してください。
これにより、Secretの`.dockerconfigjson`キーを、`DOCKER_CONFIG`で指定した
ディレクトリ`/etc/kestrelynx/docker`の下に`config.json`としてマウントします。
スキャン対象のWorkloadの`imagePullSecrets`は再利用しません。

クラスタに合わせてPVCのストレージ設定を調整し、名前空間を作成して、
準備したマニフェストを適用してください。

```bash
kubectl create namespace kestrelynx
kubectl apply -f deploy/kubernetes/
kubectl logs -n kestrelynx deployment/kestrelynx -f
```

PVCは、Podを再作成した後もスキャン履歴、初回検出日、脅威情報フィードのキャッシュを
保持します。更新中にPodが重複して稼働しないよう、レプリカ数1と`Recreate`戦略を
維持してください。2つのインスタンスで1つの状態データ用ボリュームを共有しないでください。

## タイムゾーンを設定

`schedule.daily_at`は、`TZ`で指定したタイムゾーンとして解釈されます。  
Composeの例ではUTCが既定値です。必要に応じて、運用するホストのタイムゾーンへ
変更してください。

```yaml
environment:
  - TZ=Asia/Tokyo
```

同じ設定は、`deploy/kubernetes/deployment.yaml`内の`TZ`環境変数にも適用されます。
こちらも既定値はUTCです。

## 参考ページ

- [設定](configuration.md) — 設定項目と既定値
- [スキャン通知の送信条件](notification-conditions.md#notification-conditions) — 通知モードごとの送信条件
