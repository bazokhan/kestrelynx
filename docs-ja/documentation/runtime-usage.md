# 稼働時の使用状況

!!! warning "実験的な機能"

    Sensor（稼働時の使用状況）は実験的な機能です。
    設定・表示・証拠の形式は今後変わることがあり、凍結する可能性があります。

Dockerホストに任意のSensorコンテナを追加すると、稼働中のプログラムが使っているパッケージを観測できます。
KestreLynxは観測結果をSlackとWebhookの通知に反映します。

使用状況は脆弱性の優先度を変えません。

[修正計画と修正PR（実験的）](remediation.md)にSensorは不要です。
`runtime.enabled: false`のまま利用できます。

## 使用状況の意味

| 使用状況 | 意味 |
| --- | --- |
| `in_use` | 以下の判定方法で使用を確認できた状態です。 |
| `not_observed` | 観測期間に使用を確認できなかった状態です。使われていないことは意味しません。 |
| `unavailable` | 証拠が足りず判定できない状態です。理由を付けて表示します。 |

| パッケージの種類 | 使用中とみなす条件 |
| --- | --- |
| OSパッケージ | 稼働中のプロセスが、そのパッケージのファイルを実行した、またはライブラリとして読み込んだことを、サンプリングまたはeBPFによる短命なプロセスの実行・読み込みのイベントで確認した場合です。 |
| Go・Rustなど実行ファイルに組み込まれる言語パッケージ | Trivyの検出対象（Target）の実行ファイルが、稼働中のプロセスとして動いている場合です。 |
| Python・Node.js・Javaなど実行環境が読み込む言語パッケージ | そのコンテナで`python`・`node`・`java`など対応する実行環境のプロセスが動いている場合です。そのエコシステムのパッケージをすべて使用中とみなします。 |

実行環境のプロセスを根拠に同じエコシステムのパッケージをすべて使用中とみなすのは、個々の依存パッケージの利用を確認した結果ではなく、保守的に使用中として扱うKestreLynxの判定規則です。

関数の呼び出しやモジュールの読み込みは判定しません。
データファイルの読み取りは使用の根拠にしません。

Slackの文言と観測根拠は[稼働時の使用状況の表示](slack-display.md#runtime-display)、並び順は[現在状態レポートの並び順](slack-display.md#current-order)を参照してください。
Webhookのフィールドは[稼働時のフィールド](webhook-reference.md#runtime)に記載しています。

## 動作要件

Dockerとcgroup v2が必要です。Kubernetesでは利用できません。
`runtime.enabled`と`kubernetes.enabled`の両方を有効にすると設定エラーになります。

配布のComposeファイルでは、Sensorは非rootのUID 65532で、次の設定で動作します。

- `pid: host`
- `cgroup: host`
- `userns_mode: host`
- `network_mode: none`
- `read_only: true`
- `cap_drop: [ALL]`
- `cap_add: [SYS_PTRACE, DAC_READ_SEARCH, BPF, PERFMON]`
- 配布のseccompプロファイル

`cgroup: host`が必要なのは、Sensorが自身のcgroup名前空間で動作すると、
他のコンテナの`/proc/<pid>/cgroup`のパスをその名前空間のルートからの相対パスとして読み、
どのコンテナにも対応付けられなくなるためです。cgroup v2のホストでこの設定がない場合、
Sensorは起動時に次のエラーを標準エラーに出力し、終了コード1で終了します。
`docker run`では`--cgroupns host`を指定します。

```text
kestrelynx sensor: sensor: this container is not in the host's cgroup namespace; run it with `cgroup: host` (compose) or `--cgroupns host` (docker run)
```

`userns_mode: host`は、Dockerデーモンでuserns-remapが有効な場合に必要です。
指定しないと、ホストのPID名前空間の共有が拒否されます。
それ以外の環境では、この設定は既定値と同じです。

短命なプロセスを観測するeBPFには、BTFのあるカーネルが必要です。
BPF・PERFMONがない場合、BTFがない場合、cgroup v1のホストでは、
警告してサンプリングだけで動き続けます。この場合、短命なプロセスは観測できません。

| 環境 | 確認状況 |
| --- | --- |
| Ubuntu 26.04 | Linux 7.0、AppArmor有効、Docker 29.5.1で確認済みです。x86_64、cgroup v2のsystemdドライバです。 |
| WSL2 | Linux 6.6、Docker Engine 29.1.3で確認済みです。x86_64、cgroup v2のsystemdドライバです。 |
| WSL2(cgroupfsドライバ) | Linux 6.6、Docker Engine 29.1.3で確認済みです。x86_64、cgroup v2のcgroupfsドライバです。 |
| WSL2(userns-remap) | Linux 6.6、Docker Engine 29.1.3で確認済みです。x86_64、cgroup v2のsystemdドライバです。 |
| arm64 | 未確認です。 |

AppArmor有効のホストでは、unconfined・privilegedのコンテナのファイルの読み取りが
拒否され、そのコンテナは`permission denied`になります。
`docker-default`のコンテナのファイルは読み取れます。

## Sensorの導入

### Sensorの起動

リポジトリの`deploy/docker/`にある
[`docker-compose.sensor.yml`](https://github.com/kitsunetrail/kestrelynx/blob/main/deploy/docker/docker-compose.sensor.yml)と
[`sensor-seccomp.json`](https://github.com/kitsunetrail/kestrelynx/blob/main/deploy/docker/sensor-seccomp.json)を
同じディレクトリに置き、そのディレクトリで起動します。

```bash
docker compose -f docker-compose.sensor.yml up -d
```

Sensorは本体と同じイメージ`ghcr.io/kitsunetrail/kestrelynx`を、
`kestrelynx-sensor`という別のentrypointで動かします。
証拠ボリュームの名前は`kestrelynx-runtime`に固定しています。
Sensorは自身のコンテナを観測しないため、本体がそのコンテナを使用状況の判定から外すよう、
Sensorのコンテナには`io.kestrelynx.runtime.exclude: "true"`のラベルが付いています。

### 証拠ボリュームのマウント

本体のComposeファイルに、Sensorの証拠ボリュームを読み取り専用で追加します。

```yaml
services:
  kestrelynx:
    volumes:
      - kestrelynx-runtime:/var/lib/kestrelynx-runtime:ro
volumes:
  kestrelynx-runtime:
    external: true
```

### 使用状況の有効化

本体の`config.yml`に次の設定を追加します。

```yaml
runtime:
  enabled: true
```

本体のComposeディレクトリでコンテナを作り直します。

```bash
docker compose up -d
```

`runtime.evidence_dir`の既定値は`/var/lib/kestrelynx-runtime`です。
変更する場合は絶対パスを指定し、Sensorの`--evidence-dir`と一致させます。
Sensorを置かない場合は`runtime.enabled`を`false`のままにします。
本体は証拠ディレクトリを開かず、通知に稼働時の情報を追加しません。
設定項目は[設定](configuration.md)に記載しています。

本体を再起動した直後のスキャンでは、Sensorがまだ新しいコンテナを観測していないため、
そのイメージが一時的に`container not observed`になることがあります。
次のスキャンで解消します。

### 修正版がない所見の通知オフ {#muting-findings-without-a-fix}

`runtime.mute_unfixable_not_in_use`の既定値は`false`です。
`runtime.enabled: true`のときだけ有効になります。

```yaml
runtime:
  enabled: true
  mute_unfixable_not_in_use: true
```

同じイメージの同じパッケージについて、今回のすべてのグループが
次の条件をすべて満たす場合に通知オフにします。

- 対象プラットフォーム向けの修正版がない状態：`affected`（`fix_deferred`・`unknown`などを含む）または`will_not_fix`
- 稼働時の判定が「使用が確認されない」（`not_observed`）で、「判定できない」（`unavailable`）は対象外
- 週1回の処理を含めるため、判定に使ったすべてのコンテナをSensorが7日以上観測
- Act now以外の優先度

修正版のあるもの（`fixed`）やEOLのものが混ざるパッケージは通知オフにしません。
EOLは常に通知します。スキャンに失敗した・実体を確認できなかったイメージの参照は、
そのサイクルでは通知オフにしません。

通知オフにしても優先度は変わりません。
同じイメージの同じパッケージについて、次のいずれかに該当すると通知オフを解除します。

- 使用中のグループがある
- Act nowのグループがある
- 修正版のある`fixed`のグループがある
- `end_of_life`のグループがある
- 使用状況を判定できない、または判定対象のコンテナの観測期間が7日に満たない
- 修正状態が通知オフの対象から外れた

Slackの表示と件数は[通知オフの表示](slack-display.md#muted-display)、ほかの変化と同時に起きた場合の判定順は[通常のパッケージの変化](diff-logic.md#normal-changes)を参照してください。
汎用Webhookには通知オフの所見も全件残り、追加フィールドは[パッケージ](webhook-reference.md#package-fields)と[通常のパッケージの変化](webhook-reference.md#new-fields)に記載しています。

### 観測のオプション

SensorのComposeの`command`には、次のオプションを指定できます。

| オプション | 既定値 | 説明 |
| --- | --- | --- |
| `--interval` | `30s` | サンプリングの間隔です。`10s`〜`5m`で指定します。 |
| `--exclude-id` | — | コンテナIDの先頭12文字以上で、観測しないコンテナを指定します。繰り返し指定できます。 |
| `--evidence-dir` | `/var/lib/kestrelynx-runtime` | 証拠ディレクトリです。 |

`io.kestrelynx.runtime.exclude=true`のラベルを持つコンテナは、使用状況の判定から外します。
値は小文字の`true`だけが該当します。

使用状況が有効な場合、本体はDocker APIの`GET /containers/json`に加えて
`GET /containers/{id}/json`も使用します。

## Sensorの状態

状態ごとの警告文は[Sensorの警告](slack-display.md#sensor-warnings)、Webhookのフィールドは[Sensorの情報](webhook-reference.md#sensor-fields)を参照してください。

| 状態 | 意味 |
| --- | --- |
| `ok` | 正常に動作しています。 |
| `not_reporting` | 証拠ファイルがまだありません。Sensorの未起動時や起動直後などが該当します。 |
| `stale` | 最後の報告から、intervalの10倍と5分の大きい方を超えています。 |
| `evidence_invalid` | 証拠ファイルが検証を通りません。 |
| `permission_denied` | Sensorの読み取りが拒否されています。 |
| `isolation_failed` | 読み取り以外の操作の制限の設定に失敗し、観測を始めていません。 |
| `isolation_degraded` | 読み取り以外の操作の制限の一部が効いていない状態で動いています。 |
| `degraded` | Sensorの処理が詰まっているなど、一部の観測ができていません。 |

Sensor全体が`isolation_failed`または`permission_denied`の場合は、
確認済みの使用中を除き、判定できない状態にします。
報告が古い場合は、`not_observed`を理由が`sensor_stale`の`unavailable`にします。

## 権限

### 読み取りの権限

Sensorは、ホストのすべてのコンテナのプロセス情報と、コンテナ内の設定ファイルなどを含む
ファイルを読み取れます。

`SYS_PTRACE`と`DAC_READ_SEARCH`は、他のコンテナの`/proc/<pid>/`から、
実行ファイル、読み込んだライブラリ、開いているファイルの一覧、待ち受けているソケットを
読むために使います。コンテナのファイルシステムにあるパッケージのデータベースも読み取ります。

`BPF`と`PERFMON`は、起動時にeBPFのプログラムを読み込むときだけ使い、
読み込んだ後に捨てます。

### 読み取り以外の操作の制限

- ネットワーク、Dockerソケット、`config.yml`なし
- ルートファイルシステムは読み取り専用で、書き込み先はSensor自身の証拠ボリュームのみ
- 起動時にno-new-privilegesとdumpableの解除を自身で設定
- 配布のseccompプロファイルで、書き込みのためのファイルのオープン、ptrace、他のプロセスのメモリの読み書き、ソケットの作成などを拒否
- 他のコンテナのパッケージのデータベースは、Landlockとseccompで書き込み・ネットワーク・execのできない子プロセスで解析

Composeでno-new-privilegesを付けないのは、イメージのfile capabilityを
起動時に有効にするためです。AppArmor有効のホストでは、
確認した危険な操作25件がすべて拒否されました。

### 証拠ファイル

本体は証拠ファイルを読むだけで、形式・上限・値の集合の検証を通らないファイルは使いません。
証拠はSensorのボリューム内の`procfs.json`に保存します。
所有者はSensorのUID、パーミッションは`0644`です。

## 観測の限界

- 観測はSensorの起動後からで、それより前に終了した短命なプロセスは対象外
- `not_observed`は観測期間内の状態だけを表し、Sensorの起動より前から動いていたコンテナも含め、パッケージが未使用であることは意味しない
- Sensorが一度も見つけないまま終了した、ごく短時間のコンテナは観測の対象外
- データファイルの読み取りは使用の根拠の対象外
- 実行環境による言語パッケージの判定はエコシステム全体が対象で、関数の呼び出しやモジュールの読み込みは未判定

