---
description: "bpftraceでコンテナ内の実行とファイルオープンを観測する方法を、実際に使用したプログラムと計測結果から説明します。tracepointの選択、cgroupによる対応付け、観測開始のタイミング、記録の欠落を扱います。"
---

# bpftraceでコンテナの実行とファイルオープンを観測する

公開日：2026年9月19日

## はじめに

稼働中のコンテナで使われているファイルは、`/proc/<pid>/exe`や`maps`などから確認できます。
ただし、一定間隔で読み取る方法では、次の読み取りまでに終了したプロセスや、短時間だけ開かれたファイルを見逃すことがあります。
procfsによる確認方法は、[procfsで稼働中コンテナのプロセスをOSパッケージに紐づける方法](procfs-process-to-package-mapping-ja.md)を参照してください。

この不足を補うため、bpftraceを使い、プログラムの実行とファイルオープンが発生した時点で記録する方法を検証しました。
短命なcurlとgitを繰り返し実行するケースでは、観測期間内に独立したログへ記録された116回の実行すべてを、実行イベントと対応付けられました。
一方、観測開始前に済んでいたNode.jsの読み込みは取得できず、収集設定によっては記録の欠落も発生しました。

この記事では、計測に使用したプログラムを参照し、イベントの取り方、コンテナとの対応付け、確認結果を記載します。

[bpftraceの計測プログラムの流れを追う動く図解](bpftrace-event-observation-interactive-ja.md)では、コンテナ内の`curl` 1回分について、実行とファイルオープンが出力行を経てコンテナID付きのイベントになるまでを9ステップで確認できます。

## 検証内容

次の2つのケースで、アプリケーション側のログとbpftraceの観測記録を比較しました。

| ケース | アプリケーション側で記録する内容 | 確認すること |
| --- | --- | --- |
| curlとgitを繰り返し実行 | 個々の実行の時刻、PID、実行ファイルなど | 短命なプロセスの実行をイベントとして取得できるか |
| Node.jsでlodashを読み込む | `require`の時刻と、モジュールキャッシュに新たに登録されたファイル | 読み込んだファイルに対応するオープンを取得できるか。観測開始の前後で結果が変わるか |

2026年9月13日〜16日に行った調査のうち、以下ではこの2ケースの保存済み結果を取り上げます。
検証環境と観測条件は次のとおりです。[^measurements]

- OS・カーネル：WSL2上のLinux 6.6
- アーキテクチャ：amd64
- コンテナ環境：ネイティブのDocker Engine
- cgroup：v2
- 収集ツール：bpftrace 0.25.0
- 収集プログラムの実行権限：root
- 観測期間：各300秒

非rootで必要な権限や、収集による負荷は計測していません。

## 計測に使用したプログラム

収集にはbpftraceのスクリプトを、記録の変換とコンテナの判定にはGoのプログラムを使いました。
公開ソースの主な処理は次のとおりです。

| プログラム | 役割 |
| --- | --- |
| [runtime-events-nofilter-512p.bt](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-events/bpftrace/runtime-events-nofilter-512p.bt) | 実行とファイルオープンを、時刻・プロセスの識別情報・cgroup IDとともに記録する |
| [cgroup.go](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-events/cgroup.go) | cgroup IDとコンテナIDの対応表を作成・更新する |
| [convert.go](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-events/convert.go) | オープンの開始と結果を照合し、コンテナ情報を付けてJSONLへ変換する |

計測全体は[case-run.sh](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-discovery/tools/case-run.sh)で実行しました。
必要な環境、ビルド方法、実行コマンドは[実験用ツールのREADME](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-events/README.ja.md)にあります。

## 実行とファイルオープンの記録

bpftraceは、eBPFを使うトレーシングツールです。
Linuxカーネルに用意されたtracepointに処理を登録し、イベントが発生したときに情報を取り出せます。[^bpftrace]
今回のスクリプトは、次の7つのtracepointを使っています。

| 観測対象 | tracepoint | 取得する情報 |
| --- | --- | --- |
| プログラムの実行 | `sched:sched_process_exec` | 実行ファイルのパス、時刻、プロセスの識別情報 |
| ファイルオープンの開始 | `syscalls:sys_enter_open`、`sys_enter_openat`、`sys_enter_openat2` | 指定されたパスと、`openat`・`openat2`では基準となるディレクトリのファイル記述子 |
| ファイルオープンの結果 | `syscalls:sys_exit_open`、`sys_exit_openat`、`sys_exit_openat2` | システムコールの戻り値 |

### 実行の試行と、実行された事実を分ける

`sched_process_exec`は、新しいプログラムへの切り替えが成功した時点のイベントです。
存在しないファイルを実行しようとしただけの操作を、実行済みとして数えずに済みます。
ここで確認できるのはプログラムの実行が始まったことで、そのプログラムの処理が正常終了したことではありません。[^exec-source]

### オープンの開始と結果を組み合わせる

ファイルオープンの開始時点では、指定されたパスを取得できますが、ファイルを開けたかどうかはまだ分かりません。
そのため、スレッド番号と開始時刻を使って開始と結果を対応付け、戻り値が0以上のものを成功と判定します。[^open]
失敗したオープンも`ok:false`として残し、開始と結果の片方しかない記録は、不一致として別に数えます。

計測環境のAlpineでは、muslを使うプログラムが旧来の`open`システムコールを呼ぶため、`openat`と`openat2`だけでは対象のオープンを取得できませんでした。
このため、スクリプトでは`open`も観測対象にしています。[^measurements]

取得したパスは、プログラムがシステムコールに渡した文字列です。
相対パスの場合は基準ディレクトリが必要で、この実装では、対応する作業ディレクトリの記録がないものや、任意のディレクトリ記述子を基準とするものは未解決として残します。
シンボリックリンクの解決も行っていません。[^reference]

## イベントをコンテナに対応付ける

短命なプロセスは、イベントを受け取ってから`/proc/<pid>`を調べようとしても、すでに終了していることがあります。
そこで、スクリプトはイベントが発生した時点のcgroup IDを記録します。

`cgroup.go`はホストの`/sys/fs/cgroup`を走査し、DockerのコンテナIDを含むディレクトリ名から対応表を作ります。
変換処理では、この表を使ってイベントにコンテナIDを付けます。
対応表にはcgroupの追加や削除の履歴も残し、イベントの時刻に合う対応先を調べます。[^reference]

また、コンテナ内のログと照合するには、PIDの違いにも注意が必要です。
今回のWSL2環境では、カーネルの初期PID名前空間での番号と、コンテナ内で記録した番号が異なりました。
スクリプトは両方の番号に加え、コンテナ側のPID名前空間の識別子とプロセスの開始時刻を記録し、どのプロセスのイベントかを照合できるようにしています。[^reference]

## 短命なプロセスの実行を確認した結果

このケースでは、短時間で終了するcurlとgitの実行を、bpftraceで何回確認できるかを調べました。
両コマンドを実行して5秒待つ処理を繰り返し、コンテナ内の[loop.sh](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-discovery/cases/images/13-short-lived/loop.sh)で個々の実行をログに残しました。
この処理は、bpftraceで既知のイベントを取得できることを確認した後に開始しています。

比較したのは、loop.shが残したcurl・gitの実行記録と、bpftraceが取得した実行イベントです。
実行ファイルのパス、プロセスの識別情報、時刻を照合し、ログにある各実行について、同じ実行を表すイベントがあるかを調べました。
表の右端は、両方の記録を1件ずつ対応付けられた実行の回数です。[^exec-runs]

| 計測時のバッファ設定（`perf_rb_pages`） | ログに記録されたcurl・gitの実行回数 | bpftraceでも確認できた実行回数 |
| --- | --- | --- |
| 64ページ | 116 | 116 |
| 256ページ | 116 | 116 |
| 512ページ | 116 | 116 |

各計測の300秒間では、curlとgitを合わせて116回の実行がログに記録されていました。
3回の計測とも、この116回すべてをbpftraceでも確認できました。

## バッファ設定ごとの記録の欠落

対象の実行を確認できたかに加えて、収集の途中で記録が失われていないかも調べました。
上の3回の計測では、記録バッファを64・256・512ページに設定しています。

記録バッファは、カーネル側の観測処理が出力した記録を、bpftraceが読み出すまで保持する領域です。
読み出しが追い付かずにバッファがあふれると、記録が失われます。[^bpftrace]

今回のスクリプトは、「プログラムの実行」「ファイルオープンの開始」「ファイルオープンの終了」を、それぞれ1件の記録として出力します。
例えば、1回のファイルオープンからは、開始と終了の2件の記録を出します。
以下は、bpftraceが欠落を通知した記録の件数です。集計にはその通知から得た`lost_events`を使いました。[^exec-runs]

| バッファ設定（`perf_rb_pages`） | bpftraceが報告した記録の欠落数 |
| --- | --- |
| 64ページ | 2,790件 |
| 256ページ | 12件 |
| 512ページ | 0件 |

64・256ページの計測では欠落が報告され、512ページでは報告されませんでした。
ただし、この3回は収集プログラムも変更しているため、バッファ容量だけを変えた比較ではありません。

この集計の対象は、curl・gitの実行だけでなく、ホストやほかのコンテナを含む収集全体です。
失われた記録の内容は分からないため、2,790件や12件を、特定のプログラムの実行やファイルオープンの見逃し回数には換算できません。
前の表の116回は対象の実行について照合した結果であり、この表は収集全体の欠落報告を集計したものです。

### パス取得の確認結果

ファイルを特定するには、記録の欠落がないことに加え、パスを取得できている必要があります。
そこで、収集スクリプトが実行ファイルやオープン対象のパスを取得した際に、空文字列だった回数も確認しました。
パスが空だった場合は、取得失敗として数えています。[^exec-runs]

| バッファ設定（`perf_rb_pages`） | 収集全体でパスが空だった回数 |
| --- | --- |
| 64ページ | 661回 |
| 256ページ | 667回 |
| 512ページ | 1,088回 |

これはバッファから記録が失われた件数とは別の集計です。
512ページの計測でもパスが空になる場合があり、欠落の報告が0件であることだけでは、パスまで取得できたとは判断できません。

## 観測開始のタイミングによる違い

Node.jsのケースでは、[app.js](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-discovery/cases/images/17-node-require/app.js)が`require('lodash')`を実行します。
アプリケーション側では`require`の前後でモジュールキャッシュを比較し、新たに登録されたファイルを記録しました。
そのファイルについて、同じプロセス・時間帯のオープンイベントがあるかを照合しています。

| 観測を始めるタイミング | 確認結果 |
| --- | --- |
| 最初の`require`より前 | キャッシュを使わない1回の`require`に対応するファイルオープンを取得できた |
| 最初の`require`が終わった後 | 読み込みは観測開始前に済んでおり、対応するファイルオープンを取得できなかった |

どちらも記録バッファは256ページで、`lost_events`は0でした。
2回目の`require`はキャッシュを使ったため、新たなファイル読み込みの比較対象から除外しています。[^node-runs]

イベント観測で取得できるのは、観測を始めてから発生した操作です。
起動時に一度だけ読み込むファイルを確認したい場合は、その読み込みより前に観測を開始する必要があります。

ここで比較した単位は、個々の実行と`require`です。
ファイルオープンの総回数を独立して記録したわけではないため、すべてのオープンのうち何回を取得できたかは計測していません。
また、この実装は`creat`やio_uring経由のオープンを対象に含めず、ファイルを開いた後に内容を読んだか、コードを実行したかも判定しません。[^reference]

## まとめ

bpftraceで実行時点のイベントを記録すると、短命なプロセスが終了した後でも、その実行を確認できます。
ファイルオープンでは、開始時点のパスと終了時点の戻り値を組み合わせ、成功した操作を判定します。
コンテナとの対応付けには、イベント発生時のcgroup IDを使いました。

今回の計測では、対象の短命な実行を取得できた一方、観測開始前の読み込みは取得できませんでした。
結果を読む際は、対象の操作との一致に加えて、観測期間、記録の欠落、パスなどの取得状況を確認します。

## 参考資料

///Footnotes Go Here///

[^bpftrace]: [bpftrace 0.25：言語・tracepoint・設定項目](https://bpftrace.org/docs/release_025/language)

[^exec-source]: [Linux：sched_process_execの定義](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/trace/events/sched.h?h=v6.6)と[execの処理](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/exec.c?h=v6.6)

[^open]: [Linux man-pages：open(2)](https://man7.org/linux/man-pages/man2/open.2.html)

[^reference]: [計測プログラムの入出力・対応付け・制限](https://github.com/kitsunetrail/kestrelynx/blob/2e95ae473671e1188faff0424dd88762e20bc819/experiments/runtime-events/REFERENCE.ja.md)

[^measurements]: [eBPFによる実行時証拠の観測調査：計測結果](../development/runtime-event-evidence.md#2026-09-16)

[^exec-runs]: 保存済み計測`13-root-30-300-p0-r1-startup-nofilter64p`、`13-root-30-300-p0-r2-startup-nofilter256p`、`13-root-30-300-p0-r3-startup-nofilter512p`の`csv_hc/occurrence_capture.csv`と`csv_hc/event_drops.csv`。計測手順は本文の`case-run.sh`、結果の概要は[公開開発ログ](../development/runtime-event-evidence.md#2026-09-16)を参照。

[^node-runs]: 保存済み計測`17-root-30-300-p0-r1-startup-nofilter256p`と`17-root-30-300-p0-r1-attach_running-nofilter256p`の`csv_hc/occurrence_capture.csv`と`csv_hc/event_drops.csv`。対象はnpmで配置したlodash。計測手順は本文の`case-run.sh`、結果の概要は[公開開発ログ](../development/runtime-event-evidence.md#2026-09-16)を参照。

---

KestreLynxは、稼働中のDocker・KubernetesコンテナのイメージをTrivyで定期的にスキャンし、前回からの変化と、深刻度・CISA KEV・EPSSに基づく優先度をSlackやWebhookへ通知するOSSです。Docker・Compose向けの修正計画と修正PR（実験的）で、更新候補の比較からGitHubへのPR作成まで修正を支援します（既定で無効）。マージ・再ビルド・デプロイは利用者が行います。

[KestreLynxについて](../index.md) · [GitHubでソースコードを見る](https://github.com/kitsunetrail/kestrelynx)
