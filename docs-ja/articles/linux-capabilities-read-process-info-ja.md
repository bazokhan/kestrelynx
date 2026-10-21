---
description: "Linux capabilityを使い、非rootで/procからプロセス情報を読む方法を記載します。CAP_SYS_PTRACEとCAP_DAC_READ_SEARCHの役割、ptraceアクセスチェックとファイルのアクセス権の関係、権限4条件の計測結果と使用した収集プログラムを整理します。"
---

# Linux capabilityでrootを使わずにプロセス情報を読む

公開日：2026年9月17日

## はじめに

稼働中のプロセスがどの実行ファイルや共有ライブラリを使っているかは、Linuxの`/proc`から確認できます。
この情報は、コンテナの脆弱性スキャンで検出されたパッケージの利用状況を調べるために使います。
ただし、別のユーザーが動かしているプロセスの情報は、通常のユーザー権限では読み取れない場合があります。

Linux capability（ケーパビリティ）を使うと、収集プログラムを非rootで動かしながら、必要な権限を付与できます。
収集プログラムに与える権限を絞るため、rootで取得していた情報を、どのcapabilityの組み合わせで取得できるかを検証しました。
rootでの収集を基準に、非rootでcapabilityを付与しない場合、`CAP_SYS_PTRACE`だけを付与する場合、`CAP_DAC_READ_SEARCH`も付与する場合を比較しました。

計測環境で確認できた組み合わせは次のとおりです。[^measurements][^procfs-article]

| 収集する情報 | 非rootでの収集に必要だったcapability |
| --- | --- |
| パッケージの利用確認に使う実行ファイル・読み込み済みライブラリ（`exe`・`maps`） | `CAP_SYS_PTRACE` |
| 上記に加え、待ち受けソケットをプロセスに紐づける情報（`fd/`） | `CAP_SYS_PTRACE`と`CAP_DAC_READ_SEARCH` |

この記事では、次のことを記載します。

- Linux capabilityと、プロセス情報の読み取りに関係する権限
- ptraceアクセスチェックとファイルのアクセス権の関係
- rootと非rootの権限4条件での計測結果
- 実際の計測に使用した収集プログラムの処理と結果の記録方法
- 権限を付与しても読み取れない場合の確認方法

## Linux capabilityとは

Linux capabilityは、従来rootが持っていた権限を、操作の種類ごとに分けた仕組みです。
権限はスレッドごとに管理され、カーネルの権限チェックには実効集合（effective set）が使われます。[^capabilities]

プロセス情報の収集では、主に次の2つが関係します。

| capability | 役割 |
| --- | --- |
| `CAP_SYS_PTRACE` | 他のプロセスに対するptrace操作や、`/proc`内の保護されたプロセス情報へのアクセスを許可する |
| `CAP_DAC_READ_SEARCH` | ファイルの読み取り、ディレクトリの読み取り・検索に関する通常のアクセス権チェックを回避する |

`CAP_SYS_PTRACE`は読み取り専用の権限ではなく、他のプロセスのメモリを書き換える操作にも関係します。
`CAP_DAC_READ_SEARCH`の効果も`/proc`だけには限定されません。
これらのcapabilityは、収集に必要なプログラムにだけ付与し、そのプログラムを実行できるユーザーも制限します。[^capabilities]

## CAP_SYS_PTRACEだけでは読み取れない情報がある理由

計測では、非rootの収集プログラムに`CAP_SYS_PTRACE`を付与すると、`exe`と`maps`を読めました。
一方、`fd/`の一覧取得は権限不足で失敗し、`CAP_DAC_READ_SEARCH`を追加すると取得できました。[^procfs-article]

この違いは、プロセス情報へのアクセスを許可するかどうかと、ディレクトリのアクセス権を満たすかどうかが、別々に確認されるためです。

### exeとmapsを読むための権限

`exe`のリンク先には実行ファイルのパスが、`maps`にはプロセスがメモリに読み込んだファイルなどの情報があります。
Linuxはこれらを読むとき、読み取る側が対象プロセスの情報にアクセスできるかを確認します。
この確認が「ptraceアクセスチェック」で、`CAP_SYS_PTRACE`が関係する部分です。[^exe][^maps][^ptrace]

計測環境では、`CAP_SYS_PTRACE`を付与することでこのチェックを通り、実行ファイルや読み込み済みライブラリを確認できました。[^procfs-article]

Linuxのマニュアルでは、`exe`と`maps`に使われる読み取り用のチェックを`PTRACE_MODE_READ_FSCREDS`と表記しています。
`ptrace`という名前ですが、ここでは情報を読む権限を確認しており、デバッガーを接続しているわけではありません。[^ptrace]

### fd/の一覧を取得するための権限

`fd/`には、プロセスが開いているファイルやソケットへのリンクがあります。
これらを調べるには、まずディレクトリ内の一覧を取得し、その後に各リンク先を読み取ります。[^fd]

計測対象の`fd/`はroot所有で、モードは`0500`でした。
非rootの収集プログラムには、このディレクトリの一覧を取得するアクセス権がありませんでした。
`CAP_SYS_PTRACE`を持っていてもこの制限は回避できず、一覧取得の段階で`EACCES`（権限不足）になりました。[^procfs-article][^fd-source]

`CAP_DAC_READ_SEARCH`を追加すると、ディレクトリのアクセス権による制限を回避でき、一覧を取得できました。
一覧取得後のリンク先の読み取りには、`exe`と同じくptraceアクセスチェックが関係します。[^capabilities][^fd]

このため、`CAP_SYS_PTRACE`だけの条件では、読み込み済みファイルからパッケージの利用を確認できても、`fd/`を使って待ち受けソケットをプロセスに紐づけることはできませんでした。[^procfs-article]

同様に、`/proc/<pid>/root`経由でコンテナ内のファイルを読む場合も、プロセス情報へのアクセスに加えて、たどった先のファイルやディレクトリのアクセス権が関係します。[^root]
必要な権限は対象によって異なり、procfsのマウント設定やAppArmor・SELinuxなどのLinux Security Module（LSM）による制限も受けます。[^proc][^ptrace]

## 権限4条件での計測結果

2026年9月12日の計測では、Dockerホスト上の収集プログラムについて、次の4条件を比較しました。
主環境はWSL2 Linux 6.6.114、Docker Engine 29.1.3で、`hidepid`による制限はありませんでした。
非rootの条件では、ビルド済みの実行ファイルにfile capabilityを付与しました。[^measurements][^procfs-article][^harness]

計測時のYamaの設定は`ptrace_scope=1`でした。この設定は、今回使用した`exe`や`maps`の読み取りを直接制限するものではありません。[^yama-source]

| 収集側の条件 | パッケージの利用確認 | 待ち受けプロセスの特定 | 主な結果 |
| --- | --- | --- | --- |
| root | 基準 | 取得できた | 比較の基準となる収集に成功 |
| 非root＋`CAP_SYS_PTRACE`＋`CAP_DAC_READ_SEARCH` | rootと同じ | rootと同じ | 比較対象の情報を取得できた |
| 非root＋`CAP_SYS_PTRACE` | rootと同じ | 特定できなかった | `fd/`の列挙が拒否された |
| 非root、capabilityなし | 全サンプルで観測失敗 | 不明 | 収集に必要なプロセス情報を取得できなかった |

この環境では、`CAP_SYS_PTRACE`だけで`exe`・`maps`・名前空間リンクや、`root`経由のパッケージメタデータを読めました。
ただし、コンテナ内のファイルのアクセス権によっては、メタデータの読み取りにも`CAP_DAC_READ_SEARCH`が必要になる場合があります。[^procfs-article]

capabilityなしで観測失敗になったことは、`status`などを含めて`/proc`の情報がすべて読めないことを意味しません。
表は、パッケージの利用確認に必要な情報を収集できたかを示しています。

AppArmorのプロファイルが適用された条件での非rootと各capabilityの組み合わせは引き続き未検証です。
一方、後の[実運用環境での検証](../development/runtime-environment-validation.md)では、収集プロセスがAppArmorのunconfinedで動作する条件で、非rootに`CAP_SYS_PTRACE`と`CAP_DAC_READ_SEARCH`を付与すると有効な読み取りが12/12となり、比較した全項目がrootと一致しました。
この結果を、すべてのLinuxホストで成立する最小権限として一般化することはできません。[^measurements]

## 計測に使用したプログラム

権限4条件の計測には、Goで実装した収集プログラム`runtime-discovery`を使用しました。
サンプリング計測の公開版（`ed7813e`）の[README](https://github.com/kitsunetrail/kestrelynx/blob/ed7813edc159f5ea0b6a747bfebf78e45fa2ba23/experiments/runtime-discovery/README.ja.md)と[ソースコード](https://github.com/kitsunetrail/kestrelynx/blob/ed7813edc159f5ea0b6a747bfebf78e45fa2ba23/experiments/runtime-discovery/procfs.go)を参照できます。

### どの情報を読み取るか

収集プログラムは、Docker APIから対象コンテナのホスト側PIDを取得し、ホストの`/proc`を読み取ります。
主な読み取り処理は、公開版の[procfs.go](https://github.com/kitsunetrail/kestrelynx/blob/ed7813edc159f5ea0b6a747bfebf78e45fa2ba23/experiments/runtime-discovery/procfs.go)にあります。

| 処理 | 読み取る情報 | 権限との関係 |
| --- | --- | --- |
| `readExe` | `exe`のリンク先 | 実行ファイルの確認にptraceの読み取りアクセスチェックが関係する |
| `readMaps` | `maps`内の実行可能なファイルのマッピング | 読み込み済みファイルの確認にptraceの読み取りアクセスチェックが関係する |
| `socketInodesForPID` | `fd/`の一覧とリンク先のソケットinode | ディレクトリのアクセス権とリンクに対するptraceチェックの両方が関係する |
| `readStatus` | 対象プロセスの実効UIDと`CapEff` | 観測対象がどの権限で動いているかを記録する |

`socketInodesForPID`では、まず`fd/`を列挙し、その後に各リンク先を読み取ります。
前述の`CAP_SYS_PTRACE`だけの条件では、この列挙の段階で拒否されました。
そのため、マッピングからパッケージの利用を確認できても、待ち受けソケットをPIDに紐づける情報は取得できませんでした。

### 権限条件と失敗をどう記録するか

収集時の`-permission`は、結果に権限条件を記録するためのラベルです。
この引数自体が権限を付与するわけではありません。[^harness]

| ラベル | 計測時の条件 |
| --- | --- |
| `root` | rootで実行 |
| `ptrace` | 非rootで、ビルド済み実行ファイルに`CAP_SYS_PTRACE`を付与 |
| `ptrace_dac` | 非rootで、`CAP_SYS_PTRACE`と`CAP_DAC_READ_SEARCH`を付与 |
| `none` | 非rootで、capabilityを付与しない |

権限比較には、`go run`ではなくビルド済みの実行ファイルを使いました。
必要な環境、ビルド、収集、照合の手順は、公開版の[README](https://github.com/kitsunetrail/kestrelynx/blob/ed7813edc159f5ea0b6a747bfebf78e45fa2ba23/experiments/runtime-discovery/README.ja.md)に記載されています。

失敗した操作は観測結果に残し、照合後の`permissions.csv`に操作名、結果、発生回数、エラーメッセージなどを出力します。
出力処理は[match_report.go](https://github.com/kitsunetrail/kestrelynx/blob/ed7813edc159f5ea0b6a747bfebf78e45fa2ba23/experiments/runtime-discovery/match_report.go)で確認できます。
これにより、権限条件ごとに、どの操作が失敗し、パッケージの利用確認にどう影響したかを比較できます。

## 権限を付与しても読み取れない場合

### ファイルへの設定と実行時の権限を確認する

`getcap`が表示するのは実行ファイルの設定であり、現在動いているプロセスの権限ではありません。[^getcap]
読み取る側のプロセスの`/proc/<pid>/status`にある`CapEff`と照合します。
計測プログラムの`readStatus`が収集するのは観測対象の権限なので、収集側の権限とは分けて確認します。
`cat /proc/self/status`では`cat`自身の情報になるため、別のプロセスの権限を確認する場合は、そのPIDを指定します。[^status]

| 確認項目 | 影響 |
| --- | --- |
| 起動元の`NoNewPrivs` | `1`の場合、file capabilityによる新たな権限の取得が制限される |
| 実行ファイルを置いたマウントの`nosuid` | file capabilityが実行時に適用されない |
| 起動元の`CapBnd` | 実行時に取得できるcapabilityの上限になる |
| 実行ファイルの再ビルド・置き換え | file capabilityが残っているとは限らないため、再確認が必要 |

`NoNewPrivs`・`CapBnd`は起動元の`/proc/<pid>/status`で確認できます。
`nosuid`は、収集プログラムの実行ファイルを置いたファイルシステムのマウントオプションで確認します。
実行時の制約によっては、読み取り以前にプログラムの起動が`Operation not permitted`で失敗する場合もあります。[^execve][^status]

シェルやPythonなどの汎用インタープリターにcapabilityを付けると、そのインタープリターで実行できる処理全体が権限を持つことになります。
権限を付与する対象は収集に使う実行ファイルに限定し、そのファイルの所有者と書き込み権限も確認します。

### 対象が見える名前空間とホストの制限を確認する

コンテナ内だけで有効なcapabilityを持っていても、ホスト側のプロセスに対して同じ権限を使えるとは限りません。
capabilityが有効なユーザー名前空間と、対象プロセスのユーザー名前空間の関係を確認します。
また、PID名前空間によって見えるPIDが異なるため、収集側から見える`/proc`に対象が存在する必要があります。[^userns][^proc]

`hidepid`によってほかのユーザーのプロセス情報が制限されている場合や、AppArmor・SELinuxのポリシーによって拒否されている場合もあります。
capabilityを増やす前に、`/proc`のマウントオプションとホストの監査ログを確認します。[^proc][^ptrace]

読み取り失敗は、パスと操作名を含めて記録します。
権限不足の`EACCES`・`EPERM`と、プロセスの終了やパスの消失による`ENOENT`などを分けることで、権限の追加で解決する問題かを判断しやすくなります。

### Docker APIの権限は別に扱う

ホストの`/proc`を読む権限と、Docker APIを使う権限は別です。
計測に使った収集プログラムは、コンテナ一覧やPIDを取得するためにDocker APIも使っています。[^harness]

コンテナ一覧やPIDの取得にDockerソケットを使う場合、通常のrootful Docker Engineでは、そのアクセス権自体がホストのroot相当の操作を許可し得ます。
収集プログラムがGETリクエストしか送らなくても、ソケットの権限が読み取り専用になるわけではありません。[^docker]

## 参考資料

この記事は、2026年9月17日時点で確認した情報に基づいています。
権限4条件の表は、2026年9月12日にGo製の収集プログラムで行った計測に基づいています。

///Footnotes Go Here///

[^capabilities]: [Linuxマニュアル：capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html)
[^ptrace]: [Linuxマニュアル：ptrace(2)、アクセスモードのチェック](https://man7.org/linux/man-pages/man2/ptrace.2.html)
[^exe]: [Linuxマニュアル：proc_pid_exe(5)](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html)
[^maps]: [Linuxマニュアル：proc_pid_maps(5)](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html)
[^fd]: [Linuxマニュアル：proc_pid_fd(5)](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
[^fd-source]: [Linux 6.6：procfsのfdディレクトリの実装](https://github.com/torvalds/linux/blob/v6.6/fs/proc/fd.c)
[^root]: [Linuxマニュアル：proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
[^proc]: [Linuxカーネル：/procファイルシステム](https://docs.kernel.org/filesystems/proc.html)
[^yama-source]: [Linux 6.6：Yamaのアクセスチェック](https://github.com/torvalds/linux/blob/v6.6/security/yama/yama_lsm.c)
[^status]: [Linuxマニュアル：proc_pid_status(5)](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
[^getcap]: [libcap：getcap(8)](https://man7.org/linux/man-pages/man8/getcap.8.html)
[^execve]: [Linuxマニュアル：execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html)
[^userns]: [Linuxマニュアル：user_namespaces(7)](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
[^docker]: [Docker：Linuxでのインストール後の設定](https://docs.docker.com/engine/install/linux-postinstall/)
[^measurements]: [実行時証拠による優先順位付けの計測結果](../development/runtime-prioritization.md#2026-09-12)
[^procfs-article]: [procfsで稼働中コンテナのプロセスをOSパッケージに紐づける方法](procfs-process-to-package-mapping-ja.md)
[^harness]: [サンプリング計測用プログラムのREADME（公開版ed7813e）](https://github.com/kitsunetrail/kestrelynx/blob/ed7813edc159f5ea0b6a747bfebf78e45fa2ba23/experiments/runtime-discovery/README.ja.md)

---

KestreLynxは、稼働中のDocker・KubernetesコンテナのイメージをTrivyで定期的にスキャンし、前回からの変化と、深刻度・CISA KEV・EPSSに基づく優先度をSlackやWebhookへ通知するOSSです。

Docker・Compose・Kubernetes向けの修正計画と、Docker・Compose向けの修正PR（実験的）で、更新候補の比較からGitHubへのPR作成まで修正を支援します（既定で無効）。マージ・再ビルド・デプロイは利用者が行います。

[KestreLynxについて](../index.md) · [GitHubでソースコードを見る](https://github.com/kitsunetrail/kestrelynx)
