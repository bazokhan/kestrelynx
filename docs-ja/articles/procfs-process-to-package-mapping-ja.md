---
description: "procfsと/procを使い、稼働中のDockerコンテナのプロセスをdpkg・apkの情報からOSパッケージに紐づける方法を解説します。必要な権限、コンテナ内のパス解決、ファイルの所有関係を調べる際の注意点、サンプリングの限界を確認できます。"
---

# procfsで稼働中コンテナのプロセスをOSパッケージに紐づける方法

公開日：2026年9月13日

## はじめに

イメージの脆弱性スキャンは、アプリケーションが一度も読み込まないパッケージも含め、インストール済みソフトウェアの脆弱性を報告します。
通常は`/proc`にマウントされるLinuxのprocfsでは、稼働中プロセスの実行ファイルとマッピングされたファイルを観測し、コンテナのパッケージデータベースからOSパッケージに紐づけられます。[^proc]

この記事では、次のことを記載します。

- Dockerホストから、プロセスと読み込まれたファイルの情報を収集する方法を説明する
- dpkg・apkのメタデータからファイルの所有元を特定する方法を説明する
- パスだけではパッケージを確定できない場合の扱いと、権限・サンプリングの限界を説明する
- コマンド例はLinux上のDocker Engineと既存の`web`コンテナを前提とし、Dockerデーモンが動くマシン上で実行する

[procfsのパッケージ紐づけの流れを追う動く図解](procfs-package-mapping-interactive-ja.md)では、コンテナ内のnginxワーカー1つについて、読み込んだ`libssl.so.3`をprocfsとdpkgの記録から`libssl3`に紐づけ、Trivyの結果と照合して読み込みを確認するまでを8ステップで確認できます。

## 読み込まれたファイルから分かること

実行可能なメモリマッピングにあるライブラリは、プロセスがそのファイルからコードを読み込んだ根拠になります。

| 根拠 | 確認できること |
| --- | --- |
| イメージ内でパッケージを検出 | スキャナーがインストール済みソフトウェアを特定したこと |
| procfsで実行ファイルやライブラリを観測 | サンプル取得時点で、プロセスがそのファイルを実行またはマッピングしていたこと |
| ファイルの所有元とバージョンが一致 | 観測したパスが、検出結果にあるパッケージのバージョンに対応すること |
| 脆弱な関数への到達 | この方法では確認できません |

- ここでいう「使用」は読み込まれたことを指し、特定の関数が実行されたことは意味しない
- 読み込みの観測は、対応の優先順位を判断する肯定的な根拠になる
- 未観測でも、別のリクエスト・ワーカー・短時間のプロセスが後から読み込む可能性があるため、未使用とは証明できない

## コンテナのホスト側PIDを取得する

Dockerのプロセス一覧から、ホストの`/proc/<pid>`で使うPIDを取得します。

```bash
docker top web -eo pid,ppid,user
```

出力例:

```text
PID          PPID         USER
<master-pid>  <parent-pid>  root
<worker-pid>  <master-pid>  nginx
```

- 1列目の`PID`がホスト側のPIDで、以降の`/proc/<pid>`で使う
- `PPID`は親プロセスのPIDで、ワーカーの親がマスターであることを示す
- この例では、`USER`が`root`の行はマスタープロセス、`nginx`の行はワーカープロセスである
- 確認したLinux版Docker Engineは、ランタイムから取得したPIDを基にホストで`ps`を実行し、対象プロセスの出力を抽出する[^docker-top][^moby-top]
- 以下の例では一覧から1つを選ぶが、収集プログラムではワーカーや子プロセスも含め、すべてのPIDを調べる

以下の例で使うPIDとして、プロセス一覧の先頭のPIDを1つ選んで変数`pid`に入れます。

```bash
pid=$(docker top web -eo pid,ppid,user | awk 'NR == 2 {print $1}')
```

- `/proc/<pid>/cgroup`内のコンテナIDは、所属を照合する補助情報として使う
- cgroupのパス構造はバージョン・名前空間・ランタイム設定で異なるため、Docker IDが見つからないだけではPIDを除外しない

## /procからプロセスの情報を読み取る

### 実行ファイルとマッピングされたライブラリ

対象プロセスの実行ファイルのパスを確認するため、`exe`のリンク先を読み取ります。

```bash
sudo readlink "/proc/$pid/exe"
```

出力例:

```text
/usr/sbin/nginx
```

- `/usr/sbin/nginx`が対象プロセスの実行ファイルのパスで、パッケージの所有情報と照合する対象になる
- 実行ファイルがアンリンクされると`exe`の末尾に` (deleted)`が付くが、プロセスは動作を続けることがある[^exe]

対象プロセスがマッピングしている実行ファイルやライブラリを確認するため、`maps`を読み取ります。

```bash
sudo cat "/proc/$pid/maps"
```

出力例:

```text
<range> r-xp <offset> <dev> <inode> /usr/sbin/nginx
<range> r-xp <offset> <dev> <inode> /usr/lib/x86_64-linux-gnu/libc.so.6
<range> r-xp <offset> <dev> <inode> /usr/lib/x86_64-linux-gnu/libssl.so.3
```

- 各行の末尾のパスがマッピングされたファイルで、この例では`nginx`・`libc.so.6`・`libssl.so.3`が確認できる
- 2列目の`r-xp`に含まれる`x`が、実行可能なマッピングであることを示す
- `maps`の列は、アドレス範囲・権限・ファイルオフセット・デバイスのメジャー番号とマイナー番号・inode・任意のパス名である[^maps]
- 計測用の収集プログラムは、権限に`x`を含み、パス名が`/`で始まり、inodeが0でない行を保持する[^harness]
- 対象は実行可能なファイルのマッピングであり、プロセスが読み取ったすべてのファイルではない
- 匿名メモリや`[heap]`・`[stack]`・`[vdso]`からは、パッケージが所有するファイルを特定できない
- 空白を含むパスに対応するため、固定列の後に残る部分全体をパス名として解析する
- `(path, dev, inode)`で重複を除き、各ファイルをマッピングしたプロセスの世代を保持する
- マッピングにも` (deleted)`が付くため、接尾辞を除いてパスを処理する場合も、削除の印は別に保持する[^maps]

### 実効UIDとケーパビリティ

対象プロセスの実効UIDと実効ケーパビリティを確認するため、`status`から`Uid`と`CapEff`の行を抽出します。

```bash
sudo awk '/^(Uid|CapEff):/' "/proc/$pid/status"
```

出力例:

```text
Uid:    101    101    101    101
CapEff: 0000000000000000
```

- UIDの4列は、順に実UID・実効UID・保存UID・ファイルシステムUIDである
- 実効UIDは2番目の数値で、`Uid:`を含めると3番目のフィールドであり、この例では`101`である
- `CapEff`は、実効ケーパビリティのビットマスクを16進数で表す[^status]
- この例の`CapEff`はすべて0で、実効ケーパビリティがないことを示す
- 権限を持つマスターとワーカーなどを区別する情報として、コンテナ内の全パッケージではなく個々のプロセスに紐づける
- ユーザー名前空間のリマッピング時は、ホストとコンテナ内のUIDが異なり得るため、`/proc/<pid>/uid_map`で解釈する

### 名前空間の識別情報とPIDの再利用

名前空間とプロセスの世代を記録し、収集中の入れ替わりを確認します。

対象プロセスが属するネットワーク・マウント・ユーザー名前空間の識別子を取得するため、それぞれの名前空間リンクを読み取ります。

```bash
sudo readlink "/proc/$pid/ns/net" "/proc/$pid/ns/mnt" "/proc/$pid/ns/user"
```

出力例:

```text
net:[<namespace-inode>]
mnt:[<namespace-inode>]
user:[<namespace-inode>]
```

- `net`・`mnt`・`user`の各行が、それぞれネットワーク・マウント・ユーザー名前空間を表す
- 角かっこ内の値が各名前空間の識別子で、プロセス間や収集前後で同じ種類の名前空間を比較するために使う
- 識別子でプロセスを名前空間ごとにまとめるが、同じコンテナでもすべての名前空間を共有するとは限らない[^namespaces]
- `/proc/<pid>/stat`の22番目のフィールド`starttime`は、起動からの経過時間をクロックティック単位で表し、`(PID, starttime)`で世代を区別する[^stat]
- 括弧内のプロセス名には空白や括弧が含まれ得るため、`stat`を単純な空白区切りで解析してはいけない
- 収集前後で`starttime`と名前空間を確認し、変化した場合や再確認できない場合は、そのPID経由のファイルシステム・ネットワーク情報も含めてサンプルを採用しない
- コンテナの再起動を検出するため、Dockerの`State.StartedAt`も再確認する

### 待ち受けソケットと対応するプロセス

`/proc/<pid>/net/tcp`と`tcp6`は、そのプロセスの**ネットワーク名前空間全体**のTCPテーブルを公開します。[^net]

1. 状態が`0A`のLISTEN行を選ぶ

対象プロセスのネットワーク名前空間で待ち受けているTCPソケットを調べるため、LISTEN行からローカルアドレスとポート・状態・inodeを抽出します。

```bash
sudo awk 'NR > 1 && $4 == "0A" {print $2, $4, $10}' \
  "/proc/$pid/net/tcp" "/proc/$pid/net/tcp6"
```

出力例:

```text
00000000:0050 0A <socket-inode>
```

- 1列目の`00000000:0050`はローカルアドレスとポートで、このIPv4の例では`0.0.0.0:80`を表す
- 2列目の`0A`がLISTEN状態を示す
- 3列目の`<socket-inode>`を、各プロセスのファイルディスクリプターのリンク先と照合する

2. コンテナ内の各プロセスの`fd/`を列挙し、リンクのinodeをLISTEN行と照合する

変数`pid`で指定したプロセスが持つソケットのinodeを確認するため、ファイルディスクリプターのリンク先を一覧表示します。

```bash
sudo ls -l "/proc/$pid/fd"
```

出力例:

```text
<fd-number> -> socket:[<socket-inode>]
```

- `<fd-number>`が対象プロセスのファイルディスクリプター番号である
- `socket:[<socket-inode>]`内の値がLISTEN行のinodeと一致すれば、そのプロセスが待ち受けソケットのファイルディスクリプターを持つことが分かる
- アドレスのデコードでは、32ビットワードごとのホストのネイティブバイトオーダーを考慮する[^tcp]
- マスターとワーカーがソケットを共有し得るため、一致するファイルディスクリプターを持つ全プロセスを保持する[^fd]
- TCPテーブルは名前空間ごとに1回読み取り、一致するプロセスのファイルディスクリプターがなければ紐づけを未確定にする
- 待ち受けだけでは、Dockerによるポート公開やインターネットからの到達可能性は確認できない

## コンテナ内のパスを解決する

`/usr/lib/x86_64-linux-gnu/libc.so.6`などの観測パスは、ホストではなく対象プロセスのルートから調べます。

対象プロセスのルートを変数`root`に入れ、そのルート経由でコンテナ内のdpkgデータベースのディレクトリを一覧表示します。

```bash
root="/proc/$pid/root"
sudo ls "$root/var/lib/dpkg"
```

- `/proc/<pid>/root`では、マウント名前空間やプロセスごとのマウントを含む、そのプロセスのファイルシステムにアクセスできる[^root]
- ホストのパッケージデータベースを検索すると、別の対象を調べることになる
- 絶対パスのシンボリックリンクも対象ルート内に収める必要があり、パスの先頭にルートを付けるだけでは制約を強制できない
- 変更され得るファイルシステムでは、開いたルートを基準に`openat2`の`RESOLVE_IN_ROOT`を使うなど、カーネルが制約を強制する方法が必要である[^openat2]
- 計測用実装はユーザー空間でリンクの各構成要素をたどるため、妨害的な変更のないテストには対応できるが、解決後にファイルを開くまでに競合が起こり得る[^harness]
- この実装は、カーネルによるルート内への制限と同等ではない

### DebianとUbuntu：dpkg

`/var/lib/dpkg/info/*.list`から所有元の索引を作り、`/var/lib/dpkg/status`からバージョンを取得します。

`libc6:amd64`が所有するファイルのパスを確認するため、コンテナ内の対応する`.list`ファイルを読み取ります。

```bash
sudo cat "$root/var/lib/dpkg/info/libc6:amd64.list"
```

出力例:

```text
/lib/x86_64-linux-gnu/libc.so.6
/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
```

- 各行が`libc6:amd64`の所有ファイルとして記録されたパスである
- 観測した実行ファイルやライブラリのパスを、この一覧と照合する
- `.list`にあるのはパスだけなので、バージョンは`status`内の対応する段落から読み取る

続いて確認する`/var/lib/dpkg/status`内の`libc6`の段落を、抜粋で示します。

出力例:

```text
Package: libc6
Status: install ok installed
Architecture: amd64
Version: <installed-version>
```

- `Package`の`libc6`と`Architecture`の`amd64`が、先ほどの`.list`に対応するパッケージ名とアーキテクチャである
- `Status: install ok installed`が、インストール済みの状態を示す
- `Version`の値がインストール済みバージョンで、スキャナーの検出結果との照合に使う
- `libc6:amd64.list`の基本パッケージ名は`libc6`で、`amd64`は独立したアーキテクチャ情報として扱う
- パッケージ名・バージョン・アーキテクチャ・ファイル一覧の利用可否を保持する
- ホストからの手動確認には`dpkg-query --admindir`が便利だが、所有元の検索は記録済みパスを使うため、別名のパスに注意する[^dpkg-query]

### Alpine：apk

`/lib/apk/db/installed`には、空行で区切られたパッケージレコードとファイルの所有情報があります。

コンテナ内のapkパッケージの名前・バージョン・所有ファイルを確認するため、インストール済みパッケージのデータベースを読み取ります。

```bash
sudo cat "$root/lib/apk/db/installed"
```

出力例:

```text
P:musl
V:<installed-version>
A:x86_64
F:lib
R:ld-musl-x86_64.so.1
```

- `P`はパッケージ名、`V`はバージョン、`A`はアーキテクチャであり、この例は`x86_64`向けの`musl`のレコードである
- `F`は現在のディレクトリを設定し、後続の各`R`はその中のファイル名を表す
- この例では、`/lib/ld-musl-x86_64.so.1`が`musl`に属する[^apk]
- レコード境界でディレクトリの状態をリセットし、同じレコード内に先行する`F`がない`R`は不正な形式として扱う
- 別パッケージのディレクトリを流用して、有効なパスにしてはいけない

### Distroless：status.d

Debianベースのdistrolessでは、次の配置からメタデータとファイル一覧を読み取ります。

出力例:

```text
/var/lib/dpkg/status.d/libc6
/var/lib/dpkg/status.d/libc6.md5sums
```

- 1行目は`libc6`の名前・バージョンなどのメタデータを格納するファイルのパスである
- 2行目はチェックサムと相対パスの組を格納する`.md5sums`ファイルのパスである

`libc6.md5sums`の内容を、1行の抜粋で示します。

出力例:

```text
<checksum>  lib/x86_64-linux-gnu/libc.so.6
```

- 1列目の`<checksum>`がチェックサム、2列目の`lib/x86_64-linux-gnu/libc.so.6`がファイルの相対パスである
- 相対パスの先頭に`/`を付けて索引を作れば、dpkgやシェルがなくてもファイル一覧を再構成できる[^distroless]
- `.md5sums`がなければファイル一覧は利用できないが、パッケージのメタデータもないとは限らない
- チェックサム情報はファイル名の取得に使うだけで、読み込まれたバイト列を検証しているわけではない

### docker execを使わない理由

procfs経由でメタデータを読むと、収集コマンドをホスト上で実行できます。

- `docker exec`は対象コンテナに別プロセスを起動するため、シェルや照会コマンドがサンプルに現れ、追加のライブラリを読み込む可能性がある
- distrolessには通常シェルやパッケージマネージャーのコマンドがないが、procfs経由ならそれらを追加せずに収集できる

## 実際のイメージで見つかったパスとデータベースの注意点

### /usr統合によるパスの別名

/usr統合で`/lib`が`/usr/lib`を指す場合、同じファイルが異なるパスで記録されることがあります。

| 情報源 | パス |
| --- | --- |
| dpkgの`.list` | `/lib/x86_64-linux-gnu/libc.so.6` |
| プロセスの`maps` | `/usr/lib/x86_64-linux-gnu/libc.so.6` |

- 計測したDebianでは、一覧にない別名で`dpkg-query -S`を実行すると失敗したが、libcの所有元がないことを意味しない[^harness]
- 照合する両側のパスについて、コンテナのルート内でディレクトリのシンボリックリンクを解決する
- 固定の接頭辞置換ではなく、`/bin`・`/sbin`・`/lib64`などにも同じ解決規則を適用する

### シンボリックリンクは別のパッケージに属することがある

計測したDebianでは、リンクとリンク先の所有元が異なりました。
次の例は、確認した所有関係を要約したものです。

出力例:

```text
libc-bin owns: /usr/bin/ld.so
                         -> loader owned by libc6
```

- 1行目は、シンボリックリンク`/usr/bin/ld.so`の所有元が`libc-bin`であることを示す
- 矢印の先はリンク先のローダーを表し、その所有元が`libc6`であることを示す
- 索引作成時に最後のリンクまでたどると、ローダーに存在しない2つ目の所有元が生じ、本来は有効な照合ができなくなった
- データベースの各パスは**ディレクトリ部分**だけを解決し、最後の構成要素を保持する
- リンクの所有元がリンク先も所有するわけではなく、カーネルのマッピングは実体を指すため、リンクの所有情報を引き継がない

### ファイルを持たないapkパッケージはデータベースの不備ではない

AlpineのRedisイメージにあった仮想パッケージ`.redis-rundeps`は、依存関係をまとめるだけでファイルをインストールしません。

- `F`・`R`のないこのレコードは、有効で完全な空のファイル一覧である
- 一覧の欠落と扱うと、データベース全体が不完全とみなされ、無関係な所有元のないファイルまで未解決になった
- 空の一覧と読み取り・解析できない一覧を区別し、後者だけを所有情報の欠落として扱う

### パッケージデータベースに含まれない実行ファイルもある

ある稼働中ホストでは、`/usr/local/bin/node`・同梱JDK・静的リンクのGo実行ファイルがOSパッケージの一覧にありませんでした。

- JVMが読み込んだほかのライブラリでは、所有元のOSパッケージを特定できた
- 読み取り可能で完全な一覧に所有元がなければ、`unowned`と記録する
- 実行ファイル名・配置ディレクトリ・似た名前のスキャナー検出結果から、所有元を推測してはいけない
- データベースやファイル一覧がない場合は所有元の不在を確認できないため、別の結果として扱う

### OverlayFSではデバイス番号が異なることがある

動的リンクのテストでは、`maps`とコンテナのルート経由の`stat`でデバイス番号が異なりました。

- `maps`は下位レイヤー、`stat`はオーバーレイのデバイスを示し、inodeは一致しても`dev + inode`は一致しなかった
- OverlayFSの識別情報は設定により異なるため、この不一致だけでは置き換えと判断できない[^overlayfs]
- libcなど変更されていないと見込まれるファイルで比較の成立を確認し、計測用実装では確認に失敗すると置き換え比較を未評価にした
- inodeだけの一致は観測結果にすぎず、一般的な置き換え検出方法として検証されたものではない
- 実行ファイルのアンリンク・ライブラリのアンリンク・renameによるライブラリ置き換えでは、いずれも削除済みマッピングを確認した
- 削除の印を独立して保持し、古いマッピングに同じパスの置き換え後のファイルの現行バージョンを割り当ててはいけない

## 権限：計測結果とLinuxによるチェック

必要な権限は、読み取る情報とホストの設定によって異なります。

| 操作 | 関連するチェック |
| --- | --- |
| `exe`のリンクや`maps`の読み取り | `PTRACE_MODE_READ_FSCREDS`のアクセスチェック |
| 名前空間へのリンクの読み取り | ptraceの読み取りアクセスチェック |
| `root`をたどり、コンテナ内のファイルを読み取る | ptraceの読み取りアクセスチェックと、ディレクトリおよびファイルの権限 |
| `fd/`の列挙と、そのリンクの読み取り | ディレクトリの権限と、リンクに対するptraceの読み取りアクセスチェック |
| `status`やTCPテーブルの読み取り | procfsの可視性と通常の権限。`maps`と同じ個別のptraceチェックではありません |
| Dockerへのプロセス一覧の要求 | Docker APIへのアクセス |

- WSL2では、非rootでも`CAP_SYS_PTRACE`で`exe`・`maps`・`status`・名前空間リンク・TCPテーブル・`root`経由のパッケージメタデータを読めた[^harness]
- `fd/`はroot所有のモード`0500`で、ptraceチェックに通っても列挙できず、`CAP_DAC_READ_SEARCH`が追加で必要だった
- `CAP_DAC_READ_SEARCH`は読み取り・検索の制限を回避し、コンテナ内の保護されたファイルにも必要になる場合がある[^capabilities]
- ptraceチェックはデバッガーの接続を意味せず、資格情報・対象のdumpable状態・ケーパビリティ・セキュリティモジュールの制限を評価する[^ptrace]
- `CAP_SYS_PTRACE`は、対象のユーザー名前空間で有効である必要がある
- ケーパビリティのテスト環境は、WSL2 Linux 6.6.114、Docker Engine 29.1.3、Yamaの`ptrace_scope=1`、`hidepid`制限なしだった
- AppArmorが有効な別のUbuntuホストでも収集できたが、rootのみのテストで、非rootと各ケーパビリティの組み合わせは未検証である
- Yamaの`ptrace_scope`はattachモードと`PTRACE_TRACEME`を対象とし、これらのreadモードを直接制限しないが、ほかのポリシーで拒否される場合がある[^ptrace]
- 計測結果は一般的な保証ではなく、procfsのマウントオプション・ユーザー名前空間・ファイルモード・AppArmorやSELinuxのポリシーで変わる[^proc]
- 権限による失敗は、プロセス終了やパッケージデータベース不在と分けて記録する

## プロセスとパッケージの紐づけの限界

### サンプリングでは短時間の動作を見落とす

短時間のプロセスは、定期的なサンプリングで捉えられないことがあります。

- curlを5秒ごとに約0.1秒実行し、300秒間にわたり10秒ごとに観測したところ、捉えたのは**30回のサンプルのうち1回**だった
- 別の間隔や開始タイミングでは一度も捉えられず、頻度だけでなく観測タイミングも結果に影響した
- プロセスや一時的な`dlopen`は、観測と観測の間に開始して終了する可能性がある

### 言語の依存パッケージには別の紐づけ方法が必要

OSパッケージの所有情報だけでは、言語側の依存パッケージを特定できません。

- JavaのJAR・npm・pip・Goモジュールの識別情報は、この方法ではファイル内容から復元できない
- JARやネイティブ拡張が見える場合や、言語関連ソフトウェアがディストリビューションによりパッケージ化されている場合も、特定できるのはOS側のパッケージである
- 内包されるどの言語依存パッケージがスキャナーの検出結果に対応するかは、確認できない
- PythonやNode.jsを観測しても、すべてのpip・npmパッケージの使用を確認したことにはならない

### 静的リンクでは個々のライブラリを識別できない

静的リンクされたコードには、この方法で解決できる独立したライブラリのパスがありません。

- テストした静的リンクのGoバイナリには共有ライブラリのマッピングがなく、実行ファイル自体は`exe`とメモリマッピングの両方に現れた
- 実行ファイルをパッケージに紐づけても、組み込まれた静的ライブラリやGoモジュールは再構成できない
- 所有関係はデータベース上のパス情報であり、メタデータを更新しない上書きやbindマウントで、インストール済みバージョンとの対応が崩れる場合がある

## 全体の手順

収集プログラムでは、次の処理を繰り返せます。

1. コンテナを列挙し、コンテナID、イメージID、開始時刻を記録する
2. Dockerからホスト側PIDを取得し、各プロセスの識別情報を確定する
3. 実行ファイル、実行可能なマッピング、ステータス、名前空間、ソケットを読み取る
4. 各プロセスのルートとパッケージデータベースを使って、パスを解決する
5. 根拠を採用する前に、プロセスとコンテナの識別情報を再確認する
6. 特定したパッケージ名とバージョンを、スキャナーの検出結果と照合する

- 所有元の索引はマウント名前空間とデータベースの世代ごとに作り、サンプルごとにキャッシュを再確認して、変更があれば再構築する
- 代表PIDが終了した場合は、データベース不在と判断する前に、同じマウント構成が見える別のPIDを試す
- Trivyでは、バイナリパッケージ名を`PkgName`、バージョンを`InstalledVersion`と比較する
- バージョンはエポック・リビジョンを含む完全な表記を保持し、タグだけに頼らず、観測したイメージがスキャン対象であることを確認する

| 分類 | 意味 |
| --- | --- |
| `confirmed` | 有効なサンプルで、実行ファイルまたはマッピングを、検出結果のOSパッケージ名とバージョンに紐づけられた |
| `unknown` | 読み取りの失敗、メタデータの欠落、所有元の曖昧さ、識別情報やバージョンの問題により、信頼できる結論を出せなかった |
| `unobserved` | 有効な収集を行ったものの、確認につながる根拠が得られなかった。一致するマッピングがない、言語パッケージの紐づけに未対応などの理由を添える |

- 分類と併せて、タイムスタンプ・成功したサンプル数・読み取り失敗・未解決のパスを保持する
- ソケットの紐づけに失敗しても、有効なパッケージの紐づけを取り消す必要はない
- 実行時にパッケージの使用が確認できた場合は、KEV・EPSS・深刻度などで判断した緊急度は変えず、**同じ緊急度の検出結果の中で先に対応する判断材料にし、使用を確認できなかったことを理由に優先度を下げない**
- 確認できた場合は、この方法の限界の範囲内でパッケージの使用を観測したことを示す
- `unknown`・`unobserved`は、脆弱性を報告対象から除外したり、安全と判断したりする根拠にはならない

## 参考資料

文書の確認日は2026年9月13日です。

- 計測は2026年9月12日に行い、特定のホストと実行時の結果を示している
- ほかのイメージやLinuxの設定で同じ結果を保証するものではない

///Footnotes Go Here///

[^proc]: [Linuxマニュアル：proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)

[^docker-top]: [Docker：docker container top](https://docs.docker.com/reference/cli/docker/container/top/)

[^moby-top]: [Moby：Linuxでのコンテナプロセス一覧取得の実装](https://github.com/moby/moby/blob/master/daemon/top_unix.go)

[^exe]: [Linuxマニュアル：proc_pid_exe(5)](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html)

[^maps]: [Linuxマニュアル：proc_pid_maps(5)](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html)

[^status]: [Linuxマニュアル：proc_pid_status(5)](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)

[^namespaces]: [Linuxマニュアル：namespaces(7)](https://man7.org/linux/man-pages/man7/namespaces.7.html)

[^stat]: [Linuxマニュアル：proc_pid_stat(5)](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html)

[^net]: [Linuxマニュアル：proc_pid_net(5)](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html)

[^tcp]: [Linuxカーネル：proc/net/tcpとproc/net/tcp6の変数](https://docs.kernel.org/networking/proc_net_tcp.html)

[^fd]: [Linuxマニュアル：proc_pid_fd(5)](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)

[^root]: [Linuxマニュアル：proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)

[^openat2]: [Linuxマニュアル：openat2(2)、RESOLVE_IN_ROOTの説明を含む](https://man7.org/linux/man-pages/man2/openat2.2.html)

[^dpkg-query]: [Debian：dpkg-query(1)](https://manpages.debian.org/bookworm/dpkg/dpkg-query.1.en.html)

[^apk]: [Alpine apk-tools v2.14.4：パッケージデータベースの実装](https://github.com/alpinelinux/apk-tools/blob/v2.14.4/src/database.c)

[^distroless]: [Distroless：パッケージメタデータの仕様](https://github.com/GoogleContainerTools/distroless/blob/main/PACKAGE_METADATA.md)

[^overlayfs]: [Linuxカーネル：Overlay Filesystem](https://docs.kernel.org/filesystems/overlayfs.html)

[^ptrace]: [Linuxマニュアル：ptrace(2)、アクセスモードのチェックとYama](https://man7.org/linux/man-pages/man2/ptrace.2.html)

[^capabilities]: [Linuxマニュアル：capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html)

[^harness]: [ランタイム検出の計測用ハーネスとREADME](https://github.com/kitsunetrail/kestrelynx/tree/main/experiments/runtime-discovery)

---

KestreLynxは、稼働中のDocker・KubernetesコンテナのイメージをTrivyで定期的にスキャンし、前回からの変化と、深刻度・CISA KEV・EPSSに基づく優先度をSlackやWebhookへ通知するOSSです。Docker・Compose向けの修正計画と修正PR（実験的）で、更新候補の比較からGitHubへのPR作成まで修正を支援します（既定で無効）。マージ・再ビルド・デプロイは利用者が行います。

[KestreLynxについて](../index.md) · [GitHubでソースコードを見る](https://github.com/kitsunetrail/kestrelynx)
