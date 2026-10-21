# Kubernetes での修正 PR の開発

- **状態:** 設計(実装未着手)
- **開始日:** 2026年10月20日
- **最終更新:** 2026年10月20日

## 目的

[修正計画と修正 PR](remediation-pull-requests.md)を Kubernetes でも使えるようにする。
直す場所は利用者に明示してもらい、言語パッケージの更新はクラスタの中の使い捨ての Pod で安全に動かす設計にする。

## 修正の対象と流れ

Git で管理するマニフェストに `image: nginx:1.27.2` と書かれた Deployment が動いているとする。
修正版が 1.27.3 なら、そのタグを書き換える PR を作る。

変更前のマニフェストの抜粋:

```yaml
containers:
  - name: web
    image: nginx:1.27.2
```

PR で提案する変更後の抜粋:

```yaml
containers:
  - name: web
    image: nginx:1.27.3
```

```text
稼働中のイメージ → 修正候補の比較 → Git のファイルを変更する PR
                                              ↓ 利用者がマージ
                                  利用者の GitOps・CI → クラスタへ反映
```

通常のマニフェストに加え、Kustomize の `images` と Helm の `values` に書かれたイメージの指定も対象にする。

KestreLynx は修正をクラスタへ適用しない。
マージ後の反映は利用者の GitOps・CI が行い、自動同期が有効ならマージがそのまま反映になる。

## 方針

- **直す場所は利用者が対応付けで明示し、Argo CD や Flux の情報から推測しない**
    - 管理元の情報だけでは、変更すべきリポジトリやファイルを特定できないため
- **Pod に書かれている版・動いている版・リポジトリのファイルの版の3つが一致したときだけ PR にする**
    - 稼働中の対象とは異なる版をもとに変更を作らないため
- **Compose と同じく、digest で固定した参照は手動での対応にする**
    - タグの更新とは別の変更規則が必要になるため

## 決定事項

### 作用範囲の明示(`affects`)

Helm の1つのキーや Kustomize の1つの指定が、複数のワークロードに効くことがある。
KestreLynx は Helm や Kustomize を展開しないので、効く範囲を推測せず、設定に書いてもらう。

次は、Helm の `image` キーが、対応付けた `web` の `app` に加えて `worker` の `app` にも効く場合の設定例である。
`affects` には、対応付けたコンテナ以外の作用先を、種類・namespace・名前・コンテナ名で列挙する。

```yaml
remediation:
  mappings:
    - workload: deployment/shop/web/app
      repository: example/deployment
      base_branch: main
      helm_values:
        path: releases/shop/values.yaml
        key: image
        affects:
          - deployment/shop/worker/app
```

`affects` がなければ、利用者が「対応付けたコンテナだけに効く」と確認したものとして扱う。
念のため、同じ namespace などで同じ値を使う未記載のワークロードを見つけたら PR の作成を止めるが、記載漏れをすべて見つけられるわけではない。

### 言語パッケージの更新の実行方式

Docker ではパッケージマネージャーを作業用コンテナで動かしているが、対象のクラスタ内には Docker がない。
外部の Docker ホストを使う案は利用者の準備の負担が大きいため採らず、作業専用の namespace に使い捨ての Pod を作る方式にした。

Pod を作る権限は、利用者が言語パッケージの更新を有効にしたときだけ、その作業用 namespace に限って付ける。

### 作業用 Pod の安全策

言語パッケージの更新は Kubernetes 1.30 以降を対応対象とし、次の安全策を設ける。

- クラスタの標準機能である ValidatingAdmissionPolicy で作れる Pod の形を固定し、KestreLynx は作業前に違反する Pod の試し作成が拒否されることを確かめる
- 作った Pod の実際の中身が許可した形と一致することを確かめてから、更新元のファイルを渡す
- 結果は作業ごとの鍵で暗号化し、結果の本文は暗号文だけをログに残す
- GitHub のトークンや KestreLynx の設定は作業用 Pod に入れない

## 未検証・次の作業

実装と実際の検証はまだ行っていない。
次の順で進める。

1. 読み取りだけの修正計画
2. マニフェストと Dockerfile の修正 PR
3. 言語パッケージの修正 PR
4. Kustomize の `images` の更新
5. Helm の `values` の更新
6. 検証用のホストでの K3s・Flux・Argo CD による実環境の検証と公開文書の整備

## 更新履歴

### 2026年10月20日

- 修正先の対応付けと版の照合
- 共有する設定の作用先の明示
- 作業用 Pod の実行方式と安全策
- 実装順と実環境の検証予定

---

この記事は、KestreLynxの開発記録です。[KestreLynxについて](../index.md)
