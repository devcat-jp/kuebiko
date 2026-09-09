# Kuebiko リポジトリ作業ガイド

このファイルは、Kuebiko リポジトリで作業するコーディングエージェント向けの常時参照ガイドです。既存の実装を尊重し、設計・セキュリティ・データ保護を崩さずに、小さく検証可能な変更を行ってください。

## 1. プロジェクトの目的

久延毘古（くえびこ / Kuebiko）は、ローカル PC で動作する単一ユーザー向け Web アプリケーションです。管理者が設定した期間内に生存確認を行わなかった場合、登録済みの受信者へ、保存されたシークレットと Markdown ドキュメントをメール送信します。

- 表示名は `app_name.go` の `applicationName` 定数で一元管理する。
- デフォルトは `127.0.0.1:8080` のローカル HTTP サーバー。
- 設定により LAN 公開、TLS、IP 制限、日英切り替えに対応する。
- 機密コンテンツは AES-GCM で暗号化して SQLite に保存する。
- アプリは単一ユーザーを前提とし、ユーザー ID は常に `1`。

## 2. 技術スタックと制約

- Go `1.26.1`、モジュール名 `local-app`
- HTTP: 標準ライブラリ `net/http` の `ServeMux`
- HTML: `html/template`、`go:embed` による `templates/*` と `static/*` の埋め込み
- DB: CGO 不要の `modernc.org/sqlite`
- パスワード: `golang.org/x/crypto/bcrypt`
- 暗号化: 標準ライブラリ AES-GCM
- Markdown: `github.com/gomarkdown/markdown`
- メール: `github.com/jordan-wright/email` と `net/smtp`

追加ライブラリは、標準ライブラリや既存実装で解決できない場合に限ります。依存を追加・更新した場合は `go.mod` と `go.sum` の変更理由を明確にし、ビルドで検証してください。CGO 前提の SQLite ドライバーへ変更しないでください。

## 3. リポジトリ地図

```text
.
├── main.go                 # 起動、embed、テンプレート、ルーティング、各 HTTP ハンドラ、期限監視
├── db.go                   # SQLite 接続、スキーマ、config、CRUD、暗号化データの読み書き
├── models.go               # User / SMTPSettings / Recipient / Secret / Document / AppData
├── auth.go                 # bcrypt、セッション Cookie、認証ミドルウェア
├── crypto.go               # AES-GCM、Base64 キー、暗号化・復号
├── email.go                # 期限超過時の本文・添付ファイル作成、SMTP 送信
├── env.go                  # 任意の `.env` 読み込み（既存環境変数を優先）
├── flash.go                # Cookie ベースのフラッシュメッセージ
├── i18n.go                 # `ja` / `en` 翻訳、言語 Cookie、言語切り替え
├── ipfilter.go             # `APP_ALLOWED_IPS` または DB 設定によるアクセス制限
├── tls.go                  # 外部証明書または自己署名証明書の TLS 設定
├── app_name.go             # 製品表示名
├── templates/              # HTML テンプレート。各ページの title/content と layout
├── static/style.css        # UI スタイル
├── locales/{ja,en}.json    # 翻訳辞書
├── data/                   # 実行時 DB・暗号化キー・TLS ファイル（ソース変更対象外）
├── docs/software-design.md # 詳細設計と現在の前提
├── docs/user-manual.md     # 利用者向けマニュアル
└── README.md               # 概要、ビルド、実行、環境変数
```

`app.exe`、`dms.log`、`data/` などの実行生成物を編集・コミット対象にしないでください。まず `.gitignore` と Git の追跡状態を確認してください。

## 4. アーキテクチャと処理の流れ

### 起動

`main()` は次の順で処理します。

1. `initTranslations()` で埋め込み翻訳を読み込む。
2. `.env` を読み込む。ただし既存の環境変数が優先される。
3. データディレクトリを作成する。
4. `APP_ENCRYPTION_KEY`、`APP_ENCRYPTION_KEY_FILE`、またはデフォルトの `data/encryption.key` から暗号化キーを取得する。なければ生成する。
5. `NewDB()` で SQLite を開き、スキーマを作成する。
6. 埋め込みテンプレートを解析する。
7. `watchOverdue()` をゴルーチンで起動する。
8. ミドルウェアを組み合わせ、HTTP または HTTPS で待ち受ける。

### HTTP リクエスト

全体の外側から、概ね次の順に適用されます。

```text
languageMiddleware
  -> ipFilter
    -> ServeMux
      -> 認証が必要な handler は authMiddleware
        -> App の handler
          -> render() または redirect
```

- `/setup` と `/login` は未認証で利用する。
- `/checkin/{token}` はログイン不要。ただし推測困難なトークンを bearer credential として扱う。
- `/static/` は埋め込みファイルを配信する。
- POST で状態を変更する handler は、既存の HTTP メソッド検査と redirect/flash パターンを維持する。

### 期限超過とメール送信

`watchOverdue()` は起動直後と指定間隔ごとに `checkTrigger()` を呼びます。`email_enabled=1`、未作動、`last_check_in_at` が存在し、`last_check_in_at + check_in_interval_hours` が現在時刻を過ぎた場合だけ、受信者・シークレット・ドキュメントを読み込み、`sendTriggerEmail()` を実行します。メール送信成功後にのみ `is_triggered=1` を設定します。生存確認は期限と作動状態をリセットします。

メール経路は次の通りです。

- TLS 有効かつポート `465`: implicit TLS
- TLS 有効でその他のポート: STARTTLS
- TLS 無効: 通常の SMTP

この処理は機密データを扱うため、送信失敗時に作動済みへ更新しないこと、ログへ本文・パスワード・暗号鍵を出力しないことを守ってください。

## 5. データと暗号化

SQLite スキーマは `db.go` の `createSchema()` が実体です。設計書に古い記述がある場合は、実装とマイグレーションの有無を確認してから判断してください。

主なテーブル:

- `config`: 設定値、チェックイン・トークン情報
- `users`: 単一ユーザー、セッション、生存確認、作動状態
- `smtp_settings`: SMTP 設定
- `recipients`: 受信者と表示順
- `secrets`: 暗号化された構造化シークレットと表示順
- `documents`: 暗号化された Markdown と表示順

暗号化に関する不変条件:

- `secrets.content` と `documents.content` は保存時に `encrypt()`、読み出し時に `decrypt()` を通す。
- キーは Base64 化された 32 バイト AES キー。鍵の形式を勝手に変更しない。
- チェックイン URL の token は検証用ハッシュと、認証済み設定画面で再表示するための暗号文を DB に保持する。
- SMTP パスワードなど機密値をログ、エラーメッセージ、テンプレートのデバッグ出力へ流さない。
- DB のバックアップ、暗号鍵、TLS 秘密鍵の扱いは別々に考える。DB だけの流出では暗号化の保護が限定的であることを前提にする。

DB の変更を行う場合:

1. 既存 DB に対する後方互換性を確認する。
2. `CREATE TABLE IF NOT EXISTS` だけでは既存テーブルの列追加にならないため、必要なら明示的な移行処理を設計する。
3. SQL のプレースホルダーを使い、文字列連結で値を SQL に埋め込まない。
4. 読み書き両方、エラー処理、空データ、再起動後の挙動を確認する。

## 6. テンプレート・i18n の規約

- `templates/layout.html` が共通レイアウト。
- 各ページは `{page}_title` と `{page}_content` の named template を定義する。
- `App.render()` はページの title/content を個別に実行して `layout` に渡す。named template 名を衝突させない。
- テンプレートから表示するユーザー入力は原則 `html/template` にエスケープさせる。
- Markdown の HTML 化は既存の `renderMarkdown()` に集約する。新しい `template.HTML` を安易に作らない。
- UI 文言は可能な限り `locales/ja.json` と `locales/en.json` にキーを追加し、`t` 関数で参照する。
- 翻訳キーを追加したら両言語の辞書を更新し、キー名の綴りを一致させる。
- 画面のフォーム送信、flash キー、リダイレクト先は既存ページのパターンに合わせる。

## 7. 認証・Web セキュリティ

- パスワードは必ず bcrypt で処理し、平文を保存・ログ出力しない。
- 認証済みページへ handler を追加する場合、`mux.HandleFunc()` を `app.authMiddleware(...)` で包む。
- `/checkin/{token}` のような意図的な公開 endpoint を除き、認証漏れを作らない。
- 状態を変更する処理は POST に限定する。ID、token、return URL など外部入力を検証する。
- Cookie の属性、token の比較、リダイレクトの open redirect 防止を既存実装と同等以上に保つ。
- `APP_HOST=0.0.0.0` は LAN 公開である。ネットワーク公開に関係する変更では TLS と IP 制限を考慮する。
- HTML、Markdown、メール本文、添付ファイル名に由来する入力の扱いを分け、適切なエスケープ・サニタイズを行う。

## 8. 変更時の進め方

1. まず `README.md`、`docs/software-design.md`、対象 Go ファイル、関連テンプレート・翻訳を読む。
2. 既存の handler、DB helper、ミドルウェア、テンプレート規約を再利用する。
3. 変更を最小単位にし、機能変更と無関係な大規模整形を避ける。
4. Go コードは `gofmt` を適用する。
5. 仕様・環境変数・画面・DB スキーマが変わる場合は、関連ドキュメントも更新する。
6. 機密情報や実データをテスト・ログ・コミットに含めない。

## 9. 検証コマンド

通常の変更では、リポジトリルートで次を実行します。

```text
go test ./...
go vet ./...
go build -o app.exe .
```

テストがない場合でも、少なくとも `go test ./...` と `go build -o app.exe .` を実行してください。依存関係を変更した場合は必要に応じて `go mod tidy` の差分を確認します。実行時確認では一時ディレクトリを `APP_DATA_DIR` に指定し、実データ `data/` を上書きしないでください。

## 10. 変更影響マップ

| 変更内容 | 主に確認する場所 |
|---|---|
| ルート・認証 endpoint | `main.go`, `auth.go`, 関連テンプレート |
| DB 列・CRUD | `db.go`, `models.go`, 既存 DB 互換性 |
| 暗号化対象 | `crypto.go`, `db.go`, `email.go`, バックアップ方針 |
| 期限判定・生存確認 | `main.go`, `db.go`, `templates/dashboard.html`, `templates/settings.html` |
| SMTP・メール形式 | `email.go`, `db.go`, `templates/settings.html` |
| 文言・言語 | `i18n.go`, `locales/ja.json`, `locales/en.json`, templates |
| IP 制限 | `ipfilter.go`, `main.go`, 設定画面、README |
| TLS | `tls.go`, `main.go`, README、ユーザーマニュアル |
| 表示名 | `app_name.go`, 通知メール、翻訳・テンプレート |
| UI レイアウト | `templates/layout.html`, 対象ページ、`static/style.css` |

## 11. エージェント向け注意

- 不明な仕様は、まず既存コードと `docs/software-design.md` の両方を照合する。実装が優先されるが、差異を見つけたら必要に応じてドキュメントも直す。
- セキュリティに関わる変更では、便利さより fail-safe、認証境界、秘密情報の最小露出を優先する。
- 既存の日本語 UI と英語 UI の両方を壊さない。
- ユーザーが依頼していない場合、データ削除、DB リセット、暗号鍵再生成、実行中プロセスの停止を行わない。
- 変更結果の報告では、変更ファイル、検証内容、未検証の点、DB・設定への影響を簡潔に明示する。
