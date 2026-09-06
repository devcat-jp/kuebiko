# 久延毘古（くえびこ）ソフトウェア設計書

本書は、本ソフトウェアを改修・拡張するコーディングエージェント向けの設計書です。

## 1. 目的とスコープ

ローカル環境で動作する久延毘古（くえびこ）Web アプリケーション。
管理者が一定期間生存確認を行わなかった場合、事前登録されたメールアドレスに対して暗号化されていた金融情報・Markdown ドキュメントを自動展開する。

## 2. 技術スタック

| 項目 | 採用技術 | 備考 |
|------|----------|------|
| 言語 | Go 1.26 | 単一バイナリ化を想定 |
| DB | SQLite（modernc.org/sqlite） | pure Go、CGO 不要 |
| HTTP ルータ | net/http | 標準ライブラリ |
| テンプレート | html/template + go:embed | テンプレート・静的ファイルを埋め込み |
| パスワードハッシュ | bcrypt（golang.org/x/crypto/bcrypt） | コストはデフォルト |
| Markdown レンダリング | gomarkdown/markdown | ドキュメントプレビュー用 |
| メール送信 | jordan-wright/email + net/smtp | STARTTLS / TLS 対応 |

## 3. アーキテクチャ概要

```
┌─────────────────────────────────────────┐
│  Browser (http://localhost:8080)        │
└─────────────┬───────────────────────────┘
              │ HTTP
┌─────────────▼───────────────────────────┐
│  net/http mux                           │
│  - 認証ミドルウェア                     │
│  - 各種ハンドラ                         │
└─────────────┬───────────────────────────┘
              │
┌─────────────▼───────────────────────────┐
│  App (db + templates)                   │
│  - DB レイヤー                          │
│  - 暗号化ユーティリティ                 │
│  - メール送信                           │
│  - 久延毘古（くえびこ）監視ゴルーチン     │
└─────────────┬───────────────────────────┘
              │
┌─────────────▼───────────────────────────┐
│  SQLite (app.db)                        │
│  - ユーザー、SMTP、受信者               │
│  - シークレット、ドキュメント           │
│  - 暗号化キー（config テーブル）        │
└─────────────────────────────────────────┘
```

## 4. ディレクトリ構造

```
app/
├── main.go          # エントリポイント、ハンドラ、ルーティング、監視処理
├── db.go            # SQLite 接続、スキーマ、CRUD
├── auth.go          # パスワードハッシュ化、セッション、認証ミドルウェア
├── crypto.go        # AES-GCM 暗号化・復号、キー生成
├── email.go         # トリガー時のメール構築・送信
├── flash.go         # フラッシュメッセージ（Cookie ベース）
├── models.go        # データモデル定義
├── templates/*.html # HTML テンプレート
├── static/style.css # スタイルシート
└── docs/            # ドキュメント
```

## 5. データモデル

### 5.1 users

| カラム | 型 | 備考 |
|--------|-----|------|
| id | INTEGER | 常に 1（シングルユーザー制約） |
| username | TEXT | ログインID |
| password_hash | TEXT | bcrypt ハッシュ |
| session_token | TEXT | セッション識別子 |
| session_expires_at | DATETIME | セッション有効期限 |
| check_in_interval_hours | INTEGER | 生存確認間隔（時間） |
| last_check_in_at | DATETIME | 前回生存確認日時 |
| is_triggered | INTEGER | 0/1、作動済みフラグ |
| email_enabled | INTEGER | 0/1、メール送信有効フラグ |

### 5.2 smtp_settings

| カラム | 型 | 備考 |
|--------|-----|------|
| id | INTEGER | 常に 1 |
| host | TEXT | SMTP ホスト |
| port | INTEGER | SMTP ポート |
| username | TEXT | SMTP 認証ユーザー |
| password | TEXT | SMTP 認証パスワード（平文） |
| from_address | TEXT | From アドレス |
| use_tls | INTEGER | 0/1 |

### 5.3 recipients

| カラム | 型 | 備考 |
|--------|-----|------|
| id | INTEGER | PK AUTOINCREMENT |
| email | TEXT | 受信メールアドレス |
| name | TEXT | 受信者名（省略可） |

### 5.4 secrets

| カラム | 型 | 備考 |
|--------|-----|------|
| id | INTEGER | PK AUTOINCREMENT |
| title | TEXT | タイトル（平文） |
| content | TEXT | 内容（AES-GCM 暗号化済み） |
| created_at | DATETIME | 作成日時 |
| updated_at | DATETIME | 更新日時 |

### 5.5 documents

| カラム | 型 | 備考 |
|--------|-----|------|
| id | INTEGER | PK AUTOINCREMENT |
| title | TEXT | タイトル（平文） |
| content | TEXT | Markdown 本文（AES-GCM 暗号化済み） |
| created_at | DATETIME | 作成日時 |
| updated_at | DATETIME | 更新日時 |

### 5.6 config

| カラム | 型 | 備考 |
|--------|-----|------|
| key | TEXT | PK |
| value | TEXT | 値 |

暗号化キー `encryption_key` を保存する。

## 6. 認証フロー

1. 初回 `/setup` でユーザー名・パスワードを受け取り、bcrypt でハッシュ化して保存
2. `/login` でユーザー名とパスワードを検証
3. 成功時、ランダムなセッショントークンを生成し DB + Cookie に保存
4. 有効期限は 24 時間
5. `authMiddleware` で Cookie と DB のトークンを照合
6. `/logout` で DB のセッションをクリア

## 7. 暗号化設計

- secrets / documents の `content` は AES-GCM で暗号化して保存
- 暗号化キーは 32 バイトのランダム値を base64 エンコードしたもの
- 初回起動時に `config.encryption_key` がなければ自動生成
- キー自体は DB 内に保存されるため、DB ファイル流出時に内容が読まれるリスクは残る
- 自動送信時に復号する必要があるため、キーはアプリ起動時に常に利用可能

```go
// crypto.go
encrypt(plaintext, keyB64 string) // AES-GCM + base64
 decrypt(ciphertextB64, keyB64 string)
```

## 8. 久延毘古（くえびこ）作動フロー

1. `main()` 内で `watchDeadMansSwitch(interval)` をゴルーチン起動
2. 指定間隔ごとに `checkTrigger()` を実行（初回は即時実行）
3. `users.email_enabled = 1` かつ `is_triggered = 0` かつ `last_check_in_at` が存在する場合
4. `last_check_in_at + check_in_interval_hours < now` なら作動
5. recipients、secrets、documents を DB から取得
6. `sendTriggerEmail()` でメール送信
7. 成功したら `users.is_triggered = 1` に更新
8. ユーザーが生存確認を行うと `is_triggered` が 0 にリセットされる

## 9. メール送信設計

`email.go` の `sendTriggerEmail` が担当。

- Subject: `【久延毘古（くえびこ）作動】重要な情報のご連絡`
- 本文: 説明文 + secrets 一覧 + documents 一覧
- 添付: documents を `title.md` として添付
- ポート 465 かつ TLS 有効 → `SendWithTLS`
- それ以外かつ TLS 有効 → `SendWithStartTLS`
- TLS 無効 → `Send`

## 10. Web UI 設計

テンプレートは `html/template` + `go:embed`。

- `layout.html`: 共通レイアウト（ヘッダー・ナビ・フッター）
- 各ページテンプレート: `{page}_title` と `{page}_content` の 2 つの named template を定義
- `main.go` の `render()` が title / content をそれぞれ実行し、結果を `layout` に渡す
- これにより、複数ページで同名の `content` ブロックが衝突しない

主要画面：

| パス | テンプレート | 内容 |
|------|--------------|------|
| / | dashboard.html | ステータス、生存確認 |
| /setup | setup.html | 初回管理者作成 |
| /login | login.html | ログイン |
| /settings | settings.html | SMTP 設定 |
| /recipients | recipients.html | 受信者一覧 |
| /secrets | secrets.html | シークレット一覧 |
| /documents | documents.html | ドキュメント一覧 |

## 11. 環境変数と設定

### 11.1 製品表示名

画面表示と通知メールで使用する製品表示名は、`app_name.go` の `applicationName` 定数で一元管理します。名称変更時はこの定数を変更して再ビルドしてください。実行時の設定変更には対応しません。

実行ディレクトリの `.env` ファイルから環境変数を読み込む機能があります。`.env` に書かれた値は、既存の環境変数がない場合のみ適用されます（環境変数が優先）。

### 11.2 IP アクセス制限

`APP_ALLOWED_IPS` 環境変数、または設定画面で指定した「許可する IP アドレスまたは範囲」により、アクセス元 IP を制限できます。両方が指定されている場合は環境変数が優先されます。空欄の場合はすべての IP を許可します。

指定形式はカンマ区切りで、以下を混在できます。

- 単一 IP: `192.168.11.10`
- CIDR: `192.168.11.0/24`
- ワイルドカード: `192.168.11.*`（IPv4 の場合 `/24` と同等）、`fe80::*`（IPv6 の場合 `/16` と同等）

設定画面からの変更は `config.allowed_ips` に保存され、再起動なしで次回リクエストから反映されます。

| 環境変数 | 型 | デフォルト | 用途 |
|----------|-----|------------|------|
| APP_HOST | string | 127.0.0.1 | 待ち受け IP アドレス |
| APP_PORT | string | 8080 | HTTP/HTTPS ポート |
| APP_DATA_DIR | string | data | DB 保存ディレクトリ |
| APP_CHECK_INTERVAL | duration | 1h | 久延毘古（くえびこ）監視間隔 |
| APP_TLS_AUTO | string | 未設定 | `1` で自己署名証明書を自動生成 |
| APP_TLS_CERT | string | 未設定 | サーバー証明書ファイルパス |
| APP_TLS_KEY | string | 未設定 | サーバー秘密鍵ファイルパス |

## 12. HTTPS（TLS）対応

`main.go` 起動時に `ensureTLSCertificate(dataDir)` を呼び出し、以下の優先順位で TLS を設定します。

1. `APP_TLS_CERT` と `APP_TLS_KEY` が両方指定されていれば、それらのファイルを使用
2. `APP_TLS_AUTO=1` が指定されていれば、`data/server.crt` と `data/server.key` として自己署名証明書を生成・使用
3. どちらも指定されていなければ HTTP で起動

自己署名証明書の生成は `crypto/x509` を使用した 2048 ビット RSA 鍵です。有効期限は 1 年間。

## 13. ビルドと実行

```bash
# 依存取得
go mod download

# ビルド
go build -o app.exe .

# 実行
.\app.exe
```

CGO は不要（modernc.org/sqlite を使用）。

## 14. セキュリティ考慮事項

- デフォルトはローカル専用：サーバーは `127.0.0.1` にのみバインド
- `APP_HOST=0.0.0.0` を指定すると LAN 全体に公開されるため、HTTPS 併用を推奨
- パスワードは bcrypt でハッシュ化
- 機密データは AES-GCM で暗号化（ただしキーも同 DB に保存）
- セッション Cookie は HttpOnly
- テンプレートは html/template を使用し XSS を抑制
- SMTP パスワードは DB に平文保存
- 自己署名証明書使用時はブラウザで警告が出る

## 15. 拡張ポイント

将来的に追加しやすい機能例：

- パスワード変更機能
- メール送信テスト機能
- ログ機能（作動履歴）
- 暗号化キーの外部ファイル保存オプション
- 複数ユーザー対応
- ワンタイムパスワードによる二段階認証
- 添付ファイル対応
