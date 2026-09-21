# 久延毘古（くえびこ / kuebiko）

ローカル PC で動作する「久延毘古（くえびこ）」アプリケーション。
一定期間生存確認ができなかった場合に、事前に登録したメールアドレスへ金融情報、保険情報、サブスク、メモを自動送信します。

製品表示名を変更する場合は、`app_name.go` の `applicationName` 定数を変更してください。画面表示と通知メールに共通して反映されます。実行時の設定変更には対応していません。

## インストール（Ubuntu）

3つの方法があります。いずれか一つで動作します。

### 方法1: GitHub Releases からバイナリをダウンロード（最も簡単）

[Releases ページ](../../releases)から環境に合ったアーカイブ（例: `kuebiko-v0.1.0-linux-amd64.tar.gz`）をダウンロードし、展開して実行します。

```bash
tar xzf kuebiko-v0.1.0-linux-amd64.tar.gz
chmod +x kuebiko-linux-amd64
./kuebiko-linux-amd64
```

改変チェック用に `checksums.txt`（SHA256）を同梱しています。ダウンロード後に `sha256sum -c checksums.txt` で検証してください。

### 方法2: Docker イメージを利用（git clone 不要）

GitHub Container Registry からイメージを取得できます。

```bash
docker run -d --name kuebiko -p 8080:8080 -v ./data:/data \
  --restart unless-stopped ghcr.io/devcat-jp/kuebiko:latest
```

※ リポジトリ（およびイメージ）が private の間は、事前に `docker login ghcr.io`（`read:packages` 権限の PAT が必要）が要求されます。

### 方法3: ソースから Docker ビルド（家庭内 LAN 向け推奨構成）

Docker Compose でビルドから起動まで行います。

### 前提

- Ubuntu（22.04 以降を想定）
- Docker Engine と Docker Compose プラグインが導入済みであること。未導入の場合:

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"   # 一度ログアウト/ログインして反映
```

### 手順

```bash
# 1. リポジトリを取得
git clone https://github.com/devcat-jp/kuebiko.git
cd kuebiko

# 2. 設定ファイルを用意（必要に応じて編集）
cp .env.example .env

# 3. ビルドして起動（バックグラウンド）
docker compose up -d --build
```

### 更新方法

```bash
git pull
docker compose up -d --build
```

### 停止・ログ確認

```bash
docker compose stop        # 停止
docker compose down        # 停止 + コンテナ削除（data/ は残る）
docker compose logs -f     # ログ表示
```

### 永続化とデータの所在

- SQLite データベースと暗号化キーはリポジトリ直下の `./data/` に bind mount で保存されます。
- バックアップは `data/` ディレクトリのコピーだけで完結します（アプリ停止中のコピーを推奨）。
- `data/` と `.env` は `.gitignore` に含まれているため、誤ってコミットされることはありません。

## リリースの作り方（メンテナ向け）

タグを push すると GitHub Actions がバイナリ（linux/windows/darwin）と Docker イメージ（ghcr.io）を自動ビルドし、GitHub Releases を作成します。

```bash
git tag v0.1.0
git push origin v0.1.0
```

### セキュリティの推奨事項

- `.env` で `APP_ALLOWED_IPS` を設定し、家庭内 LAN からのみアクセスを許可してください。
- `APP_TLS_AUTO=1` による HTTPS 化を推奨します。`APP_PUBLIC_URL` も `https://` で指定してください。
- ルーターのポート開放は行わないでください。外部から利用したい場合は WireGuard などの VPN 経由にしてください。

## ソースから直接ビルドして動かす

```bash
go build -o app.exe .
.\app.exe   # Windows の場合
./app       # Linux の場合
```

## 環境変数

| 変数 | 説明 | デフォルト |
|------|------|------------|
| `APP_HOST` | 待ち受け IP アドレス | `127.0.0.1` |
| `APP_PORT` | 待ち受けポート番号 | `8080` |
| `APP_DATA_DIR` | データベース保存先ディレクトリ | `data` |
| `APP_CHECK_INTERVAL` | 生存確認切れの監視間隔 | `1h` |
| `APP_TLS_AUTO` | `1` で自己署名証明書を自動生成し HTTPS で起動 | 未設定（HTTP） |
| `APP_TLS_CERT` | サーバー証明書ファイルパス | 未設定 |
| `APP_TLS_KEY` | サーバー秘密鍵ファイルパス | 未設定 |
| `APP_ALLOWED_IPS` | アクセスを許可する IP 範囲（カンマ区切り） | 未設定（すべて許可） |
| `APP_PUBLIC_URL` | 閲覧専用ページのメール掲載用公開URL | 未設定（`APP_HOST`等から生成） |

Docker 環境では `Dockerfile` の既定値により `APP_HOST=0.0.0.0` / `APP_DATA_DIR=/data` が設定されます。その他の設定はリポジトリ直下の `.env`（`cp .env.example .env` で作成）に記述し、`compose.yaml` の `env_file` で読み込まれます。

詳細は [docs/user-manual.md](docs/user-manual.md) を参照してください。
