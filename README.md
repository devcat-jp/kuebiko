# 久延毘古（くえびこ / kuebiko）

ローカル PC で動作する「久延毘古（くえびこ）」アプリケーション。
一定期間生存確認ができなかった場合に、事前に登録したメールアドレスへ金融情報やドキュメントを自動送信します。

## ビルド

```bash
go build -o kuebiko.exe .
```

## 実行

```bash
.\kuebiko.exe
```

## 環境変数

| 変数 | 説明 | デフォルト |
|------|------|------------|
| `KUEBIKO_HOST` | 待ち受け IP アドレス | `127.0.0.1` |
| `KUEBIKO_PORT` | 待ち受けポート番号 | `8080` |
| `KUEBIKO_DATA_DIR` | データベース保存先ディレクトリ | `data` |
| `KUEBIKO_CHECK_INTERVAL` | 生存確認切れの監視間隔 | `1h` |
| `KUEBIKO_TLS_AUTO` | `1` で自己署名証明書を自動生成し HTTPS で起動 | 未設定（HTTP） |
| `KUEBIKO_TLS_CERT` | サーバー証明書ファイルパス | 未設定 |
| `KUEBIKO_TLS_KEY` | サーバー秘密鍵ファイルパス | 未設定 |
| `KUEBIKO_ALLOWED_IPS` | アクセスを許可する IP 範囲（カンマ区切り） | 未設定（すべて許可） |

詳細は [docs/user-manual.md](docs/user-manual.md) を参照してください。