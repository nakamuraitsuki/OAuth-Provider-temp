#!/bin/bash

KEY_DIR="./certs"
PRIVATE_KEY="$KEY_DIR/private.pem"
PUBLIC_KEY="$KEY_DIR/public.pem"

# ディレクトリがなければ作成
mkdir -p $KEY_DIR

if [ ! -f "$PRIVATE_KEY" ]; then
    echo "Generating RSA private key..."
    # 2048bit の RSA 秘密鍵を生成
    openssl genrsa -out "$PRIVATE_KEY" 2048
    # 秘密鍵から公開鍵を抽出（デバッグや外部配布用）
    openssl rsa -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"
    echo "Keys generated in $KEY_DIR"
else
    echo "Keys already exist. Skipping generation."
fi

# アプリから読み込めるように権限調整
chmod 600 "$PRIVATE_KEY"