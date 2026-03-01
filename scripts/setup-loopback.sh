#!/bin/bash

# 127.0.0.2 をループバックアドレスとして設定するスクリプト
# 実行には管理者権限（sudo）が必要です

IP_ADDR="127.0.0.2"

set -e

# WSLかどうかを判定
IS_WSL=false
if grep -qEi "(Microsoft|WSL)" /proc/version &> /dev/null; then
    IS_WSL=true
fi

if [ "$IS_WSL" = true ]; then
    echo "Detected WSL (Windows Subsystem for Linux)..."
    
    # WSL内部のループバックにエイリアスを追加
    echo "Step 1: Configuring internal WSL loopback..."
    if ip addr show lo | grep -q "$IP_ADDR"; then
        echo "   -> $IP_ADDR is already configured in WSL."
    else
        sudo ip addr add $IP_ADDR/8 dev lo
        echo "   -> Success: Added $IP_ADDR to lo in WSL."
    fi

    # Windowsホスト側への案内
    echo ""
    echo "Step 2: Windows Host Configuration Required"
    echo "Windowsのブラウザからアクセスする場合、Windows側でも設定が必要です。"
    echo "管理者権限のPowerShellを開き、以下のコマンドを実行してください："
    echo "------------------------------------------------------------"
    echo "  netsh interface ipv4 add address \"Loopback\" $IP_ADDR"
    echo "------------------------------------------------------------"

elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Detected Native Linux..."
    sudo ip addr add $IP_ADDR/8 dev lo || echo "Already configured."

elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Detected macOS..."
    sudo ifconfig lo0 alias $IP_ADDR up || echo "Already configured."

else
    echo "Unsupported OS or Environment: $OSTYPE"
    exit 1
fi

echo ""
echo "✅ Configuration complete for the current environment."
echo "Check: ping -c 2 $IP_ADDR"