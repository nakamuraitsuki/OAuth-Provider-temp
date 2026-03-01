#!/bin/bash

# 127.0.0.2 のループバック設定を削除するスクリプト
# 実行には管理者権限（sudo）が必要です

IP_ADDR="127.0.0.2"

set -e

# WSLかどうかを判定
IS_WSL=false
if grep -qEi "(Microsoft|WSL)" /proc/version &> /dev/null; then
    IS_WSL=true
fi

if [ "$IS_WSL" = true ]; then
    echo "🚨 Detected WSL..."
    
    # WSL内部のループバックからエイリアスを削除
    echo "Step 1: Removing internal WSL loopback alias..."
    if ip addr show lo | grep -q "$IP_ADDR"; then
        sudo ip addr del $IP_ADDR/8 dev lo
        echo "   -> Success: Removed $IP_ADDR from lo in WSL."
    else
        echo "   -> $IP_ADDR was not configured in WSL."
    fi

    # Windowsホスト側への案内
    echo ""
    echo "Step 2: Windows Host Cleanup Required"
    echo "Windows側の設定を削除するには、管理者権限のPowerShellで以下を実行してください："
    echo "------------------------------------------------------------"
    echo "  netsh interface ipv4 delete address \"Loopback\" $IP_ADDR"
    echo "------------------------------------------------------------"

elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Detected Native Linux..."
    sudo ip addr del $IP_ADDR/8 dev lo || echo "Not configured."

elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Detected macOS..."
    sudo ifconfig lo0 -alias $IP_ADDR || echo "Not configured."

else
    echo "Unsupported OS or Environment: $OSTYPE"
    exit 1
fi

echo ""
echo "✅ Cleanup complete."