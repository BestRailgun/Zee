#!/bin/bash
# 双击运行：只读检查网络与工具（不需要密码）
set -uo pipefail
cd "$(dirname "$0")"
bash scripts/check-environment.sh
echo ""
read -r -p "按回车关闭窗口。" _
