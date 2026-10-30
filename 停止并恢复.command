#!/bin/bash
# 双击运行：卸载转发规则并停止透明代理（可重复执行）
set -uo pipefail
cd "$(dirname "$0")"
sudo -p "Mac 管理员密码: " bash scripts/stop-transparent.sh
echo ""
read -r -p "按回车关闭窗口。" _
