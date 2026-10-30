#!/bin/bash
# 双击运行（或把 APK 拖到这个文件上）：通过车机应用商店的更新通道安装 APK
set -uo pipefail
cd "$(dirname "$0")"
mkdir -p logs
CMDLOG="logs/sideload-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$CMDLOG") 2>&1
echo "[输出同时保存到 $CMDLOG]"
echo ""

APK=""
if [ $# -ge 1 ] && [ -f "$1" ]; then
  APK="$1"
  shift
fi
if [ -z "$APK" ]; then
  echo "把 APK 文件拖到这个窗口里，或直接输入路径："
  read -r -p "APK 路径: " APK
  APK="${APK#\'}"; APK="${APK%\'}"
fi
if [ ! -f "$APK" ]; then
  echo "找不到 APK：$APK"
  read -r -p "按回车关闭窗口。" _
  exit 1
fi

sudo -p "Mac 管理员密码: " bash scripts/zeekr-sideload.sh --apk "$APK" "$@"
status=$?

echo ""
echo "退出状态：$status"
if [ "$status" != 0 ]; then
  echo "若车机网络异常，运行『停止并恢复.command』。"
fi
read -r -p "按回车关闭窗口。" _
