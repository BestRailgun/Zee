#!/bin/bash
# zeekr-sideload.sh — 把任意 APK 通过极氪应用商店的「检查更新」通道安装到车机
#
# 原理：注入假更新（把已安装应用的版本抬高、哈希/大小指向目标 APK）+ 替换下载内容。
# 需要管理员权限（配置 pf 透明转发）。用法：
#   sudo bash scripts/zeekr-sideload.sh --apk /path/to/app.apk
#   sudo bash scripts/zeekr-sideload.sh --apk app.apk --pkg com.zeekr.media.podcast
#
# 前提：Mac 已开启互联网共享、车机已连接、车机信任 eMudhra 链。

set -uo pipefail
umask 077

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BASE=$(cd "$SELF_DIR/.." && pwd)

APK=""
PKG="ALL"

while [ $# -gt 0 ]; do
  case "$1" in
    --apk)
      [ $# -ge 2 ] || { echo "--apk 需要文件路径" >&2; exit 2; }
      APK=$2; shift 2 ;;
    --pkg)
      [ $# -ge 2 ] || { echo "--pkg 需要包名或 ALL" >&2; exit 2; }
      PKG=$2; shift 2 ;;
    -h|--help)
      sed -n '2,12p' "$0"; exit 0 ;;
    *)
      # 允许直接传 APK 路径
      if [ -f "$1" ] && [ -z "$APK" ]; then APK=$1; shift; else
        echo "未知参数：$1" >&2; exit 2
      fi ;;
  esac
done

[ -n "$APK" ] || { echo "用法：$0 --apk /path/to/app.apk [--pkg 包名|ALL]" >&2; exit 2; }
[ -f "$APK" ] || { echo "APK 不存在：$APK" >&2; exit 2; }
APK=$(cd "$(dirname "$APK")" && pwd)/$(basename "$APK")

if ! file -b "$APK" | grep -Eqi 'zip|android package|java archive'; then
  echo "错误：$APK 不是 zip/APK 文件（是不是把 .command 或其他文件当成 APK 了？）" >&2
  exit 2
fi

SIZE=$(stat -f %z "$APK")
SHA=$(shasum -a 256 "$APK" | awk '{print $1}')
MD5=$(md5 -q "$APK")
MIB=$(awk -v s="$SIZE" 'BEGIN{printf "%.2f", s/1048576}')

cat <<TXT
========================================
极载 ZEEload
  APK   : $APK
  大小   : $SIZE 字节（${MIB} MiB）
  sha256 : $SHA
  md5    : $MD5
  注入包 : $PKG
========================================

车机侧操作（脚本启动后）：
  1) 打开应用商店 → 我的 / 检查更新
  2) 出现「有更新」后，点任意一个应用的更新
  3) 进度走完即安装的是上面的 APK，然后按 Ctrl-C

注意：先看终端是否出现 [inject-update] 行。
  出现  → 商店已取到新元数据，可以点更新
  没出现 → 商店在用缓存：到 设置 → 应用 → 应用商店 里「强行停止」，
           或重启车机，再重开商店点「检查更新」
TXT

exec bash "$SELF_DIR/transparent-test.sh" --all-443 --intercept-all --inject-update "$PKG" --replace-apk "$APK"
