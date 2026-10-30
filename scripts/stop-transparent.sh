#!/bin/bash
# 紧急停止 / 恢复：卸载 anchor 规则并停止透明代理进程。可重复执行。
# 用法：sudo bash scripts/stop-transparent.sh

set -uo pipefail

ANCHOR=${ZEEKR_ANCHOR:-com.apple/zeekr-capture}

say() { printf '%s\n' "$*"; }
warn() { printf '警告：%s\n' "$*" >&2; }

[ "$(id -u)" = 0 ] || { echo "需要管理员权限：sudo bash $0" >&2; exit 1; }

say "== 卸载 pf anchor：$ANCHOR =="
pfctl -a "$ANCHOR" -F all 2>/dev/null
if pfctl -a "$ANCHOR" -s rules 2>/dev/null | grep -q .; then
  warn "anchor 仍有规则，请检查：sudo pfctl -a $ANCHOR -s rules"
else
  say "[ok] anchor 规则已清空"
fi

say ""
say "== 停止透明代理进程 =="
if pgrep -f 'mitmdump.*--mode transparent' >/dev/null 2>&1; then
  pkill -f 'mitmdump.*--mode transparent'
  sleep 1
  if pgrep -f 'mitmdump.*--mode transparent' >/dev/null 2>&1; then
    pkill -9 -f 'mitmdump.*--mode transparent'
    say "[ok] 已强制停止 mitmdump"
  else
    say "[ok] 已停止 mitmdump"
  fi
else
  say "[ok] 没有运行中的透明 mitmdump"
fi

say ""
say "== 当前状态 =="
pfctl -s info 2>/dev/null | awk '/Status|State Table|References/{print "  " $0}'
say "当前 anchor 列表（应只剩系统项）："
pfctl -s Anchors 2>/dev/null | sed 's/^/  /' | head -n 20

say ""
say "若车机仍无法上网：确认系统设置 -> 通用 -> 共享 -> 互联网共享 仍为开启；"
say "必要时关掉再打开一次共享，让系统重新加载它自己的 NAT/转发规则。"
