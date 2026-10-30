#!/bin/bash
# 只读检查：导出当前 pf 活动规则、NAT、anchor 列表，供分析透明转发挂接点。
# 不改动任何规则。用法：sudo bash scripts/inspect-pf.sh

set -uo pipefail
BASE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$BASE/logs"
STAMP=$(date +%Y%m%d-%H%M%S)
OUT=$BASE/logs/pf-inspect-$STAMP.txt

[ "$(id -u)" = 0 ] || { echo "需要管理员权限：sudo bash $0" >&2; exit 1; }

{
  echo "# pf 只读检查 $(date)"
  echo "## pfctl -s info";    pfctl -s info 2>&1
  echo "## pfctl -s rules";   pfctl -s rules 2>&1
  echo "## pfctl -s nat";     pfctl -s nat 2>&1
  echo "## pfctl -s Anchors"; pfctl -s Anchors 2>&1
  echo "## pfctl -s Tables";  pfctl -s Tables 2>&1
  echo "## pfctl -s Limits";  pfctl -s Limits 2>&1
  echo "## pfctl -s References"; pfctl -s References 2>&1
  echo "## /etc/pf.conf";     cat /etc/pf.conf 2>&1
  echo "## /etc/pf.anchors/com.apple"; cat /etc/pf.anchors/com.apple 2>&1
  echo "## ifconfig";         ifconfig 2>&1
  echo "## sysctl forwarding"; sysctl net.inet.ip.forwarding net.inet.ip.scopedroute 2>&1
} > "$OUT" 2>&1

if [ -n "${SUDO_UID:-}" ]; then chown "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$OUT" 2>/dev/null; fi

echo "已保存：$OUT"
echo ""
echo "== 关键行 =="
grep -nE 'Status:|rdr-anchor|nat-anchor|anchor "|navigators|^[a-z]+ on |^pass|^nat on|^rdr' "$OUT" | head -n 40
echo ""
echo "== 当前 anchor 列表 =="
pfctl -s Anchors 2>/dev/null | sed 's/^/  /'
