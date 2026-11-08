#!/bin/bash
# 只读环境检查（不需要管理员密码）。在接车机前后各跑一次。
# 用法：bash scripts/check-environment.sh

set -uo pipefail
BASE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [ -n "${ZEEKR_MITMDUMP:-}" ]; then
  MITMDUMP=$ZEEKR_MITMDUMP
elif [ -n "${ZEEKR_VENV:-}" ]; then
  MITMDUMP=$ZEEKR_VENV/bin/mitmdump
elif [ -x "$BASE/venv/bin/mitmdump" ]; then
  MITMDUMP=$BASE/venv/bin/mitmdump
else
  MITMDUMP=$(command -v mitmdump 2>/dev/null || echo mitmdump)
fi
PORT=${ZEEKR_PORT:-18080}
DOMAINS=${ZEEKR_DOMAINS:-"snc-api-gw.zeekrlife.com snc-download-cdn.zeekrlife.com"}
GUI=${ZEEKR_GUI:-0}
DIG_OPTIONS=(+short)
[ "$GUI" = 0 ] || DIG_OPTIONS=(+time=2 +tries=1 +short)

# 自动探测：共享接口（bridge*）与车机（DHCP 租约按名称识别）
detect_iface() {
  local cand addr status best=""
  for cand in $(ifconfig -l 2>/dev/null | tr ' ' '\n' | grep '^bridge'); do
    addr=$(ifconfig "$cand" 2>/dev/null | awk '/inet /{print $2; exit}')
    [ -n "$addr" ] || continue
    case "$addr" in 192.168.*|10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) ;; *) continue ;; esac
    status=$(ifconfig "$cand" 2>/dev/null | awk '/status:/{print $2; exit}')
    if [ "$status" = "active" ]; then
      ifconfig "$cand" 2>/dev/null | grep -q 'member: ap' && { echo "$cand"; return; }
      best="${best:-$cand}"
    fi
  done
  echo "$best"
}

detect_lease() {
  local prefix="$1" mode="$2"
  [ -r /var/db/dhcpd_leases ] || return
  awk -v prefix="$prefix" -v mode="$mode" -v car_ip="${3:-}" '
    /^\{/ { name=""; ip=""; hw=""; next }
    /name=/ { sub(/.*name=/, ""); name=$0 }
    /ip_address=/ { sub(/.*ip_address=/, ""); ip=$0 }
    /hw_address=/ { sub(/.*hw_address=/, ""); hw=$0 }
    /^\}/ {
      if (index(ip, prefix) == 1 && (car_ip == "" || ip == car_ip)) {
        wanted = (name ~ /(auto|ivt|evb|zeekr|lynk|ecarx|dhu|headunit|hu)/)
        if (mode == "ip" && wanted) print ip
        if (mode == "mac" && wanted) { n=split(hw, p, ","); s=p[n]; m=split(s, o, ":");
          if (m >= 6) printf "%s:%s:%s:%s:%s:%s\n", o[m-5], o[m-4], o[m-3], o[m-2], o[m-1], o[m] }
      }
    }
  ' /var/db/dhcpd_leases
}

IFACE=${ZEEKR_IFACE:-$(detect_iface)}
IFACE_IP=""
prefix=""
if [ -n "$IFACE" ]; then
  IFACE_IP=$(ifconfig "$IFACE" 2>/dev/null | awk '/inet /{print $2; exit}')
  [ -z "$IFACE_IP" ] || prefix="${IFACE_IP%.*}."
fi
CAR_IP=${ZEEKR_CAR_IP:-}
CAR_MAC=${ZEEKR_CAR_MAC:-}
if [ -n "$prefix" ]; then
  if [ -z "$CAR_IP" ]; then
    if [ "$GUI" = 1 ]; then
      CAR_IP=$(detect_lease "$prefix" ip | sort -u)
      [[ "$CAR_IP" != *$'\n'* ]] || CAR_IP=""
    else
      CAR_IP=$(detect_lease "$prefix" ip | head -1)
    fi
  fi
  CAR_MAC=${CAR_MAC:-$(detect_lease "$prefix" mac "$CAR_IP" | head -1)}
fi

say() { printf '%s\n' "$*"; }
ok() { printf '[ok] %s\n' "$*"; }
bad() { printf '[!!] %s\n' "$*"; }
report() {
  if [ "$GUI" = 1 ]; then printf '[gui-env] %s=%s\n' "$1" "$2"; fi
}

say "== 时间 =="; date
say ""
say "== 工具 =="
if [ -x "$MITMDUMP" ]; then
  VERSION=$("$MITMDUMP" --version 2>&1 | head -1)
  ok "mitmdump: $VERSION"
  if grep -q -- '--emudhra' <("$MITMDUMP" --help 2>&1); then
    ok "支持 --emudhra"
    report mitmdump "$VERSION"
  else
    bad "当前 mitmdump 不支持 --emudhra"
    report mitmdump unsupported
  fi
else
  bad "找不到 $MITMDUMP"
  report mitmdump missing
fi
if [ -f "$BASE/addons/zeekr_log.py" ]; then
  ok "addon 存在"
  report addon present
else
  bad "缺少 addons/zeekr_log.py"
fi

say ""
say "== 接口与地址 =="
if [ -z "$IFACE" ]; then
  bad "未检测到共享接口：请先开启「互联网共享」，或用 ZEEKR_IFACE 指定"
else
  say "  $IFACE -> ${IFACE_IP:-无 IPv4 地址}"
  if [ -n "$IFACE_IP" ]; then report bridge "$IFACE · $IFACE_IP"; fi
fi
gw=$(netstat -rn -f inet 2>/dev/null | awk '$1=="default" && $4 ~ /^en/ {print $2" via "$4; exit}')
if [ "$GUI" = 1 ] && [ -z "$gw" ]; then
  gw=$(route -n get default 2>/dev/null | awk '/gateway:/ { g=$2 } /interface:/ { i=$2 } END { if (g && i) print g " via " i }')
fi
say "  默认路由：${gw:-未找到}"
report route "$gw"
say "  热点 DHCP 配置（/etc/bootpd.plist）中的 DNS："
grep -A2 dhcp_domain_name_server /etc/bootpd.plist 2>/dev/null | grep string | sed 's/^/    /'

say ""
say "== 车机 =="
report car "$CAR_IP"
if [ -z "$CAR_IP" ]; then
  bad "尚未识别车机 IP；请确认车机已连接 Mac 的共享 Wi-Fi"
elif [ -n "$CAR_MAC" ] && arp -n "$CAR_IP" 2>/dev/null | grep -Fqi -- "$CAR_MAC"; then
  ok "ARP：$CAR_IP -> $CAR_MAC"
else
  bad "ARP 中没有 $CAR_IP -> ${CAR_MAC}（车机 IP 可能变化）"
  arp -an | grep '192\.168\.2\.' | sed 's/^/  /'
fi
if [ -n "$CAR_IP" ]; then
  ping -c 1 -t 2 "$CAR_IP" >/dev/null 2>&1 && ok "ping $CAR_IP 通" || bad "ping $CAR_IP 失败"
fi

say ""
say "== 目标域名解析（Mac 侧，车机使用 $IFACE 上的地址作为 DNS）=="
for d in $DOMAINS; do
  say "  $d:"
  if command -v dig >/dev/null 2>&1; then
    dig "${DIG_OPTIONS[@]}" A "$d" 2>/dev/null | grep -E '^[0-9]+\.' | sed 's/^/    /'
  else
    host -t A "$d" 2>/dev/null | awk '/has address/{print "    "$NF}'
  fi
done

say ""
say "== 端口与进程 =="
if command -v lsof >/dev/null 2>&1; then
  if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    bad "端口 $PORT 已被占用："
    report port busy
    lsof -nP -iTCP:"$PORT" -sTCP:LISTEN | sed 's/^/  /'
  else
    ok "端口 $PORT 空闲"
  fi
fi
pgrep -fl 'mitmdump' | sed 's/^/  /' || ok "没有运行中的 mitmdump"

say ""
say "== 权限提示 =="
if /sbin/pfctl -s info >/dev/null 2>&1; then
  ok "当前用户可读 pf（少见）"
else
  say "  pfctl 需要管理员权限：透明转发测试请用 sudo 运行 scripts/transparent-test.sh"
fi
