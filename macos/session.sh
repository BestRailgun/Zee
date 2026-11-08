#!/bin/bash
# Privileged supervisor. Logs are written to the user's folder as that user.
set -uo pipefail
umask 077
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

SELF=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
MACOS_DIR=${SELF%/*}
RESOURCES=${MACOS_DIR%/*}
ANCHOR=com.apple/zeekr-capture-gui

worker=0
if [ "${1:-}" = worker ]; then worker=1; shift; fi
[ "$#" = 8 ] && [ "$(id -u)" = 0 ] || exit 64
action=$1 owner=$2 client=$3 session=$4 apk=$5 iface=$6 car=$7 mitmdump=$8
case "$action" in run|restore) ;; *) exit 64 ;; esac
[[ "$owner" =~ ^[1-9][0-9]*$ && "$client" =~ ^[1-9][0-9]*$ && "$session" = /* ]] || exit 64
[[ -d "$session" && ! -L "$session" ]] || exit 64

if [ "$worker" = 0 ]; then
  [ "$(/usr/bin/stat -f '%u' "$session")" = "$owner" ] || exit 64
  "${RESOURCES%/*}/Helpers/session-lock" /bin/bash "$SELF" worker "$@" 2>&1 |
    /usr/bin/sudo -n -u "#$owner" -- /usr/bin/tee -a "$session/activity.log" >/dev/null
  exit $?
fi

clear_rules() {
  local nat rules
  nat=$(pfctl -a "$ANCHOR" -s nat) && rules=$(pfctl -a "$ANCHOR" -s rules) || return 1
  if [ -n "$nat" ] || [ -n "$rules" ]; then
    pfctl -a "$ANCHOR" -F nat && pfctl -a "$ANCHOR" -F rules || return 1
    nat=$(pfctl -a "$ANCHOR" -s nat) && rules=$(pfctl -a "$ANCHOR" -s rules) || return 1
  fi
  [ -z "$nat" ] && [ -z "$rules" ]
}

if [ "$action" = restore ]; then
  if clear_rules; then
    echo '[gui-session] 已确认极载 Mac 的转发规则清空'
    exit 0
  fi
  echo '错误：无法确认转发规则已清空，请查看 pf 错误。'
  exit 1
fi

client_identity() { ps -p "$client" -o uid= -o lstart= 2>/dev/null; }
identity=$(client_identity)
[ -n "$identity" ] && [ "$(awk '{print $1}' <<< "$identity")" = "$owner" ] || exit 0
[ ! -e "$session/stop" ] || exit 0

echo '[gui-session] start'
legacy_rules=$(pfctl -a com.apple/zeekr-capture -s nat 2>/dev/null) || legacy_rules=""
if [ -n "$legacy_rules" ]; then
  echo '错误：检测到命令行版仍有转发规则，请先停止命令行会话。'
  exit 1
fi
if ! clear_rules; then
  echo '错误：无法检查极载 Mac 的转发规则，请先确认互联网共享已开启。'
  exit 1
fi

runtime=$(mktemp -d /private/var/tmp/zeeload-gui.XXXXXXXX) || exit 1
child=""
stop_requested=0

finish() {
  local result=$1
  trap - EXIT
  trap '' INT TERM HUP
  if [ -n "$child" ]; then
    kill -TERM "$child" 2>/dev/null || :
    wait "$child" 2>/dev/null || :
  fi
  if clear_rules; then
    echo '[gui-session] 已确认极载 Mac 的转发规则清空'
  else
    echo '错误：转发规则清理失败，请点击「恢复转发规则」。'
    result=1
  fi
  if [ -d "$runtime/logs" ]; then
    if ! tar -cf - -C "$runtime" logs 9>&- |
      /usr/bin/sudo -n -u "#$owner" -- /usr/bin/tar -xf - -C "$session" 9>&-; then
      echo "错误：详细日志复制失败，原始文件保留在 $runtime"
      exit 1
    fi
  fi
  rm -rf -- "$runtime"
  exit "$result"
}
trap 'finish "$?"' EXIT
trap 'exit 130' INT TERM HUP

[[ "$mitmdump" = /* && -x "$mitmdump" ]] || { echo '错误：mitmdump 路径无效'; exit 1; }
export ZEEKR_GUI=1 ZEEKR_ANCHOR="$ANCHOR" ZEEKR_DATA_DIR="$runtime"
export ZEEKR_MITMDUMP="$mitmdump" ZEEKR_IFACE="$iface" ZEEKR_CAR_IP="$car"
export PATH="$PATH:${mitmdump%/*}"

/bin/bash "$RESOURCES/scripts/zeekr-sideload.sh" --apk "$apk" 9>&- &
child=$!
while kill -0 "$child" 2>/dev/null; do
  if [ -e "$session/stop" ] || [ "$(client_identity)" != "$identity" ]; then
    stop_requested=1
    kill -TERM "$child" 2>/dev/null || :
    break
  fi
  sleep 0.4
done
wait "$child"
result=$?
child=""
if [ "$stop_requested" = 1 ]; then
  case "$result" in 130|143) result=0 ;; esac
fi
exit "$result"
