"""win_sideload.py — 极载 ZEEload · Windows 版侧载工具（beta）

原理与 macOS 版一致：
  车机 → Windows 热点 → 本工具把 443 流量重定向到本地 → mitmproxy 解密 →
  注入假更新 + 替换下载内容 → 车机商店把目标 APK 当更新装上。

Windows 没有 pf，透明转发用 WinDivert（pydivert）实现：
  1. 只拦截「进入本机」的发往 443 的包，把目的地址改写成「热点网卡 IP:18081」，并记录原始目的地址；
  2. 本地 SNI 分流器（18081）读出客户端要访问的域名，用 HTTP CONNECT 喂给 mitmproxy；
  3. 分流器发出的回程包把源地址改回原始目的地址，客户端无感。

依赖（版本有硬性要求）：
  Python >= 3.12（实测 3.12.7）
  mitmproxy >= 12.3（实测 12.3.1，--emudhra 从 12.3 起提供）
  pydivert >= 4.0（实测 4.0.1）
  必须以管理员身份运行（WinDivert 需要加载驱动）

用法：
  python win_sideload.py --apk "C:\\path\\app.apk"
  python win_sideload.py --apk app.apk --pkg com.zeekr.media.podcast
  python win_sideload.py --apk app.apk --proxy-only   # 只起代理，不做透明重定向
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time

IS_WINDOWS = sys.platform.startswith("win")
MIN_PY = (3, 12)          # mitmproxy 12.3+ 要求 Python >= 3.12
MIN_MITM = (12, 3)        # --emudhra 从 mitmproxy 12.3 开始提供
SHIM_PORT = 18081
PROXY_PORT = 18080

ADDON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "addons", "zeekr_log.py")


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def is_admin() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def find_hotspot_ip() -> str:
    """找 Windows 热点（ICS）网卡地址。ICS 默认网段是 192.168.137.0/24。"""
    candidates = []
    try:
        out = subprocess.check_output(["ipconfig"], text=True, errors="ignore")
    except Exception:
        out = ""
    for line in out.splitlines():
        line = line.strip()
        if ("IPv4" in line or "IPv4 地址" in line) and ":" in line:
            ip = line.split(":")[-1].strip()
            try:
                ipaddress.IPv4Address(ip)
            except Exception:
                continue
            if ip.startswith("127.") or ip.startswith("169.254."):
                continue
            candidates.append(ip)
    for ip in candidates:
        if ip.startswith("192.168.137."):
            return ip
    for ip in candidates:
        if ip.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                          "172.2", "172.30.", "172.31.")):
            return ip
    return ""


def parse_sni(data: bytes) -> str | None:
    """从一段可能不完整的 TLS ClientHello 里解析 SNI。"""
    if len(data) < 5 or data[0] != 0x16:
        return None
    try:
        # 只处理单条 handshake 记录
        if data[5] != 0x01:
            return None
        p = 9  # 记录头5 + 握手头4
        p += 2 + 32  # version + random
        sid_len = data[p]
        p += 1 + sid_len
        cs_len = int.from_bytes(data[p : p + 2], "big")
        p += 2 + cs_len
        cm_len = data[p]
        p += 1 + cm_len
        ext_total = int.from_bytes(data[p : p + 2], "big")
        p += 2
        end = min(len(data), p + ext_total)
        while p + 4 <= end:
            etype = int.from_bytes(data[p : p + 2], "big")
            elen = int.from_bytes(data[p + 2 : p + 4], "big")
            p += 4
            if p + elen > len(data):
                return None
            if etype == 0:  # server_name
                q = p + 2
                name_type = data[q]
                name_len = int.from_bytes(data[q + 1 : q + 3], "big")
                if name_type == 0:
                    raw = data[q + 3 : q + 3 + name_len]
                    try:
                        return raw.decode("idna")
                    except Exception:
                        # Python 3.12 的 idna 编解码器不支持 ignore，且非法标签会抛错
                        return raw.decode("ascii", "ignore")
            p += elen
    except Exception:
        return None
    return None


class Shim(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, mapping):
        self.mapping = mapping
        super().__init__(addr, handler)


class ShimHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        client.settimeout(10)
        buf = b""
        try:
            while len(buf) < 4096:
                chunk = client.recv(4096)
                if not chunk:
                    return
                buf += chunk
                if len(buf) >= 5 and buf[0] == 0x16:
                    if parse_sni(buf):
                        break
        except Exception:
            return
        client.settimeout(None)

        sni = parse_sni(buf)
        key = self.client_address[:2]
        orig = self.server.mapping.get(key)
        target = sni or (orig[0] if orig else None)
        if not target:
            log(f"无法确定 {key} 的目标域名，放弃")
            return
        port = orig[1] if orig else 443

        upstream = socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=10)
        try:
            connect = f"CONNECT {target}:{port} HTTP/1.1\r\nHost: {target}:{port}\r\n\r\n".encode()
            upstream.sendall(connect)
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = upstream.recv(1)
                if not chunk:
                    return
                resp += chunk
            if b" 200 " not in resp.split(b"\r\n")[0]:
                log(f"mitmproxy 拒绝 CONNECT {target}: {resp[:80]!r}")
                return
            if buf:
                upstream.sendall(buf)
            _pipe_both(client, upstream)
        finally:
            try:
                upstream.close()
            except Exception:
                pass


def _pipe_both(a: socket.socket, b: socket.socket) -> None:
    def _fwd(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    t = threading.Thread(target=_fwd, args=(a, b), daemon=True)
    t.start()
    _fwd(b, a)
    t.join(timeout=1)


def find_mitmdump() -> list[str]:
    """定位 mitmdump：先找 Python 安装目录下的 Scripts，再找 PATH，最后退回 python -c。"""
    cands: list[str] = []
    if IS_WINDOWS:
        exe_dir = os.path.dirname(sys.executable)
        appdata = os.environ.get("APPDATA", "")
        ver = f"Python{sys.version_info.major}{sys.version_info.minor}"
        cands += [
            os.path.join(exe_dir, "Scripts", "mitmdump.exe"),   # 常规安装
            os.path.join(exe_dir, "mitmdump.exe"),
            os.path.join(appdata, "Python", ver, "Scripts", "mitmdump.exe"),  # pip --user
            os.path.join(appdata, "Python", "Scripts", "mitmdump.exe"),
        ]
    cands += [shutil.which("mitmdump"), shutil.which("mitmdump.exe") or ""]
    for c in cands:
        if c and os.path.isfile(c):
            return [c]
    # 兜底：用当前解释器直接调用 mitmproxy 的入口（mitmdump 的入口在 tools.main）
    return [sys.executable, "-c", "from mitmproxy.tools.main import mitmdump; raise SystemExit(mitmdump())"]


def mitmproxy_version(exe: list[str]) -> tuple[int, int] | None:
    try:
        r = subprocess.run(exe + ["--version"], capture_output=True, text=True, timeout=30)
        out = (r.stdout or "") + (r.stderr or "")
        m = re.search(r"Mitmproxy:\s*(\d+)\.(\d+)", out)
        if m:
            return int(m.group(1)), int(m.group(2))
    except Exception:
        pass
    return None


def start_mitmdump(apk: str, pkg: str, sha: str, md5: str, outdir: str) -> subprocess.Popen:
    base = find_mitmdump()
    if base[0] == sys.executable:
        # 回退到当前解释器时，先确认它装了 mitmproxy
        chk = subprocess.run(
            [sys.executable, "-c", "import mitmproxy"], capture_output=True, text=True
        )
        if chk.returncode != 0:
            log("当前 Python 没有安装 mitmproxy。")
            log("PowerShell 里执行：")
            log(f'  & "{sys.executable}" -m pip install -U mitmproxy')
            log("cmd 里执行：")
            log(f'  "{sys.executable}" -m pip install -U mitmproxy')
            if sys.stdin and sys.stdin.isatty():
                ans = input("现在自动安装？直接回车安装，输入 n 跳过：").strip().lower()
                if ans != "n":
                    if subprocess.call([sys.executable, "-m", "pip", "install", "-U", "mitmproxy"]) == 0:
                        chk = subprocess.run([sys.executable, "-c", "import mitmproxy"], capture_output=True)
                    if chk.returncode != 0:
                        raise SystemExit(6)
            else:
                raise SystemExit(6)
    log(f"mitmdump: {base[0] if base[0] != sys.executable else '（当前解释器内联调用）'}")
    ver = mitmproxy_version(base)
    if ver is None:
        log("无法读取 mitmproxy 版本，请确认 mitmproxy 安装正常。")
    elif ver < MIN_MITM:
        log(f"mitmproxy 版本过低：{ver[0]}.{ver[1]}，需要 12.3+（--emudhra 从 12.3 开始提供）。")
        log("请执行：python -m pip install -U mitmproxy")
        raise SystemExit(8)
    else:
        log(f"mitmproxy 版本：{ver[0]}.{ver[1]}")

    cmd = base + [
        "--mode", f"regular@{PROXY_PORT}",
        "--set", f"confdir={os.path.join(outdir, 'mitm-config')}",
        "--set", "stream_large_bodies=2m",
        "--set", f"zeekr_out={outdir}",
        "--set", f"zeekr_inject_pkg={pkg}",
        "--set", f"zeekr_replace_apk={apk}",
        "--set", f"zeekr_override_sha256={sha}",
        "--set", f"zeekr_override_md5={md5}",
        "-s", os.path.abspath(ADDON),
    ]
    try:
        return subprocess.Popen(cmd, cwd=outdir)
    except FileNotFoundError:
        log("找不到 mitmdump。请先执行：python -m pip install -U mitmproxy")
        log(f"已尝试：{base}")
        raise


def _py312_launcher() -> list[str] | None:
    """找一个 >=3.12 的解释器启动器（py -3.12 / py -3 / python3.12）。"""
    for launcher in (["py", "-3.12"], ["py", "-3"], ["python3.12"]):
        try:
            r = subprocess.run(
                launcher + ["-c", "import sys;print('%d.%d' % sys.version_info[:2])"],
                capture_output=True, text=True, timeout=15,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if r.returncode == 0:
            m = re.search(r"(\d+)\.(\d+)", r.stdout or "")
            if m and (int(m.group(1)), int(m.group(2))) >= MIN_PY:
                return launcher
    return None


def ensure_python() -> int | None:
    """Python 版本不足时，尝试用 3.12+ 重新运行自己。返回 None 表示可以继续。"""
    if sys.version_info >= MIN_PY:
        return None
    cur = "%d.%d.%d" % sys.version_info[:3]
    launcher = _py312_launcher()
    if launcher:
        log(f"当前 Python {cur} 低于 3.12，自动切换到 {' '.join(launcher)} 重新运行…")
        return subprocess.call(launcher + [os.path.abspath(__file__)] + sys.argv[1:])
    log(f"需要 Python 3.12 或更高（当前 {cur}）。")
    log("mitmproxy 12.3+（本工具依赖的 --emudhra）不支持 3.10 / 3.11。")
    log("请安装 Python 3.12+（python.org），然后执行：")
    log("  py -3.12 -m pip install -U mitmproxy")
    return 7


def run_divert(hotspot_ip: str) -> None:
    import pydivert
    from pydivert.consts import Direction

    mapping: dict[tuple, tuple] = {}
    shim = Shim((hotspot_ip, SHIM_PORT), ShimHandler, mapping)
    threading.Thread(target=shim.serve_forever, daemon=True).start()
    log(f"SNI 分流器已监听 {hotspot_ip}:{SHIM_PORT}")

    # 只处理热点网段内的客户端（车机），否则会把本机 mitmproxy 自己的上游连接也劫持成环
    base = hotspot_ip.rsplit(".", 1)[0]
    lo, hi = f"{base}.2", f"{base}.254"
    flt = (
        f"(tcp.DstPort == 443 and ip.SrcAddr >= {lo} and ip.SrcAddr <= {hi}) "
        f"or (tcp.SrcPort == {SHIM_PORT} and ip.SrcAddr == {hotspot_ip})"
    )
    log(f"WinDivert 过滤器：{flt}")

    errs = 0
    with pydivert.WinDivert(flt) as w:
        for packet in w:
            try:
                if not packet.ipv4:
                    w.send(packet)
                    continue

                # 车机 → 外网：只处理「进入本机」的那一份；
                # 转发出去的副本（OUTBOUND）如果也改写，WinDivert 会因接口/方向不匹配报 87。
                if (
                    packet.direction == Direction.INBOUND
                    and packet.tcp.dst_port == 443
                    and packet.ipv4.dst_addr != hotspot_ip
                ):
                    key = (packet.ipv4.src_addr, packet.tcp.src_port)
                    mapping[key] = (packet.ipv4.dst_addr, packet.tcp.dst_port)
                    packet.ipv4.dst_addr = hotspot_ip
                    packet.tcp.dst_port = SHIM_PORT
                    w.send(packet)
                    continue

                # 分流器 → 车机：把源地址改回原来的 CDN 地址
                if (
                    packet.direction == Direction.OUTBOUND
                    and packet.tcp.src_port == SHIM_PORT
                    and packet.ipv4.src_addr == hotspot_ip
                ):
                    key = (packet.ipv4.dst_addr, packet.tcp.dst_port)
                    orig = mapping.get(key)
                    if orig:
                        packet.ipv4.src_addr = orig[0]
                        packet.tcp.src_port = orig[1]
                    w.send(packet)
                    continue

                w.send(packet)
            except Exception as exc:  # 单个包失败不应中断整体
                errs += 1
                if errs <= 5:
                    try:
                        desc = (
                            f"{packet.ipv4.src_addr}:{packet.tcp.src_port} -> "
                            f"{packet.ipv4.dst_addr}:{packet.tcp.dst_port} "
                            f"dir={packet.direction.name} if={packet.interface}"
                        )
                    except Exception:
                        desc = "<无法读取包信息>"
                    log(f"WinDivert 处理包失败: {exc} | {desc}")
                elif errs == 6:
                    log("（后续同类错误不再逐条打印）")
                try:
                    w.send(packet)
                except Exception:
                    pass


def main() -> int:
    rc = ensure_python()
    if rc is not None:
        return rc

    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", required=True, help="要安装的 APK 路径")
    ap.add_argument("--pkg", default="ALL", help="注入目标包名，或 ALL")
    ap.add_argument("--out", default="logs", help="日志/flow 输出目录")
    ap.add_argument("--proxy-only", action="store_true", help="只起 HTTP 代理，不做透明重定向")
    args = ap.parse_args()

    apk = os.path.abspath(args.apk)
    if not os.path.isfile(apk):
        log(f"APK 不存在：{apk}")
        return 2
    with open(apk, "rb") as fh:
        blob = fh.read()
    size = len(blob)
    sha = hashlib.sha256(blob).hexdigest()
    md5 = hashlib.md5(blob).hexdigest()
    outdir = os.path.abspath(args.out)
    os.makedirs(outdir, exist_ok=True)

    log("=" * 60)
    log("极载 ZEEload · Windows 版")
    log(f"Python: {sys.version.split()[0]}  |  解释器: {sys.executable}")
    log(f"APK   : {apk}")
    log(f"大小  : {size} 字节（{size / 1048576:.2f} MiB）")
    log(f"sha256: {sha}")
    log(f"md5   : {md5}")
    log(f"注入包: {args.pkg}")
    log("=" * 60)

    if not IS_WINDOWS:
        log("这不是 Windows 环境；仅做参数校验。")
        return 0

    if not args.proxy_only and not is_admin():
        log("需要管理员权限：请右键「以管理员身份运行」PowerShell 后再执行本脚本。")
        return 3

    mitm = start_mitmdump(apk, args.pkg, sha, md5, outdir)
    time.sleep(3)
    if mitm.poll() is not None:
        log("mitmproxy 启动失败，请确认 mitmproxy 安装正常（pip install -U mitmproxy）。")
        return 4
    log(f"mitmproxy 已启动，监听 127.0.0.1:{PROXY_PORT}")

    hotspot_ip = find_hotspot_ip()
    log(f"检测到热点网卡 IP：{hotspot_ip or '未找到'}")

    try:
        if args.proxy_only:
            log(f"代理模式：在车机网络里把该 Windows 机器设为 HTTP 代理 0.0.0.0:{PROXY_PORT}")
            while True:
                time.sleep(1)
        if not hotspot_ip:
            log("找不到热点网卡 IP；请先在 Windows 设置里开启「移动热点」并让车机连上。")
            return 5
        log("开始透明重定向（Ctrl-C 停止）")
        run_divert(hotspot_ip)
    except KeyboardInterrupt:
        log("收到中断，正在退出")
    finally:
        try:
            mitm.terminate()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
