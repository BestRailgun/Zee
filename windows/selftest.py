"""Windows 版自检：不联网、不改系统，只验证模块与关键函数是否完整。

用法（任意平台均可）：
    python selftest.py
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import win_sideload as w  # noqa: E402

ok = True


def check(name, cond, detail=""):
    global ok
    print(("[ OK ] " if cond else "[FAIL] ") + name + (f"  ({detail})" if detail else ""))
    ok = ok and bool(cond)


# 1) 关键函数/类都在
for fn in (
    "log", "is_admin", "find_hotspot_ip", "parse_sni", "find_mitmdump",
    "start_mitmdump", "run_divert", "ensure_python", "mitmproxy_version", "main",
):
    check(f"函数存在：{fn}", callable(getattr(w, fn, None)))

for cls in ("Shim", "ShimHandler"):
    check(f"类存在：{cls}", isinstance(getattr(w, cls, None), type))

# 2) 版本检查不会抛异常
try:
    rc = w.ensure_python()
    check("ensure_python 可执行", rc is None or isinstance(rc, int), f"rc={rc}")
except Exception as exc:  # pragma: no cover
    check("ensure_python 可执行", False, repr(exc))


# 3) SNI 解析（构造一个最小 ClientHello）
def build_client_hello(sni: str) -> bytes:
    name = sni.encode()
    sni_ext_body = struct.pack("!HBH", 2 + len(name), 0, len(name)) + name
    ext = struct.pack("!HH", 0, len(sni_ext_body)) + sni_ext_body
    body = (
        b"\x03\x03"
        + os.urandom(32)
        + b"\x00"                              # session id len
        + struct.pack("!H", 2) + b"\x13\x01"   # cipher suites
        + b"\x01\x00"                          # compression methods
        + struct.pack("!H", len(ext)) + ext
    )
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


try:
    data = build_client_hello("snc-api-gw.zeekrlife.com")
    got = w.parse_sni(data)
    check("parse_sni 解析正确", got == "snc-api-gw.zeekrlife.com", f"got={got}")
except Exception as exc:
    check("parse_sni 解析正确", False, repr(exc))

# 4) mitmdump 定位（能找到就顺带校验版本）
try:
    cmd = w.find_mitmdump()
    check("find_mitmdump 返回命令", isinstance(cmd, list) and len(cmd) >= 1, " ".join(cmd[:2]))
    ver = w.mitmproxy_version(cmd)
    check("mitmproxy 版本可读", ver is not None, str(ver))
    if ver:
        check("mitmproxy >= 12.3", ver >= w.MIN_MITM, f"{ver[0]}.{ver[1]}")
except Exception as exc:
    check("mitmdump 定位", False, repr(exc))

print()
print("结果：" + ("全部通过" if ok else "存在失败项"))
sys.exit(0 if ok else 1)
