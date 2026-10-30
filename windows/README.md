# 极载 ZEEload · Windows 版（beta）

把任意 APK 通过**车机应用商店的「检查更新」通道**装进车机，原理与 macOS 版完全一致：

```text
车机 ──Wi-Fi──> Windows 移动热点
                  │
                  ├─ WinDivert 把发往 443 的包改写到 热点IP:18081
                  ├─ 本地 SNI 分流器读出域名，用 HTTP CONNECT 交给 mitmproxy
                  ├─ mitmproxy（透明解密）+ 注入假更新 + 替换下载内容
                  └─ 回程流量把源地址改回原目标，车机无感
```

## 前提

| 项目 | 要求 |
|---|---|
| 系统 | Windows 10 / 11（x64） |
| Python | **3.12 及以上**（实测 3.12.7；mitmproxy 12.3+ 的硬性要求） |
| mitmproxy | **12.3 及以上**（实测 12.3.1；`--emudhra` 从 12.3 起提供） |
| pydivert | **4.0 及以上**（实测 4.0.1；自带 WinDivert 驱动） |
| 安装命令 | `py -3.12 -m pip install -U mitmproxy pydivert` |
| 权限 | **必须管理员**（加载 WinDivert 驱动） |
| 网络 | Windows 开启「移动热点」，车机连上这个热点；Windows 自身能上网 |
| 车机 | 需仍信任 eMudhra 根（国内车机通常满足） |

## 安装

```powershell
# 以管理员身份打开 PowerShell
cd windows
py -3.12 -m pip install -U mitmproxy pydivert   # 默认 python 若是 3.10/3.11，请用 py -3.12
```

## 自检（可选）

不联网、不改系统，确认模块完整与版本合适：

```powershell
cd windows
python selftest.py
```

## 使用

1. Windows 设置 → 网络和 Internet → **移动热点** → 打开，记下热点网段（通常 `192.168.137.0/24`）；
2. 车机连上该热点；
3. 管理员 PowerShell 里运行：

```powershell
python win_sideload.py --apk "C:\path\ESFileExplorer-cn.apk"
```

也可以直接双击 `一键侧载-Windows.bat`，把 APK 拖到它上面（会自动申请管理员权限）。

4. 看到 `mitmproxy 已启动` 和 `开始透明重定向` 后，在车机上：

   - 打开应用商店 → 点开**任意一个应用的详情页**（会实时请求 `app/detail`，这条响应会被注入）；
   - 等终端出现 `[inject-update] ... 已武装`；
   - 在详情页点「更新/安装」。

5. 终端出现 `[replace-apk] 以 xxx.apk 替换下载` 就说明替换成功；装完后 Ctrl-C 退出。

日志与 flow 在 `logs/` 下（`requests.jsonl`、`flows.mitm`、`mitm.log`）。

## 常见问题

| 现象 | 处理 |
|---|---|
| 提示需要管理员 | 右键 PowerShell「以管理员身份运行」 |
| 提示需要 Python 3.12 / `py -3.12` 不存在 | 安装 [Python 3.12+](https://www.python.org/downloads/windows/)，安装时勾选 Add to PATH |
| 把命令粘到 PowerShell 报「意外的标记 -m」 | PowerShell 用调用运算符：`& "C:\...\python.exe" -m pip install -U mitmproxy` |
| mitmproxy 版本过低（<12.3） | 用 3.12+ 解释器执行 `python -m pip install -U mitmproxy` |
| 启动报 `WinError 2` / 找不到 `mitmdump` | 确认 `python -m pip install -U mitmproxy` 装在与运行脚本相同的 Python |
| 日志频繁 `WinError 87` | 已按方向过滤；若仍出现，把带五元组的那几行发出来 |
| WinDivert 报驱动错误 |
| `找不到热点网卡 IP` | 先打开移动热点；或在 `win_sideload.py` 里用 `--proxy-only` 手动指定 |
| WinDivert 报驱动错误 | 确认是管理员；必要时重装 `pip install --force-reinstall pydivert` |
| 车机连不上网 | 关掉脚本、关热点再开；确认 Windows 自身网络正常 |
| 终端没有 `[inject-update]` | 商店用了缓存：换到**应用详情页**操作；仍不行就重启车机 |
| 下载了但没安装 | 目标 APK 与商店元数据哈希不一致（说明替换没生效）；看终端有没有 `替换下载` 行 |
| 某个车机应用异常 | 全量解密可能触发证书固定；退出脚本即恢复 |

## 与 macOS 版的差异

| 能力 | macOS | Windows |
|---|---|---|
| 透明重定向 | pf `rdr` | WinDivert 改写目的地址 |
| 原目标地址获取 | `pfctl -s state` | WinDivert 侧表 |
| 证书链 | `--emudhra` | `--emudhra`（相同） |
| 自动探测 | 自动选 `bridge*`、从 DHCP 租约识别车机 | 自动找 `192.168.137.x` 热点网卡；车机由流量判定 |
| 稳定性 | 已验证 | **beta**，结构相同但未在真实 Windows 环境验证 |

## 已知限制（beta）

- **未在真实 Windows 车机环境验证过**：代码结构与 macOS 版一致，但 WinDivert 重定向、SNI 分流这些环节需要你在 Windows 上实测；
- 只处理 **IPv4**：WinDivert 过滤器是 `ip.*`，若车机走 IPv6 会绕过（Windows ICS 一般不给客户端 IPv6，通常没问题）；
- WinDivert 过滤器只匹配热点网段（`x.x.x.2-254`），避免把本机 mitmproxy 自己的上游连接也劫持成环；
- `addons/zeekr_log.py` 是主目录 addon 的副本，后续改了主版本记得同步：

  ```powershell
  copy ..\addons\zeekr_log.py .\addons\zeekr_log.py
  ```

## 说明

- 本工具只做本地转发与改写，不修改车机系统、不写入任何车机文件；
- 退出脚本即恢复（WinDivert 句柄关闭、mitmproxy 停止）；
- 仅用于自有车辆；车机 OTA 或商店更新后校验逻辑可能变化，需重新验证。
