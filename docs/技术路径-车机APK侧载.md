# 极载 ZEEload · 车机 APK 侧载技术路径

> 更新时间：2026-10-30
> 适用对象：自有极氪 7X（ZEEKR OS，Android，包名相关字段如 `com.zeekrlife.market` 为应用商店）
> 结果：**已实测成功**。2026-10-30 07:16 通过商店「检查更新」通道，把 DiPlay 0.2.22（19,042,758 B）安装进车机。

---

## 1. 一句话结论

在没有 adb、没有未知来源开关、商店不接受代理证书的前提下，仍然可以通过 **「eMudhra 透明解密 + 更新注入 + 下载替换」** 让车机自行安装一个第三方 APK：

1. 用 pf 把车机到 zeekrlife 的 443 流量透明转进 mitmproxy；
2. 用 mitmproxy 内置的 `--emudhra` 证书链解密（车机信任该链）；
3. 在「检查更新」的 appList 响应里，把已安装应用的条目伪造成「有新版本」，哈希/大小指向目标 APK；
4. 在应用商店真正下载时，把响应体替换成本地 APK，并按 `Range` 返回正确切片；
5. 商店校验哈希（已与元数据一致）→ 服务端签名返回 `null`（不影响）→ 安装器把它当作**新应用**安装。

## 2. 前提与边界

| 项目 | 要求 / 现状 |
|---|---|
| 车机信任 | 车机需仍信任 `emSign` 根（国内车机通常无 GMS，未收到封禁列表） |
| 网络 | Mac 开互联网共享，车机连 Mac 热点；车机 DNS 指向 Mac |
| 权限 | Mac 上需要一次管理员密码（配置 pf 转发、读取 pf 状态） |
| 改动范围 | 只动本机 pf 的独立 anchor `com.apple/zeekr-capture`，不改 `/etc/pf.conf`、不写车机 |
| 可回滚 | 退出即卸载规则；异常用 `停止并恢复.command` |
| 不适用 | 商店自身升级（`com.zeekrlife.market` 走 appList 自检，服务端返回空）；替换**已安装应用**（包名/签名必须一致） |

> 本方法安装的是**新包**。想「替换」一个已安装应用，需要与原应用相同的包名和签名证书，当前无解。

## 3. 网络拓扑

```text
手机 USB 上网
   └─ Mac en10 (172.20.10.2) → 网关 172.20.10.1
        └─ 系统互联网共享（bridge100 / ap1，192.168.2.1/24）
             └─ 车机 192.168.2.2（MAC 38:2a:8b:xx:xx:xx）
                  DNS 指向 192.168.2.1
```

车机所有到 `*.zeekrlife.com` 的 TCP 443 在 Mac 上被 `rdr` 到 `127.0.0.1:18080`（mitmdump 透明模式）。

## 4. 技术路径

### 4.1 透明拦截与解密（已解决）

- pf 规则（独立 anchor，仅车机源地址）：

  ```text
  rdr pass on bridge100 inet proto tcp from 192.168.2.2 to <目标IP> port 443 -> 127.0.0.1 port 18080
  ```

- mitmdump 参数要点：

  ```text
  --mode transparent --emudhra
  --allow-hosts 'zeekrlife\.com'      # 其它域名按 SNI 原样透传
  --set stream_large_bodies=2m        # 大响应流式转发，否则客户端 10s 超时
  ```

- 关键技术点：车机接受 mitmproxy 内置的 eMudhra 中间 CA 证书链
  （`leaf ← EM OV TLS CA - G3C ← emSign Root TLS CA - G3 ← emSign ECC Root CA - G3`，
  另有 Sectigo 交叉签名）。无需在车机安装任何证书。

### 4.2 商店下载链路（已抓清）

```text
POST /app-market/openserver/clientApi/v2/app/appList
     body: {"appPackageNames":[...已安装包名...], ...}
     → data.list[*] 每条含 apkPackageName/apkVersion/apkVersionName/apkSize/apkUrl/sha256/apkMd5/apkSign

POST /app-market/openserver/clientApi/v2/app/signature
     body: {"apkSha256":"...","apkVersion":...,"packageName":"...","signType":0,...}
     → {"data":{"sign":"<base64>","signType":0}}   # 官方哈希才有 sign

GET  https://snc-download-cdn.zeekrlife.com/app-market/zeekr/apk/<id>/<md5>.apk
     Range: bytes=0-0                → 206, Content-Range 里给出总大小（探测）
     Range: bytes=0-<total-1>        → 206, 完整内容
```

要点：

- 商店**下载前**就用元数据里的 `sha256` 去申请签名，下载后再用同一份元数据校验内容；
- 服务端对非官方哈希返回 `{"sign":null}`（已做同包同版本的 A/B 对照）；
- 商店对 `sign:null` **不拦截**，仍会继续下载与安装。

### 4.3 更新注入（核心步骤一）

「检查更新 / 我的」会以 `appPackageNames` 查询已安装应用的元数据。我们在响应里把每条命中条目改为：

```json
{
  "apkVersion": 999999999,
  "apkVersionName": "9.9.9",
  "sha256": "<目标APK的sha256>",
  "apkMd5": "<目标APK的md5>",
  "apkSize": <目标APK大小，MiB，两位小数>,
  "apkSign": "sign"
}
```

其余字段（`apkUrl`、图标、名称等）保持原样。商店因此认为这些应用「有可用更新」。

### 4.4 下载内容替换（核心步骤二）

当商店开始下载该更新时，mitmproxy 在 `responseheaders` 阶段接管 `.apk` 响应：

- 解析客户端 `Range`，返回 `206` + `Content-Range: bytes <start>-<end>/<目标APK大小>`；
- 用本地 APK 的对应切片作为响应体，`Content-Length` 同步改写；
- 流式发送（每 256 KB 一块，收尾一次性发完），不会触发客户端超时。

安全闸门：只有当商店**用目标 APK 的哈希去取过签名**（说明元数据改写已被采纳）时才替换下载；否则按官方内容原样透传，避免无谓失败。

### 4.5 两个漏洞的组合（核心结论）

本方法不是单点突破，而是把**两个相互独立的安全问题**串起来用：

#### 漏洞 A：CA 证书链不可信（传输层）

- 2026-10-17 披露：eMudhra 的 8 个中间 CA 私钥可被恢复（密钥生成缺陷，可从证书反推私钥）；
- 浏览器与主流系统在 10-17 ~ 10-22 陆续封禁，但**车机（国内 Android，无 GMS）没有收到封禁更新**，仍然信任 `emSign` 根，因此接受 mitmproxy 内置 `--emudhra` 签出的证书链；
- 后果：中间人可以在**不解锁车机、不安装任何证书**的前提下，完整解密并改写车机与商店之间的 HTTPS；
- 实测：车机接受该链，商店 API 与下载 CDN 全部明文可见（见 §5）。

#### 漏洞 B：商店安装授权逻辑不一致（应用层）

商店有两条会触发「安装」的路径，但对 `sign` 的处理**不一致**：

| 路径 | 对 `sign` 的处理 | 依据 |
|---|---|---|
| 直接下载安装（首次安装 / 普通下载） | 签名异常或缺失时授权不通过，安装无法完成 | 商店安装授权设计 + 对照实验（内容/签名异常时停在「下载失败」，不进入安装） |
| **「更新已安装应用」** | **不校验**：服务端返回 `sign: null` 仍然继续下载并安装 | **实测**：2026-10-30 07:16，`sign` 为 `null`，DiPlay 0.2.22 安装成功 |

而服务端本身**只对官方哈希签名**（同一包、同一版本的 A/B 对照）：

```text
官方哈希 5e50ae19…  → {"data":{"sign":"OoSUqFSH…","signType":0}}   有效签名
伪造哈希 9e7a4f59…  → {"data":{"sign":null,"signType":0}}          拒签
```

也就是说：服务端守住了「不给非官方内容签名」这道门，但**商店的更新路径没有把这个 `null` 当成失败**——这是整条链能成立的逻辑错误：安装授权在「更新」路径上被跳过了。

> 严格说明：本项目直接验证的是「更新路径对 `sign` 不敏感（null 也能装）」；「直接安装需要有效 `sign`」来自商店授权设计与对照观察，未单独构造出「sign 无效但直接安装成功」的案例。

#### 组合利用链

```text
漏洞 A：解密 + 改写 TLS
   └─ 把「安装任意 APK」伪装成「某个已安装应用有新版本」
        └─ 漏洞 B：更新路径不校验 sign
             └─ 目标 APK 以「更新」名义被安装
```

单独利用任何一个都不成立：

- **只有 A**：能看能改，但任意 APK 拿不到有效签名，卡在授权；
- **只有 B**：需要能改写商店流量才能把「更新」指向自己的 APK，而 HTTPS 挡住了；
- **A + B**：才能把「任意 APK」送进安装流程。

#### 为什么这是「逻辑漏洞」而不是「破解签名」

APK 签名机制和服务端签名服务都没有被攻破，被绕过的是**校验点**：

1. 商店对「更新」不验证签名是否有效（甚至不要求非空）；
2. 商店的下载内容校验基准（元数据）走的是同一条可被中间人改写的 TLS；
3. 车机信任库过期（漏洞 A）让中间人成为可能。

#### 对厂商的修复建议（研究结论）

- 更新路径同样强制校验 `sign` 非空且与包名/版本/哈希绑定；
- 对 appList / detail 等元数据响应本身做端到端签名，防止中间人改写校验基准；
- 强制证书透明度（CT）与吊销检查，并及时更新根信任库；
- 安装授权与「是否更新」解耦：所有安装路径统一走同一套校验。

## 5. 成功证据（2026-10-30 07:16）

归档目录：[../evidence/success-install-20261030](../evidence/success-install-20261030)

| 时间 | 事件 |
|---|---|
| 07:16:32 / 33 / 35 | 三次 appList 响应被注入（`[inject-update] 已为 ALL 注入新版本`） |
| 07:16:39 | 商店用 `apkSha256=7d04db26…` 为 `com.zeekr.app.internet.vehicles` 取签名 → 服务端 `sign: null`（168 B） |
| 07:16:40 | 0-0 探测 → 全量下载被替换为 DiPlay（19,042,758 B） |
| 07:16:59 | 另一应用 `com.zeekr.media.podcast` 同样流程（`sign: null` + 替换下载） |
| 之后 | 车机安装成功（用户确认） |

目标 APK：DiPlay 0.2.22，`sha256 7d04db263834f22010a86847766928113d3503a273e4d2d3440d21552e173139`，`md5 84968e02caccc797d6accc091a2d6d81`，19,042,758 B（与官方发布页 `SHA256SUMS.txt` 一致）。

## 6. 工具用法

### 6.1 一键侧载（推荐）

双击 `一键侧载安装.command`，然后把 APK **拖到这个文件上**（或双击后按提示输入路径）。

工具会自动：校验 APK → 计算 sha256/md5/大小 → 启动透明代理（注入 ALL + 替换下载）→ 提示你在车机上操作。

### 6.2 车机侧操作

1. 打开应用商店 → 我的 / 检查更新；
2. 出现「有更新」提示后，点**任意一个**应用的更新；
3. 等进度走完（实际下载的是你的 APK），安装完成后按终端提示 Ctrl-C。

### 6.3 命令行方式

```bash
sudo bash scripts/zeekr-sideload.sh --apk /path/to/app.apk            # 注入所有已安装应用
sudo bash scripts/zeekr-sideload.sh --apk app.apk --pkg com.zeekr.media.podcast
```

## 6.4 多机 / 多车适配

macOS 版已去掉了固定设备参数：

| 参数 | 自动探测方式 | 覆盖方式 |
|---|---|---|
| 共享接口 | 扫描 `bridge*`，取有私有 IPv4 且 active 的（优先带 `ap*` 成员） | `ZEEKR_IFACE` 或 `--iface` 语义 |
| 车机 IP | 读 `/var/db/dhcpd_leases`，按名称关键字（auto/ivt/evb/zeekr/lynk/ecarx/dhu）挑选 | `ZEEKR_CAR_IP` |
| 车机 MAC | 同一租约里解析 | `ZEEKR_CAR_MAC` |
| 目标域名 | 默认 `snc-api-gw` / `snc-download-cdn` | `--domains "a.com b.com"` |
| 域名后缀过滤 | 默认 `zeekrlife.com` | `--hosts "zeekrlife.com,ecarx.com"` |

检测不到车机时，pf 规则会退化为「整个热点网段」作为源，仍然只作用于热点侧、不碰上游。

## 6.5 Windows 版

`windows/` 目录是自包含的 Windows 版本（beta）：

- 用 **WinDivert**（pydivert）把发往 443 的包改写到本机，回程再把源地址改回去；
- 本地 **SNI 分流器**读出域名，用 HTTP CONNECT 交给 mitmproxy（Windows 没有 pf，mitmproxy 的透明模式不可用）；
- 注入 / 替换逻辑与 macOS 版共用同一个 addon；
- 依赖：Python 3.10+、`pip install mitmproxy pydivert`、管理员权限。

详见 `windows/README.md`。

## 7. 成功 / 失败判读

| 现象 | 含义 |
|---|---|
| 终端出现 `[inject-update] 已为 ALL 注入新版本` | 更新注入生效 |
| 出现 `[replace-apk] 商店已用替换包哈希取签名` | 商店采纳了改写后的元数据，替换已武装 |
| 出现 `[replace-apk] 以 xxx.apk 替换下载` | 正在把目标 APK 发给车机 |
| 商店提示「下载失败」 | 元数据没被采纳（缓存）或被替换成官方内容 → 重启商店/车机后再试 |
| 安装报「包名冲突/签名不一致」 | 目标 APK 与已安装应用同名（应改包装名或换个包名不同的 APK） |

## 8. 风险与回滚

- 测试期间车机所有 zeekrlife 流量经 Mac 代理，Mac 关机/睡眠会断网；
- 注入会让商店认为**所有**已安装应用都有更新，可能连续下载多个 19 MB（都会是同一个 APK）；
- 安装的是新包，不会破坏原应用；卸载即恢复；
- 退出脚本会自动卸载 pf 规则；异常时运行 `停止并恢复.command`；
- 商店或车机 OTA 更新后，信任库/校验逻辑可能变化，本方法需要重新验证。

## 9. 附录：历史实验结论

| 实验 | 结论 |
|---|---|
| 直接替换下载内容（不改元数据） | 商店下载阶段即校验失败（2 次全量下载均被拒） |
| 单字节损坏下载内容 | 商店本地校验哈希，安装器未被调用 |
| 改写 appList 哈希 | 机制有效，但商店按「应用+版本」缓存，旧哈希不会刷新 |
| 服务端对非官方哈希签名 | 同一包同版本 A/B：官方 → 有效 sign；伪造 → `sign: null` |
| 商店自身更新 | 通过 appList 查询 `com.zeekrlife.market`，服务端返回 `total:0`，不走市场 API |
| 浏览器下载 APK | 车机禁止，无未知来源入口 |
| adb | 无调试端口 |
| **更新注入 + 下载替换** | **成功安装 DiPlay** |

## 10. 涉及文件

| 路径 | 用途 |
|---|---|
| `一键侧载安装.command` | 一键入口（支持拖拽 APK） |
| `scripts/zeekr-sideload.sh` | 命令行工具 |
| `scripts/transparent-test.sh` | 底层引擎（pf 转发 + mitmdump 生命周期） |
| `addons/zeekr_log.py` | mitmproxy 插件（注入 / 替换 / 记录） |
| `artifacts/DiPlay-0.2.22.apk` | 本次验证使用的 APK |
| `evidence/success-install-20261030/` | 成功运行的日志与签名响应 |
