"""zeeload_gui.py — 极载 ZEEload · Windows 版图形界面（tkinter，无第三方依赖）

设计原则：
  * 不改动 win_sideload.py 的任何逻辑：本界面只是「组装命令行 + 起子进程 + 显示日志」，
    真正干活的是同一个 exe 的 CLI 模式（`ZEELoad.exe --apk ... [--proxy-only]`）。
  * 双击运行时（不带参数）进入本界面；带参数时仍走原来的命令行，两者互不影响。
  * 透明重定向需要管理员，界面会检测并提示；`--proxy-only` 不需要管理员。

用法：
  双击 ZEELoad.exe          -> 图形界面
  ZEELoad.exe --apk a.apk   -> 命令行（与原行为完全一致）
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

APP_TITLE = "极载 ZEEload · Windows 版"
SUBTITLE = "车机 APK 侧载 · 无需 root / adb / 证书"
NOTICE = "仅限自有车辆的研究 / 自用，请勿用于他人车辆。"

FROZEN = bool(getattr(sys, "frozen", False))
HERE = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(sys.executable) if FROZEN else HERE
RES_DIR = getattr(sys, "_MEIPASS", HERE)
CORE_SCRIPT = os.path.join(HERE, "win_sideload.py")

# ---- 配色：取自 assets/logo.svg / banner.svg 的黑金体系 ----
BG = "#0B0B0D"            # 主背景（logo 渐变起点）
BG_PANEL = "#131215"      # 卡片面板
BG_FIELD = "#17161A"      # 输入框
BG_LOG = "#08080A"        # 日志区（logo 渐变终点）
BORDER = "#3B301C"        # 卡片/描边（logo 边框色）
BORDER_SOFT = "#251F14"   # 次级描边
GOLD = "#C79A3F"          # 主金色（强调）
GOLD_LIGHT = "#E9CE93"    # 亮金（标题）
GOLD_PALE = "#FFF7E6"     # 奶白（主文字）
GOLD_DIM = "#B9A98C"      # 弱化文字（副标题色）
GOLD_DISABLED = "#6B6146"
OK_GREEN = "#8FBF6A"
WARN_AMBER = "#E0A34B"

UI_FONT = "Microsoft YaHei UI"
MONO_FONT = "Cascadia Mono"


def human_size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.2f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024.0
    return f"{n:.2f} GiB"


def decode_output(raw: bytes) -> str:
    """子进程输出可能是 UTF-8（设了 PYTHONIOENCODING），也可能是控制台默认的 GBK。

    Windows 上中文控制台默认 cp936，打包后的 exe 不一定认 PYTHONIOENCODING，
    所以这里先按 UTF-8 严格解，失败再按 GBK 解，都不行才用替换字符兜底。
    """
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        return raw.decode("gbk")
    except UnicodeDecodeError:
        return raw.decode("utf-8", "replace")


# --------------------------------------------------------------------------
# Job 对象：把子进程（以及它内部再起的 mitmdump）放进一个作业，
# 停止时一次整棵树结束，不依赖 taskkill（有些环境会因权限被拒）。
# --------------------------------------------------------------------------
class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    ]


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class ProcessJob:
    """CreateJobObject + KILL_ON_JOB_CLOSE，用于可靠地结束整棵进程树。"""

    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000

    def __init__(self) -> None:
        self.handle = None
        self._k32 = None
        if os.name != "nt":
            return
        try:
            self._k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            handle = self._k32.CreateJobObjectW(None, None)
            if not handle:
                return
            info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = self.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not self._k32.SetInformationJobObject(
                handle,
                self.JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(info),
                ctypes.sizeof(info),
            ):
                self._k32.CloseHandle(handle)
                return
            self.handle = handle
        except Exception:
            self.handle = None

    def attach(self, proc: subprocess.Popen) -> bool:
        if not self.handle:
            return False
        try:
            return bool(self._k32.AssignProcessToJobObject(self.handle, int(proc._handle)))
        except Exception:
            return False

    def terminate(self) -> None:
        if not self.handle:
            return
        try:
            self._k32.TerminateJobObject(self.handle, 1)
        except Exception:
            pass

    def close(self) -> None:
        if not self.handle:
            return
        try:
            self._k32.CloseHandle(self.handle)
        except Exception:
            pass
        self.handle = None


class ZEEloadApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.proc: subprocess.Popen | None = None
        self._reader: threading.Thread | None = None
        self._closing = False
        self._running = False
        self._stop_requested = False
        self._job: ProcessJob | None = None
        self._q: queue.Queue = queue.Queue()

        self.apk_var = tk.StringVar()
        self.pkg_var = tk.StringVar(value="ALL")
        self.out_var = tk.StringVar(value=os.path.join(BASE_DIR, "logs"))
        self.mode_var = tk.StringVar(value="transparent")
        self.hotspot_var = tk.StringVar(value="")
        self.info_var = tk.StringVar(value="尚未选择 APK")
        self.status_var = tk.StringVar(value="就绪")
        self.env_var = tk.StringVar(value="正在检测运行环境…")

        self._setup_window()
        self._build_ui()
        # 窗口真正映射之后再刷标题栏，太早设置会被 Tk 重建边框时覆盖
        self.root.after(150, self._apply_dark_titlebar)
        self.root.after(80, self._drain)
        threading.Thread(target=self._detect_env, daemon=True).start()

    # ---------------------------------------------------------------- 外观
    def _setup_window(self) -> None:
        self.root.title(APP_TITLE)
        try:
            sw = self.root.winfo_screenwidth()
            sh = self.root.winfo_screenheight()
        except Exception:
            sw, sh = 1280, 800
        w, h = min(1000, max(860, sw - 120)), min(880, max(660, sh - 90))
        self.root.geometry(f"{w}x{h}+{max(0, (sw - w) // 2)}+{max(0, (sh - h) // 2 - 24)}")
        self.root.minsize(min(860, w), min(660, h))
        self.root.configure(bg=BG)
        try:
            self.root.iconbitmap(default=os.path.join(RES_DIR, "zeeload.ico"))
        except Exception:
            pass
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.update_idletasks()

        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=GOLD_PALE, font=(UI_FONT, 10))

    def _apply_dark_titlebar(self) -> None:
        """把系统标题栏也刷成深色（Win10 20H1+ / Win11 支持，失败就算了）。"""
        if os.name != "nt":
            return
        try:
            import ctypes

            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            value = ctypes.c_int(1)
            for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE，老版本用 19
                if ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, attr, ctypes.byref(value), ctypes.sizeof(value)
                ) == 0:
                    break
            try:
                ctypes.windll.uxtheme.SetWindowTheme(hwnd, "DarkMode_Explorer", None)
            except Exception:
                pass
        except Exception:
            pass

    # ---- 小工具：卡片 / 输入框 / 按钮 / 文案，统一黑金风格 ----
    def _card(self, parent: tk.Misc, title: str) -> tuple[tk.Frame, tk.Frame]:
        outer = tk.Frame(parent, bg=BG_PANEL, bd=0,
                         highlightbackground=BORDER, highlightthickness=1)
        head = tk.Frame(outer, bg=BG_PANEL)
        head.pack(fill="x", padx=16, pady=(10, 0))
        tk.Label(head, text=title, bg=BG_PANEL, fg=GOLD_LIGHT,
                 font=(UI_FONT, 10, "bold")).pack(side="left")
        tk.Frame(head, bg=BORDER_SOFT, height=1).pack(side="left", fill="x", expand=True, padx=(12, 0))
        inner = tk.Frame(outer, bg=BG_PANEL)
        inner.pack(fill="both", expand=True, padx=16, pady=(8, 10))
        return outer, inner

    def _entry(self, parent: tk.Misc, var: tk.StringVar, width: int | None = None) -> tk.Entry:
        kwargs: dict = dict(
            textvariable=var, bg=BG_FIELD, fg=GOLD_PALE, insertbackground=GOLD_LIGHT,
            relief="flat", bd=0, highlightthickness=1,
            highlightbackground=BORDER, highlightcolor=GOLD,
            font=(UI_FONT, 10), disabledbackground=BG_FIELD, disabledforeground=GOLD_DIM,
        )
        if width:
            kwargs["width"] = width
        return tk.Entry(parent, **kwargs)

    def _btn(self, parent: tk.Misc, text: str, command, kind: str = "ghost") -> tk.Button:
        if kind == "primary":
            btn = tk.Button(parent, text=text, command=command, bg=GOLD, fg=BG,
                            activebackground=GOLD_LIGHT, activeforeground=BG,
                            disabledforeground=GOLD_DISABLED, relief="flat", bd=0,
                            font=(UI_FONT, 10, "bold"), padx=24, pady=8, cursor="hand2")
            btn.bind("<Enter>", lambda e: btn["state"] != "disabled" and btn.configure(bg=GOLD_LIGHT))
            btn.bind("<Leave>", lambda e: btn["state"] != "disabled" and btn.configure(bg=GOLD))
        else:
            btn = tk.Button(parent, text=text, command=command, bg=BG_PANEL, fg=GOLD_LIGHT,
                            activebackground=BG_FIELD, activeforeground=GOLD_PALE,
                            disabledforeground=GOLD_DISABLED, relief="flat", bd=0,
                            highlightthickness=1, highlightbackground=BORDER, highlightcolor=GOLD,
                            font=(UI_FONT, 10), padx=14, pady=7, cursor="hand2")
            btn.bind("<Enter>", lambda e: btn["state"] != "disabled" and
                     btn.configure(bg=BG_FIELD, highlightbackground=GOLD))
            btn.bind("<Leave>", lambda e: btn["state"] != "disabled" and
                     btn.configure(bg=BG_PANEL, highlightbackground=BORDER))
        return btn

    @staticmethod
    def _label(parent: tk.Misc, text: str, **kw) -> tk.Label:
        kw.setdefault("bg", BG_PANEL)
        kw.setdefault("fg", GOLD_PALE)
        kw.setdefault("font", (UI_FONT, 10))
        return tk.Label(parent, text=text, **kw)

    @staticmethod
    def _hint(parent: tk.Misc, text: str) -> tk.Label:
        return tk.Label(parent, text=text, bg=BG_PANEL, fg=GOLD_DIM, font=(UI_FONT, 9))

    def _load_logo(self) -> tk.PhotoImage | None:
        for base in (RES_DIR, os.path.join(BASE_DIR, "assets"), os.path.join(HERE, "..", "assets")):
            path = os.path.join(base, "logo-128.png")
            if os.path.isfile(path):
                try:
                    return tk.PhotoImage(file=path)
                except Exception:
                    return None
        return None

    def _build_ui(self) -> None:
        # ---------- 顶部品牌区（logo + 字标）----------
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x")

        brand = tk.Frame(header, bg=BG)
        brand.pack(fill="x", padx=22, pady=(18, 16))

        logo = self._load_logo()
        if logo is not None:
            self._logo_img = logo
            tk.Label(brand, image=logo, bg=BG, bd=0).pack(side="left", padx=(0, 16))

        titles = tk.Frame(brand, bg=BG)
        titles.pack(side="left", anchor="w")
        wordmark = tk.Frame(titles, bg=BG)
        wordmark.pack(anchor="w")
        tk.Label(wordmark, text="ZEEload", bg=BG, fg=GOLD_PALE,
                 font=(UI_FONT, 21, "bold")).pack(side="left")
        tk.Label(wordmark, text="极载", bg=BG, fg=GOLD_LIGHT,
                 font=(UI_FONT, 21, "bold")).pack(side="left", padx=(10, 0))
        tk.Label(titles, text=SUBTITLE, bg=BG, fg=GOLD_DIM,
                 font=(UI_FONT, 9)).pack(anchor="w", pady=(3, 0))

        tk.Label(brand, text="WINDOWS", bg=BG_PANEL, fg=GOLD_LIGHT,
                 font=("Consolas", 8, "bold"), padx=12, pady=5,
                 highlightbackground=BORDER, highlightthickness=1).pack(side="right", anchor="n")

        # logo 里那条金色分割线
        tk.Frame(self.root, bg=GOLD, height=2).pack(fill="x")

        # ---------- 状态栏（先占住底部，否则会被上面 expand 的区域挤掉）----------
        tk.Frame(self.root, bg=BORDER_SOFT, height=1).pack(fill="x", side="bottom")
        bar = tk.Frame(self.root, bg=BG_LOG)
        bar.pack(fill="x", side="bottom")
        tk.Label(bar, textvariable=self.env_var, bg=BG_LOG, fg=GOLD_DIM,
                 font=(UI_FONT, 9), anchor="w").pack(side="left", padx=22, pady=6)
        tk.Label(bar, text=NOTICE, bg=BG_LOG, fg="#5C5343",
                 font=(UI_FONT, 8)).pack(side="right", padx=22)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=22, pady=(16, 4))

        # ---------- 1. APK ----------
        apk_card, apk = self._card(body, "1  选择要安装的 APK")
        apk_card.pack(fill="x")
        apk_row = tk.Frame(apk, bg=BG_PANEL)
        apk_row.pack(fill="x")
        self.apk_entry = self._entry(apk_row, self.apk_var)
        self.apk_entry.pack(side="left", fill="x", expand=True, ipady=6)
        self._btn(apk_row, "浏览…", self._browse_apk).pack(side="left", padx=(10, 0))
        tk.Label(apk, textvariable=self.info_var, bg=BG_PANEL, fg=GOLD_DIM,
                 font=(UI_FONT, 9)).pack(anchor="w", pady=(8, 0))

        # ---------- 2. 运行选项 ----------
        opt_card, opt = self._card(body, "2  运行选项")
        opt_card.pack(fill="x", pady=(14, 0))
        opt.columnconfigure(1, weight=1)

        self._label(opt, "注入包名").grid(row=0, column=0, sticky="w", pady=5)
        self._entry(opt, self.pkg_var, width=26).grid(row=0, column=1, sticky="w", padx=10,
                                                      pady=5, ipady=5)
        self._hint(opt, "ALL = 匹配所有应用的更新请求；也可填 com.zeekr.xxx").grid(row=0, column=2, sticky="w")

        self._label(opt, "输出目录").grid(row=1, column=0, sticky="w", pady=5)
        out_row = tk.Frame(opt, bg=BG_PANEL)
        out_row.grid(row=1, column=1, columnspan=2, sticky="ew", padx=10, pady=5)
        self._entry(out_row, self.out_var).pack(side="left", fill="x", expand=True, ipady=5)
        self._btn(out_row, "浏览…", self._browse_out).pack(side="left", padx=(10, 0))

        self._label(opt, "运行模式").grid(row=2, column=0, sticky="nw", pady=(10, 4))
        modes = tk.Frame(opt, bg=BG_PANEL)
        modes.grid(row=2, column=1, columnspan=2, sticky="w", padx=10, pady=(10, 4))
        for value, text in (
            ("transparent", "透明重定向（车机连本机热点，需管理员）"),
            ("proxy", "仅 HTTP 代理（手动把车机代理指向本机，不需要管理员）"),
        ):
            tk.Radiobutton(modes, text=text, variable=self.mode_var, value=value,
                           bg=BG_PANEL, fg=GOLD_PALE, selectcolor=BG_FIELD,
                           activebackground=BG_PANEL, activeforeground=GOLD_LIGHT,
                           highlightthickness=0, bd=0, font=(UI_FONT, 10),
                           padx=0, pady=3).pack(anchor="w")

        self._label(opt, "热点 IP").grid(row=3, column=0, sticky="w", pady=(10, 4))
        self._entry(opt, self.hotspot_var, width=20).grid(row=3, column=1, sticky="w", padx=10,
                                                          pady=(10, 4), ipady=5)
        self._hint(opt, "留空 = 自动探测（一般 192.168.137.1）；探测不准时可手动填").grid(
            row=3, column=2, sticky="w", pady=(10, 4))

        # ---------- 操作 ----------
        actions = tk.Frame(body, bg=BG)
        actions.pack(fill="x", pady=(16, 0))
        self.start_btn = self._btn(actions, "开始", self._start, kind="primary")
        self.start_btn.pack(side="left")
        self.stop_btn = self._btn(actions, "停止", self._stop)
        self.stop_btn.pack(side="left", padx=(10, 0))
        self.stop_btn.configure(state="disabled")
        self._btn(actions, "打开输出目录", self._open_out).pack(side="left", padx=(10, 0))
        self._btn(actions, "清空日志", self._clear_log).pack(side="left", padx=(10, 0))
        self._btn(actions, "放行防火墙", self._allow_firewall).pack(side="left", padx=(10, 0))
        self._btn(actions, "抓包诊断", self._sniff).pack(side="left", padx=(10, 0))
        self._btn(actions, "诊断", self._diagnose).pack(side="left", padx=(10, 0))

        self.status_lbl = tk.Label(actions, textvariable=self.status_var, bg=BG,
                                   fg=GOLD_DIM, font=(UI_FONT, 10, "bold"))
        self.status_lbl.pack(side="right")

        # ---------- 3. 日志 ----------
        log_card, log_inner = self._card(body, "3  运行日志")
        log_card.pack(fill="both", expand=True, pady=(14, 12))
        self.log = ScrolledText(log_inner, height=15, wrap="word",
                                font=("Consolas", 9), bg=BG_LOG, fg="#D8C9A6",
                                insertbackground=GOLD_LIGHT, relief="flat", bd=0,
                                highlightthickness=0, padx=10, pady=8,
                                selectbackground="#3B301C", selectforeground=GOLD_PALE)
        self.log.pack(fill="both", expand=True)
        self.log.configure(state="disabled")

    # ---------------------------------------------------------------- 环境
    def _detect_env(self) -> None:
        admin = False
        ip = ""
        try:
            import win_sideload as core

            admin = core.is_admin()
            ip = core.find_hotspot_ip() or ""
        except Exception as exc:  # pragma: no cover - 仅用于界面提示
            self._post(self.env_var.set, f"环境检测失败：{exc!r}")
            return
        admin_txt = "管理员：是" if admin else "管理员：否（透明重定向不可用）"
        ip_txt = f"热点网卡：{ip}" if ip else "热点网卡：未找到（先在 Windows 里开启移动热点）"
        self._post(self.env_var.set, f"{admin_txt}    |    {ip_txt}    |    Python {sys.version.split()[0]}")
        self._admin = admin
        self._hotspot = ip

    def _post(self, fn, *args) -> None:
        """工作线程不能直接碰 tkinter：一律排队，由 UI 线程取出执行。"""
        self._q.put((fn, args))

    def _drain(self) -> None:
        while True:
            try:
                fn, args = self._q.get_nowait()
            except queue.Empty:
                break
            try:
                fn(*args)
            except Exception:
                pass
        try:
            self.root.after(80, self._drain)
        except tk.TclError:
            pass

    # ---------------------------------------------------------------- 交互
    def _browse_apk(self) -> None:
        path = filedialog.askopenfilename(
            title="选择 APK",
            filetypes=[("Android 安装包", "*.apk"), ("所有文件", "*.*")],
        )
        if path:
            self.apk_var.set(path)
            self._describe_apk(path)

    def _browse_out(self) -> None:
        path = filedialog.askdirectory(title="选择输出目录", initialdir=self.out_var.get() or BASE_DIR)
        if path:
            self.out_var.set(path)

    def _describe_apk(self, path: str) -> None:
        self.info_var.set("正在读取…")
        threading.Thread(target=self._describe_worker, args=(path,), daemon=True).start()

    def _describe_worker(self, path: str) -> None:
        try:
            size = os.path.getsize(path)
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            msg = f"{os.path.basename(path)}   {human_size(size)}   sha256 {h.hexdigest()[:16]}…"
        except Exception as exc:
            msg = f"读取失败：{exc}"
        self._post(self.info_var.set, msg)

    def _clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _append(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")
        fh = getattr(self, "_log_fh", None)
        if fh is not None:
            try:
                fh.write(text)
                fh.flush()
            except Exception:
                pass

    def _open_logfile(self, outdir: str) -> None:
        """把本次运行的日志同时落盘，出问题可以直接把文件发出来。"""
        self._close_logfile()
        try:
            name = "gui-run-%s.log" % time.strftime("%Y%m%d-%H%M%S")
            path = os.path.join(outdir, name)
            self._log_fh = open(path, "a", encoding="utf-8", errors="replace")
            self._log_path = path
            self._append(f"[界面] 本次日志同时写入：{path}\n\n")
        except Exception as exc:
            self._log_fh = None
            self._log_path = ""
            self._append(f"[界面] 无法写入日志文件：{exc}\n\n")

    def _close_logfile(self) -> None:
        fh = getattr(self, "_log_fh", None)
        if fh is not None:
            try:
                fh.close()
            except Exception:
                pass
        self._log_fh = None

    def _open_out(self) -> None:
        out = self.out_var.get().strip() or os.path.join(BASE_DIR, "logs")
        try:
            os.makedirs(out, exist_ok=True)
            os.startfile(out)  # type: ignore[attr-defined]
        except Exception as exc:
            messagebox.showwarning("打开失败", f"无法打开目录：\n{out}\n\n{exc}")

    # ---------------------------------------------------------------- 诊断
    def _run_capture(self, cmd: list[str], timeout: int = 20) -> str:
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=timeout,
                               creationflags=0x08000000)
            out = (r.stdout or b"") + (r.stderr or b"")
            return decode_output(out).strip()
        except Exception as exc:
            return f"<执行失败：{exc!r}>"

    def _diagnose(self) -> None:
        """把排查透明模式需要的现场信息全部打出来（同时落盘）。"""
        self._append("\n===== 诊断信息 =====\n")
        self._append(f"管理员：{getattr(self, '_admin', '未知')}\n")
        self._append(f"自动探测热点 IP：{getattr(self, '_hotspot', '') or '未找到'}\n")
        self._append(f"手动填写热点 IP：{self.hotspot_var.get().strip() or '（空）'}\n")
        self._append(f"运行模式：{self.mode_var.get()}\n")

        self._append("\n--- 本机 IPv4 ---\n")
        self._append(self._run_capture(["ipconfig"]) + "\n")

        self._append("\n--- 监听 18080 / 18081 ---\n")
        lines = [l for l in self._run_capture(["netstat", "-ano"], timeout=30).splitlines()
                 if ":18080" in l or ":18081" in l]
        self._append("\n".join(lines) if lines else "（没有在监听：程序未启动，或监听失败）\n")

        self._append("\n--- WinDivert 驱动 ---\n")
        self._append(self._run_capture(["sc", "query", "windivert"]) + "\n")

        self._append("\n--- 本机出网（前 3 行）---\n")
        self._append("\n".join(self._run_capture(["ping", "-n", "1", "-w", "2000", "223.5.5.5"]).splitlines()[:3]) + "\n")

        self._append("\n--- 热点网段里的邻居（车机应该在这里）---\n")
        self._append(self._run_capture(["arp", "-a"]) + "\n")
        self._append("===== 诊断结束 =====\n\n")

    def _allow_firewall(self) -> None:
        """放行 18080/18081 的入站 TCP —— 透明模式被防火墙拦时最常见的原因。"""
        if not getattr(self, "_admin", False):
            messagebox.showwarning("需要管理员", "放行防火墙需要管理员权限，请先把本程序以管理员身份运行。")
            return
        if not messagebox.askyesno(
            "放行防火墙",
            "将添加两条入站规则（TCP 18080、18081，允许任意来源）。\n\n"
            "场景：车机连上热点后商店一直没反应、日志里也没有 client connect —— "
            "多半是 Windows 防火墙把重定向后的连接挡了。\n\n现在添加吗？",
        ):
            return
        self._append("\n===== 放行防火墙 =====\n")
        for port, label in (("18080", "HTTP 代理"), ("18081", "SNI 分流器")):
            rule = f"ZEELoad {port} ({label})"
            self._run_capture(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"])
            out = self._run_capture([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule}", "dir=in", "action=allow", "protocol=TCP", f"localport={port}",
            ])
            self._append(f"[{port}] {out or '已添加'}\n")
        self._append("===== 完成 =====\n\n")
        messagebox.showinfo("已完成", "防火墙规则已添加（若系统提示已存在，表示之前就有了）。")

    # ---------------------------------------------------------------- 运行
    def _child_cmd(self, args: list[str]) -> list[str]:
        if FROZEN:
            return [sys.executable] + args
        return [sys.executable, CORE_SCRIPT] + args

    def _start(self) -> None:
        if self._running:
            return
        apk = self.apk_var.get().strip().strip('"')
        if not apk:
            messagebox.showwarning("还没选 APK", "请先选择要安装的 APK 文件。")
            return
        if not os.path.isfile(apk):
            messagebox.showerror("APK 不存在", f"找不到文件：\n{apk}")
            return
        if self.mode_var.get() == "transparent" and not getattr(self, "_admin", False):
            if messagebox.askyesno(
                "需要管理员权限",
                "透明重定向要加载 WinDivert 驱动，需要管理员权限。\n\n"
                "现在以管理员身份重新启动吗？",
            ):
                self._relaunch_as_admin()
            else:
                messagebox.showinfo(
                    "改用仅代理模式",
                    "可以先选「仅 HTTP 代理」：把车机 Wi-Fi 的代理指向本机 18080 端口，"
                    "同样能完成侧载，只是不做透明重定向。",
                )
            return

        outdir = self.out_var.get().strip() or os.path.join(BASE_DIR, "logs")
        try:
            os.makedirs(outdir, exist_ok=True)
        except Exception as exc:
            messagebox.showerror("输出目录不可用", f"{outdir}\n\n{exc}")
            return

        manual_ip = self.hotspot_var.get().strip()
        if self.mode_var.get() == "transparent":
            # 每次点开始都重新探测一次：用户常常是先开界面、后开热点
            live_ip = ""
            try:
                import win_sideload as core

                live_ip = core.find_hotspot_ip() or ""
            except Exception:
                live_ip = getattr(self, "_hotspot", "")
            if live_ip:
                self._hotspot = live_ip
                admin_txt = "管理员：是" if getattr(self, "_admin", False) else "管理员：否"
                self.env_var.set(f"{admin_txt}    |    热点网卡：{live_ip}    |    Python {sys.version.split()[0]}")
            ip = manual_ip or live_ip
            if not ip:
                messagebox.showerror(
                    "没找到热点网卡",
                    "透明模式需要先把 Windows「移动热点」打开，并让车机连上。\n\n"
                    "开好热点后重新点「开始」；如果自动探测到的 IP 不对，"
                    "可以在「热点 IP」里手动填（通常是 192.168.137.1）。",
                )
                return
            if not ip.startswith("192.168.137."):
                if not messagebox.askyesno(
                    "热点 IP 可能不对",
                    f"当前要用的热点网卡是 {ip}，不是常见的 192.168.137.x。\n\n"
                    "本机装了虚拟网卡（ZeroTier 等）时，自动探测可能选错，"
                    "那样 WinDivert 过滤器会一个包都匹配不到。\n\n"
                    "确认继续吗？（建议先在「热点 IP」里填 192.168.137.1）",
                ):
                    return

        args = ["--apk", apk, "--pkg", (self.pkg_var.get().strip() or "ALL"), "--out", outdir]
        if self.mode_var.get() == "proxy":
            args.append("--proxy-only")
        elif manual_ip:
            args += ["--hotspot-ip", manual_ip]

        self._launch(args, outdir)

    def _sniff(self) -> None:
        """抓包诊断：30 秒内统计热点网段的流量，判断车机到底有没有走这台机器。"""
        if not getattr(self, "_admin", False):
            messagebox.showwarning("需要管理员", "抓包诊断要用 WinDivert，请先把本程序以管理员身份运行。")
            return
        manual_ip = self.hotspot_var.get().strip()
        ip = manual_ip
        if not ip:
            try:
                import win_sideload as core

                ip = core.find_hotspot_ip() or ""
            except Exception:
                ip = getattr(self, "_hotspot", "")
        if not ip:
            messagebox.showerror("没找到热点网卡", "请先开启 Windows「移动热点」，或手动填「热点 IP」。")
            return
        outdir = self.out_var.get().strip() or os.path.join(BASE_DIR, "logs")
        try:
            os.makedirs(outdir, exist_ok=True)
        except Exception as exc:
            messagebox.showerror("输出目录不可用", f"{outdir}\n\n{exc}")
            return
        args = ["--sniff", "30", "--out", outdir, "--hotspot-ip", ip]
        self._launch(args, outdir)

    def _launch(self, args: list[str], outdir: str) -> None:
        if self._running:
            return
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"

        self._clear_log()
        self._open_logfile(outdir)
        self._append(f"$ {' '.join(self._child_cmd(args))}\n\n")
        self._stop_requested = False
        try:
            self.proc = subprocess.Popen(
                self._child_cmd(args),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                cwd=BASE_DIR,
                env=env,
                bufsize=0,
            )
        except Exception as exc:
            messagebox.showerror("启动失败", f"无法启动：\n{exc}")
            return

        self._job = ProcessJob()
        self._job.attach(self.proc)
        self._set_running(True, "运行中…")
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()

    def _pump(self) -> None:
        proc = self.proc
        assert proc is not None and proc.stdout is not None
        try:
            for raw in iter(proc.stdout.readline, b""):
                if not raw:
                    break
                self._post(self._append, decode_output(raw))
        except Exception as exc:
            self._post(self._append, f"\n[界面] 读取日志出错：{exc!r}\n")
        finally:
            code = proc.wait()
            self._post(self._on_proc_exit, code)

    def _on_proc_exit(self, code: int) -> None:
        if self._closing:
            return
        self._close_logfile()
        if self._job:
            self._job.close()
            self._job = None
        if self._stop_requested:
            self._set_running(False, "已停止")
        else:
            self._set_running(False, "已结束" if code == 0 else f"异常退出（{code}）")
        self._append(f"\n[界面] 子进程已退出，退出码 {code}\n")
        if code == 3:
            self._append("[界面] 退出码 3 = 需要管理员权限；请右键「以管理员身份运行」。\n")
        elif code == 4:
            self._append("[界面] 退出码 4 = mitmproxy 启动失败；检查内置 mitmproxy 是否完整。\n")
        elif code == 5:
            self._append("[界面] 退出码 5 = 没找到热点网卡；先在 Windows 设置里开启「移动热点」。\n")

    def _stop(self) -> None:
        if not self.proc or self.proc.poll() is not None:
            return
        self._stop_requested = True
        self.status_var.set("正在停止…")
        self._kill_tree(self.proc)

    def _kill_tree(self, proc: subprocess.Popen) -> None:
        """优先用 Job 对象整棵树结束；不行再退回 taskkill / terminate。"""
        killed = False
        if self._job:
            self._job.terminate()
            killed = True
        if not killed:
            try:
                subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                               capture_output=True, creationflags=0x08000000, timeout=10)
            except Exception:
                pass
        try:
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def _set_running(self, running: bool, status: str) -> None:
        self._running = running
        self.status_var.set(status)
        self.status_lbl.configure(fg=OK_GREEN if running else GOLD_DIM)
        self.start_btn.configure(state="disabled" if running else "normal")
        self.stop_btn.configure(state="normal" if running else "disabled")

    def _relaunch_as_admin(self) -> None:
        import ctypes

        if FROZEN:
            exe, params = sys.executable, ""
        else:
            exe, params = sys.executable, f'"{os.path.join(HERE, "zeeload_gui.py")}"'
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, BASE_DIR, 1)
        if rc <= 32:
            messagebox.showerror("提权失败", f"ShellExecuteW 返回 {rc}（可能取消了 UAC）。")
        else:
            self._on_close(force=True)

    def _on_close(self, force: bool = False) -> None:
        if self._running and not force:
            if not messagebox.askyesno("还在运行", "侧载进程还在运行，确定退出吗？\n（会一并结束后台的 mitmdump）"):
                return
        self._closing = True
        self._close_logfile()
        if self.proc and self.proc.poll() is None:
            self._kill_tree(self.proc)
        if self._job:
            self._job.close()
            self._job = None
        self.root.destroy()


def _enable_dark_app_mode() -> None:
    """Win10 上让 DWM 接受深色标题栏：uxtheme 的未公开导出 SetPreferredAppMode(2=ForceDark)。"""
    if os.name != "nt":
        return
    try:
        import ctypes

        ctypes.WinDLL("uxtheme")[135](2)
    except Exception:
        pass


def run() -> int:
    _enable_dark_app_mode()
    root = tk.Tk()
    # 走到这里说明 Tk 初始化成功，再把随 exe 一起出现的控制台窗口藏起来
    if os.name == "nt" and FROZEN:
        try:
            import ctypes

            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 0)
        except Exception:
            pass
    ZEEloadApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(run())
