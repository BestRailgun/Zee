"""zeeload_app.py — ZEELoad 的统一入口（给 PyInstaller 打包用）

规则很简单：
  * 不带任何参数（= 双击）          -> 图形界面 zeeload_gui
  * 带任何参数（--apk ... 等）       -> 原样交给 win_sideload.main()，行为与旧版完全一致
  * 显式 --gui                      -> 强制图形界面

这样 win_sideload.py 一行都不用改：命令行、`--mitmdump-inner`（exe 自己当 mitmdump 用）
都还是原来的代码路径。
"""

from __future__ import annotations

import sys


def main() -> int:
    argv = sys.argv[1:]

    if argv and argv[0] == "--gui":
        del argv[0]
        if argv:  # --gui 后面还带参数时退回命令行，避免参数被吞掉
            sys.argv = [sys.argv[0]] + argv
        else:
            from zeeload_gui import run

            return run()

    if argv:
        from win_sideload import main as cli_main

        return cli_main()

    from zeeload_gui import run

    return run()


if __name__ == "__main__":
    sys.exit(main())
