# build_exe.ps1 — 在 Windows 上把极载 ZEEload 打包成 exe
#
# 用法（在 windows 目录下，PowerShell）：
#   powershell -ExecutionPolicy Bypass -File .\build_exe.ps1            # 目录版（推荐）
#   powershell -ExecutionPolicy Bypass -File .\build_exe.ps1 -OneFile   # 单文件版
#
# 产物：
#   目录版：windows\dist\ZEELoad\ZEELoad.exe
#   单文件：windows\dist\ZEELoad.exe
#
# 环境要求：Windows 10/11 x64、Python 3.12+、管理员权限（仅运行时需要）

param([switch]$OneFile)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

Write-Host '== 安装依赖 =='
python -m pip install -U pip
python -m pip install -U mitmproxy pydivert pyinstaller

$addon = (Join-Path $root '..\addons\zeekr_log.py')
$icon  = (Join-Path $root '..\assets\zeeload.ico')
$logo  = (Join-Path $root '..\assets\logo-128.png')

$pyiArgs = @(
  '--noconfirm', '--clean',
  '--name', 'ZEELoad',
  '--console',
  '--uac-admin',
  '--icon', $icon,
  '--add-data', "$addon;addons",
  '--add-data', "$icon;.",
  '--add-data', "$logo;.",
  '--collect-all', 'mitmproxy',
  '--collect-all', 'pydivert',
  '--hidden-import', 'mitmproxy.tools.main',
  '--hidden-import', 'mitmproxy.tools.dump',
  # 入口：不带参数走图形界面，带参数仍走 win_sideload 的命令行
  (Join-Path $root 'zeeload_app.py')
)
if ($OneFile) { $pyiArgs = @('--onefile') + $pyiArgs }

Write-Host '== 开始打包 =='
python -m PyInstaller @pyiArgs

if ($OneFile) {
  Write-Host "完成：$root\dist\ZEELoad.exe"
} else {
  Write-Host "完成：$root\dist\ZEELoad\ZEELoad.exe（整个 ZEELoad 目录一起分发）"
}
