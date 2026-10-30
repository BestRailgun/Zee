@echo off
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting administrator privileges...
  if "%~1"=="" (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  ) else (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs -ArgumentList '%~1'"
  )
  exit /b
)

set "APK=%~1"
if "%APK%"=="" set /p "APK=APK path: "

if not exist "%APK%" (
  echo APK not found: %APK%
  pause
  exit /b 1
)

where python >nul 2>&1
if %errorlevel%==0 goto :runpy
where py >nul 2>&1
if %errorlevel%==0 goto :runpylauncher
echo Python 3.12+ is required. Install it and enable "Add to PATH".
pause
exit /b 1

:runpy
python "%~dp0win_sideload.py" --apk "%APK%"
goto :done

:runpylauncher
py "%~dp0win_sideload.py" --apk "%APK%"

:done
echo.
echo Exit code: %errorlevel%
pause
