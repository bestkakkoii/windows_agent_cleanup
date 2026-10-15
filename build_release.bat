@echo off
setlocal
chcp 65001 >nul
set "secure_erase_powershell=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "secure_erase_powershell=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%secure_erase_powershell%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\build_windows.ps1" %*
set "secure_erase_exit_code=%errorlevel%"
echo {"event":"build.bootstrap_finished","exit_code":%secure_erase_exit_code%}
if not defined SECURE_ERASE_NO_PAUSE pause
exit /b %secure_erase_exit_code%
