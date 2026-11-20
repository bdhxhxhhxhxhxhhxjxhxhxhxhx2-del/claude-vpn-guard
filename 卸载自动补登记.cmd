@echo off
rem Claude VPN Guard v2: remove the automatic re-registration task and the protected install folder.
rem Firewall rules are not touched. Asks for Y in this window; progress is shown here.
set "PSModulePath="
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0AutoSync.ps1" -Action Uninstall
echo.
pause
