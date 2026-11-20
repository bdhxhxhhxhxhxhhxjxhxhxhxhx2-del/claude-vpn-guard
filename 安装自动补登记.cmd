@echo off
rem Claude VPN Guard v2: install or update the automatic re-registration task (copies the scripts to a protected folder,
rem registers a SYSTEM scheduled task that syncs the program list at logon and every 30 minutes, then runs it once).
rem Asks for Y in this window; administrator rights are used by a hidden background process; progress is shown here.
set "PSModulePath="
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0AutoSync.ps1" -Action Install
echo.
pause
