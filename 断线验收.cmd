@echo off
rem Claude VPN Guard v2: stage 4 real VPN-disconnect acceptance test. Follow the prompts in this window.
rem Temporary rules apply to the probe program only and are removed at the end; progress is shown in this window.
set "PSModulePath="
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0DisconnectTest.ps1"
echo.
pause
