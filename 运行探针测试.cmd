@echo off
rem Claude VPN Guard v2: stage 2 probe test. Temporary rules apply to the probe program only and are removed at the end.
rem Needs administrator rights; the script elevates itself and asks for confirmation in a new window.
set "PSModulePath="
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0ProbeTest.ps1"
if errorlevel 1 pause
