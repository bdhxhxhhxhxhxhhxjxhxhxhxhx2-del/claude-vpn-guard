@echo off
rem Claude VPN Guard v2: turn protection OFF (rules are disabled but kept, so they can be turned on again).
rem Asks for Y in this window; administrator rights are used by a hidden background process; progress is shown here.
rem Uses the protected installed copy when it exists, otherwise the copy next to this file.
set "PSModulePath="
set "CVG=%ProgramData%\ClaudeVpnGuardV2\Guard.ps1"
if not exist "%CVG%" set "CVG=%~dp0Guard.ps1"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%CVG%" -Action Off
echo.
pause
