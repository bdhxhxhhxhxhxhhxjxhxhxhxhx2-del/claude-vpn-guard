@echo off
rem Claude VPN Guard v2: show status (read-only, no administrator rights needed).
rem Uses the protected installed copy when it exists, otherwise the copy next to this file.
set "PSModulePath="
set "CVG=%ProgramData%\ClaudeVpnGuardV2\Guard.ps1"
if not exist "%CVG%" set "CVG=%~dp0Guard.ps1"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%CVG%" -Action Status
echo.
pause
