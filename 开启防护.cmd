@echo off
rem Claude VPN Guard v2: turn protection ON (creates rules the first time; later registers new Claude programs and enables the rules).
rem Administrator rights are used by a hidden background process; all progress is shown in this window.
rem Uses the protected installed copy when it exists, otherwise the copy next to this file.
set "PSModulePath="
set "CVG=%ProgramData%\ClaudeVpnGuardV2\Guard.ps1"
if not exist "%CVG%" set "CVG=%~dp0Guard.ps1"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%CVG%" -Action On
echo.
pause
