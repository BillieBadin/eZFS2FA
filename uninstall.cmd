@echo off
setlocal

set "SCRIPT=%~dp0uninstall.ps1"
if not exist "%SCRIPT%" (
    echo ERROR: missing script "%SCRIPT%"
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
set "EXIT_CODE=%ERRORLEVEL%"
exit /b %EXIT_CODE%
