@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\OEM\Install-AegisLab.ps1 > C:\OEM\bootstrap-console.log 2>&1
exit /b %errorlevel%
