@echo off
REM AppGate SNMPv3 Configuration - Batch Wrapper
REM Usage: run_AppGate_SNMPv3_Passwordinator_v1.0.bat

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "PYTHON_SCRIPT=%SCRIPT_DIR%AppGate_SNMPv3_Passwordinator_v1.0.py"

if not exist "%PYTHON_SCRIPT%" (
    echo ERROR: Python script not found at: %PYTHON_SCRIPT%
    pause
    exit /b 1
)

echo Launching AppGate SNMPv3 Configuration Script...
echo.

python "%PYTHON_SCRIPT%"
exit /b %ERRORLEVEL%
