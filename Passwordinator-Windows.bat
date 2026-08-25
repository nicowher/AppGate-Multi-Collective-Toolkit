@echo off
setlocal
cd /d "%~dp0"
rem Why so thin: menu/dry-run/dispatch stay in Python so .bat/.sh/.command
rem never drift. This file only picks a Python and forwards args.
rem   Passwordinator-Windows.bat
rem   Passwordinator-Windows.bat 1
rem   Passwordinator-Windows.bat walk
where py >nul 2>&1
if %ERRORLEVEL%==0 (
  py -3 "app\main.py" %*
) else (
  python "app\main.py" %*
)
set "RC=%ERRORLEVEL%"
rem Pause for double-click UX; skip when args passed (scheduled tasks/CI).
if "%~1"=="" (
  echo.
  pause
)
endlocal & exit /b %RC%
