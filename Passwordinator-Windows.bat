@echo off
setlocal
cd /d "%~dp0"
rem Thin OS wrapper only. Menu, dry-run, and tool dispatch live in app\main.py (cli).
rem   Passwordinator-Windows.bat
rem   Passwordinator-Windows.bat 1
rem   Passwordinator-Windows.bat 3
rem   Passwordinator-Windows.bat walk
where py >nul 2>&1
if %ERRORLEVEL%==0 (
  py -3 "app\main.py" %*
) else (
  python "app\main.py" %*
)
set "RC=%ERRORLEVEL%"
rem Pause on double-click (no args). Skip pause when args passed (automation).
if "%~1"=="" (
  echo.
  pause
)
endlocal & exit /b %RC%
