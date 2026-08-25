@echo off
setlocal
cd /d "%~dp0"
rem AppGate Multi-Collective Toolkit — thin OS wrapper.
rem Menu/dispatch live in app\main.py (cli).
rem   MultiCollectiveToolkit-Windows.bat
rem   MultiCollectiveToolkit-Windows.bat 1
rem   MultiCollectiveToolkit-Windows.bat walk
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
