@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if %ERRORLEVEL%==0 (
  py -3 "app\download_deps.py" %*
) else (
  python "app\download_deps.py" %*
)
echo.
pause
endlocal
