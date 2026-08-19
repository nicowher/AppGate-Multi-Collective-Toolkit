@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if %ERRORLEVEL%==0 (
  py -3 "app\main.py" %*
) else (
  python "app\main.py" %*
)
echo.
pause
endlocal
