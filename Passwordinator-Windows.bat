@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1 && (
  py -3 "app\main.py" %*
) || (
  python "app\main.py" %*
)
echo.
pause
endlocal
