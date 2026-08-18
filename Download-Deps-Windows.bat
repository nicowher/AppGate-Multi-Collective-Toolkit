@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1 && (
  py -3 "app\download_deps.py" %*
) || (
  python "app\download_deps.py" %*
)
echo.
pause
endlocal
