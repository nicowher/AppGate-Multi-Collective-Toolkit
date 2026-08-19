@echo off
setlocal
REM Prefetch wheels into app\vendor\wheels (not part of the 6-step flow).
REM Run on a networked box that matches the target OS/Python, then copy
REM the whole project to the air-gapped host.
cd /d "%~dp0"
where py >nul 2>&1 && (
  py -3 "app\download_deps.py" %*
) || (
  python "app\download_deps.py" %*
)
echo.
pause
endlocal
