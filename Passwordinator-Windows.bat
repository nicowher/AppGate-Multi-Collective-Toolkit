@echo off
setlocal
REM Full configure + validate (steps 0–6 in app\main.py).
REM 1) Run from this folder so credentials.json is found.
cd /d "%~dp0"
REM 2) Prefer the Windows py launcher, else python on PATH.
where py >nul 2>&1 && (
  py -3 "app\main.py" %*
) || (
  python "app\main.py" %*
)
echo.
pause
endlocal
