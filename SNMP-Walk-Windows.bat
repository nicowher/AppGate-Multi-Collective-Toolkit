@echo off
setlocal
REM Walk only (step 6). No API login or SSH.
REM 1) Run from this folder so credentials.json is found.
cd /d "%~dp0"
REM 2) Prefer the Windows py launcher, else python on PATH.
where py >nul 2>&1 && (
  py -3 "app\snmp_walk_test.py" %*
) || (
  python "app\snmp_walk_test.py" %*
)
echo.
pause
endlocal
