@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if %ERRORLEVEL%==0 (
  py -3 "app\snmp_walk_test.py" %*
) else (
  python "app\snmp_walk_test.py" %*
)
echo.
pause
endlocal
