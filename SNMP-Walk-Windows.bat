@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1 && (
  py -3 "app\snmp_walk_test.py" %*
) || (
  python "app\snmp_walk_test.py" %*
)
echo.
pause
endlocal
