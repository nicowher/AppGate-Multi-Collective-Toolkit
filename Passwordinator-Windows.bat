@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

rem Usage:
rem   Passwordinator-Windows.bat              -> menu
rem   Passwordinator-Windows.bat 1 [args...]  -> app\main.py + args
rem   Passwordinator-Windows.bat 2 [args...]  -> app\download_deps.py + args
rem   Passwordinator-Windows.bat 3 [args...]  -> app\snmp_walk_test.py + args

if "%~1"=="" goto menu

set "CHOICE=%~1"
set "PY_ARGS="
for /f "tokens=1*" %%A in ("%*") do set "PY_ARGS=%%B"
call :run_choice "!CHOICE!" "!PY_ARGS!"
exit /b !ERRORLEVEL!

:menu
cls
echo AppGate SNMPv3 Passwordinator
echo.
echo   1^) Passwordinator  (configure appliances)
echo   2^) Download deps   (prefetch vendor wheels)
echo   3^) SNMP Walk       (validate only)
echo   Q^) Quit
echo.
set "CHOICE="
set /p CHOICE="Select 1, 2, 3, or Q: "
if not defined CHOICE goto menu
if /i "!CHOICE!"=="q" goto end
call :run_choice "!CHOICE!" ""
echo.
set "again="
set /p again="Return to menu? [Y/n]: "
if /i "!again!"=="n" goto end
goto menu

:run_choice
set "C=%~1"
set "A=%~2"
if /i "%C%"=="1" (
  call :run_py "app\main.py" %A%
  exit /b !ERRORLEVEL!
)
if /i "%C%"=="2" (
  call :run_py "app\download_deps.py" %A%
  exit /b !ERRORLEVEL!
)
if /i "%C%"=="3" (
  call :run_py "app\snmp_walk_test.py" %A%
  exit /b !ERRORLEVEL!
)
echo Invalid choice: %C%
exit /b 1

:run_py
set "SCRIPT=%~1"
shift
where py >nul 2>&1
if !ERRORLEVEL!==0 (
  py -3 "%SCRIPT%" %*
) else (
  python "%SCRIPT%" %*
)
exit /b !ERRORLEVEL!

:end
endlocal
