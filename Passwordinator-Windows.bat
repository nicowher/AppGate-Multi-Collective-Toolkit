@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

rem Usage:
rem   Passwordinator-Windows.bat              -> menu
rem   Passwordinator-Windows.bat 1 [args...]  -> app\main.py + args
rem   Passwordinator-Windows.bat 2 [args...]  -> app\download_deps.py + args
rem   Passwordinator-Windows.bat 3 [args...]  -> app\snmp_walk_test.py + args

set "MENU_CHOICE=%~1"
if defined MENU_CHOICE (
  set "REST="
  for /f "tokens=1*" %%A in ("%*") do set "REST=%%B"
  call :dispatch "!MENU_CHOICE!" !REST!
  exit /b !ERRORLEVEL!
)

:menu
cls
echo AppGate SNMPv3 Passwordinator
echo.
echo   1^) Passwordinator  (configure appliances)
echo   2^) Download deps   (prefetch vendor wheels)
echo   3^) SNMP Walk       (validate only)
echo   Q^) Quit
echo.
set "MENU_CHOICE="
set /p MENU_CHOICE="Select 1, 2, 3, or Q: "
if not defined MENU_CHOICE goto menu
if /i "!MENU_CHOICE!"=="q" goto end
call :dispatch "!MENU_CHOICE!"
set "RC=!ERRORLEVEL!"
echo.
set "again="
set /p again="Return to menu? [Y/n]: "
if /i "!again!"=="n" goto end
goto menu

:dispatch
set "CHOICE=%~1"
shift
if /i "%CHOICE%"=="1" goto run_main
if /i "%CHOICE%"=="2" goto run_deps
if /i "%CHOICE%"=="3" goto run_walk
echo Invalid choice: %CHOICE%
exit /b 1

:run_main
call :run_py "app\main.py" %2 %3 %4 %5 %6 %7 %8 %9
exit /b %ERRORLEVEL%

:run_deps
call :run_py "app\download_deps.py" %2 %3 %4 %5 %6 %7 %8 %9
exit /b %ERRORLEVEL%

:run_walk
call :run_py "app\snmp_walk_test.py" %2 %3 %4 %5 %6 %7 %8 %9
exit /b %ERRORLEVEL%

:run_py
set "SCRIPT=%~1"
shift
where py >nul 2>&1
if %ERRORLEVEL%==0 (
  py -3 "%SCRIPT%" %1 %2 %3 %4 %5 %6 %7 %8 %9
) else (
  python "%SCRIPT%" %1 %2 %3 %4 %5 %6 %7 %8 %9
)
exit /b %ERRORLEVEL%

:end
endlocal
