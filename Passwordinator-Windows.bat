@echo off
setlocal
cd /d "%~dp0"

:menu
cls
echo AppGate SNMPv3 Passwordinator
echo.
echo   1^) Passwordinator  (configure appliances)
echo   2^) Download deps   (prefetch vendor wheels)
echo   3^) SNMP Walk       (validate only)
echo   Q^) Quit
echo.
set "choice="
set /p choice="Select 1, 2, 3, or Q: "

if /i "%choice%"=="1" goto run_main
if /i "%choice%"=="2" goto run_deps
if /i "%choice%"=="3" goto run_walk
if /i "%choice%"=="q" goto end
echo Invalid choice.
pause
goto menu

:run_main
call :run_py "app\main.py"
goto after

:run_deps
call :run_py "app\download_deps.py"
goto after

:run_walk
call :run_py "app\snmp_walk_test.py"
goto after

:run_py
where py >nul 2>&1
if %ERRORLEVEL%==0 (
  py -3 %~1 %*
) else (
  python %~1 %*
)
exit /b %ERRORLEVEL%

:after
echo.
set "again="
set /p again="Return to menu? [Y/n]: "
if /i "%again%"=="n" goto end
goto menu

:end
endlocal
