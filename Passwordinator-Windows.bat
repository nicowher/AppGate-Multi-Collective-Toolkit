@echo off
setlocal
cd /d "%~dp0"
rem All menu/args handled in app\main.py (cli).
rem   Passwordinator-Windows.bat
rem   Passwordinator-Windows.bat 1
rem   Passwordinator-Windows.bat 3 --help
where py >nul 2>&1
if %ERRORLEVEL%==0 (
  py -3 "app\main.py" %*
) else (
  python "app\main.py" %*
)
set "RC=%ERRORLEVEL%"
echo.
pause
endlocal & exit /b %RC%
