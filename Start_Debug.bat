@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 PythonActivityView.py
) else (
    python PythonActivityView.py
)
if errorlevel 1 pause
endlocal
