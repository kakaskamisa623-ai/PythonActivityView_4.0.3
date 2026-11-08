@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 "%~dp0PythonActivityView.py"
) else (
    python "%~dp0PythonActivityView.py"
)
if errorlevel 1 pause
endlocal
