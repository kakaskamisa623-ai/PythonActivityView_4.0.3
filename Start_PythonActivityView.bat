@echo off
setlocal
cd /d "%~dp0"
where pyw >nul 2>nul
if %errorlevel%==0 (
    start "" pyw -3 "%~dp0PythonActivityView.pyw"
    exit /b 0
)
where pythonw >nul 2>nul
if %errorlevel%==0 (
    start "" pythonw "%~dp0PythonActivityView.pyw"
    exit /b 0
)
echo pythonw.exe не найден. Запускаю с консолью для диагностики...
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 "%~dp0PythonActivityView.py"
) else (
    python "%~dp0PythonActivityView.py"
)
if errorlevel 1 pause
endlocal
