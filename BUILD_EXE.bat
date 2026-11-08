@echo off
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo Python was not found. Install Python 3.10+ with Tcl/Tk and add it to PATH.
    pause
    exit /b 1
)

python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"
if errorlevel 1 (
    echo Python 3.10 or newer is required.
    pause
    exit /b 1
)

python -c "import tkinter"
if errorlevel 1 (
    echo Tkinter/Tcl-Tk is missing from this Python installation.
    pause
    exit /b 1
)

python -m unittest -q test_pav250.py test_pav300.py test_pav310.py test_pav320.py test_pav330.py test_pav340.py test_pav400.py test_pav401.py test_pav402.py test_pav403.py
if errorlevel 1 (
    echo Tests failed. Build stopped.
    pause
    exit /b 1
)

python -c "import PyInstaller" >nul 2>nul
if errorlevel 1 (
    echo PyInstaller is not installed. Installing it into the active Python environment...
    python -m pip install --upgrade pyinstaller
    if errorlevel 1 (
        echo PyInstaller installation failed.
        pause
        exit /b 1
    )
)

python -m PyInstaller --noconfirm --clean PythonActivityView.spec
if errorlevel 1 (
    echo Build failed. Read the error output above.
    pause
    exit /b 1
)

if not exist "dist\PythonActivityView.exe" (
    echo The expected EXE was not found.
    pause
    exit /b 1
)
echo.
echo Build complete: dist\PythonActivityView.exe
echo Optional parsers are embedded only if installed before this build.
echo Read BUILD_EXE_RU.txt for optional parser setup and Windows verification.
pause
endlocal
