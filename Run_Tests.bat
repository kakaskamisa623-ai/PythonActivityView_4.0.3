@echo off
setlocal
cd /d "%~dp0"
python -m unittest -v test_pav250.py test_pav300.py test_pav310.py test_pav320.py test_pav330.py test_pav340.py test_pav400.py test_pav401.py test_pav402.py test_pav403.py
if errorlevel 1 (
    echo Tests failed.
    pause
    exit /b 1
)
echo.
echo All test suites passed.
pause
endlocal
