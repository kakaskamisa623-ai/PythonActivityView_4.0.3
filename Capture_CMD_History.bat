@echo off
setlocal
set "OUT=%USERPROFILE%\cmd_history_python.txt"
echo ==== CMD history capture %DATE% %TIME% ====>>"%OUT%"
doskey /history | findstr /i /r /c:"python" /c:"py " /c:"py -" /c:"py\.exe" /c:"pip" /c:"ipython" /c:"jupyter" /c:"conda" /c:"mamba" /c:"uv " /c:"poetry" /c:"pdm" /c:"hatch" >>"%OUT%"
echo.
echo Python-related CMD history appended to:
echo %OUT%
echo.
echo Note: run this BAT using CALL from the CMD window whose history you want to save.
endlocal
