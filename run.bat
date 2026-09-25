@echo off
rem DirHunter Windows launcher - auto find Python 3
chcp 936 >nul
title DirHunter dir scanner
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 "%~dp0dirhunter.py" %*
    goto :end
)
where python >nul 2>nul
if %errorlevel%==0 (
    python "%~dp0dirhunter.py" %*
    goto :end
)
echo [!] Python 3 not found. Please install: https://www.python.org/downloads/
echo     Remember to check "Add Python to PATH" during install.
:end
pause
