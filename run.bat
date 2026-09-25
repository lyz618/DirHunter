@echo off
rem DirHunter Windows 启动器 - 自动寻找 Python 3
chcp 936 >nul
title DirHunter 目录扫描
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
echo [!] 未找到 Python 3，请先安装: https://www.python.org/downloads/
echo     安装时记得勾选 "Add Python to PATH"
:end
pause
