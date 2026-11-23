@echo off
cd /d "%~dp0"
where py >nul 2>nul && (py -3 snapshot.py) || (where python >nul 2>nul && (python snapshot.py) || (echo This needs Python 3 ^(free^). Get it at https://www.python.org/downloads/ - tick "Add python.exe to PATH" - then double-click this file again.))
pause
