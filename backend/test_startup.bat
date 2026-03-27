@echo off
echo Testing backend startup performance...
echo.
cd /d "%~dp0"
venv\Scripts\python.exe main.py
