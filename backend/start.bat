@echo off
REM DNS Security Monitor - Windows Backend Startup Script

echo.
echo ╔═══════════════════════════════════════════════════════╗
echo ║  DNS Security Monitor - Backend                       ║
echo ║  Windows Setup                                        ║
echo ╚═══════════════════════════════════════════════════════╝
echo.

cd /d "%~dp0"

echo [*] Setting up virtual environment...
if not exist venv (
    python -m venv venv
)

echo [*] Activating virtual environment...
call venv\Scripts\activate.bat

echo [*] Installing dependencies...
pip install -r requirements.txt

echo.
echo [✓] Starting FastAPI server...
echo [*] Server will run on: http://localhost:8000
echo [*] Press Ctrl+C to stop
echo.

python main.py

pause
