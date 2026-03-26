@echo off
REM DNS Security Monitor - Windows Quick Start Script

echo.
echo ╔════════════════════════════════════════════════════════════╗
echo ║                                                            ║
echo ║      🛡️  DNS Security Monitor - Windows Quick Start       ║
echo ║                                                            ║
echo ╚════════════════════════════════════════════════════════════╝
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] ERROR: Python is not installed or not in PATH
    echo [*] Please install Python 3.8+ from https://www.python.org/
    echo [*] Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

REM Check if Node.js is installed
node --version >nul 2>&1
if errorlevel 1 (
    echo [!] ERROR: Node.js is not installed or not in PATH
    echo [*] Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

echo [✓] Python is installed:
python --version
echo.

echo [✓] Node.js is installed:
node --version
echo.

echo ════════════════════════════════════════════════════════════════
echo Ready to start DNS Security Monitor!
echo ════════════════════════════════════════════════════════════════
echo.
echo This will open 2 new windows:
echo   1) Backend (FastAPI) on http://localhost:8000
echo   2) Frontend (React) on http://localhost:5173
echo.

pause

echo.
echo [*] Starting Backend (Terminal 1)...
start cmd /k "cd backend && call start.bat"

timeout /t 3 /nobreak

echo [*] Starting Frontend (Terminal 2)...
start cmd /k "cd frontend && call start.bat"

echo.
echo [✓] Both servers are starting!
echo.
echo Next steps:
echo   1. Wait 10 seconds for both servers to start
echo   2. Open your browser: http://localhost:5173
echo   3. In another terminal, run: py scripts\generate_dns_traffic.py
echo.
echo Close an window to stop that server.
echo.

pause
