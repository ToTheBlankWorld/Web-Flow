@echo off
REM Start DNS Monitoring Backend on Windows Laptop

cd /d "%~dp0"

echo.
echo ========================================
echo DNS SECURITY MONITORING PLATFORM
echo ========================================
echo.
echo Starting Backend and Traffic Generator...
echo.

REM Terminal 1: Backend Server
start "DNS Backend Server" cmd /k "venv\Scripts\python main.py"

REM Wait for backend to start
timeout /t 2 /nobreak

REM Terminal 2: Traffic Generator
start "DNS Traffic Generator" cmd /k "python generate_events.py"

echo.
echo ========================================
echo BACKEND RUNNING
echo ========================================
echo Backend HTTP: http://localhost:9000
echo WebSocket:    ws://localhost:9000/ws/logs
echo Health:       http://localhost:9000/health
echo ========================================
echo.
echo Open your frontend at: http://localhost:5173
echo.
pause

