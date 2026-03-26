@echo off
REM Master startup script for DNS Security Monitoring Platform

echo ==========================================
echo DNS Security Monitoring Platform - Startup
echo ==========================================
echo.
echo This will start:
echo 1. Backend server (port 9000)
echo 2. Frontend dev server (port 5173)
echo 3. DNS traffic generator
echo.

REM Start backend
echo Starting backend...
start "Backend Server" cmd /k "cd /d d:\My Projects\DNS Detc\backend && run.bat"

REM Give backend time to start
timeout /t 2 /nobreak

REM Start frontend
echo Starting frontend...
start "Frontend Server" cmd /k "cd /d d:\My Projects\DNS Detc\frontend && run.bat"

REM Give frontend time to start
timeout /t 2 /nobreak

REM Start event generator
echo Starting DNS traffic generator...
start "DNS Traffic Generator" cmd /k "cd /d d:\My Projects\DNS Detc && python generate_events.py"

echo.
echo ==========================================
echo Services starting. Wait 10-15 seconds for them to initialize.
echo.
echo Frontend: http://localhost:5173
echo Backend: http://localhost:9000
echo ==========================================
echo.

REM Open frontend in browser if available
timeout /t 5 /nobreak
if exist "C:\Program Files\Google\Chrome\Application\chrome.exe" (
    start "" "C:\Program Files\Google\Chrome\Application\chrome.exe" http://localhost:5173
) else if exist "C:\Program Files\Mozilla Firefox\firefox.exe" (
    start "" "C:\Program Files\Mozilla Firefox\firefox.exe" http://localhost:5173
) else (
    start http://localhost:5173
)

pause
