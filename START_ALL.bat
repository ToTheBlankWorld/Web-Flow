@echo off
REM DNS SECURITY MONITORING PLATFORM - ONE-CLICK START
REM This starts everything you need on Windows

echo.
echo =====================================================
echo  DNS GUARDIAN - Security Monitoring Platform
echo =====================================================
echo.
echo This will start:
echo   1. Backend Server (port 9000)
echo   2. Frontend Dev Server (port 5173)
echo   3. DNS Traffic Generator
echo.
echo Press any key to start all services...
pause > nul

REM Change to project root
cd /d "%~dp0"

REM Start Backend
echo Starting Backend...
start "DNS Backend" cmd /k "cd backend && venv\Scripts\python main.py"

REM Wait for backend
timeout /t 2 /nobreak

REM Start Traffic Generator
echo Starting Traffic Generator...
start "DNS Traffic Generator" cmd /k "cd backend && python generate_events.py"

REM Wait a bit
timeout /t 1 /nobreak

REM Start Frontend
echo Starting Frontend...
start "DNS Frontend" cmd /k "cd frontend && npm run dev"

REM Wait for frontend to start
timeout /t 5 /nobreak

REM Try to open browser
echo.
echo =====================================================
echo Services starting... Opening browser...
echo =====================================================
echo.

if exist "C:\Program Files\Google\Chrome\Application\chrome.exe" (
    start "" "C:\Program Files\Google\Chrome\Application\chrome.exe" "http://localhost:5173"
) else if exist "C:\Program Files\Mozilla Firefox\firefox.exe" (
    start "" "C:\Program Files\Mozilla Firefox\firefox.exe" "http://localhost:5173"
) else (
    echo Open browser manually and go to: http://localhost:5173
)

echo.
echo =====================================================
echo ENDPOINTS
echo =====================================================
echo Frontend:     http://localhost:5173
echo Backend:      http://localhost:9000
echo Health:       http://localhost:9000/health
echo WebSocket:    ws://localhost:9000/ws/logs
echo =====================================================
echo.
pause
