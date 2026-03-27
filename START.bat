@echo off
echo ========================================
echo  DNS Guardian - Full Stack Launcher
echo ========================================
echo.

REM Start Backend in a new window
echo [1/2] Starting Backend (port 9000)...
start "DNS Guardian - Backend" cmd /k "cd /d %~dp0backend && call start.bat"

REM Wait for backend to initialize
timeout /t 8 /nobreak >nul

REM Start Frontend dev server in a new window
echo [2/2] Starting Frontend (port 5173)...
start "DNS Guardian - Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo ========================================
echo  Waiting for services to start...
echo ========================================
timeout /t 6 /nobreak >nul

echo.
echo  Backend:  http://localhost:9000
echo  Frontend: http://localhost:5173
echo.
echo  Opening dashboard in your browser...
start http://localhost:5173

echo.
echo Both servers are running in separate windows.
echo Close those windows to stop the servers.
pause
