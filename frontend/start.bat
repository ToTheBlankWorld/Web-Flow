@echo off
REM DNS Security Monitor - Windows Frontend Startup Script

echo.
echo ╔═══════════════════════════════════════════════════════╗
echo ║  DNS Security Monitor - Frontend                      ║
echo ║  Windows Setup                                        ║
echo ╚═══════════════════════════════════════════════════════╝
echo.

cd /d "%~dp0"

echo [*] Installing dependencies...
call npm install

echo.
echo [✓] Starting Vite dev server...
echo [*] Server will run on: http://localhost:5173
echo [*] Press Ctrl+C to stop
echo.

call npm run dev

pause
