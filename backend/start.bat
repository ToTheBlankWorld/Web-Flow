@echo off
echo ========================================
echo  DNS Guardian - Backend Server
echo ========================================
echo.

cd /d "%~dp0"

REM ── Request admin for live DNS capture via ETW ────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator access for live DNS monitoring...
    powershell -Command "Start-Process cmd -ArgumentList '/k cd /d ""%~dp0"" && ""%~f0""' -Verb RunAs" 2>nul
    exit /b
)

REM Check venv exists and has pip
if exist "venv\Scripts\python.exe" (
    venv\Scripts\python.exe -c "import pip" >nul 2>&1
    if not errorlevel 1 goto :run_venv
)

REM Venv missing or broken - recreate it
echo Setting up virtual environment...
C:\Python312\python.exe -m venv venv 2>nul || python -m venv venv
venv\Scripts\python.exe -m ensurepip -q 2>nul
venv\Scripts\python.exe -m pip install -q ^
    "fastapi==0.104.1" "uvicorn[standard]==0.24.0" ^
    "pydantic==2.12.5" "pydantic-core==2.41.5" ^
    "aiofiles==23.2.1" "websockets==12.0" "dnspython==2.4.2"
if errorlevel 1 (
    echo ERROR: Could not install packages. Run fix_deps.py manually.
    pause & exit /b 1
)

:run_venv
echo Starting DNS Security Monitor on port 9000...
echo Dashboard: http://localhost:5173
echo API:       http://localhost:9000
echo.
echo Monitoring REAL DNS traffic - just browse normally to see data.
echo Press Ctrl+C to stop.
echo.
venv\Scripts\python.exe -u main.py
pause
