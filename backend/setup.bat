@echo off
echo ========================================
echo  DNS Guardian - Backend Setup
echo ========================================
echo.

REM Use the system Python
set PYTHON=C:\Python312\python.exe
if not exist "%PYTHON%" set PYTHON=python

echo [1/3] Creating virtual environment...
%PYTHON% -m venv venv
if errorlevel 1 (
    echo ERROR: Could not create virtual environment
    pause
    exit /b 1
)

echo [2/3] Installing dependencies...
venv\Scripts\python.exe -m pip install --upgrade pip --quiet
venv\Scripts\python.exe -m pip install ^
    fastapi==0.104.1 ^
    "uvicorn[standard]==0.24.0" ^
    pydantic==2.5.0 ^
    aiofiles==23.2.1 ^
    websockets==12.0 ^
    "dnspython==2.4.2"

if errorlevel 1 (
    echo ERROR: Failed to install packages
    pause
    exit /b 1
)

echo [3/3] Verifying installation...
venv\Scripts\python.exe -c "import fastapi, uvicorn, pydantic, aiofiles, dns; print('All packages OK')"
if errorlevel 1 (
    echo ERROR: Package verification failed
    pause
    exit /b 1
)

echo.
echo Setup complete!
echo Run START.bat to launch the backend.
pause
