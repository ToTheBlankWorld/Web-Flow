@echo off
cd /d "d:\My Projects\DNS Detc\backend"

REM Create venv if it doesn't exist
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

REM Install dependencies
echo Installing dependencies...
call venv\Scripts\pip install -q -r requirements.txt

REM Start the backend
echo Starting backend server on port 9000...
call venv\Scripts\python -m uvicorn main:app --host 0.0.0.0 --port 9000 --reload
