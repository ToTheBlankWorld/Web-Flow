@echo off
cd /d "d:\My Projects\DNS Detc\frontend"

REM Install dependencies if needed
if not exist node_modules (
    echo Installing dependencies...
    call npm install -q
)

REM Start the frontend dev server
echo Starting frontend on port 5173...
call npm run dev
