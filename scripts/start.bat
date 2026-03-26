@echo off
REM DNS Traffic Generator - Windows Startup Script

echo.
echo ╔═══════════════════════════════════════════════════════╗
echo ║  DNS Traffic Generator                               ║
echo ║  Windows Setup                                        ║
echo ╚═══════════════════════════════════════════════════════╝
echo.

cd /d "%~dp0"

echo [*] Installing dnspython dependency...
pip install dnspython

echo.
echo [✓] Starting DNS traffic generator...
echo [*] This will generate DNS queries every 1-3 seconds
echo [*] Press Ctrl+C to stop
echo.

python generate_dns_traffic.py

pause
