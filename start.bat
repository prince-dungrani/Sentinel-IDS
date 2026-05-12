@echo off
echo =========================================
echo    STARTING SOC PLATFORM (IDS + DASHBOARD)
echo =========================================

echo [*] Starting Flask Dashboard in the background...
start /b python dashboard\app.py

echo [*] Starting Packet Sniffer Engine...
python main.py
