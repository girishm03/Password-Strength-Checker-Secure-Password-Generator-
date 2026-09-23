@echo off
title CyberShield Password Security Suite
echo ======================================================================
echo    Starting CyberShield Webpage Frontend & Security API...
echo ======================================================================
echo.
echo Launching server at http://localhost:8000 ...
start http://localhost:8000
python server.py
pause
