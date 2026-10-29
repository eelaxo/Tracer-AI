@echo off
title Tracer AI - Stratagem Crew
echo ================================
echo   $Tracer AI - Local Server
echo   Team ID 176962
echo ================================
echo.
echo Installing dependencies...
py -m pip install -r requirements.txt
echo.
echo Starting server at http://127.0.0.1:8000
echo Press Ctrl+C to stop.
echo.
py -m uvicorn app:app --reload
pause
