@echo off
title TERMINATOR - Phishing Threat Intelligence
cls

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python is not installed or not added to PATH.
    echo Please install Python 3.8+ from https://www.python.org/
    pause
    exit /b
)

:: Install required dependencies automatically if missing
python -c "import colorama, requests, tldextract, dotenv" >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Installing required dependencies...
    pip install colorama requests tldextract python-dotenv
    cls
)

:: Run TERMINATOR
python terminator.py
pause