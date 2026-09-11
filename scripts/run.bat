@echo off
title TERMINATOR - Phishing Threat Intelligence
cls

:: Change working directory to the parent directory (project root)
cd /d "%~dp0.."

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python is not installed or not added to PATH.
    echo Please install Python 3.8+ from https://www.python.org/
    pause
    exit /b
)

:: Automatically install required packages if missing
python -c "import colorama, requests, tldextract, dotenv" >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Installing required dependencies...
    pip install colorama requests tldextract python-dotenv
    cls
)

:: Run TERMINATOR from the root directory
python terminator.py

pause