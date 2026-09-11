#!/bin/bash

# Ensure script halts on fatal error
set -e

# Make sure python3 is available
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 is not installed. Please install python3 to continue."
    exit 1
fi

# Automatically install required packages if missing
python3 -c "import colorama, requests, tldextract, dotenv" &> /dev/null || {
    echo "[*] Installing required dependencies..."
    pip3 install colorama requests tldextract python-dotenv
    clear
}

# Run TERMINATOR
python3 terminator.py