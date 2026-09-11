#!/bin/bash

# Ensure script halts on fatal error
set -e

# Change working directory to the parent directory (project root)
cd "$(dirname "$0")/.."

# Check if Python 3 is installed
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

# Run TERMINATOR from the root directory
python3 terminator.py