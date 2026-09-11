# TERMINATOR

TERMINATOR is a command-line threat intelligence tool designed to analyze URLs for potential phishing indicators, domain typosquatting, and suspicious hosting patterns. It performs multi-layered heuristic analysis and optionally queries the VirusTotal API v3 for threat data.



## Features

* **Protocol Inspection:** Identifies unencrypted HTTP endpoints.
* **IP-Based Host Detection:** Flags requests targeting direct IP addresses rather than registered domain names.
* **Entropy Analysis:** Measures domain string randomness using Shannon entropy algorithms to detect Algorithmically Generated Domains (DGA).
* **Homograph & Typosquatting Detection:** Identifies Punycode (IDN) obfuscation and calculates Levenshtein distances against target commercial brands.
* **Redirect Tracing:** Follows HTTP redirection chains to expose final destination URLs.
* **VirusTotal Integration:** Optional reputation lookup via VirusTotal API v3.
* **Interactive Configuration:** Dynamic API key prompting with persistent `.env` storage.



## Repository Structure

```text
terminator/
├── assets/
│   └── icon.ico
├── launch/
│   ├── run.bat
│   └── run.sh
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
└── terminator.py

```



## Prerequisites

* **Python:** Version 3.8 or higher.
* **VirusTotal API Key (Optional):** Required for live vendor reputation lookups. Local heuristic checks operate without an API key.



## Installation

1. **Clone the repository:**
```bash
git clone https://github.com/your-username/terminator.git
cd terminator

```


2. **Install dependencies:**
```bash
pip install -r requirements.txt

```




## Usage

### Interactive Execution

Run the main script directly:

```bash
python terminator.py

```

Upon launching, the tool checks for an existing `.env` configuration file containing `VT_API_KEY`. If no key is configured, an interactive setup prompt allows you to enter and store your key locally.

### Passing a Target URL

You can pass a target URL directly as a command-line argument:

```bash
python terminator.py http://example-phishing-domain.com

```

### Script Launchers

* **Windows:** Double-click or execute `launch/run.bat` to automatically check dependencies and start the program.
* **Linux / macOS:** Make the shell script executable and run it:
```bash
chmod +x launch/run.sh
./launch/run.sh

```


## Pre-Compiled Releases

Pre-compiled binaries for Windows environments are hosted under the **Releases** section of this repository.

To download pre-built executables:

1. Navigate to the Releases section on the right sidebar.
2. Select the latest release version.
3. Download `TERMINATOR.exe` from the attached release assets.



## License

This project is distributed under the MIT License. Refer to the `LICENSE` file for full terms and conditions.