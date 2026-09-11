#!/usr/bin/env python3
"""
TERMINATOR - Advanced Phishing Threat Intelligence CLI
Author: mahidulhq
Version: 1.0.0 
"""

import os
import sys
import math
import ipaddress
import requests
from urllib.parse import urlparse
import tldextract
from dotenv import load_dotenv
from colorama import init, Fore, Style

# Initialize colorama for cross-platform ANSI support (Windows/Linux)
init(autoreset=True)

# Load environment variables from .env file securely
load_dotenv()

# Banner Art
BANNER = f"""{Fore.YELLOW}
████████╗███████╗██████╗ ███╗   ███╗██╗███╗   ██╗ █████╗ ████████╗ ██████╗ ██████╗ 
╚══██╔══╝██╔════╝██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
   ██║   █████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║███████║   ██║   ██║   ██║██████╔╝
   ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██╔══██║   ██║   ██║   ██║██╔══██╗
   ██║   ███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██║  ██║   ██║   ╚██████╔╝██║  ██║
   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝                                                                            
{Style.RESET_ALL}"""

# Target Brands for Typosquatting Checks
TARGET_BRANDS = [
    "paypal", "google", "microsoft", "apple", "facebook", 
    "amazon", "netflix", "wellsfargo", "chase", "binance"
]


class TerminatorAnalyzer:
    def __init__(self, raw_url: str, vt_api_key: str = None):
        self.raw_url = raw_url.strip()
        self.vt_api_key = vt_api_key or os.getenv("VT_API_KEY")
        self.parsed = self._normalize_and_parse(self.raw_url)
        self.extracted = tldextract.extract(self.parsed.netloc)
        self.risk_score = 0
        self.findings = []
        self.resolved_url = self.raw_url

    def _normalize_and_parse(self, url: str):
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return urlparse(url)

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def _calculate_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        for x in set(data):
            p_x = float(data.count(x)) / len(data)
            entropy -= p_x * math.log2(p_x)
        return entropy

    def analyze_protocol(self):
        if self.parsed.scheme != "https":
            self.risk_score += 2
            self.findings.append("[WARNING] Insecure Protocol: Missing HTTPS encryption.")

    def analyze_ip_hostname(self):
        hostname = self.parsed.hostname or ""
        try:
            ipaddress.ip_address(hostname)
            self.risk_score += 4
            self.findings.append("[CRITICAL] Raw IP Hostname: Host uses direct IP address instead of domain.")
        except ValueError:
            pass

    def analyze_entropy(self):
        domain = self.extracted.domain
        entropy = self._calculate_entropy(domain)
        if entropy > 3.8:
            self.risk_score += 2
            self.findings.append(f"[WARNING] High Domain Entropy ({entropy:.2f}): Potential DGA generation.")

    def analyze_subdomains(self):
        subdomain = self.extracted.subdomain
        if subdomain:
            parts = subdomain.split(".")
            if len(parts) >= 3:
                self.risk_score += 3
                self.findings.append(f"[WARNING] Excessive Subdomains ({len(parts)} levels): Potential obfuscation.")

    def analyze_homograph_and_typosquatting(self):
        domain = self.extracted.domain
        
        # IDN Homograph check
        if domain.startswith("xn--"):
            self.risk_score += 4
            self.findings.append("[CRITICAL] Punycode Detected: Potential Internationalized Domain Name (IDN) homograph attack.")

        # Brand spoofing / Levenshtein check
        for brand in TARGET_BRANDS:
            dist = self._levenshtein_distance(domain.lower(), brand)
            if 0 < dist <= 2:
                self.risk_score += 4
                self.findings.append(f"[CRITICAL] Typosquatting Indicator: Domain '{domain}' mimics target brand '{brand}'.")

    def analyze_redirects(self):
        try:
            response = requests.head(self.parsed.geturl(), allow_redirects=True, timeout=5)
            if len(response.history) > 0:
                self.resolved_url = response.url
                self.findings.append(f"[INFO] URL Redirection Detected: Resolves to -> {self.resolved_url}")
                if len(response.history) >= 2:
                    self.risk_score += 2
                    self.findings.append(f"[WARNING] Multiple HTTP Redirects ({len(response.history)} hops).")
        except requests.RequestException:
            self.findings.append("[INFO] Could not expand URL redirects (Host unreachable or blocked).")

    def query_virustotal(self):
        if not self.vt_api_key:
            self.findings.append("[INFO] VirusTotal API Key not found. Skipping live threat intel lookup.")
            return

        headers = {"x-apikey": self.vt_api_key}
        domain = self.parsed.netloc or self.parsed.hostname
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"

        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                stats = response.json()["data"]["attributes"]["last_analysis_stats"]
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)

                if malicious > 0 or suspicious > 0:
                    self.risk_score += (malicious * 2) + suspicious
                    self.findings.append(f"[CRITICAL] VirusTotal Detections: {malicious} engines flagged as malicious, {suspicious} as suspicious.")
                else:
                    self.findings.append("[INFO] VirusTotal Reputation: Domain marked clean by security vendors.")
            elif response.status_code == 401:
                self.findings.append("[ERROR] VirusTotal API Key is invalid.")
        except requests.RequestException:
            self.findings.append("[ERROR] Failed to communicate with VirusTotal API.")

    def run(self):
        self.analyze_protocol()
        self.analyze_ip_hostname()
        self.analyze_entropy()
        self.analyze_subdomains()
        self.analyze_homograph_and_typosquatting()
        self.analyze_redirects()
        self.query_virustotal()

        # Final score calculation capped cleanly at 10
        final_score = min(self.risk_score, 10)

        return final_score, self.findings


def manage_api_key():
    """Interactive VirusTotal API Key setup menu."""
    current_key = os.getenv("VT_API_KEY")
    print(f"\n{Fore.CYAN}[CONFIG] VirusTotal API Key Management{Style.RESET_ALL}")
    
    if current_key:
        print(f"[+] Current API Key: {current_key[:4]}...' (Configured)")
    else:
        print("[-] Current API Key: Not configured")
        
    print("\nOptions:")
    print("  [E] Enter / Update VirusTotal API Key")
    print("  [S] Skip API setup (Use local heuristic checks only)")
    
    choice = input("\nSelect an option [E/S]: ").strip().upper()
    
    if choice == 'E':
        new_key = input("Paste your VirusTotal API Key: ").strip()
        if new_key:
            with open(".env", "w") as f:
                f.write(f"VT_API_KEY={new_key}\n")
            os.environ["VT_API_KEY"] = new_key
            print(f"{Fore.GREEN}[+] API Key saved successfully to .env file!{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.YELLOW}[!] Empty key provided. Skipping.{Style.RESET_ALL}\n")
    else:
        print(f"{Fore.YELLOW}[!] Continuing without VirusTotal API Key.{Style.RESET_ALL}\n")


def main():
    print(BANNER)
    print("=================================================================")
    print("                    ADVANCED PHISHING ANALYZER                   ")
    print("=================================================================\n")

    # Check for API Key configuration status
    if not os.getenv("VT_API_KEY"):
        manage_api_key()

    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        print("Enter 'K' to configure API Key, or enter target URL to analyze.")
        user_input = input("Target URL / Option: ").strip()
        
        if user_input.upper() == 'K':
            manage_api_key()
            target_url = input("Enter target URL to analyze: ").strip()
        else:
            target_url = user_input

    if not target_url:
        print(f"{Fore.RED}[-] Error: No URL provided. Exiting.{Style.RESET_ALL}")
        sys.exit(1)

    print(f"\n[*] Initiating Threat Analysis on: {target_url}")
    print("-" * 65)

    analyzer = TerminatorAnalyzer(target_url)
    score, findings = analyzer.run()

    for finding in findings:
        if "[CRITICAL]" in finding or "[ERROR]" in finding:
            print(f"{Fore.RED}{finding}{Style.RESET_ALL}")
        elif "[WARNING]" in finding:
            print(f"{Fore.YELLOW}{finding}{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}{finding}{Style.RESET_ALL}")

    print("-" * 65)
    
    # Verdict output
    if score >= 7:
        verdict_str = f"{Fore.RED}HIGH RISK / MALICIOUS{Style.RESET_ALL}"
    elif score >= 4:
        verdict_str = f"{Fore.YELLOW}SUSPICIOUS{Style.RESET_ALL}"
    else:
        verdict_str = f"{Fore.GREEN}LOW RISK / CLEAN{Style.RESET_ALL}"

    print(f"[*] TOTAL RISK SCORE: {score}/10")
    print(f"[*] FINAL VERDICT   : {verdict_str}")
    print("=================================================================\n")


if __name__ == "__main__":
    main()