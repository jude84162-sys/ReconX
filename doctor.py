#!/usr/bin/env python3
"""
ReconX Doctor & Self-Healing Utility
------------------------------------
Automatically diagnoses and repairs common structural, import, and network issues in ReconX.
Usage: python doctor.py [--fix]
"""

import os
import sys
import ast
import importlib
import pkgutil
import urllib.request
import urllib.error
from pathlib import Path

# ANSI Color Codes for terminal output
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"

def print_status(status, message):
    if status == "OK":
        print(f"  {GREEN}[✓]{RESET} {message}")
    elif status == "FIXED":
        print(f"  {BLUE}[FIXED]{RESET} {message}")
    elif status == "WARN":
        print(f"  {YELLOW}[⚠]{RESET} {message}")
    else:
        print(f"  {RED}[✗]{RESET} {message}")

class ReconXDoctor:
    def __init__(self, auto_fix=True):
        self.root_dir = Path(__file__).parent.resolve()
        self.auto_fix = auto_fix
        self.issues_found = 0
        self.issues_fixed = 0

    def run_diagnosis(self):
        print(f"\n{BLUE}╔══════════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{BLUE}║             ReconX Self-Healing & Diagnostic Engine              ║{RESET}")
        print(f"{BLUE}╚══════════════════════════════════════════════════════════════════╝{RESET}\n")

        self.check_environment()
        self.check_directories()
        self.check_syntax_and_imports()
        self.check_api_connectivity()

        print(f"\n{BLUE}══════════════════════════════════════════════════════════════════{RESET}")
        print(f"  📊 DIAGNOSIS COMPLETE")
        print(f"  Issues detected: {self.issues_found}")
        print(f"  Issues auto-fixed: {self.issues_fixed}")
        print(f"{BLUE}══════════════════════════════════════════════════════════════════{RESET}\n")

    def check_environment(self):
        print("[-] Checking Python environment & path...")
        if sys.version_info < (3, 8):
            print_status("FAIL", f"Python version {sys.version_info.major}.{sys.version_info.minor} detected. ReconX requires Python 3.8+")
            self.issues_found += 1
        else:
            print_status("OK", f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} compatible.")
        
        # Ensure root dir is in sys.path
        if str(self.root_dir) not in sys.path:
            sys.path.insert(0, str(self.root_dir))
            if self.auto_fix:
                print_status("FIXED", "Added repository root to sys.path.")
                self.issues_fixed += 1

    def check_directories(self):
        print("\n[-] Checking required directory structure...")
        required_dirs = ["outputs", "modules", "modules/network", "modules/web", "modules/report", "modules/utils"]
        for d in required_dirs:
            dir_path = self.root_dir / d
            if not dir_path.exists():
                self.issues_found += 1
                if self.auto_fix:
                    dir_path.mkdir(parents=True, exist_ok=True)
                    print_status("FIXED", f"Created missing directory: {d}/")
                    self.issues_fixed += 1
                else:
                    print_status("FAIL", f"Missing directory: {d}/")
            else:
                print_status("OK", f"Directory exists: {d}/")

    def check_syntax_and_imports(self):
        print("\n[-] Scanning modules for syntax & import integrity...")
        modules_dir = self.root_dir / "modules"
        
        if not modules_dir.exists():
            return

        python_files = list(modules_dir.glob("**/*.py"))
        python_files.extend((self.root_dir / "scorpion").glob("**/*.py"))
        python_files.append(self.root_dir / "recon.py")

        for file_path in python_files:
            if not file_path.exists():
                continue
            
            rel_path = file_path.relative_to(self.root_dir)
            
            # 1. Check Syntax via AST
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    source_code = f.read()
                ast.parse(source_code, filename=str(file_path))
            except SyntaxError as e:
                print_status("FAIL", f"Syntax error in {rel_path}: {e}")
                self.issues_found += 1
                continue

            # 2. Check Importability
            module_name = str(rel_path.with_suffix('')).replace(os.sep, '.')
            try:
                if module_name != ".":
                    importlib.import_module(module_name)
                    print_status("OK", f"Module healthy: {rel_path}")
            except Exception as e:
                print_status("WARN", f"Import runtime issue in {rel_path}: {e}")
                self.issues_found += 1
                # Auto-fix: Check if it's a relative import glitch and can be patched
                if "attempted relative import with no known parent package" in str(e) and self.auto_fix:
                    self._patch_relative_import(file_path)

    def _patch_relative_import(self, file_path):
        """Attempts to fix standard import misconfigurations automatically."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            patched = content.replace("from .utils", "from modules.utils")
            if patched != content:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(patched)
                print_status("FIXED", f"Patched imports in {file_path.name}")
                self.issues_fixed += 1
        except Exception as ex:
            print_status("FAIL", f"Could not auto-patch {file_path.name}: {ex}")

    def check_api_connectivity(self):
        print("\n[-] Testing critical external DoH & OSINT endpoints...")
        test_endpoints = {
            "Cloudflare DoH": "https://cloudflare-dns.com/dns-query?name=example.com&type=A",
            "Google DoH": "https://dns.google/resolve?name=example.com&type=A",
            "IP-API Geolocation": "http://ip-api.com/json/8.8.8.8"
        }

        for name, url in test_endpoints.items():
            try:
                # Cloudflare DoH requires 'application/dns-json' instead of standard 'application/json'
                accept_header = "application/dns-json" if "cloudflare-dns.com" in url else "application/json"
                
                req = urllib.request.Request(
                    url, 
                    headers={"Accept": accept_header, "User-Agent": "ReconX-Doctor/5.0"}
                )
                with urllib.request.urlopen(req, timeout=5) as response:
                    if response.status == 200:
                        print_status("OK", f"{name} is reachable.")
                    else:
                        print_status("WARN", f"{name} returned status code {response.status}")
            except urllib.error.URLError as e:
                print_status("WARN", f"{name} unreachable (Network/DNS issue): {e.reason}")
                self.issues_found += 1
            except Exception as e:
                print_status("WARN", f"{name} check failed: {e}")

if __name__ == "__main__":
    auto_fix_flag = "--no-fix" not in sys.argv
    doctor = ReconXDoctor(auto_fix=auto_fix_flag)
    doctor.run_diagnosis()