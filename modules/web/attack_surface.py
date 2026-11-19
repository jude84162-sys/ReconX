#!/usr/bin/env python3
"""
ReconX Advanced Attack Surface Engine
--------------------------------------------------
Elite Bug Bounty Reconnaissance & Vulnerability Discovery Module.
Pure Python 3.8+ Standard Library — Zero external dependencies.
"""

import io
import os
import sys
import json
import re
import ssl
import socket
import struct
import hashlib
import urllib.request
import urllib.parse
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# ANSI Color Codes
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"

class TorSOCKS5Handler(urllib.request.BaseHandler):
    """Zero-dependency SOCKS5h / Tor proxy handler using raw socket handshakes."""
    def __init__(self, proxy_host="127.0.0.1", proxy_port=9050):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port

    def http_open(self, req):
        return self._open_connection(req)

    def https_open(self, req):
        return self._open_connection(req, secure=True)

    def _open_connection(self, req, secure=False):
        host = req.host
        port = req.port or (443 if secure else 80)
        
        try:
            # 1. Connect to Tor SOCKS5 proxy
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.proxy_host, self.proxy_port))

            # SOCKS5 Greeting: NO AUTHENTICATION REQUIRED (0x00)
            sock.sendall(b"\x05\x01\x00")
            response = sock.recv(2)
            if response != b"\x05\x00":
                sock.close()
                raise ConnectionError("Tor SOCKS5 proxy rejected connection or requires auth.")

            # SOCKS5 Connect Request (Command 0x01: CONNECT, ATYP 0x03: Domain name)
            host_bytes = host.encode("idna")
            req_packet = b"\x05\x01\x00\x03" + struct.pack("B", len(host_bytes)) + host_bytes + struct.pack(">H", port)
            sock.sendall(req_packet)

            resp = sock.recv(10)
            if len(resp) < 2 or resp[1] != 0x00:
                sock.close()
                raise ConnectionError(f"Tor SOCKS5 failed to establish tunnel to {host}:{port}")

            # Discard remaining bind address bytes
            atyp = resp[3]
            if atyp == 0x01:
                sock.recv(4)
            elif atyp == 0x03:
                domain_len = ord(sock.recv(1))
                sock.recv(domain_len)
            elif atyp == 0x04:
                sock.recv(16)
            sock.recv(2) # port

            if secure:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            # Construct HTTP request over the wrapped socket
            selector = req.selector if req.selector else "/"
            http_req = f"{req.get_method()} {selector} HTTP/1.1\r\n"
            for header, value in req.header_items():
                http_req += f"{header}: {value}\r\n"
            http_req += f"Host: {host}\r\nConnection: close\r\n\r\n"
            
            sock.sendall(http_req.encode("utf-8"))

            # Read response
            buf = bytearray()
            while True:
                data = sock.recv(8192)
                if not data:
                    break
                buf.extend(data)
            sock.close()

            header_data, _, body_data = buf.partition(b"\r\n\r\n")
            header_text = header_data.decode("utf-8", errors="ignore")
            status_line = header_text.split("\r\n")[0]
            status_code = int(status_line.split(" ")[1])

            hdrs = {}
            for line in header_text.split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    hdrs[k.strip().lower()] = v.strip()

            addinfourl = urllib.request.addinfourl(
                io.BytesIO(body_data), hdrs, req.full_url, status_code
            )
            addinfourl.code = status_code
            return addinfourl

        except Exception as e:
            raise urllib.error.URLError(f"Tor Proxy Tunnel Error: {e}")

class AttackSurfaceEngine:
    def __init__(self, target, use_tor=False, discord_webhook=None, telegram_token=None, telegram_chat_id=None, delay=0.5):
        self.target = target.replace("http://", "").replace("https://", "").strip("/")
        self.use_tor = use_tor
        self.discord_webhook = discord_webhook
        self.telegram_token = telegram_token
        self.telegram_chat_id = telegram_chat_id
        self.delay = delay
        self.subdomains = set()
        self.endpoints = set()
        self.js_files = set()
        self.sensitive_findings = []
        self.parameter_findings = []
        
        # Setup Opener
        if self.use_tor:
            print(f"  {BLUE}[*]{RESET} Routing traffic through Tor SOCKS5h (127.0.0.1:9050)...", flush=True)
            self.opener = urllib.request.build_opener(TorSOCKS5Handler())
        else:
            self.opener = urllib.request.build_opener()

    def _request(self, url, headers=None):
        if not headers:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconX/4.0"}
        try:
            req = urllib.request.Request(url, headers=headers)
            with self.opener.open(req, timeout=10) as resp:
                return resp.code, resp.read().decode("utf-8", errors="ignore")
        except Exception as e:
            return 0, str(e)

    def run_recon_pipeline(self):
        print(f"\n{BLUE}╔══════════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{BLUE}║        ReconX Advanced Attack Surface & Vuln Engine v5.0        ║{RESET}")
        print(f"{BLUE}╚══════════════════════════════════════════════════════════════════╝{RESET}\n", flush=True)
        print(f"  🎯 Target Domain: {self.target}", flush=True)
        print(f"  📅 Execution Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", flush=True)

        # 1. Certificate Mining (crt.sh)
        print(f"  {YELLOW}[1/4]{RESET} Mining wildcard SSL certificates via crt.sh...", flush=True)
        self._mine_crtsh()

        # 2. Wayback Machine & JS Harvesting
        print(f"  {YELLOW}[2/4]{RESET} Harvesting historical endpoints and JavaScript assets...", flush=True)
        self._harvest_wayback()

        # 3. Parameter Classification Analysis
        print(f"  {YELLOW}[3/4]{RESET} Analyzing URL parameters for SSRF, SQLi, and XSS vectors...", flush=True)
        self._classify_parameters()

        # 4. Active Sensitive File Fuzzing & Soft-404 Validation
        print(f"  {YELLOW}[4/4]{RESET} Fuzzing configuration leaks and sensitive directories...", flush=True)
        self._fuzz_sensitive_files()

        # Export Results & Alert
        report_path = self._export_results()
        print(f"\n  {GREEN}[✓]{RESET} Attack Surface analysis completed successfully!", flush=True)
        print(f"  {GREEN}[✓]{RESET} JSON Manifest saved to: {report_path}\n", flush=True)
        return report_path

    def _mine_crtsh(self):
        url = f"https://crt.sh/?q=%.{self.target}&output=json"
        code, body = self._request(url)
        if code == 200:
            try:
                data = json.loads(body)
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.split("\n"):
                        sub = sub.strip().lower()
                        if sub and sub.endswith(self.target) and "*" not in sub:
                            self.subdomains.add(sub)
                print(f"    {GREEN}[✓]{RESET} Discovered {len(self.subdomains)} unique subdomains from crt.sh", flush=True)
            except Exception as e:
                print(f"    {RED}[✗]{RESET} Failed to parse crt.sh JSON: {e}", flush=True)
        else:
            print(f"    {RED}[✗]{RESET} crt.sh returned HTTP status {code}", flush=True)

    def _harvest_wayback(self):
        cdx_url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.target}/*&output=json&collapse=urlkey"
        code, body = self._request(cdx_url)
        if code == 200:
            try:
                rows = json.loads(body)
                # Skip header row if present
                if len(rows) > 1:
                    rows = rows[1:]
                for row in rows:
                    if len(row) > 2:
                        orig_url = row[2]
                        self.endpoints.add(orig_url)
                        parsed = urllib.parse.urlparse(orig_url)
                        domain = parsed.netloc.lower()
                        if domain.endswith(self.target):
                            self.subdomains.add(domain)
                        if parsed.path.endswith(".js"):
                            self.js_files.add(orig_url)
                print(f"    {GREEN}[✓]{RESET} Harvested {len(self.endpoints)} historical endpoints & {len(self.js_files)} JS assets", flush=True)
            except Exception as e:
                print(f"    {RED}[✗]{RESET} Failed to parse Wayback CDX data: {e}", flush=True)
        else:
            print(f"    {RED}[✗]{RESET} Wayback CDX API returned status {code}", flush=True)

    def _classify_parameters(self):
        # High-risk parameter signatures for SSRF, SQLi, Reflected XSS
        high_risk_keys = {"url", "proxy", "redirect", "next", "dest", "uri", "path", "q", "s", "search", "query", "id", "user", "account", "file", "page", "doc", "download", "callback", "feed", "eval", "cmd"}
        
        for ep in self.endpoints:
            parsed = urllib.parse.urlparse(ep)
            if parsed.query:
                params = urllib.parse.parse_qsl(parsed.query)
                for k, v in params:
                    k_lower = k.lower()
                    if k_lower in high_risk_keys:
                        vector_type = "UNKNOWN"
                        if k_lower in {"url", "proxy", "redirect", "next", "dest", "uri", "path"}:
                            vector_type = "Potential SSRF / Open Redirect"
                        elif k_lower in {"id", "user", "account", "page", "file"}:
                            vector_type = "Potential SQLi / Path Traversal"
                        elif k_lower in {"q", "s", "search", "query", "callback"}:
                            vector_type = "Potential Reflected XSS"
                        
                        self.parameter_findings.append({
                            "url": ep,
                            "parameter": k,
                            "vector": vector_type
                        })
        print(f"    {GREEN}[✓]{RESET} Classified {len(self.parameter_findings)} high-risk parameters across harvested endpoints", flush=True)

    def _fuzz_sensitive_files(self):
        # Baseline request for Soft-404 detection
        rand_token = hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]
        baseline_code, baseline_body = self._request(f"https://{self.target}/{rand_token}.html")
        baseline_len = len(baseline_body)

        sensitive_paths = [
            "/.env",
            "/.git/HEAD",
            "/config.json",
            "/.aws/credentials",
            "/backup.zip",
            "/backup.bak",
            "/database.sql",
            "/composer.json",
            "/package.json"
        ]

        base_url = f"https://{self.target}"
        for path in sensitive_paths:
            target_url = base_url + path
            code, body = self._request(target_url)
            
            # Soft-404 filter: status code must be 200 and body length/hash must significantly differ from random 404 page
            if code == 200 and len(body) != baseline_len and "<html>" not in body[:50].lower():
                finding = {
                    "path": path,
                    "url": target_url,
                    "status": code,
                    "size": len(body)
                }
                self.sensitive_findings.append(finding)
                print(f"    {RED}[!] CRITICAL LEAK FOUND:{RESET} {target_url} (HTTP 200, Size: {len(body)})", flush=True)
                self._send_alerts(f"🚨 **ReconX Critical Leak Alert!**\nTarget: `{target_url}`\nSize: `{len(body)} bytes`")
            
            import time
            time.sleep(self.delay)

    def _send_alerts(self, message):
        # Dispatch Discord Webhook
        if self.discord_webhook:
            try:
                payload = json.dumps({"content": message}).encode("utf-8")
                req = urllib.request.Request(self.discord_webhook, data=payload, headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass

        # Dispatch Telegram Bot API Alert
        if self.telegram_token and self.telegram_chat_id:
            try:
                tg_url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
                payload = json.dumps({"chat_id": self.telegram_chat_id, "text": message, "parse_mode": "Markdown"}).encode("utf-8")
                req = urllib.request.Request(tg_url, data=payload, headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass

    def _export_results(self):
        output_dir = Path("outputs")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        filename = f"recon_attacksurface_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = output_dir / filename

        report_data = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "subdomains_count": len(self.subdomains),
            "subdomains": list(self.subdomains),
            "endpoints_count": len(self.endpoints),
            "js_files_count": len(self.js_files),
            "js_assets": list(self.js_files),
            "parameter_findings": self.parameter_findings,
            "sensitive_findings": self.sensitive_findings
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        return str(filepath)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m modules.web.attack_surface example.com [--tor]")
        sys.exit(1)
    
    target_domain = sys.argv[1]
    tor_flag = "--tor" in sys.argv
    engine = AttackSurfaceEngine(target=target_domain, use_tor=tor_flag)
    engine.run_recon_pipeline()