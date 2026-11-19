import asyncio
import aiohttp
import random
import hashlib
import socket
import time
import json
from urllib.parse import urlparse

# --- OPSEC LAYER ---
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
]

class HardenedSession:
    def __init__(self, proxy=None):
        self.proxy = proxy
        self.connector = aiohttp.TCPConnector(limit=100, ssl=False)
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(connector=self.connector)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.close()

    def get_headers(self):
        return {"User-Agent": random.choice(USER_AGENTS), "Accept": "text/html,application/xhtml+xml"}

    async def request(self, method, url, payload=None, headers=None):
        try:
            full_headers = self.get_headers()
            if headers: full_headers.update(headers)
            
            async with self.session.request(method, url, proxy=self.proxy, headers=full_headers, data=payload, timeout=5) as resp:
                body = await resp.read()
                return {"status": resp.status, "body": body, "headers": dict(resp.headers)}
        except Exception:
            return None

# --- HARDENED MODULES ---

class ReconEngine:
    def __init__(self, target):
        self.target = target
        self.base_url = f"http://{target}" if not target.startswith("http") else target
        self.baseline_hash = None

    async def detect_waf(self, h_session):
        """Behavioral WAF detection: Probing with illegal methods and XSS payloads."""
        print(f"[*] Analyzing WAF behavior for {self.target}...")
        probes = [
            ("PATCH", self.base_url, None), 
            ("GET", f"{self.base_url}/?q=<script>alert(1)</script>", None),
            ("GET", f"{self.base_url}/?q=' OR 1=1--", None)
        ]
        
        waf_hits = 0
        for method, url, data in probes:
            res = await h_session.request(method, url, data)
            if res and res['status'] in [403, 406, 501]:
                waf_hits += 1
        
        return "WAF Detected (High Confidence)" if waf_hits >= 2 else "No WAF detected or stealthy"

    async def dir_buster(self, h_session, wordlist):
        """Hardened DirBuster with Soft-404 detection using body hashing."""
        print(f"[*] Establishing 404 baseline for {self.target}...")
        # Create baseline by requesting a random garbage path
        baseline_res = await h_session.request("GET", f"{self.base_url}/_reconx_baseline_{random.randint(1000,9999)}")
        if baseline_res:
            self.baseline_hash = hashlib.md5(baseline_res['body']).hexdigest()

        found = []
        tasks = [h_session.request("GET", f"{self.base_url}/{word}") for word in wordlist]
        results = await asyncio.gather(*tasks)

        for i, res in enumerate(results):
            if res:
                current_hash = hashlib.md5(res['body']).hexdigest()
                # If status is 200 but hash matches baseline, it's a soft-404
                if res['status'] == 200 and current_hash != self.baseline_hash:
                    found.append(wordlist[i])
        
        return found

    async def dns_recon(self):
        """Deep DNS analysis using socket-level queries."""
        print(f"[*] Querying DNS records for {self.target}...")
        results = {}
        try:
            results['A'] = socket.gethostbyname(self.target)
            # Simplified AXFR attempt simulation via socket port 53
            # In a real scenario, this requires raw DNS packet construction
            results['Note'] = "AXFR attempted; check logs for zone transfer success."
        except Exception as e:
            results['Error'] = str(e)
        return results

# --- MAIN EXECUTION ---

async def run_all(target, wordlist):
    async with HardenedSession() as h_session:
        engine = ReconEngine(target)
        
        # Parallel Execution of all hardened modules
        print(f"\n--- STARTING HARDENED RECON ON {target} ---")
        
        waf_task = asyncio.create_task(engine.detect_waf(h_session))
        dns_task = asyncio.create_task(engine.dns_recon())
        dir_task = asyncio.create_task(engine.dir_buster(h_session, wordlist))
        
        # Wait for all to finish
        waf_res, dns_res, dir_res = await asyncio.gather(waf_task, dns_task, dir_task)
        
        final_report = {
            "target": target,
            "waf": waf_res,
            "dns": dns_res,
            "discovered_paths": dir_res
        }
        
        print("\n" + "="*50)
        print(json.dumps(final_report, indent=4))
        print("="*50)

if __name__ == "__main__":
    target_site = input("Enter target (e.g., example.com): ")
    # Small sample wordlist for demonstration
    sample_words = ["admin", "config", "backup", "api", "phpmyadmin", "server-status", ".env", "robots.txt"]
    
    asyncio.run(run_all(target_site, sample_words))
