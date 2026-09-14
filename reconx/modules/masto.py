"""Mastodon CLI wrapper.

⚠️ LEGAL: Only use against targets you own or have written authorization.
Instagram scraping may violate Instagram ToS. Users are responsible for
compliance with CFAA and GDPR.
"""

import json
import shutil
import subprocess


class MastoModule:
    def run(self, handle: str, timeout: int = 30) -> dict:
        if shutil.which("masto") is None:
            return {"error": "Install: npm i -g masto"}
        try:
            completed = subprocess.run(
                ["masto", "accounts", "lookup", handle, "--json"],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if completed.returncode != 0:
                return {"error": completed.stderr.strip() or "masto command failed"}
            return json.loads(completed.stdout)
        except subprocess.TimeoutExpired:
            return {"error": f"masto timed out after {timeout} seconds"}
        except json.JSONDecodeError:
            return {"error": "masto returned invalid JSON"}
