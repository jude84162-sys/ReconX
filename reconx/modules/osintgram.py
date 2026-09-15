"""Wrapper for the external Osintgram tool.

⚠️ LEGAL: Only use against targets you own or have written authorization.
Instagram scraping may violate Instagram ToS. Users are responsible for
compliance with CFAA and GDPR. ReconX never stores credentials.
"""

import os
import subprocess


class OsintgramModule:
    def run(self, target: str, command: str = "info", timeout: int = 120) -> dict:
        path = os.environ.get("OSINTGRAM_PATH")
        if not path:
            return {"error": "Set OSINTGRAM_PATH env var"}
        try:
            completed = subprocess.run(
                ["python3", "main.py", target, command],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {"target": target, "command": command, "error": f"Osintgram timed out after {timeout} seconds"}
        return {
            "target": target,
            "command": command,
            "output": completed.stdout.strip(),
            "error": completed.stderr.strip() if completed.returncode else None,
        }
