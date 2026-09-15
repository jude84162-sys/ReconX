"""Adapters for optional ReconX companion tools.

External tools are intentionally not cloned or installed automatically. This
keeps normal ReconX execution safe and makes the dependency boundary explicit.
"""

import os
import subprocess
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_GITGHOST_PATH = REPO_ROOT.parent / "gitghost"


def _configured_path(env_name: str, default: Path) -> Path:
    configured = os.environ.get(env_name)
    return Path(configured).expanduser() if configured else default


def _github_token_for_child() -> str | None:
    """Resolve a GitHub token, decrypting the protected form in memory."""
    encrypted_token = os.environ.get("GITHUB_ENCRYPTED_TOKEN")
    encryption_key = os.environ.get("GITHUB_ENCRYPTION_KEY")

    if encrypted_token or encryption_key:
        if not encrypted_token or not encryption_key:
            raise ValueError(
                "Set both GITHUB_ENCRYPTION_KEY and GITHUB_ENCRYPTED_TOKEN, "
                "or use GITHUB_TOKEN."
            )
        try:
            return Fernet(encryption_key.encode("ascii")).decrypt(
                encrypted_token.encode("ascii")
            ).decode("utf-8")
        except (ValueError, UnicodeEncodeError, InvalidToken) as exc:
            raise ValueError("The encrypted GitHub token could not be decrypted.") from exc

    return os.environ.get("GITHUB_TOKEN")


def run_gitghost(target: str | None, extra_args=None, timeout: int = 600) -> dict:
    """Run the adjacent GitGhost checkout against a target."""
    tool_path = _configured_path("GITGHOST_PATH", DEFAULT_GITGHOST_PATH)
    if not tool_path.is_dir():
        raise FileNotFoundError(
            f"GitGhost was not found at {tool_path}. Clone it from "
            "https://github.com/cy3erm/gitghost or set GITGHOST_PATH."
        )

    command = [sys.executable, "-m", "gitghost"]
    if target:
        command.append(target)
    command.extend(extra_args or [])
    child_environment = os.environ.copy()
    token = _github_token_for_child()
    if token:
        child_environment["GITHUB_TOKEN"] = token
    completed = subprocess.run(
        command,
        cwd=tool_path,
        check=False,
        timeout=timeout,
        env=child_environment,
    )
    return {"target": target, "returncode": completed.returncode}


def run_tikosint(target: str | None = None, timeout: int = 600) -> dict:
    """Run TikOsint when a valid local checkout and entry point are available."""
    configured = os.environ.get("TIKOSINT_PATH")
    if not configured:
        raise FileNotFoundError(
            "TikOsint is unavailable: https://github.com/cy3erm/TikOsint.git "
            "currently returns 404. Set TIKOSINT_PATH to a valid checkout "
            "once the repository is available."
        )

    tool_path = Path(configured).expanduser()
    if not tool_path.is_dir():
        raise FileNotFoundError(f"TIKOSINT_PATH is not a directory: {tool_path}")

    candidates = ("TikOsint.py", "tikosint.py", "main.py")
    script = next((tool_path / name for name in candidates if (tool_path / name).is_file()), None)
    if script is None:
        raise FileNotFoundError(
            f"No supported TikOsint entry point found in {tool_path}; expected one of {', '.join(candidates)}."
        )

    command = [sys.executable, str(script)]
    if target:
        command.append(target)
    completed = subprocess.run(command, cwd=tool_path, check=False, timeout=timeout)
    return {"target": target, "returncode": completed.returncode}
