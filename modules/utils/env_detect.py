# modules/env_detect.py
"""
ReconX - Environment Detection
Supports: Termux (Android), Kali Linux, WSL.
"""

import os
import platform
import subprocess


def get_environment():
    """Detect current environment."""
    system = platform.system().lower()
    release = platform.release().lower()

    env = {
        "os": system,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "is_termux": False,
        "is_kali": False,
        "is_wsl": False,
        "is_linux": False,
        "is_root": False,
        "has_whois": False,
        "has_dig": False,
        "has_nslookup": False,
        "has_curl": False,
        "has_phonenumbers": False,
        "has_pillow": False,
    }

    # Termux
    if os.environ.get("TERMUX_VERSION") or "com.termux" in os.environ.get("PREFIX", ""):
        env["is_termux"] = True

    # WSL
    if "microsoft" in release or "microsoft" in platform.version().lower():
        env["is_wsl"] = True
    if os.environ.get("WSL_DISTRO_NAME"):
        env["is_wsl"] = True

    # Kali
    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release") as f:
                content = f.read().lower()
                if "kali" in content:
                    env["is_kali"] = True
    except Exception:
        pass

    env["is_linux"] = system == "linux"

    # Root
    try:
        env["is_root"] = os.geteuid() == 0
    except AttributeError:
        pass

    # Tools
    for tool in ["whois", "dig", "nslookup", "curl"]:
        try:
            r = subprocess.run(["which", tool], capture_output=True, timeout=2)
            env[f"has_{tool.replace('-', '_')}"] = r.returncode == 0
        except Exception:
            pass

    # Python libs
    try:
        import phonenumbers  # noqa
        env["has_phonenumbers"] = True
    except ImportError:
        pass

    try:
        from PIL import Image  # noqa
        env["has_pillow"] = True
    except ImportError:
        pass

    return env


def get_env_label(env):
    """Human-readable environment label."""
    if env["is_termux"]:
        return "Termux (Android)"
    if env["is_wsl"]:
        distro = os.environ.get("WSL_DISTRO_NAME", "WSL")
        return f"WSL ({distro})"
    if env["is_kali"]:
        return "Kali Linux"
    if env["is_linux"]:
        return "Linux"
    return platform.system()


def print_env_info(env):
    """Print environment summary."""
    label = get_env_label(env)

    print(f"\n[*] Environment: {label}")
    print(f"[*] Python:      {env['python']}")
    print(f"[*] Root:        {'YES' if env['is_root'] else 'no'}")

    tools = []
    if env["has_whois"]:
        tools.append("whois")
    if env["has_dig"]:
        tools.append("dig")
    if env["has_nslookup"]:
        tools.append("nslookup")
    if env["has_curl"]:
        tools.append("curl")

    if tools:
        print(f"[*] Tools:       {', '.join(tools)}")

    libs = []
    if env["has_phonenumbers"]:
        libs.append("phonenumbers")
    if env["has_pillow"]:
        libs.append("Pillow")

    if libs:
        print(f"[*] Libraries:   {', '.join(libs)}")


if __name__ == "__main__":
    env = get_environment()
    print_env_info(env)
