#!/usr/bin/env python3
"""
ReconX Attack Surface Auto-Fixer
--------------------------------
Audits the Attack Surface Engine integration and repairs whatever is broken.
Idempotent: safe to run as many times as you like, it only touches what is
actually missing or malformed.

It checks and fixes two things:

  1. modules/web/attack_surface.py
       - module present and syntactically valid
       - Tor SOCKS5 handler builds a real response object (the old
         `urllib.response.addcloseiso(...)` call does not exist in the stdlib)
       - `import io` present when the response body is wrapped in BytesIO

  2. cli.py
       - menu entry for [26] under "Advanced Attack Surface"
       - "26" registered in the main_menu handlers dict
       - attack_surface_menu() defined
       - module listed in show_env()'s health check

Usage:
    python fix_attack_surface.py            # audit, then auto-fix
    python fix_attack_surface.py --check    # audit only, non-zero exit if broken
"""

import ast
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
CLI = ROOT / "cli.py"
ENGINE = ROOT / "modules" / "web" / "attack_surface.py"

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"

MENU_OPTION = "26"

# ------------------------------------------------------------
# Patch templates
# ------------------------------------------------------------

MENU_BLOCK = [
    '        print(f"{C.BOLD}{C.MAGENTA}  ── Advanced Attack Surface ──{C.RESET}")',
    f'        print(f"  {{C.RED}}[{MENU_OPTION}]{{C.RESET}} 🚀 Attack Surface & Vuln Fuzzer (crt.sh + Wayback + Leaks)")',
    '        print()',
]

HANDLER_ENTRY = f'            "{MENU_OPTION}": attack_surface_menu,'

ENV_ENTRY = '            ("web.attack_surface", "🚀"),'

MENU_FUNCTION = '''def attack_surface_menu():
    clear()
    banner()
    section("🚀 Attack Surface & Vuln Fuzzer")

    print(f"  {C.GRAY}crt.sh subdomains + Wayback endpoints + param triage + leak fuzzing{C.RESET}")
    print(f"  {C.RED}⚠ Active fuzzing — use only on authorized targets{C.RESET}\\n")

    target = prompt("  Target domain (e.g. example.com)")
    if not target:
        print(f"{C.RED}  [!] Target cannot be empty.{C.RESET}")
        pause()
        return

    use_tor = confirm("  Route through Tor SOCKS5h (127.0.0.1:9050)?")

    print(f"\\n{C.YELLOW}  ⚡ Building attack surface for {target}...{C.RESET}\\n")

    try:
        from modules.web.attack_surface import AttackSurfaceEngine
        engine = AttackSurfaceEngine(target=target, use_tor=use_tor)
        engine.run_recon_pipeline()
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")
        import traceback
        traceback.print_exc()

    pause()


'''

# Anchors used to place a patch. Each is a literal line already in cli.py.
ANCHOR_MENU = '        print(f"{C.BOLD}{C.MAGENTA}  ── Actions ──{C.RESET}")'
ANCHOR_DICT = '            "i": show_env,'
# Preferred spot matches the shipped layout; show_env() is the fallback.
ANCHOR_FUNC_CANDIDATES = ("def fast_web_recon_menu():", "def show_env():")
# Insert before report.html_report so the entry lands right after web_monitor,
# matching the shipped ordering in show_env().
ANCHOR_ENV = '            ("report.html_report", "📊"),'


class Fixer:
    def __init__(self, check_only=False):
        self.check_only = check_only
        self.issues = 0
        self.fixed = 0
        self.warnings = 0

    # ---------------- reporting ----------------

    def ok(self, msg):
        print(f"  {GREEN}[✓]{RESET} {msg}")

    def bad(self, msg):
        self.issues += 1
        print(f"  {RED}[✗]{RESET} {msg}")

    def fix(self, msg):
        self.fixed += 1
        print(f"  {BLUE}[FIXED]{RESET} {msg}")

    def warn(self, msg):
        self.warnings += 1
        print(f"  {YELLOW}[⚠]{RESET} {msg}")

    # ---------------- helpers ----------------

    @staticmethod
    def read(path):
        with open(path, "r", encoding="utf-8", newline="") as fh:
            return fh.read()

    @staticmethod
    def write(path, text):
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)

    @staticmethod
    def newline_of(text):
        return "\r\n" if "\r\n" in text else "\n"

    def backup(self, path):
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest = path.with_name(f"{path.name}.bak_{stamp}")
        shutil.copy2(path, dest)
        return dest

    @staticmethod
    def insert_before(text, anchor, block, nl):
        """Insert `block` (a list of lines) immediately before the anchor line."""
        if anchor not in text:
            return None
        idx = text.index(anchor)
        return text[:idx] + nl.join(block) + nl + text[idx:]

    # ---------------- engine checks ----------------

    def check_engine(self):
        print(f"\n{BLUE}[-]{RESET} Auditing modules/web/attack_surface.py")

        if not ENGINE.exists():
            self.bad(f"missing file: {ENGINE.relative_to(ROOT)}")
            self.warn("cannot recreate the engine automatically — restore it from git/backup")
            return
        self.ok(f"engine present: {ENGINE.relative_to(ROOT)}")

        text = self.read(ENGINE)
        nl = self.newline_of(text)
        changed = False

        # The stdlib has no urllib.response.addcloseiso — this call crashed
        # every Tor request. Rewrite it to a real BytesIO wrapper.
        if "addcloseiso" in text:
            self.bad("Tor handler calls urllib.response.addcloseiso(), which does not exist")
            if not self.check_only:
                text = re.sub(
                    r"urllib\.response\.addcloseiso\(\s*BytesIO_wrapper\(\s*(\w+)\s*\)\s*\)",
                    r"io.BytesIO(\1)",
                    text,
                )
                text = re.sub(
                    r"urllib\.response\.addcloseiso\(\s*([^()]*?)\s*\)",
                    r"io.BytesIO(\1)",
                    text,
                )
                changed = True
                self.fix("Tor handler now wraps the body in io.BytesIO")
        else:
            self.ok("Tor handler builds a valid response object")

        # Drop the hand-rolled shim once nothing references it.
        if "class BytesIO_wrapper" in text:
            body_after = text.split("class BytesIO_wrapper", 1)[1]
            if "BytesIO_wrapper(" not in body_after:
                self.bad("dead BytesIO_wrapper shim still defined")
                if not self.check_only:
                    text = re.sub(
                        r"class BytesIO_wrapper:.*?(?=^class |^if __name__)",
                        "",
                        text,
                        flags=re.S | re.M,
                    )
                    text = re.sub(r"\n{3,}", nl + nl, text)
                    changed = True
                    self.fix("removed unused BytesIO_wrapper shim")

        # BytesIO needs its import.
        if "io.BytesIO" in text and not re.search(r"^import io$", text, re.M):
            self.bad("io.BytesIO used but `import io` missing at top of file")
            if not self.check_only:
                text = re.sub(r"^import os$", "import io" + nl + "import os", text, count=1, flags=re.M)
                changed = True
                self.fix("added `import io`")
        elif "io.BytesIO" in text:
            self.ok("`import io` present")

        if changed:
            self.backup(ENGINE)
            self.write(ENGINE, text)

        # Syntax gate after any rewrite.
        try:
            ast.parse(self.read(ENGINE), filename=str(ENGINE))
            self.ok("engine parses cleanly")
        except SyntaxError as e:
            self.bad(f"engine syntax error: {e}")

        if "attack_surface" in str(ENGINE) and not re.search(r"^class AttackSurfaceEngine", self.read(ENGINE), re.M):
            self.bad("AttackSurfaceEngine class not found")

    # ---------------- cli checks ----------------

    def check_cli(self):
        print(f"\n{BLUE}[-]{RESET} Auditing cli.py")

        if not CLI.exists():
            self.bad("missing file: cli.py")
            return

        text = self.read(CLI)
        nl = self.newline_of(text)
        before = text

        # 1. Menu entry
        if f"[{MENU_OPTION}]" in text and "Attack Surface & Vuln Fuzzer" in text:
            self.ok(f"menu entry [{MENU_OPTION}] present")
        elif f'"{MENU_OPTION}":' in text or re.search(rf"\[{MENU_OPTION}\]", text):
            self.bad(f"option [{MENU_OPTION}] already taken by another tool — pick a free number")
        else:
            self.bad(f"menu entry [{MENU_OPTION}] missing")
            if not self.check_only:
                patched = self.insert_before(text, ANCHOR_MENU, MENU_BLOCK, nl)
                if patched is None:
                    patched = self.insert_before(text, "        choice = input(", MENU_BLOCK, nl)
                if patched is None:
                    self.warn("could not find the menu anchor — add the [26] block by hand")
                else:
                    text = patched
                    self.fix("inserted the Advanced Attack Surface menu block")

        # 2. Handler registration
        if HANDLER_ENTRY.strip() in text:
            self.ok(f"handler dict maps [{MENU_OPTION}] -> attack_surface_menu")
        else:
            self.bad(f"main_menu handlers dict has no [{MENU_OPTION}] entry")
            if not self.check_only:
                patched = self.insert_before(text, ANCHOR_DICT, [HANDLER_ENTRY], nl)
                if patched is None:
                    self.warn(f"could not find the handlers dict — register [{MENU_OPTION}] by hand")
                else:
                    text = patched
                    self.fix("registered attack_surface_menu in the handlers dict")

        # 3. Handler function
        if "def attack_surface_menu():" in text:
            self.ok("attack_surface_menu() defined")
        else:
            self.bad("attack_surface_menu() is not defined")
            if not self.check_only:
                block = MENU_FUNCTION.split("\n")
                patched = None
                for anchor in ANCHOR_FUNC_CANDIDATES:
                    patched = self.insert_before(text, anchor, block, nl)
                    if patched is not None:
                        break
                if patched is None:
                    self.warn("could not find show_env() — add attack_surface_menu() by hand")
                else:
                    text = patched
                    self.fix("inserted attack_surface_menu()")

        # 4. Lazy import inside the handler (project convention: every handler
        #    imports its module lazily, so the engine never loads at startup).
        if "from modules.web.attack_surface import AttackSurfaceEngine" in text:
            self.ok("handler imports AttackSurfaceEngine lazily")
        else:
            self.bad("handler does not import AttackSurfaceEngine")
            self.warn("re-run after restoring attack_surface_menu(), or add the import by hand")

        # 5. show_env health listing
        if ENV_ENTRY.strip() in text:
            self.ok("show_env() lists web.attack_surface")
        else:
            self.bad("web.attack_surface missing from show_env() module list")
            if not self.check_only:
                patched = self.insert_before(text, ANCHOR_ENV, [ENV_ENTRY], nl)
                if patched is None:
                    self.warn("could not find the show_env module list — add it by hand")
                else:
                    text = patched
                    self.fix("added web.attack_surface to show_env()")

        if text != before:
            dest = self.backup(CLI)
            self.write(CLI, text)
            print(f"  {YELLOW}↳ backup: {dest.name}{RESET}")

        # Syntax gate after any rewrite.
        try:
            ast.parse(self.read(CLI), filename=str(CLI))
            self.ok("cli.py parses cleanly")
        except SyntaxError as e:
            self.bad(f"cli.py syntax error: {e}")

    # ---------------- runtime smoke test ----------------

    def smoke_test(self):
        print(f"\n{BLUE}[-]{RESET} Runtime smoke test")

        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))

        try:
            engine_mod = __import__("modules.web.attack_surface", fromlist=["AttackSurfaceEngine"])
            assert hasattr(engine_mod, "AttackSurfaceEngine")
            assert hasattr(engine_mod, "TorSOCKS5Handler")
            self.ok("AttackSurfaceEngine + TorSOCKS5Handler import")
        except Exception as e:
            self.bad(f"engine import failed: {e}")
            return

        try:
            cli_mod = __import__("cli", fromlist=["attack_surface_menu"])
            if callable(getattr(cli_mod, "attack_surface_menu", None)):
                self.ok("cli.attack_surface_menu is callable")
            else:
                self.bad("cli.attack_surface_menu is missing or not callable")
        except Exception as e:
            self.bad(f"cli import failed: {e}")

    # ---------------- driver ----------------

    def run(self):
        print(f"\n{BLUE}╔══════════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{BLUE}║          ReconX Attack Surface Auto-Fixer / Auditor             ║{RESET}")
        print(f"{BLUE}╚══════════════════════════════════════════════════════════════════╝{RESET}")
        print(f"  Mode: {'CHECK ONLY' if self.check_only else 'CHECK + AUTO-FIX'}")

        self.check_engine()
        self.check_cli()
        self.smoke_test()

        print(f"\n{BLUE}══════════════════════════════════════════════════════════════════{RESET}")
        print(f"  Issues found:  {self.issues}")
        print(f"  Auto-fixed:    {self.fixed}")
        print(f"  Warnings:      {self.warnings}")

        remaining = self.issues - self.fixed
        if remaining > 0 and not self.check_only:
            print(f"  {YELLOW}Still needs attention: {remaining}{RESET}")
        elif self.issues == 0:
            print(f"  {GREEN}Everything is wired correctly.{RESET}")
        print(f"{BLUE}══════════════════════════════════════════════════════════════════{RESET}\n")

        return 0 if self.issues == 0 else (1 if self.check_only else (0 if remaining <= 0 else 1))


def main():
    check_only = "--check" in sys.argv[1:]
    if "--help" in sys.argv[1:] or "-h" in sys.argv[1:]:
        print(__doc__.strip())
        return 0
    sys.exit(Fixer(check_only=check_only).run())


if __name__ == "__main__":
    main()
