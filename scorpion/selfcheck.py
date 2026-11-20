"""Scorpion.ai self-check — run this on the server where Scorpion will run.

    python3 -m scorpion.selfcheck              # offline: what is configured?
    python3 -m scorpion.selfcheck --live       # also ping Claude + Telegram
    python3 -m scorpion.selfcheck --find-chat-id   # discover your Telegram chat id

It reads the same .env / environment Scorpion does and never prints secrets in
the clear. `--live` makes one tiny Claude request and sends one Telegram test
message, so you can confirm the keys actually work end to end.
"""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .config import load_config
from .scope import Scope

OK = "✓"
NO = "✗"
WARN = "!"


def _line(mark: str, label: str, detail: str = "") -> str:
    return "  [%s] %-22s %s" % (mark, label, detail)


def _check_tools() -> int:
    try:
        from .tools.recon_tools import ALL_TOOLS
        return len(ALL_TOOLS)
    except Exception as exc:  # noqa: BLE001
        print(_line(NO, "tools", "failed to load: %s" % exc))
        return 0


def run(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="scorpion.selfcheck",
                                 description="Verify Scorpion.ai is wired up.")
    ap.add_argument("--live", action="store_true",
                    help="actually ping Claude and send a Telegram test message")
    ap.add_argument("--find-chat-id", action="store_true",
                    help="list Telegram chat ids that have messaged your bot")
    args = ap.parse_args(argv)

    cfg = load_config()
    problems = 0

    print("\n  Scorpion.ai self-check\n")

    # --- scope (the one thing that blocks all scanning) ---
    scope = Scope.from_config(cfg)
    if scope.is_empty:
        print(_line(WARN, "scope", "EMPTY — nothing can be scanned until you "
                                   "set SCORPION_SCOPE"))
        problems += 1
    else:
        print(_line(OK, "scope", scope.describe()))

    # --- brain ---
    if cfg.no_llm:
        print(_line(OK, "brain", "planner mode (SCORPION_NO_LLM=1, no API key used)"))
    elif not cfg.anthropic_api_key:
        print(_line(WARN, "brain", "no ANTHROPIC_API_KEY -> falls back to planner mode"))
    else:
        print(_line(OK, "brain", "Claude key set, model=%s" % cfg.model))
        if args.live:
            try:
                from .brain import Brain
                r = Brain(cfg).complete(
                    system="You are a connectivity probe.",
                    messages=[{"role": "user", "content": "Reply with the single word: pong"}],
                    max_tokens=8)
                if r.get("error"):
                    print(_line(NO, "  live brain ping", r["error"]))
                    problems += 1
                else:
                    print(_line(OK, "  live brain ping", "model replied: %r"
                                % (r.get("text", "")[:40])))
            except Exception as exc:  # noqa: BLE001
                print(_line(NO, "  live brain ping", str(exc)))
                problems += 1

    # --- telegram ---
    from .notify.telegram import Telegram
    tg = Telegram(cfg)
    if not cfg.telegram_token:
        print(_line(WARN, "telegram", "no TELEGRAM_BOT_TOKEN (notifications off)"))
    elif not cfg.telegram_chat_id and not args.find_chat_id:
        print(_line(WARN, "telegram", "token set but no TELEGRAM_CHAT_ID -> run "
                                      "--find-chat-id"))
        problems += 1
    else:
        print(_line(OK, "telegram", "token + chat id set"))
        if args.live:
            sent = tg.send("Scorpion.ai self-check %s — notifications work." % OK)
            print(_line(OK if sent else NO, "  live telegram send",
                        "message delivered" if sent else "send failed (check token/chat id/network)"))
            if not sent:
                problems += 1

    if args.find_chat_id:
        if not cfg.telegram_token:
            print(_line(NO, "find-chat-id", "set TELEGRAM_BOT_TOKEN first"))
            problems += 1
        else:
            print("\n  Looking for chats... (message your bot first, then re-run)")
            try:
                updates = tg.get_updates()
            except Exception as exc:  # noqa: BLE001
                updates = None
                print(_line(NO, "find-chat-id", str(exc)))
                problems += 1
            seen = {}
            for u in (updates or []):
                msg = (u.get("message") or u.get("edited_message")
                       or u.get("channel_post") or {})
                chat = msg.get("chat") or {}
                if chat.get("id") is not None:
                    seen[chat["id"]] = chat.get("username") or chat.get("title") \
                        or chat.get("first_name") or "?"
            if seen:
                for cid, who in seen.items():
                    print(_line(OK, "  chat id", "%s  (%s)" % (cid, who)))
                print("\n  Put one of these in .env as TELEGRAM_CHAT_ID.")
            else:
                print(_line(WARN, "  chat id", "none found — send a message to your "
                                              "bot, then re-run"))

    # --- voice ---
    from .notify.voice import Voice
    v = Voice(cfg)
    if not cfg.voice_enabled:
        print(_line(OK, "voice", "disabled (SCORPION_VOICE=0)"))
    elif v.engine_name:
        print(_line(OK, "voice", "engine: %s" % v.engine_name))
    else:
        print(_line(WARN, "voice", "no local TTS engine (espeak/piper/say) — "
                                   "Telegram voice notes still work"))

    # --- tools ---
    n = _check_tools()
    print(_line(OK if n else NO, "tools", "%d recon tools loaded" % n))
    if not n:
        problems += 1

    print("")
    if problems:
        print("  %d thing(s) need attention above.\n" % problems)
        return 1
    print("  All good. Launch with:  python3 -m scorpion\n")
    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
