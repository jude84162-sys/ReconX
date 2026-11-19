# modules/web/live_probe.py
"""ReconX - Live Host Prober (httpx / httprobe clone, no external tools).

Turns a list of hostnames (e.g. subdomain_enum results) into the subset that
actually serves HTTP(S), with the metadata httpx prints: status code, title,
server, content-type, length, redirect chain and TLS protocol.

Stdlib only. Bare hostnames are tried over HTTPS first, then HTTP.
"""

import html
import http.client
import json
import re
import socket
import ssl
import sys
import time
import urllib.parse
import concurrent.futures
from datetime import datetime

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

BODY_LIMIT = 200_000
MAX_REDIRECTS = 5
REDIRECT_CODES = {301, 302, 303, 307, 308}

C_CYAN = "\033[96m"
C_GREEN = "\033[92m"
C_GRAY = "\033[90m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_RST = "\033[0m"

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


# ============================================================
# Single request / redirect chain
# ============================================================

def _ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _request(url, timeout=6):
    """One HTTP GET. Returns dict with status/headers/body/tls or raises."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme: {parts.scheme}")
    if not parts.hostname:
        raise ValueError("missing hostname")

    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    if parts.scheme == "https":
        conn = http.client.HTTPSConnection(
            parts.hostname, parts.port or 443, timeout=timeout, context=_ssl_context()
        )
    else:
        conn = http.client.HTTPConnection(
            parts.hostname, parts.port or 80, timeout=timeout
        )

    started = time.time()
    try:
        conn.request("GET", path, headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "identity",
            "Connection": "close",
        })
        resp = conn.getresponse()
        body = resp.read(BODY_LIMIT)
        headers = {k.lower(): v for k, v in resp.getheaders()}
        elapsed = int((time.time() - started) * 1000)

        tls = None
        sock = getattr(conn, "sock", None)
        if parts.scheme == "https" and sock is not None:
            try:
                cipher = sock.cipher()
                tls = {
                    "version": sock.version(),
                    "cipher": cipher[0] if cipher else None,
                }
            except Exception:
                tls = None
        conn.close()

        return {
            "url": url,
            "status": resp.status,
            "reason": resp.reason,
            "headers": headers,
            "body": body,
            "elapsed_ms": elapsed,
            "tls": tls,
        }
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _follow(url, timeout=6, follow_redirects=True):
    """Request a URL, optionally following redirects. Returns (final, chain)."""
    chain = []
    current = url

    for _ in range(MAX_REDIRECTS + 1):
        resp = _request(current, timeout=timeout)
        entry = {
            "url": current,
            "status": resp["status"],
            "location": resp["headers"].get("location"),
        }
        chain.append(entry)

        if (follow_redirects and resp["status"] in REDIRECT_CODES
                and entry["location"]):
            nxt = urllib.parse.urljoin(current, entry["location"])
            if urllib.parse.urlsplit(nxt).scheme not in ("http", "https"):
                break
            current = nxt
            continue
        return resp, chain

    return resp, chain


# ============================================================
# Helpers
# ============================================================

def extract_title(body):
    if not body:
        return None
    try:
        text = body.decode("utf-8", errors="ignore")
    except Exception:
        return None
    match = _TITLE_RE.search(text)
    if not match:
        return None
    title = html.unescape(re.sub(r"\s+", " ", match.group(1))).strip()
    return title[:120] or None


def _candidate_urls(target):
    """Build probe URLs: explicit scheme is respected, otherwise https then http."""
    target = (target or "").strip().rstrip("/")
    if not target:
        return []

    if "://" in target:
        return [target]
    return [f"https://{target}", f"http://{target}"]


def _dedupe(targets):
    seen = set()
    out = []
    for t in targets or []:
        host = normalize_host(t)
        if host and host.lower() not in seen:
            seen.add(host.lower())
            out.append(host)
    return out


def normalize_host(entry):
    """Accept a URL string or a subdomain_enum dict; return a host/URL string."""
    if isinstance(entry, dict):
        entry = entry.get("url") or entry.get("hostname") or entry.get("host") or ""
    entry = str(entry or "").strip()
    if entry.startswith(("http://", "https://")):
        return entry
    return entry.split("/")[0].strip()


# ============================================================
# Probe
# ============================================================

def probe_host(target, timeout=6, follow_redirects=True):
    """Probe one host over HTTPS then HTTP. Always returns a dict."""
    host = normalize_host(target)
    result = {
        "input": host,
        "host": urllib.parse.urlsplit(
            host if "://" in host else f"//{host}"
        ).netloc or host,
        "alive": False,
        "url": None,
        "status": None,
        "title": None,
        "server": None,
        "content_type": None,
        "content_length": None,
        "redirects": [],
        "final_url": None,
        "tls": None,
        "elapsed_ms": None,
        "errors": [],
    }
    if not host:
        result["errors"].append("empty target")
        return result

    for url in _candidate_urls(host):
        try:
            resp, chain = _follow(url, timeout=timeout, follow_redirects=follow_redirects)
        except (socket.timeout, TimeoutError):
            result["errors"].append(f"{url}: timeout")
            continue
        except ssl.SSLError as e:
            result["errors"].append(f"{url}: tls {str(e)[:80]}")
            continue
        except ConnectionError:
            result["errors"].append(f"{url}: connection refused/reset")
            continue
        except Exception as e:
            result["errors"].append(f"{url}: {str(e)[:100]}")
            continue

        headers = resp["headers"]
        body_text_len = len(resp["body"]) if resp["body"] else 0
        content_length = headers.get("content-length")

        result.update({
            "alive": True,
            "url": url,
            "status": resp["status"],
            "title": extract_title(resp["body"]),
            "server": headers.get("server"),
            "content_type": headers.get("content-type", "").split(";")[0] or None,
            "content_length": content_length if content_length else str(body_text_len),
            # every hop except the final response
            "redirects": chain[:-1] if len(chain) > 1 else [],
            "final_url": chain[-1]["url"],
            "tls": resp["tls"],
            "elapsed_ms": resp["elapsed_ms"],
        })
        return result

    return result


def probe_hosts(targets, threads=20, timeout=6, follow_redirects=True, verbose=False):
    """Probe many hosts in parallel and return the httpx-style summary."""
    hosts = _dedupe(targets)
    result = {
        "timestamp": datetime.now().isoformat(),
        "total": len(hosts),
        "alive": 0,
        "dead": 0,
        "results": [],
    }
    if not hosts:
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        futures = {
            ex.submit(probe_host, h, timeout, follow_redirects): h for h in hosts
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                entry = future.result()
            except Exception as e:
                entry = {
                    "input": futures[future], "alive": False,
                    "errors": [str(e)[:100]],
                }
            result["results"].append(entry)
            if entry.get("alive"):
                result["alive"] += 1
            else:
                result["dead"] += 1
            if verbose and entry.get("alive"):
                print(f"      {C_GREEN}✓{C_RST} {entry['url']:<55} [{entry['status']}]")

    result["results"].sort(
        key=lambda r: (not r.get("alive"), r.get("status") or 0, r.get("input") or "")
    )
    return result


def live_hosts(probe_result):
    """Return only the alive entries from a probe result."""
    return [r for r in probe_result.get("results", []) if r.get("alive")]


# ============================================================
# Report
# ============================================================

def print_probe_report(result, limit=50):
    print("\n" + "=" * 78)
    print("  Live Host Prober (httpx / httprobe clone) — ReconX")
    print("=" * 78)
    print(f"\n[*] Probed: {result.get('total', 0)}  "
          f"alive: {result.get('alive', 0)}  dead: {result.get('dead', 0)}")

    alive = live_hosts(result)
    if alive:
        print(f"\n[+] Live hosts:")
        print(f"    {'URL':<48} {'STATUS':>6}  {'SERVER':<18} TITLE")
        for r in alive[:limit]:
            url = (r.get("final_url") or r.get("url") or "")[:47]
            server = (r.get("server") or "-")[:17]
            title = (r.get("title") or "-")[:34]
            print(f"    {url:<48} {r.get('status'):>6}  {server:<18} {title}")
        if len(alive) > limit:
            print(f"    ... and {len(alive) - limit} more")

        redirects = [r for r in alive if r.get("redirects")]
        if redirects:
            print(f"\n[*] Redirects:")
            for r in redirects[:10]:
                hop = r["redirects"][0]
                print(f"    {r['url']} -> {hop.get('location')}")

    dead = [r for r in result.get("results", []) if not r.get("alive")]
    if dead:
        print(f"\n[-] No HTTP response ({len(dead)}):")
        for r in dead[:10]:
            reason = (r.get("errors") or ["no response"])[-1]
            print(f"    ✗ {r.get('input', '?'):<45} {reason[:60]}")
        if len(dead) > 10:
            print(f"    ... and {len(dead) - 10} more")

    print("\n" + "=" * 78 + "\n")


def save_probe_report(result, outdir="outputs"):
    from pathlib import Path
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"live_hosts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False, default=str)
    return path


# ============================================================
# CLI
# ============================================================

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="ReconX Live Host Prober (httpx / httprobe clone)"
    )
    parser.add_argument("hosts", nargs="*", help="Hostnames or URLs")
    parser.add_argument("-f", "--file", help="File with one host per line")
    parser.add_argument("--json", action="store_true", help="Save JSON report")
    parser.add_argument("--threads", type=int, default=20)
    parser.add_argument("--timeout", type=int, default=6)
    parser.add_argument("--no-follow", action="store_true",
                        help="Do not follow redirects")
    args = parser.parse_args()

    targets = list(args.hosts)
    if args.file:
        try:
            with open(args.file, encoding="utf-8", errors="ignore") as fh:
                targets += [l.strip() for l in fh
                            if l.strip() and not l.startswith("#")]
        except OSError as e:
            print(f"  ✗ Can't read {args.file}: {e}")
            return 1

    if not targets:
        print("Usage: python -m modules.web.live_probe <host> [...] | -f hosts.txt")
        return 1

    print(f"\n  [*] Probing {len(targets)} host(s) with {args.threads} threads...")
    result = probe_hosts(
        targets, threads=args.threads, timeout=args.timeout,
        follow_redirects=not args.no_follow, verbose=True,
    )
    print_probe_report(result)

    if args.json:
        print(f"  ✓ Saved: {save_probe_report(result)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
