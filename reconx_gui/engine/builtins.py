"""Self-contained scanners (stdlib only).

Every function has the signature:  fn(params: dict, log, cancel) -> dict
  log(str)            -> stream a line to the live console
  cancel              -> threading.Event; check cancel.is_set() in loops
Return dict shape:
  {"summary": str, "findings": [finding...], "data": {...}}
  finding = {"title","severity","detail","evidence"}  severity in
            info|low|medium|high|critical

These power ReconX-GUI's "standalone" mode. When the full ReconX `modules/`
package is present next to the app, the bridge prefers those richer engines.
All active checks use benign probes; the GUI gates them behind an explicit
authorization confirmation.
"""
from __future__ import annotations

import re
import ssl
import json
import socket
import concurrent.futures as cf
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from . import http_client as hc

SEV = ("info", "low", "medium", "high", "critical")


def _f(title, severity, detail="", evidence=""):
    return {"title": title, "severity": severity, "detail": detail, "evidence": evidence}


def _title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:160] if m else ""


# ----------------------------------------------------------------- DNS / DoH
def _doh(name: str, rtype: str):
    """Resolve via Google DoH JSON (stdlib urllib). Returns list of strings."""
    r = hc.request(f"https://dns.google/resolve?name={name}&type={rtype}", timeout=8)
    out = []
    if r.ok and r.body:
        try:
            for ans in (json.loads(r.body).get("Answer") or []):
                out.append(str(ans.get("data", "")).strip())
        except Exception:
            pass
    return out


def dns_deep(params, log, cancel):
    domain = hc.host_of(params.get("domain", "")) or params.get("domain", "").strip()
    if not domain:
        return {"summary": "no domain", "findings": []}
    data, findings = {}, []
    log(f"[*] DNS deep recon for {domain}")

    # A / AAAA via system resolver (fast, offline-capable)
    try:
        infos = socket.getaddrinfo(domain, None)
        a = sorted({i[4][0] for i in infos if ":" not in i[4][0]})
        aaaa = sorted({i[4][0] for i in infos if ":" in i[4][0]})
        data["A"], data["AAAA"] = a, aaaa
        for ip in a:
            log(f"    A     {ip}")
        for ip in aaaa:
            log(f"    AAAA  {ip}")
    except Exception as e:
        log(f"    [!] system resolve failed: {e}")

    for rt in ("CNAME", "MX", "NS", "TXT", "SOA", "CAA"):
        if cancel.is_set():
            break
        vals = _doh(domain, rt)
        if vals:
            data[rt] = vals
            for v in vals:
                log(f"    {rt:5} {v}")
    # findings
    if not data.get("CAA"):
        findings.append(_f("No CAA record", "info",
                           "No CAA record restricts which CAs may issue certs."))
    spf = [t for t in data.get("TXT", []) if "v=spf1" in t.lower()]
    if not spf:
        findings.append(_f("No SPF record", "low",
                           "Missing SPF TXT record — email spoofing surface."))
    if not any("dmarc" in t.lower() for t in _doh("_dmarc." + domain, "TXT")):
        findings.append(_f("No DMARC record", "low",
                           "Missing _dmarc TXT record — email spoofing surface."))
    return {"summary": f"{len(data)} record types resolved", "findings": findings, "data": data}


# --------------------------------------------------------------- subdomains
def subdomain_enum(params, log, cancel):
    domain = hc.host_of(params.get("domain", "")) or params.get("domain", "").strip()
    if not domain:
        return {"summary": "no domain", "findings": []}
    log(f"[*] crt.sh certificate transparency for {domain}")
    subs = set()
    r = hc.request(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=25)
    if r.ok and r.body:
        try:
            for row in json.loads(r.body):
                for nm in str(row.get("name_value", "")).splitlines():
                    nm = nm.strip().lstrip("*.").lower()
                    if nm.endswith(domain):
                        subs.add(nm)
        except Exception as e:
            log(f"    [!] parse error: {e}")
    else:
        log(f"    [!] crt.sh returned status {r.status} {r.error}")
    subs = sorted(subs)
    for s in subs[:400]:
        log(f"    {s}")
    if len(subs) > 400:
        log(f"    ... and {len(subs) - 400} more")
    return {"summary": f"{len(subs)} unique subdomains (crt.sh)",
            "findings": [], "data": {"subdomains": subs}}


# ---------------------------------------------------------------- port scan
_PRESETS = {
    "common": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993,
               995, 1723, 3306, 3389, 5900, 8080],
    "web": [80, 81, 443, 591, 2082, 2087, 2095, 2096, 3000, 4443, 5000, 7001,
            8000, 8008, 8080, 8081, 8088, 8443, 8834, 8888, 9000, 9090, 9443],
    "db": [1433, 1521, 3306, 5432, 6379, 7000, 9042, 9200, 11211, 27017, 27018, 5984],
    "top100": [7, 20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 179,
               389, 443, 445, 465, 514, 587, 636, 993, 995, 1025, 1433, 1521,
               1723, 2049, 2082, 3128, 3306, 3389, 5060, 5432, 5900, 5985, 6379,
               8000, 8008, 8080, 8443, 8888, 9090, 9200, 9443, 10000, 11211, 27017],
}


def port_scan(params, log, cancel):
    target = hc.host_of(params.get("target", "")) or params.get("target", "").strip()
    preset = (params.get("preset") or "common").strip()
    if params.get("ports"):
        ports = _parse_ports(params["ports"])
    else:
        ports = _PRESETS.get(preset, _PRESETS["common"])
    try:
        ip = socket.gethostbyname(target)
    except Exception as e:
        return {"summary": f"resolve failed: {e}", "findings": []}
    log(f"[*] Scanning {len(ports)} ports on {target} ({ip})")
    open_ports, done = [], 0

    def probe(p):
        if cancel.is_set():
            return None
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        try:
            if s.connect_ex((ip, p)) == 0:
                banner = ""
                try:
                    s.settimeout(1.0)
                    banner = s.recv(80).decode("latin-1", "replace").strip()
                except Exception:
                    pass
                return (p, banner)
        except Exception:
            pass
        finally:
            s.close()
        return None

    with cf.ThreadPoolExecutor(max_workers=100) as ex:
        for res in ex.map(probe, ports):
            done += 1
            if res:
                p, banner = res
                open_ports.append({"port": p, "banner": banner})
                log(f"    [+] {p:>5}/tcp OPEN  {('· ' + banner) if banner else ''}")
    findings = []
    risky = {23: "Telnet", 21: "FTP", 3389: "RDP", 5900: "VNC",
             6379: "Redis (often no auth)", 9200: "Elasticsearch", 27017: "MongoDB",
             11211: "Memcached", 3306: "MySQL", 5432: "Postgres"}
    for op in open_ports:
        if op["port"] in risky:
            findings.append(_f(f"Exposed {risky[op['port']]} on :{op['port']}",
                               "medium", "Sensitive service reachable.",
                               op.get("banner", "")))
    return {"summary": f"{len(open_ports)}/{len(ports)} ports open",
            "findings": findings, "data": {"ip": ip, "open": open_ports}}


def _parse_ports(spec):
    ports = set()
    for part in str(spec).replace(" ", "").split(","):
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                ports.update(range(int(a), int(b) + 1))
            except Exception:
                pass
        elif part.isdigit():
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


# ------------------------------------------------------------ fingerprint
_TECH = [
    ("Server", r"(nginx|apache|iis|caddy|litespeed|openresty|cloudflare)"),
    ("X-Powered-By", r"(php|express|asp\.net|servlet|next\.js)"),
    ("Set-Cookie", r"(laravel_session|csrftoken|PHPSESSID|JSESSIONID|wordpress|wp-|ci_session)"),
]


def web_fingerprint(params, log, cancel):
    url = hc.normalize_url(params.get("url") or params.get("target", ""))
    if not url:
        return {"summary": "no url", "findings": []}
    log(f"[*] Fingerprinting {url}")
    r = hc.request(url, timeout=12)
    if r.status == 0:
        return {"summary": f"unreachable: {r.error}", "findings": []}
    tech, findings = [], []
    log(f"    HTTP {r.status}  ({r.elapsed_ms} ms)")
    for k in ("Server", "X-Powered-By", "X-AspNet-Version", "Via", "X-Generator"):
        v = r.header(k)
        if v:
            log(f"    {k}: {v}")
            tech.append(f"{k}: {v}")
    title = _title(r.body)
    if title:
        log(f"    <title> {title}")
    body = r.body.lower()
    if "wp-content" in body or "/wp-includes/" in body:
        tech.append("WordPress")
    if 'name="generator"' in body:
        m = re.search(r'name="generator"\s+content="([^"]+)"', r.body, re.I)
        if m:
            tech.append("Generator: " + m.group(1))
    # security headers quick look
    for h, sev in (("Content-Security-Policy", "low"),
                   ("X-Frame-Options", "low"),
                   ("Strict-Transport-Security", "low")):
        if not r.header(h):
            findings.append(_f(f"Missing {h}", sev, "Security header not set."))
    return {"summary": f"HTTP {r.status} · {title or 'no title'}",
            "findings": findings,
            "data": {"status": r.status, "title": title, "tech": tech,
                     "headers": r.headers}}


def http_headers(params, log, cancel):
    url = hc.normalize_url(params.get("url") or params.get("target", ""))
    r = hc.request(url, timeout=12, allow_redirects=False)
    log(f"[*] {url} -> HTTP {r.status}")
    for k, v in r.headers.items():
        log(f"    {k}: {v}")
    return {"summary": f"HTTP {r.status}, {len(r.headers)} headers",
            "findings": [], "data": {"status": r.status, "headers": r.headers,
                                     "location": r.header("Location")}}


# --------------------------------------------------------------- SSL / TLS
def ssl_analyzer(params, log, cancel):
    host = hc.host_of(params.get("hostname") or params.get("target", ""))
    port = int(params.get("port") or 443)
    if not host:
        return {"summary": "no host", "findings": []}
    log(f"[*] TLS inspect {host}:{port}")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    findings, data = [], {}
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                data["version"] = ss.version()
                data["cipher"] = ss.cipher()
                log(f"    Protocol: {ss.version()}")
                log(f"    Cipher:   {ss.cipher()[0]}")
                if ss.version() in ("TLSv1", "TLSv1.1", "SSLv3"):
                    findings.append(_f(f"Legacy TLS: {ss.version()}", "medium",
                                       "Deprecated protocol enabled."))
    except Exception as e:
        # retry without validation already done; report
        try:
            ctx2 = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx2.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert(binary_form=True)
                    data["version"] = ss.version()
                    log(f"    Protocol: {ss.version()} (unverified)")
        except Exception as e2:
            return {"summary": f"TLS error: {e2}", "findings": []}
    # cert details via verified fetch
    try:
        vctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with vctx.wrap_socket(sock, server_hostname=host) as ss:
                c = ss.getpeercert()
                data["subject"] = dict(x[0] for x in c.get("subject", []))
                data["issuer"] = dict(x[0] for x in c.get("issuer", []))
                data["notAfter"] = c.get("notAfter")
                sans = [v for (t, v) in c.get("subjectAltName", []) if t == "DNS"]
                data["san"] = sans
                log(f"    Issuer:   {data['issuer'].get('organizationName','?')}")
                log(f"    Expires:  {c.get('notAfter')}")
                log(f"    SANs:     {len(sans)}")
    except ssl.SSLCertVerificationError as e:
        findings.append(_f("Certificate verification failed", "medium", str(e)))
    except Exception:
        pass
    return {"summary": f"{data.get('version','?')} · expires {data.get('notAfter','?')}",
            "findings": findings, "data": data}


# ------------------------------------------------------------- WAF detect
_WAF_SIGS = [
    ("Cloudflare", [("server", "cloudflare"), ("set-cookie", "__cf"), ("header", "cf-ray")]),
    ("Akamai", [("server", "akamaighost"), ("header", "x-akamai")]),
    ("Sucuri", [("server", "sucuri"), ("header", "x-sucuri")]),
    ("Imperva/Incapsula", [("set-cookie", "incap_ses"), ("set-cookie", "visid_incap"), ("header", "x-iinfo")]),
    ("AWS WAF", [("header", "x-amzn-requestid"), ("server", "awselb")]),
    ("F5 BIG-IP", [("set-cookie", "bigipserver"), ("set-cookie", "ts")]),
    ("Barracuda", [("set-cookie", "barra_counter")]),
    ("Fastly", [("header", "x-served-by"), ("header", "x-fastly")]),
]


def waf_detector(params, log, cancel):
    url = hc.normalize_url(params.get("url") or params.get("target", ""))
    log(f"[*] WAF fingerprint {url}")
    base = hc.request(url, timeout=12)
    # benign probe that many WAFs flag
    probe = hc.request(url + ("&" if "?" in url else "?") + "x=1%27%22%3E", timeout=12)
    detected = []
    hay = {**{k.lower(): v.lower() for k, v in base.headers.items()}}
    cookies = hay.get("set-cookie", "")
    for name, sigs in _WAF_SIGS:
        for kind, needle in sigs:
            if kind == "server" and needle in hay.get("server", ""):
                detected.append(name); break
            if kind == "header" and needle in hay:
                detected.append(name); break
            if kind == "set-cookie" and needle in cookies:
                detected.append(name); break
    detected = sorted(set(detected))
    for d in detected:
        log(f"    [+] {d}")
    findings = []
    if probe.status in (403, 406, 429, 501) and base.status not in (403, 406, 429, 501):
        log(f"    [i] probe triggered HTTP {probe.status} (WAF-like blocking)")
    if not detected:
        log("    [-] no known WAF signature")
    return {"summary": (", ".join(detected) if detected else "none detected"),
            "findings": findings, "data": {"waf": detected,
            "base_status": base.status, "probe_status": probe.status}}


# --------------------------------------------------- content / path discovery
_DIR_WL = ["admin", "login", "dashboard", "api", "api/v1", "api/v2", "config",
           "backup", "backups", ".git/HEAD", ".env", "robots.txt", "sitemap.xml",
           "wp-admin", "wp-login.php", "phpinfo.php", "server-status", "status",
           "health", "metrics", "swagger", "swagger-ui.html", "openapi.json",
           "graphql", "actuator", "actuator/env", "debug", "test", "dev",
           "uploads", "files", "static", "assets", "js", "css", "old", "tmp",
           ".svn/entries", ".DS_Store", "web.config", "crossdomain.xml",
           "security.txt", ".well-known/security.txt", "console", "adminer.php"]

_LOGIN_WL = ["login", "signin", "sign-in", "admin", "admin/login", "user/login",
             "account/login", "auth", "auth/login", "session/new", "wp-login.php",
             "administrator", "cp", "controlpanel", "portal", "sso", "oauth/authorize"]

_REGISTER_WL = ["register", "signup", "sign-up", "join", "account/create",
                "users/new", "registration", "create-account", "auth/register"]

_COMMON_PARAMS = ["id", "page", "q", "search", "url", "redirect", "next", "file",
                  "path", "lang", "debug", "admin", "user", "callback", "return",
                  "r", "ref", "dest", "continue", "data", "view", "template"]


def _bust(url, paths, log, cancel, label):
    base = hc.normalize_url(url).rstrip("/")
    hits = []

    def check(p):
        if cancel.is_set():
            return None
        full = f"{base}/{p}"
        r = hc.request(full, timeout=8, allow_redirects=False)
        if r.status and r.status not in (404, 0):
            return {"path": p, "url": full, "status": r.status,
                    "len": len(r.raw), "location": r.header("Location")}
        return None

    with cf.ThreadPoolExecutor(max_workers=25) as ex:
        for res in ex.map(check, paths):
            if res:
                hits.append(res)
                loc = f" -> {res['location']}" if res["location"] else ""
                log(f"    [{res['status']}] /{res['path']}  ({res['len']} B){loc}")
    return hits


def dir_buster(params, log, cancel):
    url = params.get("url") or params.get("target", "")
    log(f"[*] Directory brute ({len(_DIR_WL)} paths) on {url}")
    hits = _bust(url, _DIR_WL, log, cancel, "dir")
    findings = []
    for h in hits:
        p = h["path"]
        if p in (".git/HEAD", ".env", ".svn/entries", ".DS_Store", "web.config") and h["status"] < 400:
            findings.append(_f(f"Exposed sensitive file: /{p}", "high",
                               "Potential source/secret disclosure.", f"HTTP {h['status']}"))
        if p in ("phpinfo.php", "server-status", "actuator/env") and h["status"] < 400:
            findings.append(_f(f"Exposed debug endpoint: /{p}", "medium", "", f"HTTP {h['status']}"))
    return {"summary": f"{len(hits)} responsive paths", "findings": findings,
            "data": {"hits": hits}}


def login_finder(params, log, cancel):
    url = params.get("url") or params.get("target", "")
    log(f"[*] Login/admin path search on {url}")
    hits = _bust(url, _LOGIN_WL, log, cancel, "login")
    return {"summary": f"{len(hits)} candidate login pages", "findings": [],
            "data": {"hits": hits}}


def register_finder(params, log, cancel):
    url = params.get("url") or params.get("target", "")
    log(f"[*] Register/signup path search on {url}")
    hits = _bust(url, _REGISTER_WL, log, cancel, "reg")
    return {"summary": f"{len(hits)} candidate signup pages", "findings": [],
            "data": {"hits": hits}}


def param_finder(params, log, cancel):
    url = hc.normalize_url(params.get("url") or params.get("target", ""))
    log(f"[*] Reflected-parameter probe on {url}")
    canary = "rcnx9134"
    reflected = []
    for p in _COMMON_PARAMS:
        if cancel.is_set():
            break
        sep = "&" if "?" in url else "?"
        test = f"{url}{sep}{p}={canary}"
        r = hc.request(test, timeout=8)
        if canary in (r.body or ""):
            reflected.append(p)
            log(f"    [+] param '{p}' reflected in response")
    findings = []
    if reflected:
        findings.append(_f(f"{len(reflected)} reflected parameters", "info",
                           "Reflected input — candidates for XSS/redirect/SSRF testing.",
                           ", ".join(reflected)))
    return {"summary": f"{len(reflected)} reflected params", "findings": findings,
            "data": {"reflected": reflected}}


# --------------------------------------------------------- bounty quick checks
def bounty_checks(params, log, cancel):
    url = hc.normalize_url(params.get("url") or params.get("target", ""))
    base = url.rstrip("/")
    log(f"[*] Bug-bounty quick checks on {base}")
    findings, data = [], {}

    # exposed VCS / env
    for path, sev, label in ((".git/HEAD", "high", "Exposed .git"),
                             (".env", "high", "Exposed .env"),
                             (".svn/entries", "medium", "Exposed .svn")):
        r = hc.request(f"{base}/{path}", timeout=8, allow_redirects=False)
        if r.status == 200 and r.body and ("ref:" in r.body or "=" in r.body or "svn" in r.body.lower()):
            findings.append(_f(label, sev, f"/{path} readable", r.body[:120]))
            log(f"    [+] {label}: /{path}")

    # security.txt
    for p in (".well-known/security.txt", "security.txt"):
        r = hc.request(f"{base}/{p}", timeout=8)
        if r.status == 200 and "contact" in (r.body or "").lower():
            data["security_txt"] = p
            log(f"    [i] security.txt present at /{p}")
            break

    # CORS reflection
    r = hc.request(url, timeout=8, headers={"Origin": "https://evil.example"})
    acao = r.header("Access-Control-Allow-Origin")
    acac = r.header("Access-Control-Allow-Credentials")
    if acao == "https://evil.example" or acao == "*":
        sev = "high" if (acao == "https://evil.example" and acac.lower() == "true") else "medium"
        findings.append(_f("CORS misconfiguration", sev,
                           f"ACAO reflects/allows arbitrary origin (creds={acac or 'n/a'}).",
                           f"ACAO: {acao}"))
        log(f"    [+] CORS: ACAO={acao} creds={acac}")

    # security headers
    base_r = hc.request(url, timeout=8)
    for h, sev in (("Content-Security-Policy", "low"), ("X-Frame-Options", "low"),
                   ("Strict-Transport-Security", "low"),
                   ("X-Content-Type-Options", "info")):
        if not base_r.header(h):
            findings.append(_f(f"Missing header: {h}", sev, "", ""))

    # GraphQL + swagger presence
    for p in ("graphql", "api/graphql", "swagger.json", "openapi.json",
              "swagger-ui.html", "actuator"):
        r = hc.request(f"{base}/{p}", timeout=8)
        if r.status in (200, 400) and r.body:
            data.setdefault("endpoints", []).append(p)
            log(f"    [i] endpoint reachable: /{p} (HTTP {r.status})")
    return {"summary": f"{len(findings)} findings", "findings": findings, "data": data}


# -------------------------------------------------------------- open redirect
def open_redirect(params, log, cancel):
    url = hc.normalize_url(params.get("url") or params.get("target", ""))
    canary = "https://example.org/rcnx"
    param = params.get("param", "")
    test_params = [param] if param else ["redirect", "url", "next", "return",
                                         "returnUrl", "dest", "continue", "r", "u"]
    findings = []
    log(f"[*] Open-redirect probe on {url}")
    for p in test_params:
        if cancel.is_set():
            break
        sep = "&" if "?" in url else "?"
        test = f"{url}{sep}{p}={canary}"
        r = hc.request(test, timeout=8, allow_redirects=False)
        loc = r.header("Location")
        if loc and ("example.org/rcnx" in loc):
            findings.append(_f(f"Open redirect via '{p}'", "medium",
                               "Location header follows attacker-controlled value.",
                               f"Location: {loc}"))
            log(f"    [+] open redirect: {p} -> {loc}")
    return {"summary": f"{len(findings)} open-redirect(s)", "findings": findings, "data": {}}


# ------------------------------------------------------------ reflected XSS
def reflected_xss(params, log, cancel):
    url = hc.normalize_url(params.get("url") or params.get("target", ""))
    if "?" not in url:
        log("    [i] no query string; add params e.g. ?q=test to test reflection")
    marker = "rcnx<svg/onload=1>"
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    findings = []
    log(f"[*] Reflected-XSS probe on {url}")
    targets = qs if qs else [("q", "1"), ("search", "1")]
    for i, (k, _v) in enumerate(targets):
        if cancel.is_set():
            break
        newqs = list(targets)
        newqs[i] = (k, marker)
        test = urlunparse(parsed._replace(query=urlencode(newqs)))
        r = hc.request(test, timeout=8)
        body = r.body or ""
        if "rcnx<svg/onload=1>" in body:
            findings.append(_f(f"Reflected XSS (unencoded) in '{k}'", "high",
                               "Payload reflected without HTML-encoding.",
                               "rcnx<svg/onload=1>"))
            log(f"    [+] unencoded reflection in '{k}' — likely XSS")
        elif "rcnx" in body and "&lt;svg" in body:
            log(f"    [i] '{k}' reflected but HTML-encoded (safe)")
    return {"summary": f"{len(findings)} reflected-XSS", "findings": findings, "data": {}}


# --------------------------------------------------------------- SQLi error
_SQL_ERR = [r"SQL syntax.*MySQL", r"Warning.*mysqli?", r"PostgreSQL.*ERROR",
            r"ORA-\d{5}", r"Microsoft OLE DB Provider for SQL Server",
            r"SQLite/JDBCDriver", r"Unclosed quotation mark after the character string",
            r"quoted string not properly terminated", r"you have an error in your sql syntax"]


def sqli_error(params, log, cancel):
    url = hc.normalize_url(params.get("url") or params.get("target", ""))
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    findings = []
    log(f"[*] Error-based SQLi probe on {url}")
    if not qs:
        log("    [i] no parameters to test; provide a URL with ?param=value")
    for i, (k, v) in enumerate(qs):
        if cancel.is_set():
            break
        for payload in ("'", "\"", "')", "' OR '1'='1"):
            newqs = list(qs)
            newqs[i] = (k, v + payload)
            test = urlunparse(parsed._replace(query=urlencode(newqs)))
            r = hc.request(test, timeout=8)
            for pat in _SQL_ERR:
                if re.search(pat, r.body or "", re.I):
                    findings.append(_f(f"SQL error disclosed via '{k}'", "high",
                                       "Database error triggered by quote — probable SQLi.",
                                       f"payload={payload!r} pattern={pat}"))
                    log(f"    [+] SQL error in '{k}' with payload {payload!r}")
                    break
            else:
                continue
            break
    return {"summary": f"{len(findings)} SQLi signal(s)", "findings": findings, "data": {}}


# ----------------------------------------------------------------- SSTI probe
def ssti_probe(params, log, cancel):
    url = hc.normalize_url(params.get("url") or params.get("target", ""))
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True) or [("q", "1")]
    findings = []
    log(f"[*] SSTI probe on {url}")
    payloads = [("${{7*7}}", "49"), ("{{7*7}}", "49"), ("<%= 7*7 %>", "49"),
                ("#{7*7}", "49"), ("{7*7}", None)]
    for i, (k, _v) in enumerate(qs):
        if cancel.is_set():
            break
        for pl, expect in payloads:
            newqs = list(qs)
            newqs[i] = (k, pl)
            test = urlunparse(parsed._replace(query=urlencode(newqs)))
            r = hc.request(test, timeout=8)
            if expect and expect in (r.body or "") and pl not in (r.body or ""):
                findings.append(_f(f"Server-side template injection in '{k}'", "critical",
                                   f"Expression {pl} evaluated to {expect}.", pl))
                log(f"    [+] SSTI in '{k}': {pl} -> {expect}")
                break
    return {"summary": f"{len(findings)} SSTI signal(s)", "findings": findings, "data": {}}


# ---------------------------------------------------- cloud metadata / SSRF
_META = {
    "AWS IMDSv1": "http://169.254.169.254/latest/meta-data/",
    "AWS IAM creds": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "GCP": "http://metadata.google.internal/computeMetadata/v1/",
    "Azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "Alibaba": "http://100.100.100.200/latest/meta-data/",
    "DigitalOcean": "http://169.254.169.254/metadata/v1.json",
}


def cloud_metadata_ssrf(params, log, cancel):
    """Tests an SSRF-prone URL param by swapping in cloud-metadata endpoints.
    Provide `url` containing the fetch param and name it in `param`
    (e.g. url=https://t/api?img=FUZZ or param=img)."""
    url = hc.normalize_url(params.get("url") or params.get("target", ""))
    param = params.get("param", "")
    findings = []
    log(f"[*] SSRF / cloud-metadata probe on {url}")
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    if param:
        idxs = [i for i, (k, _v) in enumerate(qs) if k == param]
    else:
        idxs = list(range(len(qs)))
        if not idxs:
            log("    [i] no params; provide ?param=URL and set 'param' to the fetch field")
    for name, meta in _META.items():
        if cancel.is_set():
            break
        for i in idxs:
            newqs = list(qs)
            newqs[i] = (qs[i][0], meta)
            test = urlunparse(parsed._replace(query=urlencode(newqs)))
            r = hc.request(test, timeout=9)
            b = (r.body or "")
            sig = ("ami-id" in b or "instance-id" in b or "iam/" in b or
                   "computeMetadata" in b or '"droplet_id"' in b or
                   "securityCredentials" in b)
            if sig:
                findings.append(_f(f"SSRF to {name} metadata via '{qs[i][0]}'", "critical",
                                   "Response contains cloud metadata — SSRF confirmed.",
                                   meta))
                log(f"    [+] SSRF confirmed -> {name} ({meta})")
    return {"summary": f"{len(findings)} SSRF/metadata hit(s)", "findings": findings, "data": {}}


# ------------------------------------------------------- GraphQL introspection
def graphql_introspection(params, log, cancel):
    url = hc.normalize_url(params.get("url") or params.get("target", ""))
    candidates = [url] if ("graphql" in url or "?" in url) else \
        [url.rstrip("/") + p for p in ("/graphql", "/api/graphql", "/v1/graphql", "/query")]
    q = {"query": "query{__schema{queryType{name} types{name kind}}}"}
    findings, data = [], {}
    log(f"[*] GraphQL introspection probe")
    for ep in candidates:
        if cancel.is_set():
            break
        r = hc.request(ep, method="POST", timeout=10,
                       headers={"Content-Type": "application/json"},
                       data=json.dumps(q))
        if r.body and '"__schema"' in r.body:
            types = re.findall(r'"name":"(\w+)"', r.body)
            data["endpoint"] = ep
            data["types"] = sorted(set(types))[:60]
            findings.append(_f("GraphQL introspection enabled", "medium",
                               f"{ep} exposes schema ({len(set(types))} type names).",
                               ep))
            log(f"    [+] introspection OPEN at {ep} ({len(set(types))} types)")
            break
        elif r.status in (200, 400) and r.body and "errors" in r.body:
            log(f"    [i] {ep} is a GraphQL endpoint but introspection seems blocked")
    return {"summary": ("introspection enabled" if findings else "not found/blocked"),
            "findings": findings, "data": data}


# ------------------------------------------------------------- live probe
def live_probe(params, log, cancel):
    raw = params.get("hosts") or params.get("target", "")
    hosts = [h.strip() for h in re.split(r"[\s,]+", raw) if h.strip()]
    log(f"[*] Probing {len(hosts)} host(s)")
    alive = []

    def probe(h):
        if cancel.is_set():
            return None
        for scheme in ("https://", "http://"):
            if "://" in h:
                u = h
            else:
                u = scheme + h
            r = hc.request(u, timeout=8, allow_redirects=False)
            if r.status:
                return {"host": h, "url": u, "status": r.status,
                        "title": _title(r.body), "server": r.header("Server")}
            if "://" in h:
                break
        return None

    with cf.ThreadPoolExecutor(max_workers=30) as ex:
        for res in ex.map(probe, hosts):
            if res:
                alive.append(res)
                log(f"    [{res['status']}] {res['url']}  {res['title'][:60]}")
    return {"summary": f"{len(alive)}/{len(hosts)} alive", "findings": [],
            "data": {"alive": alive}}


# registry of builtin callables by id
BUILTINS = {
    "dns": dns_deep,
    "subdomain": subdomain_enum,
    "portscan": port_scan,
    "fingerprint": web_fingerprint,
    "http_headers": http_headers,
    "ssl": ssl_analyzer,
    "waf": waf_detector,
    "dirbuster": dir_buster,
    "login_finder": login_finder,
    "register_finder": register_finder,
    "param_finder": param_finder,
    "bounty_checks": bounty_checks,
    "open_redirect": open_redirect,
    "xss": reflected_xss,
    "sqli": sqli_error,
    "ssti": ssti_probe,
    "cloud_metadata": cloud_metadata_ssrf,
    "graphql": graphql_introspection,
    "live_probe": live_probe,
    "cors": bounty_checks,  # alias subset
}
