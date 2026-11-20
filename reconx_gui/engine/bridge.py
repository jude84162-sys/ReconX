"""Adapters to the real ReconX `modules/` engines when that repo is present.

Call signatures were lifted from the uploaded cli.py so the GUI drives the exact
same backend. Each adapter normalizes the module's return value into our
{summary, findings, data} shape and streams the module's stdout into the live
console. If the module import fails, the adapter raises ImportError and the job
manager falls back to a builtin (engine.builtins).
"""
from __future__ import annotations

import io
import importlib
import contextlib

_import_cache: dict = {}


def module_importable(path: str) -> bool:
    if not path:
        return False
    if path in _import_cache:
        return _import_cache[path] is not None
    try:
        _import_cache[path] = importlib.import_module(path)
    except Exception:
        _import_cache[path] = None
    return _import_cache[path] is not None


# tool_id -> scanner_manager key (only these dispatch through run_scanner)
SCANNER_TOOL_KEYS = {
    "sqli": "sqli", "xss": "xss", "ssrf": "ssrf", "ssti": "ssti",
    "cmdi": "cmdi", "jwt": "jwt", "graphql": "graphql", "api_spec": "api_spec",
    "deserialization": "deserialization", "xxe": "xxe",
    "cloud_metadata": "cloud_metadata", "buckets": "buckets",
}


def _scanner_supports(key: str) -> bool:
    """True if the installed scanner_manager actually registers `key`.
    Different ReconX versions ship different scanner sets."""
    try:
        m = importlib.import_module("modules.vuln.scanner_manager")
        return key in getattr(m, "SCANNERS", {})
    except Exception:
        return False


def availability(tool: dict) -> str:
    """'module' | 'builtin' | 'none' — what will actually run for this tool."""
    mod = tool.get("module", "")
    tid = tool.get("id", "")
    if mod == "modules.vuln.scanner_manager" and tid in SCANNER_TOOL_KEYS:
        # only module-backed when this build's scanner_manager knows the key
        if module_importable(mod) and _scanner_supports(SCANNER_TOOL_KEYS[tid]):
            return "module"
    elif module_importable(mod):
        return "module"
    if tool.get("builtin"):
        return "builtin"
    return "none"


def _imp(path):
    m = importlib.import_module(path)
    return m


def _header_from_input(value):
    if not value:
        return None
    if ":" in value:
        name, val = value.split(":", 1)
        return {name.strip(): val.strip()}
    return {"Authorization": value}


class _LogWriter(io.TextIOBase):
    """File-like that forwards writes (line-buffered) to a log callback."""
    def __init__(self, log):
        self._log = log
        self._buf = ""

    def write(self, s):
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            if line.strip():
                self._log("    " + line.rstrip())
        return len(s)

    def flush(self):
        if self._buf.strip():
            self._log("    " + self._buf.rstrip())
        self._buf = ""


def _normalize(ret, default_summary=""):
    if isinstance(ret, dict):
        findings = ret.get("findings") or []
        norm = []
        for f in findings:
            if isinstance(f, dict):
                norm.append({
                    "title": f.get("title") or f.get("name") or f.get("type") or "finding",
                    "severity": (f.get("severity") or f.get("sev") or "info").lower(),
                    "detail": f.get("detail") or f.get("description") or f.get("desc") or "",
                    "evidence": f.get("evidence") or f.get("poc") or f.get("payload") or "",
                })
            else:
                norm.append({"title": str(f), "severity": "info", "detail": "", "evidence": ""})
        summary = ret.get("summary")
        if not isinstance(summary, str) or not summary:
            # modules may return a non-string/absent summary; synthesize one
            summary = default_summary or f"{len(norm)} finding(s)"
        return {"summary": summary, "findings": norm, "data": ret}
    return {"summary": default_summary or "done", "findings": [], "data": {"result": ret}}


def run(tool_id: str, params: dict, log, cancel) -> dict:
    """Dispatch to the matching ReconX module. Raises ImportError if absent."""
    out = _LogWriter(log)

    def call(fn, *a, **k):
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            r = fn(*a, **k)
        out.flush()
        return r

    # -- Recon --
    if tool_id == "domain":
        m = _imp("modules.web.domain_osint")
        return _normalize(call(m.run_domain_osint, params["domain"]))
    if tool_id == "ip":
        m = _imp("modules.network.ip_osint")
        return _normalize(call(m.run_ip_osint, params["ip"]))
    if tool_id == "portscan":
        m = _imp("modules.network.port_scan")
        spec = params.get("ports") or params.get("preset") or "common"
        ports = m.get_ports(spec)
        return _normalize(call(m.scan_port_range, params["target"], ports))
    if tool_id == "dns":
        m = _imp("modules.network.dns_deep")
        return _normalize(call(m.run_dns_deep, params["domain"]))
    if tool_id == "subdomain":
        m = _imp("modules.web.subdomain_enum")
        return _normalize(call(m.run_subdomain_enum, params["domain"]))
    # -- Web discovery --
    if tool_id == "fingerprint":
        m = _imp("modules.web.web_fingerprint")
        return _normalize(call(m.run_web_fingerprint, params["url"]))
    if tool_id == "dirbuster":
        m = _imp("modules.web.dir_buster")
        return _normalize(call(m.run_dir_bust, params["url"]))
    if tool_id == "login_finder":
        m = _imp("modules.web.login_finder")
        return _normalize(call(m.run_login_finder, params["url"]))
    if tool_id == "register_finder":
        m = _imp("modules.web.register_finder")
        return _normalize(call(m.run_register_finder, params["url"]))
    if tool_id == "param_finder":
        m = _imp("modules.web.param_finder")
        return _normalize(call(m.run_param_finder, params["url"]))
    # -- Security --
    if tool_id == "waf":
        m = _imp("modules.web.waf_detector")
        return _normalize(call(m.run_waf_detector, params["url"]))
    if tool_id == "web_monitor":
        m = _imp("modules.web.web_monitor")
        return _normalize(call(m.run_web_monitor, params["url"]))
    if tool_id == "ssl":
        m = _imp("modules.network.ssl_analyzer")
        return _normalize(call(m.run_ssl_analyzer, params["hostname"]))
    # -- Vuln scanners via scanner_manager --
    _SCAN_KEYS = {"sqli": "sqli", "xss": "xss", "ssrf": "ssrf", "ssti": "ssti",
                  "cmdi": "cmdi", "jwt": "jwt", "graphql": "graphql",
                  "api_spec": "api_spec", "deserialization": "deserialization",
                  "xxe": "xxe", "cloud_metadata": "cloud_metadata", "buckets": "buckets"}
    if tool_id in _SCAN_KEYS:
        m = _imp("modules.vuln.scanner_manager")
        if _SCAN_KEYS[tool_id] not in getattr(m, "SCANNERS", {}):
            raise ImportError(f"scanner '{_SCAN_KEYS[tool_id]}' not in this build")
        tgt = params.get("url") or params.get("target", "")
        return _normalize(call(m.run_scanner, _SCAN_KEYS[tool_id], tgt,
                               timeout=300, verbose=True))
    if tool_id == "all_vuln":
        m = _imp("modules.vuln.scanner_manager")
        raw = params.get("workers")
        workers = int(raw) if raw is not None and str(raw).strip() else None
        return _normalize(call(m.run_all, params["url"], workers=workers, verbose=True))
    # -- Bounty --
    if tool_id == "dirb":
        m = _imp("modules.vuln.dirb_engine")
        return _normalize(call(m.run_dirb, params["url"], wordlist=None,
                               timeout=300, verbose=True))
    if tool_id == "bounty_checks":
        m = _imp("modules.vuln.bounty_checks")
        return _normalize(call(m.run_bounty_checks, params["url"]))
    if tool_id == "nikto":
        m = _imp("modules.vuln.bugbounty_nikto")
        targets = [h.strip() for h in str(params.get("hosts", "")).splitlines() if h.strip()]
        return _normalize(call(m.scan_targets, targets,
                               workers=int(params.get("workers", 3) or 3),
                               waf_skip=False, verbose=True))
    # -- Full recon --
    if tool_id in ("full_recon", "fast_recon"):
        m = _imp("recon")
        deep = tool_id == "full_recon"
        call(m.run_recon, params["domain"], deep=deep, save_json=True,
             max_ips=int(params.get("max_ips", 3) or 3))
        return {"summary": f"{'full' if deep else 'fast'} recon complete",
                "findings": [], "data": {"note": "report written to outputs/"}}
    # -- Attack surface --
    if tool_id == "attack_surface":
        m = _imp("modules.web.attack_surface")
        eng = m.AttackSurfaceEngine(target=params["target"],
                                    use_tor=bool(params.get("use_tor")))
        call(eng.run_recon_pipeline)
        return {"summary": "attack-surface pipeline complete", "findings": [], "data": {}}
    # -- Advanced API/logic --
    if tool_id == "mass_assignment":
        m = _imp("modules.vuln.advanced.mass_assignment")
        return _normalize(call(m.scan, params["url"], body=params.get("body") or None,
                               headers=_header_from_input(params.get("auth")), verbose=True))
    if tool_id == "bola":
        m = _imp("modules.vuln.advanced.bola_mapper")
        return _normalize(call(m.scan, params["url"], params["token_a"], params["token_b"],
                               header=params.get("header", "Authorization"), verbose=True))
    if tool_id == "race":
        m = _imp("modules.vuln.advanced.race_condition")
        return _normalize(call(m.scan, params["url"],
                               method=params.get("method", "POST"),
                               data=params.get("data") or None,
                               headers=_header_from_input(params.get("auth")),
                               threads=int(params.get("threads", 20) or 20),
                               max_expected=int(params.get("max_expected", 1) or 1),
                               verbose=True))
    if tool_id == "dom_xss":
        m = _imp("modules.vuln.web.dom_xss")
        return _normalize(call(m.scan, params["url"],
                               use_browser=bool(params.get("use_browser")), verbose=True))
    if tool_id == "live_probe":
        m = _imp("modules.web.live_probe")
        targets = [h.strip() for h in __import__("re").split(r"[\s,]+", params.get("hosts", "")) if h.strip()]
        return _normalize(call(m.probe_hosts, targets, timeout=6, verbose=True))
    if tool_id == "screenshot":
        m = _imp("modules.web.aquatone_clone")
        targets = [h.strip() for h in __import__("re").split(r"[\s,]+", params.get("hosts", "")) if h.strip()]
        return _normalize(call(m.run_screenshots, targets, outdir="outputs/screenshots",
                               verbose=True, source="gui"))
    raise ImportError(f"no bridge for {tool_id}")
