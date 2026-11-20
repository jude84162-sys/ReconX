"""ReconX modules wrapped as LLM-callable Scorpion tools.

Each class here is a thin :class:`~scorpion.tools.base.Tool` subclass around one
ReconX module function. The heavy lifting (DNS, HTTP, TLS, scanning) lives in the
`modules/*` and `recon.py` code that already ships with ReconX; this file only:

  * declares an Anthropic-style ``input_schema`` so the model can call the tool,
  * names the ``scope_field`` so the base class routes the target through the
    Scope Guard + rate limiter BEFORE any packet is sent,
  * imports the underlying module **lazily inside ``_execute``** so a missing
    optional dependency in one module never breaks importing this package, and
  * squeezes the module's big result dict down to a compact ``ToolResult.data``
    plus a one-line ``summary`` the agent and dashboard can read.

The public surface is the :data:`ALL_TOOLS` list, handed straight to
``ToolRegistry.register_all(ALL_TOOLS)``.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional

from .base import Tool, ToolResult


# --------------------------------------------------------------------------- #
# small shared helpers
# --------------------------------------------------------------------------- #
def _trim(seq: Optional[List[Any]], limit: int) -> List[Any]:
    """Return at most ``limit`` items from ``seq`` (never None)."""
    if not seq:
        return []
    return list(seq)[:limit]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except (ValueError, AttributeError):
        return False


def _compact_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only the fields the agent needs to triage a vuln finding."""
    out = {
        "title": f.get("title") or f.get("name") or f.get("type"),
        "severity": (f.get("severity") or "info"),
        "type": f.get("type") or f.get("category"),
        "url": f.get("url") or f.get("endpoint") or f.get("target"),
    }
    param = f.get("param") or f.get("parameter")
    if param:
        out["param"] = param
    return {k: v for k, v in out.items() if v is not None}


# --------------------------------------------------------------------------- #
# OSINT / enumeration
# --------------------------------------------------------------------------- #
class ResolveAndOsintTool(Tool):
    name = "resolve_and_osint"
    description = (
        "Resolve a domain and gather passive OSINT: A/AAAA records, reverse DNS, "
        "WHOIS registrar, DNS records, and certificate-transparency subdomains. "
        "Passive — a good first move on a new target."
    )
    scope_field = "domain"
    input_schema = {
        "type": "object",
        "properties": {
            "domain": {"type": "string",
                       "description": "The apex domain or hostname to profile."},
            "deep": {"type": "boolean",
                     "description": "Verify discovered subdomains (slower).",
                     "default": False},
        },
        "required": ["domain"],
    }

    def _execute(self, domain: str = "", deep: bool = False, **_: Any) -> ToolResult:
        from modules.web import domain_osint
        r = domain_osint.run_domain_osint(domain, deep=bool(deep))
        ips = r.get("ips", {}) or {}
        subs = r.get("subdomains", []) or []
        whois = r.get("whois", {}) or {}
        registrar = whois.get("registrar")
        a_records = ips.get("A", []) or []
        data = {
            "ips": {"A": a_records, "AAAA": ips.get("AAAA", []) or []},
            "primary_ip": a_records[0] if a_records else None,
            "subdomains_found": len(subs),
            "subdomains": [s.get("hostname") for s in _trim(subs, 25)],
            "registrar": registrar,
            "reverse_dns": r.get("reverse_dns", {}) or {},
            "sources_used": r.get("sources_used", []) or [],
            "errors": _trim(r.get("errors", []), 5),
        }
        summary = "%s: %d A-record(s), %d subdomain(s)%s" % (
            domain, len(a_records), len(subs),
            (", registrar=%s" % registrar) if registrar else "")
        return ToolResult(ok=True, tool=self.name, target=domain,
                          summary=summary, data=data)


class EnumSubdomainsTool(Tool):
    name = "enum_subdomains"
    description = (
        "Enumerate subdomains of a domain using the passive subfinder clone "
        "(crt.sh, hackertarget, rapiddns, alienvault, urlscan, web archive, "
        "threatcrowd) plus optional DNS bruteforce. Returns the discovered hosts "
        "with their resolved IPs."
    )
    scope_field = "domain"
    input_schema = {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "Apex domain to enumerate."},
            "passive": {"type": "boolean",
                        "description": "Use passive OSINT sources.", "default": True},
            "bruteforce": {"type": "boolean",
                           "description": "Also DNS-bruteforce common labels.",
                           "default": True},
        },
        "required": ["domain"],
    }

    def _execute(self, domain: str = "", passive: bool = True,
                 bruteforce: bool = True, **_: Any) -> ToolResult:
        from modules.web import subfinder_clone
        r = subfinder_clone.run_subfinder_clone(
            domain, passive=bool(passive), bruteforce=bool(bruteforce))
        subs = r.get("subdomains", []) or []
        resolved = [s for s in subs if s.get("ip")]
        data = {
            "total": r.get("total", len(subs)),
            "resolved": len(resolved),
            "by_source": r.get("by_source", {}) or {},
            "wildcard": bool(r.get("wildcard", False)),
            "hostnames": [s.get("hostname") for s in _trim(subs, 50)],
            "errors": _trim(r.get("errors", []), 5),
        }
        summary = "found %d subdomain(s), %d resolved" % (data["total"], len(resolved))
        return ToolResult(ok=True, tool=self.name, target=domain,
                          summary=summary, data=data)


class DnsReconTool(Tool):
    name = "dns_recon"
    description = (
        "Deep DNS reconnaissance over DNS-over-HTTPS: A/AAAA/NS/MX/TXT/SOA/CAA/"
        "CNAME records, SPF and DMARC posture, and an AXFR zone-transfer attempt "
        "against the nameservers."
    )
    scope_field = "domain"
    input_schema = {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "Domain to query."},
        },
        "required": ["domain"],
    }

    def _execute(self, domain: str = "", **_: Any) -> ToolResult:
        from modules.network import dns_deep
        r = dns_deep.run_dns_deep(domain)
        zt = r.get("zone_transfer")
        data = {
            "nameservers": r.get("nameservers", []) or [],
            "mx": _trim(r.get("mx", []), 10),
            "spf": r.get("spf"),
            "dmarc": r.get("dmarc"),
            "caa": r.get("caa", []) or [],
            "cname": r.get("cname", []) or [],
            "zone_transfer_open": bool(zt),
            "zone_transfer_ns": (zt or {}).get("nameserver") if zt else None,
            "indicators": _trim(r.get("indicators", []), 10),
            "error": r.get("error"),
        }
        summary = "NS=%d MX=%d SPF=%s DMARC=%s AXFR=%s" % (
            len(data["nameservers"]), len(data["mx"]),
            "set" if data["spf"] else "missing",
            "set" if data["dmarc"] else "missing",
            "OPEN" if data["zone_transfer_open"] else "closed")
        return ToolResult(ok=not bool(r.get("error")), tool=self.name,
                          target=domain, summary=summary, data=data,
                          error=r.get("error") or "")


# --------------------------------------------------------------------------- #
# network
# --------------------------------------------------------------------------- #
class PortScanTool(Tool):
    name = "port_scan"
    description = (
        "TCP connect-scan a host for open ports with light banner grabbing. "
        "Accepts a domain (resolved to its primary A record first) or a raw IP. "
        "The 'ports' argument is a preset name (common/top100/top1000/web/db/"
        "windows/ssh_ftp), a range like '1-1024', or a list like '80,443,8080'."
    )
    scope_field = "target"
    input_schema = {
        "type": "object",
        "properties": {
            "target": {"type": "string",
                       "description": "Domain or IP to scan."},
            "ports": {"type": "string",
                      "description": "Port preset, range, or comma list.",
                      "default": "common"},
        },
        "required": ["target"],
    }

    def _execute(self, target: str = "", ports: str = "common",
                 **_: Any) -> ToolResult:
        from modules.network import port_scan as port_scan_mod
        # Resolve a domain to its primary IP (task: via domain_osint._resolve_all_ips).
        scan_target = target
        resolved_ip = None
        if not _is_ip(target):
            try:
                from modules.web import domain_osint
                ips = domain_osint._resolve_all_ips(target) or {}
                a = (ips.get("A") or [])
                if a:
                    resolved_ip = a[0]
                    scan_target = a[0]
            except Exception:  # noqa: BLE001 - resolution is best-effort
                pass
        port_list = port_scan_mod.get_ports(ports or "common")
        r = port_scan_mod.scan_port_range(scan_target, port_list)
        open_ports = r.get("open_ports", []) or []
        data = {
            "scanned_target": scan_target,
            "resolved_ip": r.get("resolved_ip") or resolved_ip,
            "total_ports": r.get("total_ports", len(port_list)),
            "open_count": len(open_ports),
            "filtered_count": r.get("filtered_count", 0),
            "open_ports": [
                {"port": p.get("port"), "service": p.get("service"),
                 "banner": (p.get("banner") or None),
                 "vuln_hint": p.get("vuln_hint")}
                for p in _trim(open_ports, 50)
            ],
            "errors": _trim(r.get("errors", []), 5),
        }
        summary = "%d open of %d port(s) on %s" % (
            len(open_ports), data["total_ports"],
            data["resolved_ip"] or scan_target)
        return ToolResult(ok=True, tool=self.name, target=target,
                          summary=summary, data=data)


class SslAnalyzeTool(Tool):
    name = "ssl_analyze"
    description = (
        "Inspect a host's TLS certificate and configuration: protocol, cipher, "
        "issuer/subject, SAN list, expiry, and a letter grade with the issues "
        "that lowered it."
    )
    scope_field = "hostname"
    input_schema = {
        "type": "object",
        "properties": {
            "hostname": {"type": "string", "description": "Host to connect to."},
            "port": {"type": "integer", "description": "TLS port.", "default": 443},
        },
        "required": ["hostname"],
    }

    def _execute(self, hostname: str = "", port: int = 443, **_: Any) -> ToolResult:
        from modules.network import ssl_analyzer
        r = ssl_analyzer.run_ssl_analyzer(hostname, port=int(port))
        cert = r.get("certificate", {}) or {}
        issuer = cert.get("issuer", {}) or {}
        subject = cert.get("subject", {}) or {}
        data = {
            "grade": r.get("grade"),
            "protocol": r.get("protocol"),
            "cipher": (r.get("cipher") or {}).get("name") if r.get("cipher") else None,
            "security_score": r.get("security_score"),
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "subject_cn": subject.get("commonName"),
            "not_after": cert.get("notAfter"),
            "days_until_expiry": cert.get("days_until_expiry"),
            "san_count": len(r.get("san_domains", []) or []),
            "issues": _trim(r.get("issues", []), 10),
            "error": r.get("error"),
        }
        summary = "grade=%s proto=%s%s" % (
            data["grade"], data["protocol"],
            (", expires in %s days" % data["days_until_expiry"])
            if data["days_until_expiry"] is not None else "")
        return ToolResult(ok=not bool(r.get("error")), tool=self.name,
                          target=hostname, summary=summary, data=data,
                          error=r.get("error") or "")


# --------------------------------------------------------------------------- #
# web
# --------------------------------------------------------------------------- #
class WebFingerprintTool(Tool):
    name = "web_fingerprint"
    description = (
        "Fingerprint a web URL: HTTP status, server and X-Powered-By, detected "
        "technologies, present/missing security headers, cookies, and title."
    )
    scope_field = "url"
    input_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Full URL to fingerprint."},
        },
        "required": ["url"],
    }

    def _execute(self, url: str = "", **_: Any) -> ToolResult:
        from modules.web import web_fingerprint
        r = web_fingerprint.run_web_fingerprint(url)
        techs = r.get("technologies", []) or []
        tech_names = [t.get("name") if isinstance(t, dict) else t for t in techs]
        missing = r.get("missing_headers", []) or []
        data = {
            "status": r.get("status"),
            "final_url": r.get("final_url"),
            "server": r.get("server"),
            "powered_by": r.get("powered_by"),
            "title": r.get("title"),
            "technologies": tech_names,
            "security_headers": list((r.get("security_headers", {}) or {}).keys()),
            "missing_headers": missing,
            "error": r.get("error"),
        }
        summary = "status=%s server=%s %d tech %d missing-header(s)" % (
            r.get("status"), r.get("server"), len(tech_names), len(missing))
        return ToolResult(ok=not bool(r.get("error")), tool=self.name,
                          target=url, summary=summary, data=data,
                          error=r.get("error") or "")


class DetectWafTool(Tool):
    name = "detect_waf"
    description = (
        "Probe a URL with benign and suspicious requests to detect a Web "
        "Application Firewall and how many payloads it blocks."
    )
    scope_field = "url"
    input_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Base URL to test."},
            "timeout": {"type": "integer", "description": "Per-request timeout (s).",
                        "default": 10},
        },
        "required": ["url"],
    }

    def _execute(self, url: str = "", timeout: int = 10, **_: Any) -> ToolResult:
        from modules.web import waf_detector
        r = waf_detector.run_waf_detector(url, timeout=int(timeout))
        wafs = r.get("wafs_detected", []) or []
        names = [w.get("waf") if isinstance(w, dict) else w for w in wafs]
        data = {
            "wafs_detected": names,
            "blocked_payloads": r.get("blocked_payloads", 0),
            "tests_run": len(r.get("tests", []) or []),
            "error": r.get("error"),
        }
        summary = ("WAF: %s; blocked %d payload(s)" %
                   (", ".join(names) if names else "none detected",
                    data["blocked_payloads"]))
        return ToolResult(ok=not bool(r.get("error")), tool=self.name,
                          target=url, summary=summary, data=data,
                          error=r.get("error") or "")


class DirBustTool(Tool):
    name = "dir_bust"
    description = (
        "Directory/file brute force against a base URL with soft-404 filtering. "
        "Returns discovered paths with status, size, and a sensitivity flag."
    )
    scope_field = "url"
    input_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Base URL to scan."},
            "paths": {"type": "array", "items": {"type": "string"},
                      "description": "Optional custom path list."},
            "workers": {"type": "integer", "description": "Concurrency.",
                        "default": 40},
            "timeout": {"type": "integer", "description": "Per-request timeout (s).",
                        "default": 8},
        },
        "required": ["url"],
    }

    def _execute(self, url: str = "", paths: Optional[List[str]] = None,
                 workers: int = 40, timeout: int = 8, **_: Any) -> ToolResult:
        from modules.web import dir_buster
        r = dir_buster.run_dir_bust(url, workers=int(workers), paths=paths,
                                    timeout=int(timeout))
        found = r.get("found", []) or []
        sensitive = r.get("sensitive_findings", []) or []
        data = {
            "found_count": len(found),
            "total_checked": r.get("total_checked", 0),
            "sensitive_count": len(sensitive),
            "found": [
                {"path": f.get("path"), "status": f.get("status"),
                 "severity": f.get("severity"), "sensitive": f.get("sensitive")}
                for f in _trim(found, 40)
            ],
            "errors": _trim(r.get("errors", []), 5),
        }
        summary = "found %d path(s) of %d checked (%d sensitive)" % (
            len(found), data["total_checked"], len(sensitive))
        return ToolResult(ok=True, tool=self.name, target=url,
                          summary=summary, data=data)


class FindLoginTool(Tool):
    name = "find_login"
    description = (
        "Search a site for login / admin / auth pages and rank them by "
        "confidence."
    )
    scope_field = "url"
    input_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Base URL to search."},
            "paths": {"type": "array", "items": {"type": "string"},
                      "description": "Optional custom login paths."},
            "workers": {"type": "integer", "description": "Concurrency.",
                        "default": 30},
            "timeout": {"type": "integer", "description": "Per-request timeout (s).",
                        "default": 8},
        },
        "required": ["url"],
    }

    def _execute(self, url: str = "", paths: Optional[List[str]] = None,
                 workers: int = 30, timeout: int = 8, **_: Any) -> ToolResult:
        from modules.web import login_finder
        r = login_finder.run_login_finder(url, workers=int(workers),
                                          custom_paths=paths, timeout=int(timeout))
        found = r.get("found", []) or []
        data = {
            "found_count": len(found),
            "total_checked": r.get("total_checked", 0),
            "found": [
                {"url": f.get("url"), "path": f.get("path"),
                 "confidence": f.get("confidence")}
                for f in _trim(found, 25)
            ],
            "errors": _trim(r.get("errors", []), 5),
        }
        summary = "found %d login page(s) of %d checked" % (
            len(found), data["total_checked"])
        return ToolResult(ok=True, tool=self.name, target=url,
                          summary=summary, data=data)


class FindParamsTool(Tool):
    name = "find_params"
    description = (
        "Discover accepted query parameters on a URL and flag ones whose value "
        "is reflected in the response (potential XSS / injection surface)."
    )
    scope_field = "url"
    input_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Base URL to test."},
            "params": {"type": "array", "items": {"type": "string"},
                       "description": "Optional custom parameter names."},
            "workers": {"type": "integer", "description": "Concurrency.",
                        "default": 20},
            "timeout": {"type": "integer", "description": "Per-request timeout (s).",
                        "default": 8},
        },
        "required": ["url"],
    }

    def _execute(self, url: str = "", params: Optional[List[str]] = None,
                 workers: int = 20, timeout: int = 8, **_: Any) -> ToolResult:
        from modules.web import param_finder
        r = param_finder.run_param_finder(url, workers=int(workers),
                                          custom_params=params, timeout=int(timeout))
        accepted = r.get("accepted", []) or []
        reflected = [p for p in accepted if p.get("reflected")]
        data = {
            "accepted_count": len(accepted),
            "reflected_count": len(reflected),
            "total_checked": r.get("total_checked", 0),
            "accepted": [
                {"param": p.get("param"), "reflected": bool(p.get("reflected")),
                 "confidence": p.get("confidence")}
                for p in _trim(accepted, 30)
            ],
            "errors": _trim(r.get("errors", []), 5),
        }
        summary = "%d accepted param(s), %d reflected, of %d tested" % (
            len(accepted), len(reflected), data["total_checked"])
        return ToolResult(ok=True, tool=self.name, target=url,
                          summary=summary, data=data)


class LiveProbeTool(Tool):
    name = "live_probe"
    description = (
        "HTTP/HTTPS probe a set of hosts and report which are live, with status, "
        "title, server and final URL. Pass the primary host as 'target' and any "
        "extra hosts in 'hosts'; every host is scope-checked and out-of-scope "
        "hosts are dropped."
    )
    scope_field = "target"
    input_schema = {
        "type": "object",
        "properties": {
            "target": {"type": "string",
                       "description": "Primary host/URL to probe (scope-checked)."},
            "hosts": {"type": "array", "items": {"type": "string"},
                      "description": "Additional hosts/URLs to probe."},
            "threads": {"type": "integer", "description": "Concurrency.",
                        "default": 20},
            "timeout": {"type": "integer", "description": "Per-host timeout (s).",
                        "default": 6},
        },
        "required": ["target"],
    }

    def _execute(self, target: str = "", hosts: Optional[List[str]] = None,
                 threads: int = 20, timeout: int = 6, **_: Any) -> ToolResult:
        from modules.web import live_probe
        candidates: List[str] = [target]
        for h in (hosts or []):
            if h and h not in candidates:
                candidates.append(h)
        # Scope-check every host ourselves; the base class only guarded `target`.
        in_scope: List[str] = []
        dropped: List[str] = []
        for h in candidates:
            if self.scope.is_in_scope(h):
                in_scope.append(h)
            else:
                dropped.append(h)
        if not in_scope:
            return ToolResult(ok=False, tool=self.name, target=target,
                              blocked=True,
                              summary="no in-scope hosts to probe",
                              data={"out_of_scope": dropped})
        r = live_probe.probe_hosts(in_scope, threads=int(threads),
                                   timeout=int(timeout))
        results = r.get("results", []) or []
        alive = [x for x in results if x.get("alive")]
        data = {
            "total": r.get("total", len(in_scope)),
            "alive": r.get("alive", len(alive)),
            "dead": r.get("dead", 0),
            "out_of_scope": dropped,
            "live": [
                {"input": x.get("input"), "url": x.get("url"),
                 "status": x.get("status"), "title": x.get("title"),
                 "server": x.get("server")}
                for x in _trim(alive, 40)
            ],
        }
        summary = "%d alive of %d probed%s" % (
            data["alive"], data["total"],
            (" (%d out-of-scope dropped)" % len(dropped)) if dropped else "")
        return ToolResult(ok=True, tool=self.name, target=target,
                          summary=summary, data=data)


# --------------------------------------------------------------------------- #
# vulnerability scanning
# --------------------------------------------------------------------------- #
class VulnScanTool(Tool):
    name = "vuln_scan"
    description = (
        "Run ONE active vulnerability scanner against a target URL. Valid "
        "scanner keys: sqli, xss, ssrf, ssti, cmdi, jwt, graphql, api_spec, "
        "deserialization, xxe, cloud_metadata, buckets."
    )
    scope_field = "target"
    input_schema = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "URL/host to scan."},
            "scanner": {
                "type": "string",
                "description": "Scanner key to run.",
                "enum": ["sqli", "xss", "ssrf", "ssti", "cmdi", "jwt", "graphql",
                         "api_spec", "deserialization", "xxe", "cloud_metadata",
                         "buckets"],
            },
            "timeout": {"type": "integer", "description": "Scanner timeout (s).",
                        "default": 300},
        },
        "required": ["target", "scanner"],
    }

    def _execute(self, target: str = "", scanner: str = "", timeout: int = 300,
                 **_: Any) -> ToolResult:
        from modules.vuln import scanner_manager
        if scanner not in scanner_manager.SCANNERS:
            return ToolResult(
                ok=False, tool=self.name, target=target,
                error="unknown scanner: %s" % scanner,
                summary="unknown scanner '%s' (valid: %s)" % (
                    scanner, ", ".join(sorted(scanner_manager.SCANNERS))))
        r = scanner_manager.run_scanner(scanner, target, timeout=int(timeout))
        findings = r.get("findings", []) or []
        err = r.get("error")
        data = {
            "scanner": r.get("scanner", scanner),
            "scanner_name": r.get("scanner_name"),
            "findings_count": len(findings),
            "findings": [_compact_finding(f) for f in _trim(findings, 25)],
            "error": err,
        }
        summary = "%s: %d finding(s)%s" % (
            r.get("scanner_name") or scanner, len(findings),
            (" (error: %s)" % err) if err and not findings else "")
        return ToolResult(ok=not (err and not findings), tool=self.name,
                          target=target, summary=summary, data=data,
                          error=err or "")


class VulnScanAllTool(Tool):
    name = "vuln_scan_all"
    description = (
        "Run the full suite of active vulnerability scanners against a target and "
        "return the de-duplicated findings ranked by severity. Heavy — use once "
        "the surface is mapped."
    )
    scope_field = "target"
    input_schema = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "URL/host to scan."},
            "scanners": {"type": "array", "items": {"type": "string"},
                         "description": "Optional subset of scanner keys; omit for all."},
            "timeout": {"type": "integer", "description": "Per-scanner timeout (s).",
                        "default": 300},
        },
        "required": ["target"],
    }

    def _execute(self, target: str = "", scanners: Optional[List[str]] = None,
                 timeout: int = 300, **_: Any) -> ToolResult:
        from modules.vuln import scanner_manager
        r = scanner_manager.run_all(target, scanners=scanners, timeout=int(timeout),
                                    verbose=False)
        findings = r.get("findings", []) or []
        by_sev: Dict[str, int] = {}
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            by_sev[sev] = by_sev.get(sev, 0) + 1
        data = {
            "scanners_run": r.get("scanners_run", []) or [],
            "scanners_failed": len(r.get("scanners_failed", []) or []),
            "total_findings": r.get("total_findings", len(findings)),
            "by_severity": by_sev,
            "findings": [_compact_finding(f) for f in _trim(findings, 25)],
            "errors": _trim(r.get("errors", []), 5),
        }
        summary = "%d finding(s) across %d scanner(s) [%s]" % (
            data["total_findings"], len(data["scanners_run"]),
            ", ".join("%s=%d" % (k, v) for k, v in sorted(by_sev.items())) or "none")
        return ToolResult(ok=True, tool=self.name, target=target,
                          summary=summary, data=data)


# --------------------------------------------------------------------------- #
# the whole pipeline
# --------------------------------------------------------------------------- #
class FullReconTool(Tool):
    name = "full_recon"
    description = (
        "Run the full ReconX pipeline on a target (domain OSINT, IP intel, port "
        "scan, DNS, subdomains, fingerprint, SSL, dir-bust, login/register finder, "
        "WAF, params) in parallel and return the compact summary with the risk "
        "indicators. The big one — use it to bootstrap an engagement."
    )
    scope_field = "target"
    input_schema = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Domain to profile."},
            "deep": {"type": "boolean", "description": "Deep mode (slower).",
                     "default": True},
            "max_ips": {"type": "integer",
                        "description": "How many resolved IPs to profile.",
                        "default": 3},
        },
        "required": ["target"],
    }

    def _execute(self, target: str = "", deep: bool = True, max_ips: int = 3,
                 **_: Any) -> ToolResult:
        import recon
        r = recon.run_recon(target, deep=bool(deep), save_json=False,
                            max_ips=int(max_ips), screenshots=False)
        summary_block = r.get("summary", {}) or {}
        risk = summary_block.get("risk", {}) or {}
        # The pipeline's own summary dict is already compact; pass it through.
        data = {
            "duration_seconds": r.get("duration_seconds"),
            "deep_mode": r.get("deep_mode"),
            "summary": summary_block,
            "risk_indicators": _trim(risk.get("indicators", []), 25),
        }
        ports = summary_block.get("ports", {}) or {}
        subs = summary_block.get("subdomains", {}) or {}
        summary = "full recon on %s: %d open port(s), %d subdomain(s), %d risk indicator(s)" % (
            target, ports.get("open", 0), subs.get("total", 0),
            risk.get("total", 0))
        return ToolResult(ok=True, tool=self.name, target=target,
                          summary=summary, data=data)


# --------------------------------------------------------------------------- #
# registry export
# --------------------------------------------------------------------------- #
ALL_TOOLS = [
    ResolveAndOsintTool,
    EnumSubdomainsTool,
    DnsReconTool,
    PortScanTool,
    SslAnalyzeTool,
    WebFingerprintTool,
    DetectWafTool,
    DirBustTool,
    FindLoginTool,
    FindParamsTool,
    LiveProbeTool,
    VulnScanTool,
    VulnScanAllTool,
    FullReconTool,
]

__all__ = [
    "ResolveAndOsintTool", "EnumSubdomainsTool", "DnsReconTool", "PortScanTool",
    "SslAnalyzeTool", "WebFingerprintTool", "DetectWafTool", "DirBustTool",
    "FindLoginTool", "FindParamsTool", "LiveProbeTool", "VulnScanTool",
    "VulnScanAllTool", "FullReconTool", "ALL_TOOLS",
]
