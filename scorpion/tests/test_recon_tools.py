"""Unit tests for the ReconX tool wrappers.

Every wrapped ReconX module function is monkeypatched to return a canned dict,
so these tests never touch DNS, HTTP, TLS, or any scanner — no real network and
no real scanning. We assert:

  * the registry exposes well-formed Anthropic tool specs for every tool,
  * an in-scope call returns ok=True with a compact, extracted ``data`` payload,
  * an out-of-scope target is refused by the Scope Guard before the module runs,
  * the list-taking ``live_probe`` tool drops out-of-scope hosts itself, and
  * argument / error edge cases (bad scanner key, domain->IP resolution) behave.
"""
import unittest
from unittest import mock

from scorpion.scope import Scope
from scorpion.ratelimit import NullRateLimiter
from scorpion.tools.base import ToolRegistry, ToolResult
from scorpion.tools import recon_tools
from scorpion.tools.recon_tools import ALL_TOOLS


ALLOW = ["example.com"]


def make_registry():
    reg = ToolRegistry(Scope(allow=ALLOW), NullRateLimiter())
    reg.register_all(ALL_TOOLS)
    return reg


# --------------------------------------------------------------------------- #
# canned module return values (shaped like the real modules')
# --------------------------------------------------------------------------- #
CANNED = {
    "domain_osint": {
        "domain": "example.com",
        "ips": {"A": ["93.184.216.34"], "AAAA": []},
        "reverse_dns": {"93.184.216.34": "example.com"},
        "dns_records": {"A": ["93.184.216.34"]},
        "whois": {"registrar": "ICANN Reserved"},
        "subdomains": [{"hostname": "www.example.com", "ip": "93.184.216.34"},
                       {"hostname": "api.example.com", "ip": "93.184.216.35"}],
        "unverified": [],
        "sources_used": ["crt.sh (2 found)", "whois"],
        "errors": [],
    },
    "subfinder": {
        "domain": "example.com",
        "subdomains": [
            {"hostname": "www.example.com", "ip": "93.184.216.34", "sources": ["crtsh"]},
            {"hostname": "api.example.com", "ip": "93.184.216.35", "sources": ["crtsh"]},
            {"hostname": "dev.example.com", "ip": None, "sources": ["bruteforce"]},
        ],
        "by_source": {"crtsh": 2, "bruteforce": 1},
        "total": 3,
        "errors": [],
        "wildcard": False,
    },
    "dns_deep": {
        "domain": "example.com",
        "records": {},
        "nameservers": ["a.iana-servers.net", "b.iana-servers.net"],
        "mx": ["0 ."],
        "txt": ["v=spf1 -all"],
        "caa": [],
        "cname": [],
        "spf": "v=spf1 -all",
        "dmarc": "v=DMARC1; p=reject;",
        "soa": None,
        "zone_transfer": None,
        "indicators": [],
        "error": None,
    },
    "port_scan": {
        "target": "93.184.216.34",
        "resolved_ip": "93.184.216.34",
        "total_ports": 22,
        "open_ports": [
            {"port": 80, "state": "open", "service": "http", "banner": None,
             "vuln_hint": None},
            {"port": 443, "state": "open", "service": "https", "banner": None,
             "vuln_hint": None},
        ],
        "closed_count": 20,
        "filtered_count": 0,
        "errors": [],
    },
    "ssl": {
        "hostname": "example.com",
        "port": 443,
        "certificate": {
            "subject": {"commonName": "example.com"},
            "issuer": {"organizationName": "DigiCert Inc"},
            "notAfter": "Jan 15 23:59:59 2027 GMT",
            "days_until_expiry": 420,
        },
        "protocol": "TLSv1.3",
        "cipher": {"name": "TLS_AES_256_GCM_SHA384"},
        "san_domains": ["example.com", "www.example.com"],
        "issues": [],
        "security_score": 100,
        "grade": "A",
        "error": None,
    },
    "fingerprint": {
        "url": "http://example.com",
        "final_url": "https://example.com/",
        "status": 200,
        "server": "ECS",
        "powered_by": "?",
        "technologies": [{"name": "nginx"}, {"name": "React"}],
        "security_headers": {"Strict-Transport-Security": {"value": "max-age=1"}},
        "missing_headers": ["Content-Security-Policy", "X-Frame-Options"],
        "cookies": [],
        "title": "Example Domain",
        "error": None,
    },
    "waf": {
        "url": "http://example.com",
        "wafs_detected": [{"waf": "Cloudflare", "confidence": 0.9}],
        "blocked_payloads": 3,
        "tests": [{"type": "normal"}, {"type": "suspicious"}],
        "error": None,
    },
    "dir_bust": {
        "url": "http://example.com",
        "found": [
            {"path": "/admin", "status": 200, "severity": "high", "sensitive": True},
            {"path": "/robots.txt", "status": 200, "severity": "info",
             "sensitive": False},
        ],
        "total_checked": 120,
        "sensitive_findings": [
            {"path": "/admin", "status": 200, "severity": "high", "sensitive": True}],
        "errors": [],
    },
    "login": {
        "url": "http://example.com",
        "found": [{"url": "http://example.com/login", "path": "/login",
                   "is_login": True, "confidence": 0.95}],
        "total_checked": 30,
        "errors": [],
    },
    "params": {
        "url": "http://example.com",
        "accepted": [
            {"param": "q", "reflected": True, "confidence": 0.8},
            {"param": "id", "reflected": False, "confidence": 0.5},
        ],
        "total_checked": 50,
        "errors": [],
    },
    "scanner_one": {
        "scanner": "sqli",
        "scanner_name": "SQL Injection",
        "findings": [
            {"title": "SQLi in id", "severity": "critical", "type": "sqli",
             "url": "http://example.com/?id=1", "param": "id"}],
    },
    "scanner_all": {
        "target": "http://example.com",
        "scanners_run": ["sqli", "xss"],
        "scanners_failed": [{"scanner": "jwt", "error": "no token"}],
        "findings": [
            {"title": "SQLi in id", "severity": "critical", "type": "sqli",
             "url": "http://example.com/?id=1"},
            {"title": "Reflected XSS", "severity": "high", "type": "xss",
             "url": "http://example.com/?q=x"},
        ],
        "errors": [],
        "total_findings": 2,
    },
    "recon": {
        "target": "example.com",
        "deep_mode": True,
        "duration_seconds": 12.3,
        "steps": {"domain": {"_big": "dropped"}},
        "summary": {
            "target": "example.com",
            "primary_ip": "93.184.216.34",
            "ports": {"scanned": 100, "open": 2},
            "subdomains": {"total": 7, "by_source": {"crtsh": 7}, "live": 4},
            "ssl": {"grade": "A", "protocol": "TLSv1.3"},
            "risk": {"severity_counts": {"HIGH": 1}, "total": 1,
                     "indicators": [{"severity": "HIGH", "category": "exposed",
                                     "detail": "Exposed /admin"}]},
        },
    },
}


def probe_fake(targets, **kwargs):
    """Mimic live_probe.probe_hosts for whatever host list it is handed."""
    targets = list(targets)
    results = []
    for t in targets:
        results.append({"input": t, "host": t, "alive": True,
                        "url": "http://%s/" % t, "status": 200,
                        "title": "T", "server": "nginx"})
    return {"timestamp": "x", "total": len(targets), "alive": len(targets),
            "dead": 0, "results": results}


# --------------------------------------------------------------------------- #
# registry / spec shape
# --------------------------------------------------------------------------- #
class RegistryShapeTests(unittest.TestCase):
    def test_all_tools_registered(self):
        reg = make_registry()
        self.assertEqual(len(reg.names()), len(ALL_TOOLS))
        # names are unique
        self.assertEqual(len(set(reg.names())), len(ALL_TOOLS))
        for expected in ("resolve_and_osint", "enum_subdomains", "dns_recon",
                         "port_scan", "ssl_analyze", "web_fingerprint",
                         "detect_waf", "dir_bust", "find_login", "find_params",
                         "live_probe", "vuln_scan", "vuln_scan_all", "full_recon"):
            self.assertIn(expected, reg.names())

    def test_specs_are_anthropic_shaped(self):
        reg = make_registry()
        specs = reg.specs()
        self.assertTrue(specs)
        self.assertEqual(len(specs), len(ALL_TOOLS))
        for spec in specs:
            self.assertIn("name", spec)
            self.assertIn("description", spec)
            self.assertIn("input_schema", spec)
            self.assertTrue(spec["name"])
            self.assertTrue(spec["description"])
            schema = spec["input_schema"]
            self.assertEqual(schema.get("type"), "object")
            self.assertIsInstance(schema.get("properties"), dict)
            self.assertTrue(schema["properties"])
            # every required field is actually a declared property
            for req in schema.get("required", []):
                self.assertIn(req, schema["properties"])


# --------------------------------------------------------------------------- #
# scope enforcement
# --------------------------------------------------------------------------- #
class ScopeEnforcementTests(unittest.TestCase):
    def test_out_of_scope_is_blocked_before_module_runs(self):
        reg = make_registry()
        with mock.patch("modules.web.web_fingerprint.run_web_fingerprint") as m:
            res = reg.call("web_fingerprint", {"url": "http://evil.com/"})
        self.assertFalse(res.ok)
        self.assertTrue(res.blocked)
        self.assertEqual(res.data, {})          # _execute never ran
        m.assert_not_called()                    # the module was never invoked

    def test_out_of_scope_domain_tool_blocked(self):
        reg = make_registry()
        with mock.patch("modules.network.dns_deep.run_dns_deep") as m:
            res = reg.call("dns_recon", {"domain": "evil.org"})
        self.assertTrue(res.blocked)
        m.assert_not_called()


# --------------------------------------------------------------------------- #
# per-tool in-scope happy paths
# --------------------------------------------------------------------------- #
class ToolHappyPathTests(unittest.TestCase):
    def _assert_compact(self, res: ToolResult):
        self.assertIsInstance(res, ToolResult)
        self.assertTrue(res.ok, msg=res.error)
        self.assertFalse(res.blocked)
        self.assertTrue(res.summary)
        self.assertIsInstance(res.data, dict)
        # for_llm must stay small and serialisable
        self.assertLessEqual(len(res.for_llm()), 12000)

    def test_resolve_and_osint(self):
        reg = make_registry()
        with mock.patch("modules.web.domain_osint.run_domain_osint",
                        return_value=CANNED["domain_osint"]) as m:
            res = reg.call("resolve_and_osint", {"domain": "example.com"})
        m.assert_called_once()
        self._assert_compact(res)
        self.assertEqual(res.data["primary_ip"], "93.184.216.34")
        self.assertEqual(res.data["subdomains_found"], 2)
        self.assertEqual(res.data["registrar"], "ICANN Reserved")
        self.assertNotIn("dns_records", res.data)   # big field dropped

    def test_enum_subdomains(self):
        reg = make_registry()
        with mock.patch("modules.web.subfinder_clone.run_subfinder_clone",
                        return_value=CANNED["subfinder"]) as m:
            res = reg.call("enum_subdomains", {"domain": "example.com"})
        m.assert_called_once()
        self._assert_compact(res)
        self.assertEqual(res.data["total"], 3)
        self.assertEqual(res.data["resolved"], 2)
        self.assertIn("www.example.com", res.data["hostnames"])
        self.assertIn("found 3 subdomain(s)", res.summary)

    def test_dns_recon(self):
        reg = make_registry()
        with mock.patch("modules.network.dns_deep.run_dns_deep",
                        return_value=CANNED["dns_deep"]) as m:
            res = reg.call("dns_recon", {"domain": "example.com"})
        m.assert_called_once()
        self._assert_compact(res)
        self.assertEqual(len(res.data["nameservers"]), 2)
        self.assertFalse(res.data["zone_transfer_open"])
        self.assertIn("SPF=set", res.summary)
        self.assertIn("DMARC=set", res.summary)

    def test_port_scan_resolves_domain(self):
        reg = make_registry()
        with mock.patch("modules.web.domain_osint._resolve_all_ips",
                        return_value={"A": ["93.184.216.34"], "AAAA": []}) as rm, \
             mock.patch("modules.network.port_scan.scan_port_range",
                        return_value=CANNED["port_scan"]) as sm:
            res = reg.call("port_scan", {"target": "example.com", "ports": "common"})
        rm.assert_called_once()           # domain was resolved to an IP
        sm.assert_called_once()
        # the scan ran against the resolved IP, not the domain
        self.assertEqual(sm.call_args[0][0], "93.184.216.34")
        self._assert_compact(res)
        self.assertEqual(res.data["open_count"], 2)
        self.assertEqual(res.data["resolved_ip"], "93.184.216.34")
        self.assertIn("2 open", res.summary)

    def test_port_scan_ip_skips_resolution(self):
        # An IP target that is in scope via a CIDR allow-list.
        reg = ToolRegistry(Scope(allow=["93.184.216.0/24"]), NullRateLimiter())
        reg.register_all(ALL_TOOLS)
        with mock.patch("modules.web.domain_osint._resolve_all_ips") as rm, \
             mock.patch("modules.network.port_scan.scan_port_range",
                        return_value=CANNED["port_scan"]) as sm:
            res = reg.call("port_scan", {"target": "93.184.216.34"})
        rm.assert_not_called()            # already an IP, no resolution
        sm.assert_called_once()
        self.assertEqual(sm.call_args[0][0], "93.184.216.34")
        self.assertTrue(res.ok)

    def test_ssl_analyze(self):
        reg = make_registry()
        with mock.patch("modules.network.ssl_analyzer.run_ssl_analyzer",
                        return_value=CANNED["ssl"]) as m:
            res = reg.call("ssl_analyze", {"hostname": "example.com"})
        m.assert_called_once()
        self._assert_compact(res)
        self.assertEqual(res.data["grade"], "A")
        self.assertEqual(res.data["issuer"], "DigiCert Inc")
        self.assertEqual(res.data["san_count"], 2)
        self.assertIn("grade=A", res.summary)

    def test_web_fingerprint(self):
        reg = make_registry()
        with mock.patch("modules.web.web_fingerprint.run_web_fingerprint",
                        return_value=CANNED["fingerprint"]) as m:
            res = reg.call("web_fingerprint", {"url": "http://example.com"})
        m.assert_called_once()
        self._assert_compact(res)
        self.assertEqual(res.data["technologies"], ["nginx", "React"])
        self.assertEqual(res.data["status"], 200)
        self.assertEqual(len(res.data["missing_headers"]), 2)

    def test_detect_waf(self):
        reg = make_registry()
        with mock.patch("modules.web.waf_detector.run_waf_detector",
                        return_value=CANNED["waf"]) as m:
            res = reg.call("detect_waf", {"url": "http://example.com"})
        m.assert_called_once()
        self._assert_compact(res)
        self.assertEqual(res.data["wafs_detected"], ["Cloudflare"])
        self.assertEqual(res.data["blocked_payloads"], 3)

    def test_dir_bust(self):
        reg = make_registry()
        with mock.patch("modules.web.dir_buster.run_dir_bust",
                        return_value=CANNED["dir_bust"]) as m:
            res = reg.call("dir_bust", {"url": "http://example.com"})
        m.assert_called_once()
        self._assert_compact(res)
        self.assertEqual(res.data["found_count"], 2)
        self.assertEqual(res.data["sensitive_count"], 1)

    def test_find_login(self):
        reg = make_registry()
        with mock.patch("modules.web.login_finder.run_login_finder",
                        return_value=CANNED["login"]) as m:
            res = reg.call("find_login", {"url": "http://example.com"})
        m.assert_called_once()
        self._assert_compact(res)
        self.assertEqual(res.data["found_count"], 1)
        self.assertEqual(res.data["found"][0]["url"], "http://example.com/login")

    def test_find_params(self):
        reg = make_registry()
        with mock.patch("modules.web.param_finder.run_param_finder",
                        return_value=CANNED["params"]) as m:
            res = reg.call("find_params", {"url": "http://example.com"})
        m.assert_called_once()
        self._assert_compact(res)
        self.assertEqual(res.data["accepted_count"], 2)
        self.assertEqual(res.data["reflected_count"], 1)

    def test_vuln_scan_one(self):
        reg = make_registry()
        with mock.patch("modules.vuln.scanner_manager.run_scanner",
                        return_value=CANNED["scanner_one"]) as m:
            res = reg.call("vuln_scan",
                           {"target": "http://example.com", "scanner": "sqli"})
        m.assert_called_once()
        self._assert_compact(res)
        self.assertEqual(res.data["findings_count"], 1)
        self.assertEqual(res.data["findings"][0]["severity"], "critical")
        self.assertIn("param", res.data["findings"][0])

    def test_vuln_scan_all(self):
        reg = make_registry()
        with mock.patch("modules.vuln.scanner_manager.run_all",
                        return_value=CANNED["scanner_all"]) as m:
            res = reg.call("vuln_scan_all", {"target": "http://example.com"})
        m.assert_called_once()
        self._assert_compact(res)
        self.assertEqual(res.data["total_findings"], 2)
        self.assertEqual(res.data["by_severity"], {"critical": 1, "high": 1})
        self.assertEqual(res.data["scanners_failed"], 1)

    def test_full_recon(self):
        reg = make_registry()
        with mock.patch("recon.run_recon", return_value=CANNED["recon"]) as m:
            res = reg.call("full_recon", {"target": "example.com"})
        m.assert_called_once()
        self._assert_compact(res)
        self.assertEqual(res.data["summary"]["ports"]["open"], 2)
        self.assertEqual(len(res.data["risk_indicators"]), 1)
        # the enormous raw `steps` dict must not be carried through
        self.assertNotIn("steps", res.data)
        self.assertIn("full recon on example.com", res.summary)


# --------------------------------------------------------------------------- #
# vuln_scan edge cases
# --------------------------------------------------------------------------- #
class VulnScanEdgeTests(unittest.TestCase):
    def test_unknown_scanner_key_errors_without_running(self):
        reg = make_registry()
        with mock.patch("modules.vuln.scanner_manager.run_scanner") as m:
            res = reg.call("vuln_scan",
                           {"target": "http://example.com", "scanner": "nope"})
        self.assertFalse(res.ok)
        self.assertFalse(res.blocked)        # it is in scope; just a bad arg
        self.assertIn("unknown scanner", res.error)
        m.assert_not_called()

    def test_scanner_error_with_no_findings_is_not_ok(self):
        reg = make_registry()
        errored = {"scanner": "sqli", "scanner_name": "SQL Injection",
                   "error": "boom", "findings": []}
        with mock.patch("modules.vuln.scanner_manager.run_scanner",
                        return_value=errored):
            res = reg.call("vuln_scan",
                           {"target": "http://example.com", "scanner": "sqli"})
        self.assertFalse(res.ok)
        self.assertIn("boom", res.error)


# --------------------------------------------------------------------------- #
# live_probe: list input + its own scope filtering
# --------------------------------------------------------------------------- #
class LiveProbeTests(unittest.TestCase):
    def test_drops_out_of_scope_hosts(self):
        reg = make_registry()
        with mock.patch("modules.web.live_probe.probe_hosts",
                        side_effect=probe_fake) as m:
            res = reg.call("live_probe", {
                "target": "example.com",
                "hosts": ["www.example.com", "evil.com", "api.example.com"],
            })
        self.assertTrue(res.ok)
        # only in-scope hosts were handed to probe_hosts
        probed = list(m.call_args[0][0])
        self.assertIn("example.com", probed)
        self.assertIn("www.example.com", probed)
        self.assertIn("api.example.com", probed)
        self.assertNotIn("evil.com", probed)
        self.assertEqual(res.data["out_of_scope"], ["evil.com"])
        self.assertEqual(res.data["alive"], 3)
        self.assertIn("out-of-scope dropped", res.summary)

    def test_primary_target_out_of_scope_is_blocked(self):
        reg = make_registry()
        with mock.patch("modules.web.live_probe.probe_hosts") as m:
            res = reg.call("live_probe", {"target": "evil.com",
                                          "hosts": ["www.example.com"]})
        # base class scope-check on the primary target refuses the whole call
        self.assertTrue(res.blocked)
        m.assert_not_called()

    def test_all_extra_hosts_out_of_scope_still_probes_primary(self):
        reg = make_registry()
        with mock.patch("modules.web.live_probe.probe_hosts",
                        side_effect=probe_fake) as m:
            res = reg.call("live_probe", {"target": "example.com",
                                          "hosts": ["evil.com", "bad.net"]})
        self.assertTrue(res.ok)
        probed = list(m.call_args[0][0])
        self.assertEqual(probed, ["example.com"])
        self.assertEqual(sorted(res.data["out_of_scope"]), ["bad.net", "evil.com"])


if __name__ == "__main__":
    unittest.main()
