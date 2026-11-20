"""The Scope Guard.

Every tool call routes its target through a Scope before a single packet is
sent. The guard is **fail-closed**: an empty scope allows nothing, so a
freshly started agent cannot touch any host until the operator declares what
is in scope. This keeps the agent inside the bug-bounty program's authorised
targets and keeps the operator out of legal trouble.

Scope entries (allow or deny):

    example.com            apex AND every subdomain (the common bounty meaning)
    *.example.com          subdomains only (not the apex)
    .example.com           same as *.example.com
    app.example.com        that exact host (and its own subdomains)
    203.0.113.10           a single IP
    203.0.113.0/24         a CIDR range
    10.0.0.0/8             a CIDR range

A host is in scope when it matches at least one allow entry and matches no
deny entry. Deny always wins.
"""
from __future__ import annotations

import ipaddress
from typing import List, Optional, Tuple
from urllib.parse import urlparse


class ScopeError(Exception):
    """Raised when a target is outside the authorised scope."""


def extract_host(target: str) -> str:
    """Pull a bare hostname/IP out of a URL, host:port, or plain host."""
    if not target:
        return ""
    t = target.strip()
    if "://" in t:
        netloc = urlparse(t).netloc or ""
    else:
        netloc = t.split("/")[0]
    # strip credentials and port (but keep IPv6 brackets handling simple)
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    if netloc.startswith("[") and "]" in netloc:          # [::1]:8080
        return netloc[1:netloc.index("]")].lower()
    if netloc.count(":") == 1:                             # host:port
        netloc = netloc.split(":")[0]
    return netloc.strip(".").lower()


def _as_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _as_net(value: str):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


class _Entry:
    """One parsed scope pattern."""

    __slots__ = ("raw", "net", "ip", "domain", "subdomains_only")

    def __init__(self, raw: str):
        self.raw = raw
        self.net = None
        self.ip = None
        self.domain = None
        self.subdomains_only = False

        value = raw.strip().lower()
        if not value:
            return

        net = _as_net(value) if "/" in value else None
        if net is not None:
            self.net = net
            return
        ip = _as_ip(value)
        if ip is not None:
            self.ip = ip
            return
        if value.startswith("*."):
            self.subdomains_only = True
            value = value[2:]
        elif value.startswith("."):
            self.subdomains_only = True
            value = value[1:]
        self.domain = value.strip(".")

    def matches(self, host: str, host_ip) -> bool:
        if not host:
            return False
        # IP / CIDR entries
        if self.net is not None:
            return host_ip is not None and host_ip in self.net
        if self.ip is not None:
            return host_ip is not None and host_ip == self.ip
        # domain entries
        if self.domain:
            if host_ip is not None:
                return False
            if host == self.domain:
                return not self.subdomains_only
            return host.endswith("." + self.domain)
        return False


class Scope:
    """An allow/deny list of hosts, IPs and CIDRs."""

    def __init__(self, allow: Optional[List[str]] = None,
                 deny: Optional[List[str]] = None):
        self.allow_raw = [a for a in (allow or []) if a and a.strip()]
        self.deny_raw = [d for d in (deny or []) if d and d.strip()]
        self._allow = [_Entry(a) for a in self.allow_raw]
        self._deny = [_Entry(d) for d in self.deny_raw]

    @classmethod
    def from_config(cls, cfg) -> "Scope":
        return cls(allow=getattr(cfg, "scope_allow", None),
                   deny=getattr(cfg, "scope_deny", None))

    @property
    def is_empty(self) -> bool:
        return not self._allow

    def classify(self, target: str) -> Tuple[bool, str]:
        """Return (in_scope, reason)."""
        host = extract_host(target)
        if not host:
            return False, "no host could be parsed from the target"
        if self.is_empty:
            return False, ("scope is empty — nothing is allowed until you set "
                           "an allow-list (fail-closed)")
        host_ip = _as_ip(host)
        for entry in self._deny:
            if entry.matches(host, host_ip):
                return False, "%s is explicitly out of scope (deny: %s)" % (host, entry.raw)
        for entry in self._allow:
            if entry.matches(host, host_ip):
                return True, "%s matches allowed scope %s" % (host, entry.raw)
        return False, "%s is not in the allowed scope %s" % (host, self.allow_raw)

    def is_in_scope(self, target: str) -> bool:
        return self.classify(target)[0]

    def check(self, target: str) -> str:
        """Return the matched host, or raise ScopeError. Call before any request."""
        ok, reason = self.classify(target)
        if not ok:
            raise ScopeError(reason)
        return extract_host(target)

    def describe(self) -> str:
        if self.is_empty:
            return "scope: (empty — all targets blocked)"
        txt = "allow=" + ", ".join(self.allow_raw)
        if self.deny_raw:
            txt += " | deny=" + ", ".join(self.deny_raw)
        return "scope: " + txt
