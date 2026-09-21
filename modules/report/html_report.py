# modules/html_report.py
"""ReconX - HTML Dashboard Generator."""

import html
import json
from datetime import datetime
from pathlib import Path


def _esc(t):
    return html.escape(str(t)) if t is not None else ""


def _badge(level):
    colors = {
        "CRITICAL": "#dc2626", "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04", "LOW": "#2563eb", "UNKNOWN": "#6b7280",
    }
    color = colors.get(str(level).upper(), "#6b7280")
    return f'<span class="badge" style="background:{color}">{_esc(level)}</span>'


def _severity_icon(level):
    icons = {"CRITICAL": "🔴", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
    return icons.get(str(level).upper(), "⚪")


def generate_report(report_data, output_path):
    """Generate HTML report."""
    sections = []

    # Phone
    if "phone" in report_data and report_data["phone"]:
        p = report_data["phone"]
        if p.get("valid"):
            risk = p.get("risk", {})
            sections.append(f"""
            <section>
                <h2>📱 Phone OSINT</h2>
                <div class="info-grid">
                    <div><strong>Input:</strong> {_esc(p.get('input'))}</div>
                    <div><strong>E.164:</strong> {_esc(p.get('formats', {}).get('e164'))}</div>
                    <div><strong>Country:</strong> {_esc(p.get('country'))}</div>
                    <div><strong>Carrier:</strong> {_esc(p.get('carrier'))}</div>
                    <div><strong>Type:</strong> {_esc(p.get('type'))}</div>
                    <div><strong>Timezone:</strong> {_esc(p.get('timezone'))}</div>
                    <div><strong>Risk:</strong> {_badge(risk.get('level'))} (score {risk.get('score', 0)})</div>
                </div>
                {_render_risk_reasons(risk.get('reasons', []))}
            </section>
            """)

    # IP
    if "ip" in report_data and report_data["ip"]:
        ip = report_data["ip"]
        cons = ip.get("consensus", {})
        if cons:
            sections.append(f"""
            <section>
                <h2>🌍 IP OSINT</h2>
                <div class="info-grid">
                    <div><strong>IP:</strong> {_esc(ip.get('ip'))}</div>
                    <div><strong>Version:</strong> {_esc(ip.get('ip_version'))}</div>
                    <div><strong>Country:</strong> {_esc(cons.get('country'))}</div>
                    <div><strong>City:</strong> {_esc(cons.get('city'))}</div>
                    <div><strong>ISP:</strong> {_esc(cons.get('isp'))}</div>
                    <div><strong>ASN:</strong> {_esc(cons.get('asn'))}</div>
                </div>
                <div class="confidence">
                    Country: {'✓' if cons.get('country_confidence') else '⚠'}
                    • City: {'✓' if cons.get('city_confidence') else '⚠'}
                    • ISP: {'✓' if cons.get('isp_confidence') else '⚠'}
                </div>
            </section>
            """)

    # Domain
    if "domain" in report_data and report_data["domain"]:
        d = report_data["domain"]
        subs = d.get("subdomains", [])
        whois = d.get("whois", {})
        ips = d.get("ips", {}).get("A", [])

        sections.append(f"""
        <section>
            <h2>🌐 Domain OSINT</h2>
            <div class="info-grid">
                <div><strong>Domain:</strong> {_esc(d.get('domain'))}</div>
                <div><strong>IPs:</strong> {len(ips)}</div>
                <div><strong>Subdomains:</strong> {len(subs)}</div>
                <div><strong>Registrar:</strong> {_esc(whois.get('registrar') or '?')}</div>
            </div>
            {_render_list("IPv4", ips[:20])}
            {_render_subdomains(subs[:30])}
        </section>
        """)

    # Username
    if "username" in report_data and report_data["username"]:
        u = report_data["username"]
        found = u.get("found_on", [])
        sections.append(f"""
        <section>
            <h2>👤 Username OSINT</h2>
            <div class="info-grid">
                <div><strong>Username:</strong> {_esc(u.get('username'))}</div>
                <div><strong>Found on:</strong> {len(found)} platforms</div>
                <div><strong>Tools:</strong> {_esc(', '.join(u.get('tools_used', [])))}</div>
            </div>
            {_render_username_results(found)}
        </section>
        """)

    # CB-UserHunter
    if "username" in report_data and isinstance(report_data["username"], dict) and "found" in report_data["username"]:
        u = report_data["username"]
        found = u.get("found", [])
        sections.append(f"""
        <section>
            <h2>👤 Username OSINT (CB-UserHunter)</h2>
            <div class="info-grid">
                <div><strong>Username:</strong> {_esc(u.get('username'))}</div>
                <div><strong>Platforms:</strong> {u.get('total_platforms', 0)}</div>
                <div><strong>Found:</strong> {len(found)}</div>
                <div><strong>Duration:</strong> {u.get('duration', 0):.1f}s</div>
            </div>
            {_render_cb_results(found)}
        </section>
        """)

    # SSL
    if "ssl" in report_data and report_data["ssl"]:
        s = report_data["ssl"]
        cert = s.get("certificate", {})
        sections.append(f"""
        <section>
            <h2>🔐 SSL/TLS Analyzer</h2>
            <div class="info-grid">
                <div><strong>Host:</strong> {_esc(s.get('hostname'))}</div>
                <div><strong>Protocol:</strong> {_esc(s.get('protocol'))}</div>
                <div><strong>Grade:</strong> {_badge(s.get('grade', '?'))} ({s.get('security_score', 0)}/100)</div>
                <div><strong>CN:</strong> {_esc(cert.get('subject', {}).get('commonName', '?'))}</div>
                <div><strong>Issuer:</strong> {_esc(cert.get('issuer', {}).get('organizationName', '?'))}</div>
                <div><strong>Expires:</strong> {_esc(cert.get('days_until_expiry', '?'))} days</div>
            </div>
            {_render_san(s.get('san_domains', [])[:20])}
        </section>
        """)

    # Ports
    if "port_scan" in report_data and report_data["port_scan"]:
        ps = report_data["port_scan"]
        open_ports = ps.get("open_ports", [])
        sections.append(f"""
        <section>
            <h2>🔍 Port Scanner</h2>
            <div class="info-grid">
                <div><strong>Target:</strong> {_esc(ps.get('target'))}</div>
                <div><strong>Ports scanned:</strong> {ps.get('total_ports', 0)}</div>
                <div><strong>Open:</strong> {len(open_ports)}</div>
                <div><strong>Duration:</strong> {ps.get('scan_duration', 0):.1f}s</div>
            </div>
            {_render_ports(open_ports)}
        </section>
        """)

    # Web fingerprint
    if "fingerprint" in report_data and report_data["fingerprint"]:
        f = report_data["fingerprint"]
        techs = f.get("technologies", [])
        sections.append(f"""
        <section>
            <h2>🌍 Web Fingerprint</h2>
            <div class="info-grid">
                <div><strong>URL:</strong> {_esc(f.get('url'))}</div>
                <div><strong>Server:</strong> {_esc(f.get('server'))}</div>
                <div><strong>Technologies:</strong> {len(techs)}</div>
            </div>
            {_render_techs(techs)}
        </section>
        """)

    # Metadata
    if "metadata" in report_data and report_data["metadata"]:
        m = report_data["metadata"]
        gps = m.get("gps", {})
        sections.append(f"""
        <section>
            <h2>🖼️ Image Metadata</h2>
            <div class="info-grid">
                <div><strong>File:</strong> {_esc(m.get('filepath'))}</div>
                <div><strong>Size:</strong> {_esc(m.get('size_human'))}</div>
                <div><strong>Risk:</strong> {m.get('risk_score', 0)}/100</div>
                <div><strong>EXIF tags:</strong> {len(m.get('exif', {}))}</div>
            </div>
            {_render_gps(gps)}
        </section>
        """)

    # Subdomains
    if "subdomains" in report_data and report_data["subdomains"]:
        s = report_data["subdomains"]
        subs = s.get("subdomains", [])
        by_src = s.get("by_source", {})
        sections.append(f"""
        <section>
            <h2>🌐 Subdomain Enumerator</h2>
            <div class="info-grid">
                <div><strong>Domain:</strong> {_esc(s.get('domain'))}</div>
                <div><strong>Found:</strong> {s.get('total_unique', 0)}</div>
            </div>
            {_render_sources(by_src)}
            {_render_subdomains(subs[:50])}
        </section>
        """)

    # Job scan
    if "job_scan" in report_data and report_data["job_scan"]:
        js = report_data["job_scan"]
        res = js.get("results", {})
        sections.append(f"""
        <section>
            <h2>🎯 Job Scan — {_esc(js.get('target'))}</h2>
            <div class="info-grid">
                <div><strong>IPs:</strong> {len(res.get('domain', {}).get('ips', {}).get('A', []))}</div>
                <div><strong>Subdomains:</strong> {len(res.get('domain', {}).get('subdomains', []))}</div>
                <div><strong>Open ports:</strong> {len(res.get('ports', {}).get('open_ports', []))}</div>
                <div><strong>Technologies:</strong> {len(res.get('fingerprint', {}).get('technologies', []))}</div>
                <div><strong>SSL Grade:</strong> {_badge(res.get('ssl', {}).get('grade', '?'))}</div>
            </div>
        </section>
        """)

    # Build full HTML
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconX Report - {_esc(report_data.get('username', report_data.get('domain', 'Report')))}</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #0f172a;
    color: #e2e8f0;
    padding: 20px;
    line-height: 1.6;
}}
.container {{ max-width: 1200px; margin: 0 auto; }}
header {{
    background: linear-gradient(135deg, #1e293b, #0f172a);
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 30px;
    margin-bottom: 24px;
    text-align: center;
}}
h1 {{ font-size: 32px; color: #38bdf8; margin-bottom: 12px; }}
.subtitle {{ color: #94a3b8; font-size: 14px; margin: 4px 0; }}
section {{
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 20px;
}}
h2 {{ color: #38bdf8; margin-bottom: 20px; border-bottom: 1px solid #334155; padding-bottom: 12px; }}
.info-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 12px;
    margin-bottom: 16px;
}}
.info-grid > div {{
    background: #0f172a;
    padding: 12px;
    border-radius: 8px;
    border: 1px solid #334155;
    font-size: 14px;
}}
.badge {{
    display: inline-block;
    padding: 2px 10px;
    border-radius: 6px;
    color: white;
    font-size: 12px;
    font-weight: 600;
}}
.confidence {{
    background: #0f172a;
    padding: 12px;
    border-radius: 8px;
    color: #94a3b8;
    font-size: 13px;
}}
ul {{ list-style: none; }}
li {{ padding: 8px 12px; border-bottom: 1px solid #334155; font-size: 14px; }}
li:last-child {{ border-bottom: none; }}
li:hover {{ background: #0f172a; }}
table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}
th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #334155; font-size: 13px; }}
th {{ background: #0f172a; color: #94a3b8; font-size: 11px; text-transform: uppercase; }}
.warn {{ color: #fbbf24; padding: 12px; background: rgba(251, 191, 36, 0.1); border-left: 3px solid #fbbf24; border-radius: 4px; margin: 8px 0; }}
.high {{ color: #ef4444; }}
footer {{ text-align: center; color: #64748b; padding: 20px; font-size: 13px; }}
a {{ color: #38bdf8; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>🔍 ReconX Report</h1>
        <div class="subtitle">Comprehensive OSINT Toolkit v1.0.0</div>
        <div class="subtitle">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    </header>

    {''.join(sections) if sections else '<section><h2>No data</h2><p>Report is empty.</p></section>'}

    <footer>
        ReconX v1.0.0 — Open Source OSINT Toolkit<br>
        <a href="https://github.com/jude84162-sys/ReconX">github.com/jude84162-sys/ReconX</a>
    </footer>
</div>
</body>
</html>
"""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_content, encoding="utf-8")
    return path


def _render_risk_reasons(reasons):
    if not reasons:
        return ""
    items = "".join(
        f'<li class="{level.lower()}">{_severity_icon(level)} {_esc(reason)}</li>'
        for level, reason in reasons
    )
    return f"<h3>Risk Reasons</h3><ul>{items}</ul>"


def _render_list(title, items):
    if not items:
        return ""
    lis = "".join(f"<li>{_esc(i)}</li>" for i in items)
    return f"<h3>{_esc(title)}</h3><ul>{lis}</ul>"


def _render_subdomains(subs):
    if not subs:
        return ""
    rows = "".join(
        f"<tr><td>{_esc(s.get('hostname'))}</td><td>{_esc(s.get('ip', '?'))}</td></tr>"
        for s in subs
    )
    return f"<h3>Subdomains</h3><table><thead><tr><th>Hostname</th><th>IP</th></tr></thead><tbody>{rows}</tbody></table>"


def _render_username_results(found):
    if not found:
        return ""
    rows = "".join(
        f'<tr><td>{_esc(f.get("platform"))}</td><td><a href="{_esc(f.get("url"))}">{_esc(f.get("url"))}</a></td></tr>'
        for f in found
    )
    return f"<table><thead><tr><th>Platform</th><th>URL</th></tr></thead><tbody>{rows}</tbody></table>"


def _render_cb_results(found):
    if not found:
        return ""
    rows = "".join(
        f'<tr><td>{_esc(f.get("platform"))}</td><td>{_esc(f.get("type", "?"))}</td>'
        f'<td><a href="{_esc(f.get("url"))}">{_esc(f.get("url"))}</a></td></tr>'
        for f in found
    )
    return f"<table><thead><tr><th>Platform</th><th>Type</th><th>URL</th></tr></thead><tbody>{rows}</tbody></table>"


def _render_san(domains):
    if not domains:
        return ""
    lis = "".join(f"<li>{_esc(d)}</li>" for d in domains)
    return f"<h3>SAN Domains</h3><ul>{lis}</ul>"


def _render_ports(ports):
    if not ports:
        return ""
    rows = "".join(
        f"<tr><td>{p.get('port')}</td><td>{_esc(p.get('service'))}</td>"
        f"<td>{_esc(p.get('banner') or '')[:80]}</td>"
        f"<td>{_esc(p.get('vuln_hint') or '')[:80]}</td></tr>"
        for p in ports
    )
    return f"<table><thead><tr><th>Port</th><th>Service</th><th>Banner</th><th>Hint</th></tr></thead><tbody>{rows}</tbody></table>"


def _render_techs(techs):
    if not techs:
        return ""
    lis = "".join(f"<li>{_esc(t.get('name'))} <span style='color:#94a3b8'>[{_esc(t.get('type'))}]</span></li>" for t in techs)
    return f"<ul>{lis}</ul>"


def _render_gps(gps):
    if not gps:
        return ""
    if gps.get("_decimal"):
        d = gps["_decimal"]
        url = gps.get("_maps_url", "")
        return f'<div class="warn">📍 GPS: {d["lat"]}, {d["lon"]} — <a href="{url}">View on Map</a></div>'
    return ""


def _render_sources(sources):
    if not sources:
        return ""
    lis = "".join(f"<li>{_esc(k)}: {v}</li>" for k, v in sources.items())
    return f"<h3>Sources</h3><ul>{lis}</ul>"


def save_html_report(report_data, prefix="report"):
    """Save HTML report."""
    outputs = Path(__file__).parent.parent / "outputs"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_{ts}.html"
    return generate_report(report_data, outputs / filename)


if __name__ == "__main__":
    # Test
    test_data = {
        "phone": {
            "valid": True,
            "input": "+19005551234",
            "country": "United States",
            "carrier": "Unknown",
            "type": "PREMIUM_RATE",
            "timezone": "America/Adak",
            "formats": {"e164": "+19005551234"},
            "risk": {"level": "CRITICAL", "score": 70, "reasons": [["HIGH", "Premium rate"], ["HIGH", "US Premium"]]},
        },
    }
    out = save_html_report(test_data, "test")
    print(f"✓ Generated: {out}")
