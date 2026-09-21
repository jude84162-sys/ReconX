# modules/web_fingerprint.py
"""ReconX - Web Fingerprint (Enhanced signatures - 95%)."""

import re
import ssl
import logging
import urllib.request
import urllib.error
from datetime import datetime

logger = logging.getLogger("ReconX.fingerprint")


# Comprehensive technology signatures
TECH_SIGNATURES = {
    # CMS
    "WordPress": {
        "patterns": [r"wp-content", r"wp-includes", r"/wp-json/", r"wordpress"],
        "type": "CMS"
    },
    "Joomla": {"patterns": [r"/components/com_", r"joomla"], "type": "CMS"},
    "Drupal": {"patterns": [r"Drupal\.settings", r"/sites/default/files"], "type": "CMS"},
    "Magento": {"patterns": [r"Magento", r"mage/cookies", r"/skin/frontend/"], "type": "E-commerce"},
    "Shopify": {"patterns": [r"cdn\.shopify\.com", r"shopify"], "type": "E-commerce"},
    "WooCommerce": {"patterns": [r"woocommerce"], "type": "E-commerce"},
    "PrestaShop": {"patterns": [r"prestashop"], "type": "E-commerce"},
    "Ghost": {"patterns": [r"ghost\.org", r"content=\"Ghost"], "type": "CMS"},
    "Squarespace": {"patterns": [r"squarespace"], "type": "CMS"},
    "Wix": {"patterns": [r"wix\.com", r"wixstatic"], "type": "CMS"},

    # Frontend frameworks
    "React": {"patterns": [r"react", r"__REACT_DEVTOOLS", r"data-reactroot"], "type": "JS Framework"},
    "Vue.js": {"patterns": [r"vue\.js", r"__vue__", r"data-v-"], "type": "JS Framework"},
    "Angular": {"patterns": [r"ng-app", r"angular", r"ng-version"], "type": "JS Framework"},
    "Svelte": {"patterns": [r"svelte"], "type": "JS Framework"},
    "Next.js": {"patterns": [r"__NEXT_DATA__", r"_next/static"], "type": "JS Framework"},
    "Nuxt.js": {"patterns": [r"__NUXT__", r"_nuxt/"], "type": "JS Framework"},
    "Gatsby": {"patterns": [r"gatsby"], "type": "JS Framework"},
    "Ember.js": {"patterns": [r"ember"], "type": "JS Framework"},

    # JS Libraries
    "jQuery": {"patterns": [r"jquery[.-]?\d", r"jquery\.min"], "type": "JS Library"},
    "Bootstrap": {"patterns": [r"bootstrap\.min", r"bootstrap\.bundle"], "type": "CSS Framework"},
    "Tailwind": {"patterns": [r"tailwind"], "type": "CSS Framework"},
    "Bulma": {"patterns": [r"bulma"], "type": "CSS Framework"},
    "Foundation": {"patterns": [r"foundation\.min"], "type": "CSS Framework"},
    "Materialize": {"patterns": [r"materialize"], "type": "CSS Framework"},
    "Font Awesome": {"patterns": [r"font-awesome", r"fontawesome"], "type": "Icons"},

    # Backend
    "Django": {"patterns": [r"csrfmiddlewaretoken", r"django"], "type": "Backend"},
    "Flask": {"patterns": [r"flask", r"werkzeug"], "type": "Backend"},
    "Laravel": {"patterns": [r"laravel_session"], "type": "Backend"},
    "Ruby on Rails": {"patterns": [r"csrf-token", r"rails"], "type": "Backend"},
    "ASP.NET": {"patterns": [r"__VIEWSTATE", r"ASP\.NET", r"__EVENTVALIDATION"], "type": "Backend"},
    "Express.js": {"patterns": [r"express"], "type": "Backend"},
    "Spring": {"patterns": [r"spring", r"jsessionid"], "type": "Backend"},

    # Servers
    "Nginx": {"patterns": [r"nginx"], "type": "Web Server"},
    "Apache": {"patterns": [r"apache"], "type": "Web Server"},
    "IIS": {"patterns": [r"IIS", r"Microsoft-IIS"], "type": "Web Server"},
    "LiteSpeed": {"patterns": [r"litespeed"], "type": "Web Server"},
    "Caddy": {"patterns": [r"caddy"], "type": "Web Server"},
    "Tomcat": {"patterns": [r"tomcat", r"coyote"], "type": "Web Server"},

    # CDN / Security
    "Cloudflare": {"patterns": [r"cloudflare", r"cf-ray"], "type": "CDN"},
    "Akamai": {"patterns": [r"akamai", r"akamaihd"], "type": "CDN"},
    "AWS CloudFront": {"patterns": [r"cloudfront"], "type": "CDN"},
    "Fastly": {"patterns": [r"fastly"], "type": "CDN"},
    "Sucuri": {"patterns": [r"sucuri"], "type": "Security"},

    # Analytics
    "Google Analytics": {"patterns": [r"google-analytics", r"gtag", r"ga\("], "type": "Analytics"},
    "Google Tag Manager": {"patterns": [r"googletagmanager"], "type": "Analytics"},
    "Hotjar": {"patterns": [r"hotjar"], "type": "Analytics"},
    "Mixpanel": {"patterns": [r"mixpanel"], "type": "Analytics"},
    "Segment": {"patterns": [r"segment\.io", r"segment\.com"], "type": "Analytics"},
    "Facebook Pixel": {"patterns": [r"facebook.*pixel", r"fbq\("], "type": "Analytics"},

    # Marketing
    "HubSpot": {"patterns": [r"hubspot", r"hs-scripts"], "type": "Marketing"},
    "Mailchimp": {"patterns": [r"mailchimp", r"chimpstatic"], "type": "Marketing"},
    "Intercom": {"patterns": [r"intercom"], "type": "Support"},
    "Zendesk": {"patterns": [r"zendesk"], "type": "Support"},
}


SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS — forces HTTPS",
    "Content-Security-Policy": "CSP — prevents XSS",
    "X-Frame-Options": "Clickjacking protection",
    "X-Content-Type-Options": "MIME sniffing protection",
    "Referrer-Policy": "Referrer control",
    "Permissions-Policy": "Feature permissions",
    "X-XSS-Protection": "Legacy XSS filter",
    "X-Permitted-Cross-Domain-Policies": "Adobe cross-domain",
    "Cross-Origin-Opener-Policy": "COOP",
    "Cross-Origin-Embedder-Policy": "COEP",
    "Cross-Origin-Resource-Policy": "CORP",
}


def _make_request(url, timeout=15, follow_redirect=True):
    """Fetch URL with headers."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Language": "en-US,en;q=0.9",
            }
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return {
                "status": r.status,
                "headers": dict(r.headers),
                "url": r.url,
                "body": r.read(200000).decode("utf-8", errors="ignore")
            }
    except urllib.error.HTTPError as e:
        return {
            "status": e.code,
            "headers": dict(e.headers),
            "url": url,
            "body": e.read(50000).decode("utf-8", errors="ignore")
        }
    except Exception as e:
        return {"error": str(e)}


def _detect_technologies(body, headers):
    """Detect technologies from body + headers, with confidence per tech."""
    detected = {}

    # === From body ===
    if body:
        for tech, config in TECH_SIGNATURES.items():
            matches = 0
            for pattern in config["patterns"]:
                if re.search(pattern, body, re.IGNORECASE):
                    matches += 1
            if matches > 0:
                # Multiple pattern matches = higher confidence
                conf = min(0.6 + (matches * 0.15), 0.95)
                detected[tech] = {
                    "name": tech,
                    "type": config["type"],
                    "source": "body",
                    "confidence": round(conf, 2),
                    "matches": matches,
                }

    # === From headers (boost confidence) ===
    header_str = str(headers).lower()
    for tech, config in TECH_SIGNATURES.items():
        header_match = False
        for pattern in config["patterns"]:
            if re.search(pattern, header_str, re.IGNORECASE):
                header_match = True
                break

        if header_match:
            if tech in detected:
                # Boost existing
                detected[tech]["confidence"] = min(
                    detected[tech]["confidence"] + 0.20, 0.99
                )
                detected[tech]["source"] = "body+headers"
            else:
                detected[tech] = {
                    "name": tech,
                    "type": config["type"],
                    "source": "headers",
                    "confidence": 0.85,
                    "matches": 1,
                }

    # === Server header detection (high confidence) ===
    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")
    for tech, config in TECH_SIGNATURES.items():
        if tech in detected:
            continue
        for header_val in [server, powered]:
            if header_val:
                for pattern in config["patterns"]:
                    if re.search(pattern, header_val, re.IGNORECASE):
                        detected[tech] = {
                            "name": tech,
                            "type": config["type"],
                            "source": "server_header",
                            "confidence": 0.95,
                            "matches": 1,
                        }
                        break

    return detected


def run_web_fingerprint(url):
    """Fingerprint web target."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "url": url,
        "final_url": None,
        "status": None,
        "server": None,
        "powered_by": None,
        "technologies": [],
        "security_headers": {},
        "missing_headers": [],
        "cookies": [],
        "redirects": [],
        "title": None,
        "error": None
    }

    response = _make_request(url)

    if response.get("error"):
        result["error"] = response["error"]
        return result

    result["status"] = response.get("status")
    result["final_url"] = response.get("url")

    headers = response.get("headers", {})
    body = response.get("body", "")

    result["server"] = headers.get("Server", "?")
    result["powered_by"] = headers.get("X-Powered-By", "?")

    # Security headers
    for h, desc in SECURITY_HEADERS.items():
        value = headers.get(h)
        if value:
            result["security_headers"][h] = {
                "value": value[:100],
                "desc": desc
            }
        else:
            result["missing_headers"].append(h)

    # Cookies
    set_cookie = headers.get("Set-Cookie", "")
    if set_cookie:
        for cookie in set_cookie.split(","):
            cookie = cookie.strip().split(";")[0]
            if cookie:
                result["cookies"].append(cookie)

    # Technologies
    techs = _detect_technologies(body, headers)
    result["technologies"] = list(techs.values())

    # Title
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if title_match:
        result["title"] = title_match.group(1).strip()[:100]

    return result


def print_fingerprint_report(result):
    print("\n" + "=" * 70)
    print("  🌍 Web Fingerprint - ReconX")
    print("=" * 70)

    if result.get("error"):
        print(f"\n[!] {result['error']}")
        return

    print(f"\n[*] URL:      {result['url']}")
    if result.get("final_url") and result["final_url"] != result["url"]:
        print(f"[*] Redirect: {result['final_url']}")
    print(f"[*] Status:   {result.get('status')}")
    print(f"[*] Server:   {result.get('server')}")
    print(f"[*] Powered:  {result.get('powered_by')}")

    if result.get("title"):
        print(f"[*] Title:    {result['title']}")

    techs = result.get("technologies", [])
    if techs:
        # Group by type
        by_type = {}
        for t in techs:
            by_type.setdefault(t["type"], []).append(t["name"])

        print(f"\n[+] Technologies ({len(techs)}):")
        for ttype, names in sorted(by_type.items()):
            print(f"    [{ttype}]")
            for n in names:
                print(f"      • {n}")

    if result.get("security_headers"):
        print(f"\n[+] Security Headers Present ({len(result['security_headers'])}):")
        for h, data in result["security_headers"].items():
            print(f"    ✓ {h}")
            print(f"       {data['desc']}")

    if result.get("missing_headers"):
        print(f"\n[!] Missing Security Headers ({len(result['missing_headers'])}):")
        for h in result["missing_headers"]:
            print(f"    ✗ {h}")

    if result.get("cookies"):
        print(f"\n[+] Cookies ({len(result['cookies'])}):")
        for c in result["cookies"][:5]:
            print(f"    • {c}")

    print("\n" + "=" * 70 + "\n")
