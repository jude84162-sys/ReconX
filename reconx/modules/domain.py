import socket
import concurrent.futures
from urllib.parse import urlparse

from reconx.core.engine import Module
from reconx.utils.http import safe_request, dns_lookup
from reconx.utils.output import (
    print_found, print_not_found, print_error, print_info, print_success, print_warning,
)


# Common subdomain wordlist
DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "api", "dev", "staging",
    "test", "admin", "portal", "blog", "shop", "store", "app", "apps",
    "cdn", "static", "media", "images", "img", "assets", "css", "js",
    "vpn", "remote", "gateway", "proxy", "firewall", "router", "switch",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "git", "gitlab", "github", "svn", "ci", "cd", "jenkins", "build",
    "monitor", "grafana", "prometheus", "kibana", "logstash", "elk",
    "mail1", "mail2", "imap", "pop3", "webdisk", "backup", "old",
    "new", "beta", "alpha", "demo", "sandbox", "stage", "prod",
    "production", "internal", "intranet", "extranet", "secure", "ssl",
    "autodiscover", "discover", "directory", "ldap", "ad", "sso",
    "auth", "login", "signin", "signup", "register", "s3", "storage",
    "cloud", "aws", "azure", "gcp", "heroku", "vercel", "netlify",
    "status", "health", "ping", "trace", "debug", "info", "help",
    "support", "tickets", "crm", "erp", "hr", "payroll", "wiki",
    "docs", "doc", "knowledge", "kb", "forum", "community", "chat",
    "teams", "slack", "discord", "webhook", "notify", "notification",
    "search", "analytics", "tracking", "pixel", "ads", "marketing",
    "newsletter", "news", "press", "investor", "legal", "privacy",
    "terms", "about", "contact", "careers", "jobs", "partners",
    "api2", "api-v2", "v1", "v2", "v3", "rest", "graphql",
    "staging1", "staging2", "dev1", "dev2", "qa", "uat", "pre-prod",
    "origin", "edge", "node", "master", "primary", "secondary",
    "relay", "hub", "agent", "worker", "queue", "task", "job",
    "cache", "memcached", "varnish", "nginx", "apache", "tomcat",
    "web", "web1", "web2", "app1", "app2", "srv", "server",
    "client", "portal", "panel", "cpanel", "plesk", "whm",
    "email", "elearning", "lms", "moodle", "canvas", "blackboard",
    "video", "stream", "live", "radio", "tv", "podcast",
    "download", "upload", "files", "share", "drive", "dropbox",
    "calendar", "meet", "zoom", "teams", "webex", "gmeet",
    "pay", "billing", "checkout", "cart", "order", "invoice",
    "oauth", "token", "key", "cert", "pki", "ca",
    "whois", "rdap", "lookup", "query", "search", "find",
    "m", "mobile", "wap", "touch", "pda", "wap",
    "rss", "feed", "atom", "xml", "json", "sitemap",
    "robots", "humans", "security", "securitytxt", "well-known",
    "metrics", "stats", "statistics", "dashboard", "reporting",
    "data", "bigdata", "hadoop", "spark", "kafka", "rabbitmq",
    "consul", "etcd", "zookeeper", "vault", "secret", "config",
    "feature", "flag", "experiment", "ab", "a-b", "split",
]


def _resolve_subdomain(subdomain, domain, timeout):
    """Try to resolve a subdomain."""
    fqdn = f"{subdomain}.{domain}"
    try:
        ips = socket.getaddrinfo(fqdn, None, socket.AF_INET)
        if ips:
            ip_list = list(set([addr[4][0] for addr in ips]))
            return {"subdomain": fqdn, "ips": ip_list, "status": "found"}
    except socket.gaierror:
        pass
    except Exception:
        pass
    return {"subdomain": fqdn, "ips": [], "status": "not_found"}


class DomainRecon(Module):
    """Domain intelligence: DNS, WHOIS, subdomain enumeration, and more."""

    name = "domain"
    description = "Domain intelligence: DNS records, WHOIS, subdomain enumeration"

    def run(self, target):
        """Run full domain reconnaissance."""
        self.target = target.strip()
        if not self.target.startswith("http"):
            self.target = f"https://{self.target}"

        parsed = urlparse(self.target)
        self.domain = parsed.netloc or parsed.path
        self.domain = self.domain.split(":")[0]  # remove port

        print_info(f"Starting domain reconnaissance for: {self.domain}")

        self._dns_records()
        self._whois_lookup()
        self._http_headers()
        self._tech_detect()
        self._subdomain_enum(workers=30)

        return self.results

    def _dns_records(self):
        """Gather DNS records."""
        print_info("Gathering DNS records...")
        record_types = {
            "A": self.domain,
            "AAAA": self.domain,
        }

        for rtype, domain in record_types.items():
            ips = dns_lookup(domain)
            if ips:
                print_success(f"{rtype} Records: {', '.join(ips)}")
                self.add_result(f"{rtype} Record", ", ".join(ips), "found")

        # Try CNAME
        try:
            import dns.resolver
            try:
                answers = dns.resolver.resolve(self.domain, "CNAME")
                for r in answers:
                    print_success(f"CNAME: {r.target}")
                    self.add_result("CNAME Record", str(r.target), "found")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
        except ImportError:
            print_warning("dnspython not installed - limited DNS enumeration")

        # Try NS
        try:
            import dns.resolver
            try:
                answers = dns.resolver.resolve(self.domain, "NS")
                ns_list = [str(r.target).rstrip(".") for r in answers]
                print_success(f"NS Records: {', '.join(ns_list)}")
                self.add_result("NS Record", ", ".join(ns_list), "found")
            except Exception:
                pass
        except ImportError:
            pass

        # Try MX
        try:
            import dns.resolver
            try:
                answers = dns.resolver.resolve(self.domain, "MX")
                mx_list = [f"{r.preference} {r.exchange}" for r in answers]
                print_success(f"MX Records: {', '.join(mx_list)}")
                self.add_result("MX Record", ", ".join(mx_list), "found")
            except Exception:
                pass
        except ImportError:
            pass

        # Try TXT
        try:
            import dns.resolver
            try:
                answers = dns.resolver.resolve(self.domain, "TXT")
                for r in answers:
                    txt = str(r).strip('"')
                    print_success(f"TXT Record: {txt[:100]}")
                    self.add_result("TXT Record", txt, "found")
            except Exception:
                pass
        except ImportError:
            pass

    def _whois_lookup(self):
        """Perform WHOIS lookup."""
        print_info("Performing WHOIS lookup...")
        try:
            import whois
            w = whois.whois(self.domain)
            if w:
                fields = [
                    ("Registrar", w.registrar),
                    ("Creation Date", str(w.creation_date) if w.creation_date else None),
                    ("Expiration Date", str(w.expiration_date) if w.expiration_date else None),
                    ("Name Servers", ", ".join(w.name_servers) if w.name_servers else None),
                    ("Organization", w.org),
                    ("Country", w.country),
                    ("State", w.state),
                    ("City", w.city),
                    ("Updated Date", str(w.updated_date) if w.updated_date else None),
                    ("Status", ", ".join(w.status) if w.status else None),
                    ("DNSSEC", w.dnssec),
                ]
                for label, value in fields:
                    if value:
                        print_success(f"WHOIS {label}: {value}")
                        self.add_result(f"WHOIS {label}", str(value), "found")
            else:
                print_warning("WHOIS: No data returned")
                self.add_result("WHOIS", "", "not_found")
        except ImportError:
            print_warning("python-whois not installed - skipping WHOIS. Install: pip install python-whois")
        except Exception as e:
            print_error(f"WHOIS lookup failed: {e}")

    def _http_headers(self):
        """Check HTTP security headers."""
        print_info("Checking HTTP headers...")
        url = f"https://{self.domain}"
        resp = safe_request(url, timeout=self.timeout, verify_ssl=False)
        if resp:
            security_headers = [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "X-XSS-Protection",
                "Referrer-Policy",
                "Permissions-Policy",
                "Cross-Origin-Opener-Policy",
                "Cross-Origin-Resource-Policy",
            ]
            present = []
            missing = []
            for header in security_headers:
                if header in resp.headers:
                    present.append(header)
                    print_success(f"Header {header}: {resp.headers[header][:60]}")
                else:
                    missing.append(header)
                    print_warning(f"Header {header}: MISSING")

            self.add_result(
                "Security Headers",
                f"Present: {len(present)}, Missing: {len(missing)}",
                "found",
                {"present": present, "missing": missing},
            )

            # Server info
            server = resp.headers.get("Server", "Unknown")
            print_info(f"Server: {server}")
            self.add_result("Server", server, "found")

            # Powered by
            powered = resp.headers.get("X-Powered-By", "Not disclosed")
            if powered != "Not disclosed":
                print_found(f"X-Powered-By: {powered}")
            self.add_result("X-Powered-By", powered, "found")
        else:
            print_error("Could not connect to the domain")

    def _tech_detect(self):
        """Basic technology detection from headers and page content."""
        print_info("Detecting technologies...")
        url = f"https://{self.domain}"
        resp = safe_request(url, timeout=self.timeout, verify_ssl=False)
        if resp:
            techs = []
            content = resp.text.lower()
            headers_str = str(resp.headers).lower()

            # Check various technologies
            checks = [
                ("WordPress", "wp-content" in content or "wordpress" in content),
                ("React", "react" in content or "__next" in content or "_next" in content),
                ("Next.js", "_next" in content or "__next" in content),
                ("Vue.js", "vue" in content or "v-cloak" in content),
                ("Angular", "ng-version" in content or "angular" in content),
                ("jQuery", "jquery" in content),
                ("Bootstrap", "bootstrap" in content),
                ("Tailwind CSS", "tailwind" in content),
                ("Cloudflare", "cloudflare" in headers_str),
                ("Nginx", "nginx" in headers_str),
                ("Apache", "apache" in headers_str),
                ("Express", "x-powered-by: express" in headers_str),
                ("Django", "csrfmiddlewaretoken" in content or "django" in content),
                ("Flask", "flask" in headers_str),
                ("Laravel", "laravel" in content or "laravel_session" in headers_str),
                ("PHP", ".php" in content or "php" in headers_str),
                ("ASP.NET", "asp.net" in headers_str or "__viewstate" in content),
                ("Shopify", "shopify" in content),
                ("WooCommerce", "woocommerce" in content),
                ("Joomla", "joomla" in content),
                ("Drupal", "drupal" in content),
                ("CloudFront", "cloudfront" in headers_str),
                ("Vercel", "vercel" in headers_str or "vercel" in content),
                ("Netlify", "netlify" in headers_str or "netlify" in content),
                ("Heroku", "heroku" in headers_str),
                ("GitHub Pages", "github.io" in content or "github-pages" in headers_str),
            ]

            for tech_name, detected in checks:
                if detected:
                    techs.append(tech_name)
                    print_found(f"Technology detected: {tech_name}")

            if techs:
                self.add_result("Technologies", ", ".join(techs), "found")
            else:
                print_warning("No common technologies detected")
                self.add_result("Technologies", "", "not_found")
        else:
            print_error("Could not connect for tech detection")

    def _subdomain_enum(self, workers=30):
        """Enumerate subdomains using a built-in wordlist."""
        print_info(f"Enumerating subdomains with {workers} threads...")
        print_info(f"Wordlist size: {len(DEFAULT_SUBDOMAINS)} subdomains")

        found_subdomains = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(_resolve_subdomain, sub, self.domain, self.timeout): sub
                for sub in DEFAULT_SUBDOMAINS
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result["status"] == "found":
                    ips_str = ", ".join(result["ips"])
                    print_found(f"Subdomain: {result['subdomain']} -> {ips_str}")
                    self.add_result(
                        "Subdomain",
                        result["subdomain"],
                        "found",
                        {"ips": result["ips"]},
                    )
                    found_subdomains.append(result["subdomain"])

        if found_subdomains:
            print_success(f"Found {len(found_subdomains)} subdomains")
        else:
            print_warning("No subdomains found")

        return found_subdomains
