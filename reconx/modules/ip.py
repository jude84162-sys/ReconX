import json
from reconx.core.engine import Module
from reconx.utils.http import safe_request, reverse_dns
from reconx.utils.output import (
    print_found, print_not_found, print_error, print_info, print_success, print_warning,
)


class IPRecon(Module):
    """IP geolocation, ASN lookup, and profiling."""

    name = "ip"
    description = "IP geolocation, ASN lookup, reverse DNS, and threat intelligence"

    def run(self, target):
        """Run full IP reconnaissance."""
        self.target = target.strip()
        print_info(f"Starting IP reconnaissance for: {self.target}")

        self._validate_ip()
        self._geolocation()
        self._reverse_dns()
        self._asn_lookup()
        self._threat_intel()
        self._ports_check()
        self._abuse_contacts()

        return self.results

    def _validate_ip(self):
        """Validate the IP address format."""
        import re
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'

        if re.match(ipv4_pattern, self.target):
            print_success(f"Valid IPv4 address")
            self.ip_version = 4
            self.add_result("Validation", self.target, "valid", {"version": 4})
        elif re.match(ipv6_pattern, self.target):
            print_success(f"Valid IPv6 address")
            self.ip_version = 6
            self.add_result("Validation", self.target, "valid", {"version": 6})
        else:
            print_error(f"Invalid IP address format")
            self.add_result("Validation", self.target, "invalid")
            return

    def _geolocation(self):
        """Get geolocation data from ip-api.com (free, no key)."""
        print_info("Querying geolocation (ip-api.com)...")
        url = f"http://ip-api.com/json/{self.target}?fields=66846719"
        resp = safe_request(url, timeout=self.timeout)
        if resp and resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                geo_fields = [
                    ("Country", data.get("country")),
                    ("Region", data.get("regionName")),
                    ("City", data.get("city")),
                    ("ZIP", data.get("zip")),
                    ("Latitude", data.get("lat")),
                    ("Longitude", data.get("lon")),
                    ("Timezone", data.get("timezone")),
                    ("ISP", data.get("isp")),
                    ("Org", data.get("org")),
                    ("AS", data.get("as")),
                ]
                for label, value in geo_fields:
                    if value:
                        print_success(f"{label}: {value}")
                        self.add_result(f"Geo {label}", str(value), "found")
                self._geo_data = data
            else:
                print_warning(f"Geolocation API returned: {data.get('message', 'unknown error')}")
        else:
            print_error("Geolocation API request failed")

    def _reverse_dns(self):
        """Perform reverse DNS lookup."""
        print_info("Performing reverse DNS lookup...")
        hostname = reverse_dns(self.target)
        if hostname:
            print_found(f"Reverse DNS: {hostname}")
            self.add_result("Reverse DNS", hostname, "found")
        else:
            print_warning("No reverse DNS record found")
            self.add_result("Reverse DNS", "", "not_found")

    def _asn_lookup(self):
        """Get ASN information."""
        print_info("Looking up ASN information...")
        # Using ip-api.com already gave us ASN, let's also check BGPView
        url = f"https://api.bgpview.io/ip/{self.target}"
        resp = safe_request(url, timeout=self.timeout)
        if resp and resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "ok":
                asn_data = data.get("data", {}).get("asn", {})
                if asn_data:
                    print_success(f"ASN: {asn_data.get('asn')} - {asn_data.get('name')}")
                    print_success(f"AS Description: {asn_data.get('description', 'N/A')}")
                    self.add_result(
                        "ASN",
                        f"{asn_data.get('asn')} - {asn_data.get('name')}",
                        "found",
                        asn_data,
                    )
                    # Prefixes
                    prefixes = data.get("data", {}).get("prefixes", [])
                    if prefixes:
                        print_info(f"BGP Prefixes: {len(prefixes)}")
                        for p in prefixes[:5]:
                            print_info(f"  {p.get('prefix')} ({p.get('name', '')})")
            else:
                print_warning("BGPView: ASN data not available")
        else:
            print_warning("BGPView lookup failed or unavailable")

    def _threat_intel(self):
        """Check threat intelligence sources."""
        print_info("Checking threat intelligence sources...")

        # AbuseIPDB (free with key, but we can show the concept)
        print_info("AbuseIPDB: Requires API key for results. Get free key at abuseipdb.com")
        self.add_result("AbuseIPDB", "https://www.abuseipdb.com/check/{self.target}".format(target=self.target), "api_key_required")

        # VirusTotal
        print_info("VirusTotal: Checking public report...")
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{self.target}"
        print_warning("VirusTotal requires API key for full results")
        self.add_result("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{self.target}", "api_key_required")

        # Shodan
        print_info("Shodan: Checking public report...")
        self.add_result("Shodan", f"https://www.shodan.io/host/{self.target}", "api_key_required")

        # Censys
        self.add_result("Censys", f"https://search.censys.io/hosts/{self.target}", "link")

        # AlienVault OTX
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{self.target}/general"
        resp = safe_request(otx_url, timeout=self.timeout)
        if resp and resp.status_code == 200:
            data = resp.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            if pulse_count > 0:
                print_found(f"AlienVault OTX: {pulse_count} threat pulses found")
                self.add_result("AlienVault OTX", f"{pulse_count} pulses", "found")
            else:
                print_not_found("AlienVault OTX: No threat pulses")
                self.add_result("AlienVault OTX", "0 pulses", "clean")
        else:
            print_warning("AlienVault OTX: Could not retrieve data")

    def _ports_check(self):
        """Check common ports (basic TCP connect)."""
        print_info("Checking common ports (this may take a moment)...")
        import socket

        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            1521: "Oracle",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            9200: "Elasticsearch",
            27017: "MongoDB",
        }

        open_ports = []
        for port, service in common_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                print_found(f"Port {port}/{service}: OPEN")
                open_ports.append({"port": port, "service": service})
                self.add_result(
                    f"Port {port}",
                    service,
                    "open",
                )
            sock.close()

        if open_ports:
            print_success(f"Found {len(open_ports)} open ports")
        else:
            print_warning("No common open ports detected (may be firewalled)")

    def _abuse_contacts(self):
        """Find abuse contacts."""
        print_info("Looking up abuse contacts...")
        # Using AbuseIPDB check URL (public, no key needed for the page)
        url = f"https://www.abuseipdb.com/check/{self.target}"
        self.add_result("Abuse Contact", url, "link")
        print_info(f"Abuse report: {url}")
