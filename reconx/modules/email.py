import hashlib
import requests
from reconx.core.engine import Module
from reconx.utils.http import safe_request, dns_lookup
from reconx.utils.output import (
    print_found, print_not_found, print_error, print_info, print_success, print_warning,
)

requests.packages.urllib3.disable_warnings()


class EmailRecon(Module):
    """Gather intelligence on email addresses."""

    name = "email"
    description = "Email reconnaissance: breach checks, domain info, and linked accounts"

    def run(self, target):
        """Run full email reconnaissance."""
        self.target = target.lower().strip()
        print_info(f"Starting email reconnaissance for: {self.target}")

        self._check_syntax()
        self._extract_domain()
        self._check_hibp()
        self._check_gravatar()
        self._check_fullcontact()
        self._domain_intel()
        self._social_guess()

        return self.results

    def _check_syntax(self):
        """Validate email syntax."""
        import re
        pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
        if re.match(pattern, self.target):
            print_success(f"Valid email format")
            self.add_result("Syntax Check", self.target, "valid")
        else:
            print_error(f"Invalid email format")
            self.add_result("Syntax Check", self.target, "invalid")

    def _extract_domain(self):
        """Extract domain from email."""
        self.domain = self.target.split("@")[-1]
        print_info(f"Domain: {self.domain}")
        self.add_result("Domain", self.domain, "extracted")

    def _check_hibp(self):
        """Check Have I Been Pwned for breaches."""
        print_info("Checking Have I Been Pwned...")
        sha1 = hashlib.sha1(self.target.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        try:
            resp = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                hashes = resp.text.splitlines()
                for h in hashes:
                    parts = h.split(":")
                    if len(parts) == 2 and parts[0] == suffix:
                        count = int(parts[1].strip())
                        print_found(f"HIBP: Email found in {count} data breaches")
                        self.add_result(
                            "Have I Been Pwned",
                            f"https://haveibeenpwned.com/account/{self.target}",
                            "found",
                            {"breaches": count},
                        )
                        return
                print_not_found("HIBP: No breaches found")
                self.add_result("Have I Been Pwned", "", "not_found")
            else:
                print_warning("HIBP: API request failed (rate limited or unavailable)")
                self.add_result("Have I Been Pwned", "", "error")
        except Exception as e:
            print_error(f"HIBP check failed: {e}")
            self.add_result("Have I Been Pwned", "", "error")

    def _check_gravatar(self):
        """Check if Gravatar profile exists for this email."""
        print_info("Checking Gravatar...")
        md5 = hashlib.md5(self.target.encode().strip().lower()).hexdigest()
        url = f"https://www.gravatar.com/avatar/{md5}"
        profile_url = f"https://www.gravatar.com/{md5}"

        try:
            resp = requests.head(url + "?d=404", timeout=self.timeout, verify=False)
            if resp.status_code == 200:
                print_found(f"Gravatar profile found: {profile_url}")
                self.add_result("Gravatar", profile_url, "found")
            else:
                print_not_found("Gravatar: No profile found")
                self.add_result("Gravatar", "", "not_found")
        except Exception as e:
            print_error(f"Gravatar check failed: {e}")

    def _check_fullcontact(self):
        """Check FullContact (free tier - limited info)."""
        print_info("Checking FullContact...")
        url = f"https://api.fullcontact.com/v3/person.enrich"
        print_warning("FullContact requires an API key for full results")
        self.add_result("FullContact", "https://www.fullcontact.com/", "api_key_required")

    def _domain_intel(self):
        """Gather domain intelligence."""
        print_info(f"Gathering domain intelligence for {self.domain}...")

        # MX Record Check
        try:
            import dns.resolver
            try:
                answers = dns.resolver.resolve(self.domain, "MX")
                mx_records = [str(r.exchange).rstrip(".") for r in answers]
                print_success(f"MX Records: {', '.join(mx_records)}")
                self.add_result("MX Records", ", ".join(mx_records), "found")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                print_warning("No MX records found (may not be a real email domain)")
                self.add_result("MX Records", "", "not_found")
            except Exception:
                print_warning("Could not check MX records (DNS library issue)")
        except ImportError:
            print_warning("dnspython not installed - skipping MX lookup. Install with: pip install dnspython")

        # SPF Record
        try:
            import dns.resolver
            try:
                answers = dns.resolver.resolve(self.domain, "TXT")
                spf_records = [
                    str(r).strip('"')
                    for r in answers
                    if str(r).startswith("v=spf1")
                ]
                if spf_records:
                    print_success(f"SPF Record: {spf_records[0][:80]}...")
                    self.add_result("SPF Record", spf_records[0], "found")
                else:
                    print_warning("No SPF record found")
            except Exception:
                pass
        except ImportError:
            pass

        # DMARC Record
        try:
            import dns.resolver
            try:
                answers = dns.resolver.resolve(f"_dmarc.{self.domain}", "TXT")
                dmarc_records = [
                    str(r).strip('"') for r in answers
                ]
                if dmarc_records:
                    print_success(f"DMARC Record: {dmarc_records[0]}")
                    self.add_result("DMARC Record", dmarc_records[0], "found")
            except Exception:
                print_warning("No DMARC record found")
        except ImportError:
            pass

        # IP resolution
        ips = dns_lookup(self.domain)
        if ips:
            print_success(f"Domain IPs: {', '.join(ips)}")
            self.add_result("Domain IPs", ", ".join(ips), "found")
        else:
            print_warning("Could not resolve domain")

    def _social_guess(self):
        """Guess possible social media accounts based on email username."""
        username = self.target.split("@")[0]
        print_info(f"Possible usernames derived from email: {username}")
        print_info("Use the username module to search: python -m reconx -u {username}")
        self.add_result(
            "Derived Username",
            username,
            "suggestion",
            {"note": "Run username module with this"},
        )
