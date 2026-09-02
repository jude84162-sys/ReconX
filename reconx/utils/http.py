import requests
import socket
import urllib.parse
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def safe_request(url, method="GET", timeout=10, headers=None, params=None, allow_redirects=True, verify_ssl=True):
    """Make an HTTP request with error handling."""
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    if headers:
        default_headers.update(headers)

    try:
        response = requests.request(
            method=method,
            url=url,
            headers=default_headers,
            timeout=timeout,
            params=params,
            allow_redirects=allow_redirects,
            verify=verify_ssl,
        )
        return response
    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.RequestException:
        return None


def check_username_url(url_template, username, timeout=10):
    """Check if a username exists on a platform given a URL template."""
    url = url_template.format(username=urllib.parse.quote(username))
    try:
        response = requests.get(
            url,
            timeout=timeout,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
            allow_redirects=False,
            verify=False,
        )
        return response
    except Exception:
        return None


def dns_lookup(domain, record_type="A"):
    """Perform DNS lookup for a domain."""
    try:
        answers = socket.getaddrinfo(domain, None)
        ips = list(set([addr[4][0] for addr in answers]))
        return ips
    except socket.gaierror:
        return []


def reverse_dns(ip):
    """Perform reverse DNS lookup."""
    try:
        hostname = socket.gethostbyaddr(ip)
        return hostname[0]
    except (socket.herror, socket.gaierror):
        return None
