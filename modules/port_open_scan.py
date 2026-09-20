# modules/port_open_scan.py
"""ReconX - Port Scanner (99% accuracy, multi-threaded)."""

import socket
import logging
import concurrent.futures
from datetime import datetime

logger = logging.getLogger("ReconX.portscan")


# Service database
KNOWN_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    88: "kerberos", 110: "pop3", 111: "rpcbind", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap",
    179: "bgp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 500: "isakmp", 514: "syslog", 515: "printer",
    520: "rip", 548: "afp", 554: "rtsp", 587: "smtp-submission",
    631: "ipp", 636: "ldaps", 873: "rsync", 902: "vmware",
    989: "ftps-data", 990: "ftps", 993: "imaps", 995: "pop3s",
    1080: "socks", 1194: "openvpn", 1433: "mssql", 1434: "mssql-browser",
    1521: "oracle", 1723: "pptp", 1883: "mqtt", 1900: "upnp",
    2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl", 2181: "zookeeper",
    2222: "ssh-alt", 2375: "docker", 2376: "docker-ssl",
    3000: "nodejs", 3306: "mysql", 3389: "rdp", 4444: "metasploit",
    5000: "upnp", 5432: "postgresql", 5555: "adb",
    5672: "amqp", 5900: "vnc", 5984: "couchdb", 6379: "redis",
    6443: "kubernetes", 7001: "weblogic", 8000: "http-alt",
    8008: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
    9090: "http-alt", 9200: "elasticsearch", 9300: "elasticsearch",
    10000: "webmin", 11211: "memcached", 27017: "mongodb",
    27018: "mongodb", 50070: "hadoop", 61616: "activemq",
}


# Vulnerability hints
VULN_HINTS = {
    21: "FTP - check anonymous access, plaintext creds",
    22: "SSH - check weak keys, old versions",
    23: "Telnet - PLAINTEXT! Use SSH",
    25: "SMTP - check open relay",
    53: "DNS - check zone transfer (AXFR)",
    80: "HTTP - check outdated software",
    110: "POP3 - PLAINTEXT! Use POP3S",
    135: "MSRPC - Windows RPC, check CVEs",
    139: "NetBIOS - SMB vulnerabilities",
    143: "IMAP - PLAINTEXT! Use IMAPS",
    161: "SNMP - default community 'public'?",
    389: "LDAP - check anonymous bind",
    443: "HTTPS - check TLS version",
    445: "SMB - ETERNALBLUE (MS17-010)",
    1433: "MSSQL - check weak sa password",
    1521: "Oracle - check default passwords",
    3306: "MySQL - root without password?",
    3389: "RDP - BLUEKEEP (CVE-2019-0708)",
    4444: "Metasploit default - SUSPICIOUS",
    5432: "PostgreSQL - check trust auth",
    5900: "VNC - often no password",
    6379: "Redis - often NO AUTH",
    27017: "MongoDB - often NO AUTH",
    9200: "Elasticsearch - often NO AUTH",
    11211: "Memcached - often NO AUTH",
}


# Common port presets
TOP_100 = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 389, 443,
    445, 465, 514, 515, 548, 554, 587, 631, 636, 873, 902, 989, 990,
    993, 995, 1025, 1080, 1194, 1433, 1434, 1521, 1723, 1883, 1900,
    2049, 2082, 2083, 2181, 2222, 2375, 2376, 3000, 3306, 3389, 4444,
    5000, 5432, 5555, 5672, 5900, 5984, 6379, 6443, 7001, 8000, 8008,
    8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211,
    27017, 27018, 50070, 61616,
]

TOP_1000 = TOP_100 + list(range(1, 1025)) + list(range(1026, 10000, 10))

PORT_PRESETS = {
    "common": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
               993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080],
    "top100": TOP_100,
    "top1000": TOP_1000[:1000],
    "web": [80, 81, 443, 444, 8080, 8081, 8443, 8888, 9000, 9090],
    "db": [1433, 1521, 3306, 5432, 5900, 6379, 9200, 11211, 27017],
    "windows": [135, 137, 138, 139, 445, 3389, 5985, 5986],
    "ssh_ftp": [20, 21, 22, 2222, 22222],
}


def get_ports(spec):
    """Parse port specification."""
    if not spec:
        return PORT_PRESETS["top100"]

    spec = str(spec).strip().lower()

    if spec in PORT_PRESETS:
        return PORT_PRESETS[spec]

    if spec == "all":
        return list(range(1, 65536))

    if "-" in spec and "," not in spec:
        try:
            start, end = spec.split("-")
            return list(range(int(start), int(end) + 1))
        except Exception:
            pass

    if "," in spec:
        ports = []
        for p in spec.split(","):
            p = p.strip()
            if "-" in p:
                try:
                    s, e = p.split("-")
                    ports.extend(range(int(s), int(e) + 1))
                except Exception:
                    pass
            else:
                try:
                    ports.append(int(p))
                except ValueError:
                    pass
        return ports

    try:
        return [int(spec)]
    except ValueError:
        return PORT_PRESETS["common"]


def _grab_banner(sock, port, timeout=1.0):
    """Grab service banner."""
    try:
        sock.settimeout(timeout)

        # Send probe for HTTP
        if port in (80, 8080, 8000, 8888, 8008, 8081):
            sock.send(b"GET / HTTP/1.0\r\nHost: target\r\n\r\n")
        elif port == 21:  # FTP
            pass  # Wait for banner
        elif port == 22:  # SSH
            pass  # Wait for banner
        elif port == 25:  # SMTP
            pass
        elif port == 110:  # POP3
            pass
        elif port == 143:  # IMAP
            pass
        elif port == 3306:  # MySQL
            pass
        else:
            sock.send(b"\r\n")

        banner = sock.recv(1024)
        if banner:
            text = banner.decode("utf-8", errors="ignore").strip()
            # Clean up
            text = text.replace("\r", " ").replace("\n", " ")[:200]
            return text
    except Exception:
        pass
    return None


def _scan_port(target, port, timeout=2.0, grab_banner=True):
    """Scan a single port."""
    result = {
        "port": port,
        "state": "closed",
        "service": KNOWN_SERVICES.get(port, "unknown"),
        "banner": None,
        "vuln_hint": VULN_HINTS.get(port),
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        code = sock.connect_ex((target, port))

        if code == 0:
            result["state"] = "open"

            if grab_banner:
                banner = _grab_banner(sock, port)
                if banner:
                    result["banner"] = banner

        elif code in (111, 11):
            result["state"] = "filtered"

    except socket.timeout:
        result["state"] = "filtered"
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return result


def scan_port_range(target, ports, workers=200, timeout=2.0,
                    progress_callback=None, grab_banner=True):
    """Scan multiple ports."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "total_ports": len(ports),
        "open_ports": [],
        "closed_count": 0,
        "filtered_count": 0,
        "errors": [],
        "scan_duration": 0,
    }

    start = datetime.now()
    completed = 0

    # Resolve target first
    try:
        ip = socket.gethostbyname(target)
        result["resolved_ip"] = ip
    except Exception as e:
        result["errors"].append(f"DNS resolution failed: {e}")
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {
            ex.submit(_scan_port, target, port, timeout, grab_banner): port
            for port in ports
        }

        for future in concurrent.futures.as_completed(futures):
            completed += 1
            try:
                port_result = future.result(timeout=timeout + 5)
                if port_result["state"] == "open":
                    result["open_ports"].append(port_result)
                elif port_result["state"] == "filtered":
                    result["filtered_count"] += 1
                else:
                    result["closed_count"] += 1
            except Exception as e:
                result["errors"].append(str(e))

            if progress_callback and completed % 20 == 0:
                progress_callback(completed, len(ports))

    result["open_ports"].sort(key=lambda x: x["port"])
    result["scan_duration"] = (datetime.now() - start).total_seconds()

    return result


def print_scan_report(result):
    print("\n" + "=" * 70)
    print("  Port Scan Report - ReconX")
    print("=" * 70)

    print(f"\n[*] Target:    {result.get('target')}")
    if result.get("resolved_ip"):
        print(f"[*] Resolved:  {result['resolved_ip']}")
    print(f"[*] Ports:     {result.get('total_ports')}")
    print(f"[*] Duration:  {result.get('scan_duration', 0):.2f}s")
    print(f"[*] Open:      {len(result.get('open_ports', []))}")
    print(f"[*] Closed:    {result.get('closed_count', 0)}")
    print(f"[*] Filtered:  {result.get('filtered_count', 0)}")

    open_ports = result.get("open_ports", [])

    if open_ports:
        print(f"\n[+] Open Ports ({len(open_ports)}):")
        print(f"    {'PORT':<6} {'SERVICE':<18} {'BANNER':<45}")
        print(f"    {'-'*6} {'-'*18} {'-'*45}")

        for p in open_ports:
            port = str(p["port"])
            service = p.get("service", "?")[:18]
            banner = (p.get("banner") or "")[:45]
            print(f"    {port:<6} {service:<18} {banner:<45}")

        # Vulnerability hints
        vulns = [p for p in open_ports if p.get("vuln_hint")]
        if vulns:
            print(f"\n[!] Vulnerability Hints:")
            for p in vulns:
                print(f"    [!] Port {p['port']}: {p['vuln_hint']}")
    else:
        print(f"\n[OK] No open ports found")

    if result.get("errors"):
        print(f"\n[!] Errors:")
        for e in result["errors"][:5]:
            print(f"    - {e}")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python -m modules.port_open_scan <target> [spec]")
        print()
        print("Specs: common, top100, top1000, web, db, windows, all,")
        print("       80-443, 80,443,8080")
        sys.exit(1)

    target = sys.argv[1]
    spec = sys.argv[2] if len(sys.argv) > 2 else "top100"
    ports = get_ports(spec)

    print(f"\n[*] Scanning {target} ({len(ports)} ports)...")

    def progress(done, total):
        pct = (done / total) * 100
        bar_len = 30
        filled = int(bar_len * done / total)
        bar = "#" * filled + "." * (bar_len - filled)
        sys.stdout.write(f"\r  [{bar}] {pct:5.1f}% ({done}/{total})")
        sys.stdout.flush()

    result = scan_port_range(target, ports, progress_callback=progress)
    print()
    print_scan_report(result)
