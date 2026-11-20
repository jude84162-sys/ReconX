"""Speed/correctness tests for modules/network (loopback only, no internet access)."""

import errno
import io
import socket
import struct
import threading
import time
import unittest
from contextlib import redirect_stdout
from unittest import mock

from modules.network import dns_deep, port_scan
from tests.helpers import LocalServer, free_port


# ============================================================
# Mock DNS-over-TCP server
# ============================================================

def _recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _name(domain):
    out = b""
    for label in domain.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _rr(owner, rtype, rdata):
    return owner + struct.pack("!HHIH", rtype, 1, 300, len(rdata)) + rdata


def _soa_rdata():
    return _name("ns1.example.test") + _name("admin.example.test") + struct.pack(
        "!IIIII", 2024010101, 3600, 600, 86400, 300)


def _frame(msg):
    return struct.pack("!H", len(msg)) + msg


class MockDnsTcpServer:
    """Length-framed DNS-over-TCP server on 127.0.0.1.

    mode: "refused", "notauth", "noerror", "badid", "silent", "stream".
    The connection is kept open after replying, so a client that waits for
    EOF instead of parsing the reply would hang until its timeout.
    """

    def __init__(self, mode):
        self.mode = mode
        self.queries = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.stop = threading.Event()
        self.conns = []
        self.thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def port(self):
        return self.sock.getsockname()[1]

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        for c in self.conns:
            try:
                c.close()
            except OSError:
                pass
        self.thread.join(timeout=5)

    def _serve(self):
        self.sock.settimeout(0.2)
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.conns.append(conn)
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(5)
            head = _recv_exact(conn, 2)
            if head is None:
                return
            (length,) = struct.unpack("!H", head)
            query = _recv_exact(conn, length)
            if query is None:
                return
            self.queries.append(query)
            (txn_id,) = struct.unpack("!H", query[:2])
            question = query[12:]
            send = lambda msg: conn.sendall(_frame(msg))

            if self.mode == "silent":
                self.stop.wait(10)
            elif self.mode in ("refused", "notauth"):
                rcode = 5 if self.mode == "refused" else 9
                send(struct.pack("!HHHHHH", txn_id, 0x8000 | rcode, 1, 0, 0, 0) + question)
            elif self.mode == "badid":
                rr = _rr(b"\xc0\x0c", 6, _soa_rdata())
                send(struct.pack("!HHHHHH", (txn_id + 1) & 0xFFFF, 0x8400, 1, 1, 0, 0)
                     + question + rr)
            elif self.mode == "noerror":
                # Message 1: echoes the question, uses compression pointers.
                rrs = (_rr(b"\xc0\x0c", 6, _soa_rdata())
                       + _rr(b"\x03www\xc0\x0c", 1, socket.inet_aton("10.0.0.1")))
                send(struct.pack("!HHHHHH", txn_id, 0x8400, 1, 2, 0, 0) + question + rrs)
                # Message 2: no question, full names, closing SOA.
                rrs = (_rr(_name("mail.example.test"), 1, socket.inet_aton("10.0.0.2"))
                       + _rr(_name("example.test"), 6, _soa_rdata()))
                send(struct.pack("!HHHHHH", txn_id, 0x8400, 0, 2, 0, 0) + rrs)
            elif self.mode == "stream":
                rr = _rr(b"\xc0\x0c", 6, _soa_rdata())
                send(struct.pack("!HHHHHH", txn_id, 0x8400, 1, 1, 0, 0) + question + rr)
                i = 0
                while not self.stop.is_set():
                    i += 1
                    owner = _name("h%d.example.test" % i)
                    send(struct.pack("!HHHHHH", txn_id, 0x8400, 0, 1, 0, 0)
                         + _rr(owner, 1, socket.inet_aton("10.0.0.3")))
            self.stop.wait(10)
        except OSError:
            pass


# ============================================================
# AXFR
# ============================================================

class ZoneTransferTests(unittest.TestCase):
    def test_query_is_length_framed_axfr(self):
        with MockDnsTcpServer("refused") as srv:
            dns_deep._try_zone_transfer("example.test", "127.0.0.1",
                                        timeout=2, port=srv.port)
            self.assertEqual(len(srv.queries), 1)
            q = srv.queries[0]
        _id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", q[:12])
        self.assertEqual((flags, qd, an, ns, ar), (0, 1, 0, 0, 0))
        self.assertEqual(q[12:], _name("example.test") + struct.pack("!HH", 252, 1))

    def test_refused_returns_none_fast(self):
        with MockDnsTcpServer("refused") as srv:
            start = time.monotonic()
            zt = dns_deep._try_zone_transfer("example.test", "127.0.0.1",
                                             timeout=3, port=srv.port)
            elapsed = time.monotonic() - start
        self.assertIsNone(zt)
        self.assertLess(elapsed, 1.0)

    def test_other_error_rcode_returns_none(self):
        with MockDnsTcpServer("notauth") as srv:
            zt = dns_deep._try_zone_transfer("example.test", "127.0.0.1",
                                             timeout=3, port=srv.port)
        self.assertIsNone(zt)

    def test_mismatched_id_is_ignored(self):
        with MockDnsTcpServer("badid") as srv:
            zt = dns_deep._try_zone_transfer("example.test", "127.0.0.1",
                                             timeout=3, port=srv.port)
        self.assertIsNone(zt)

    def test_noerror_transfer_parsed_and_stops_at_closing_soa(self):
        with MockDnsTcpServer("noerror") as srv:
            start = time.monotonic()
            zt = dns_deep._try_zone_transfer("example.test", "127.0.0.1",
                                             timeout=3, port=srv.port)
            elapsed = time.monotonic() - start
        self.assertIsNotNone(zt)
        self.assertLess(elapsed, 1.0)
        self.assertIn("4 records", zt)
        self.assertIn("from 127.0.0.1", zt)
        self.assertNotIn("[partial]", zt)
        for host in ("example.test", "www.example.test", "mail.example.test"):
            self.assertIn(host, zt)

    def test_stream_is_capped_by_max_bytes(self):
        with MockDnsTcpServer("stream") as srv:
            start = time.monotonic()
            zt = dns_deep._try_zone_transfer("example.test", "127.0.0.1",
                                             timeout=3, port=srv.port,
                                             max_bytes=4000)
            elapsed = time.monotonic() - start
        self.assertIsNotNone(zt)
        self.assertIn("[partial]", zt)
        self.assertLess(elapsed, 2.0)
        total = int(zt.split("Received ", 1)[1].split(" ", 1)[0])
        self.assertGreaterEqual(total, 4000)
        self.assertLess(total, 4000 + 200)

    def test_silent_server_bounded_by_timeout(self):
        with MockDnsTcpServer("silent") as srv:
            start = time.monotonic()
            zt = dns_deep._try_zone_transfer("example.test", "127.0.0.1",
                                             timeout=0.5, port=srv.port)
            elapsed = time.monotonic() - start
        self.assertIsNone(zt)
        self.assertLess(elapsed, 2.0)

    def test_closed_port_returns_none(self):
        start = time.monotonic()
        zt = dns_deep._try_zone_transfer("example.test", "127.0.0.1",
                                         timeout=2, port=free_port())
        self.assertIsNone(zt)
        self.assertLess(time.monotonic() - start, 1.0)

    def test_no_global_socket_timeout_side_effect(self):
        before = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(None)
            dns_deep._socket_resolve("127.0.0.1")
            with MockDnsTcpServer("refused") as srv:
                dns_deep._try_zone_transfer("example.test", "127.0.0.1",
                                            timeout=2, port=srv.port)
            self.assertIsNone(socket.getdefaulttimeout())
        finally:
            socket.setdefaulttimeout(before)


class RunDnsDeepTests(unittest.TestCase):
    @staticmethod
    def _fake_doh(nameservers):
        def fake(domain, rtype, timeout=10):
            if rtype == "NS" and not domain.startswith("_dmarc."):
                return [{"name": domain, "ttl": 60, "data": ns} for ns in nameservers]
            return []
        return fake

    def test_nameservers_tried_concurrently_first_success_in_order(self):
        calls = []

        def fake_axfr(domain, ns, timeout=None, **kw):
            calls.append((ns, timeout))
            time.sleep(0.5)
            return None if ns == "ns1.example.test" else "Received 99 bytes from " + ns

        with mock.patch.object(dns_deep, "_doh_query",
                               self._fake_doh(["ns1.example.test", "ns2.example.test"])), \
                mock.patch.object(dns_deep, "_try_zone_transfer", fake_axfr), \
                redirect_stdout(io.StringIO()):
            start = time.monotonic()
            result = dns_deep.run_dns_deep("example.test", axfr_timeout=1.5)
            elapsed = time.monotonic() - start

        self.assertLess(elapsed, 0.9)
        self.assertEqual(sorted(c[0] for c in calls),
                         ["ns1.example.test", "ns2.example.test"])
        self.assertTrue(all(c[1] == 1.5 for c in calls))
        self.assertEqual(result["zone_transfer"]["nameserver"], "ns2.example.test")
        self.assertTrue(result["summary"]["zone_transfer"])
        crit = [i for i in result["indicators"] if i[0] == "CRITICAL"]
        self.assertEqual(len(crit), 1)

    def test_end_to_end_against_mock_servers(self):
        real = dns_deep._try_zone_transfer
        with MockDnsTcpServer("refused") as refused, MockDnsTcpServer("noerror") as ok:
            ports = {"ns-a.example.test": refused.port, "ns-b.example.test": ok.port}

            def routed(domain, ns, timeout=dns_deep.AXFR_TIMEOUT, **kw):
                return real(domain, "127.0.0.1", timeout=timeout, port=ports[ns])

            with mock.patch.object(dns_deep, "_doh_query",
                                   self._fake_doh(list(ports))), \
                    mock.patch.object(dns_deep, "_try_zone_transfer", routed), \
                    redirect_stdout(io.StringIO()):
                start = time.monotonic()
                result = dns_deep.run_dns_deep("example.test")
                elapsed = time.monotonic() - start

        self.assertLess(elapsed, 1.5)
        self.assertEqual(result["zone_transfer"]["nameserver"], "ns-b.example.test")
        self.assertIn("4 records", result["zone_transfer"]["content"])

    def test_all_refused_has_no_zone_transfer(self):
        real = dns_deep._try_zone_transfer
        with MockDnsTcpServer("refused") as srv:
            def routed(domain, ns, timeout=dns_deep.AXFR_TIMEOUT, **kw):
                return real(domain, "127.0.0.1", timeout=timeout, port=srv.port)

            with mock.patch.object(dns_deep, "_doh_query",
                                   self._fake_doh(["a.test", "b.test", "c.test"])), \
                    mock.patch.object(dns_deep, "_try_zone_transfer", routed), \
                    redirect_stdout(io.StringIO()):
                start = time.monotonic()
                result = dns_deep.run_dns_deep("example.test")
                elapsed = time.monotonic() - start
            self.assertEqual(len(srv.queries), 2)

        self.assertLess(elapsed, 1.5)
        self.assertIsNone(result["zone_transfer"])
        self.assertFalse(result["summary"]["zone_transfer"])


# ============================================================
# Port scan
# ============================================================

class PortScanResolveOnceTests(unittest.TestCase):
    def test_hostname_resolved_once_and_ip_used_for_every_port(self):
        seen = []
        real_scan = port_scan._scan_port

        def recording(target, port, timeout=2.0, grab_banner=True, host=None):
            seen.append((target, host, timeout))
            return real_scan(target, port, timeout, grab_banner, host=host)

        lookups = []

        def fake_gethostbyname(name):
            lookups.append(name)
            return "127.0.0.1"

        with LocalServer() as srv:
            closed = [free_port() for _ in range(5)]
            ports = [srv.port] + closed
            with mock.patch.object(port_scan.socket, "gethostbyname", fake_gethostbyname), \
                    mock.patch.object(port_scan, "_scan_port", recording):
                result = port_scan.scan_port_range("scanhost.test", ports,
                                                   grab_banner=False)

        self.assertEqual(lookups, ["scanhost.test"])
        self.assertEqual(len(seen), len(ports))
        self.assertTrue(all(t == "127.0.0.1" and h == "scanhost.test" for t, h, _ in seen))
        self.assertEqual(result["target"], "scanhost.test")
        self.assertEqual(result["resolved_ip"], "127.0.0.1")
        self.assertEqual([p["port"] for p in result["open_ports"]], [srv.port])
        for key in ("timestamp", "total_ports", "open_ports", "closed_count",
                    "filtered_count", "errors", "scan_duration"):
            self.assertIn(key, result)

    def test_refused_counts_as_closed_not_filtered(self):
        ports = [free_port() for _ in range(3)]
        result = port_scan.scan_port_range("127.0.0.1", ports, grab_banner=False)
        self.assertEqual(result["closed_count"], 3)
        self.assertEqual(result["filtered_count"], 0)
        self.assertEqual(result["open_ports"], [])

    def test_timed_out_connect_counts_as_filtered(self):
        class FakeSock(object):
            def __init__(self, *a, **k):
                pass

            def settimeout(self, t):
                pass

            def connect_ex(self, addr):
                return errno.EAGAIN

            def close(self):
                pass

        with mock.patch.object(port_scan.socket, "socket", FakeSock):
            r = port_scan._scan_port("127.0.0.1", 81, timeout=0.1, grab_banner=False)
        self.assertEqual(r["state"], "filtered")

    def test_dns_failure_reported(self):
        def boom(name):
            raise socket.gaierror("nope")

        with mock.patch.object(port_scan.socket, "gethostbyname", boom):
            result = port_scan.scan_port_range("nx.test", [80])
        self.assertTrue(result["errors"])
        self.assertNotIn("resolved_ip", result)


class PortScanPlanTests(unittest.TestCase):
    def test_small_scan_defaults(self):
        workers, timeout = port_scan._scan_plan(22)
        self.assertEqual(timeout, port_scan.DEFAULT_TIMEOUT)
        self.assertLessEqual(workers, port_scan.DEFAULT_WORKERS)
        self.assertGreaterEqual(workers, 16)
        self.assertTrue(1.0 <= timeout <= 1.5)

    def test_wide_scan_lifts_workers_and_shortens_timeout(self):
        with mock.patch.object(port_scan, "_fd_limit", return_value=20000):
            workers, timeout = port_scan._scan_plan(65535)
        self.assertEqual(workers, port_scan.WIDE_SCAN_WORKERS)
        self.assertGreater(workers, port_scan.DEFAULT_WORKERS)
        self.assertEqual(timeout, port_scan.WIDE_SCAN_TIMEOUT)

    def test_workers_bounded_by_fd_limit(self):
        with mock.patch.object(port_scan, "_fd_limit", return_value=256):
            workers, _ = port_scan._scan_plan(65535)
        self.assertEqual(workers, 128)

    def test_explicit_values_win(self):
        with mock.patch.object(port_scan, "_fd_limit", return_value=256):
            self.assertEqual(port_scan._scan_plan(65535, 100, 2.0), (100, 2.0))
            self.assertEqual(port_scan._scan_plan(10, 300, 0.5), (300, 0.5))

    def test_scan_reports_effective_settings(self):
        result = port_scan.scan_port_range("127.0.0.1", [free_port()],
                                           workers=7, timeout=0.75,
                                           grab_banner=False)
        self.assertEqual(result["workers"], 7)
        self.assertEqual(result["timeout"], 0.75)


class BannerHostHeaderTests(unittest.TestCase):
    def test_http_probe_sends_real_host(self):
        a, b = socket.socketpair()
        try:
            b.sendall(b"HTTP/1.0 200 OK\r\nServer: mock\r\n\r\n")
            banner = port_scan._grab_banner(a, 80, timeout=1.0, host="scanhost.test")
            sent = b.recv(1024)
        finally:
            a.close()
            b.close()
        self.assertIn(b"Host: scanhost.test\r\n", sent)
        self.assertIn("HTTP/1.0 200 OK", banner)

    def test_unsafe_host_falls_back(self):
        self.assertEqual(port_scan._host_header("evil\r\nX: 1"), b"target")
        self.assertEqual(port_scan._host_header(None), b"target")
        self.assertEqual(port_scan._host_header("1.2.3.4"), b"1.2.3.4")


if __name__ == "__main__":
    unittest.main()
