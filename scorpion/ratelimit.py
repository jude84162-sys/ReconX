"""A small, thread-safe, per-host token bucket.

Tools share one RateLimiter so the agent stays polite even when several tools
hit the same host concurrently. It never raises; it blocks (briefly) until a
token is available, which smooths bursts without failing requests.
"""
from __future__ import annotations

import threading
import time
from typing import Dict


class RateLimiter:
    def __init__(self, per_host_rate: float = 8.0, burst: float = 0.0):
        self.rate = max(0.1, float(per_host_rate))
        self.capacity = burst if burst > 0 else max(1.0, self.rate)
        self._tokens: Dict[str, float] = {}
        self._stamp: Dict[str, float] = {}
        self._lock = threading.Lock()

    def acquire(self, host: str) -> None:
        if not host:
            return
        host = host.lower()
        while True:
            with self._lock:
                now = time.monotonic()
                tokens = self._tokens.get(host, self.capacity)
                last = self._stamp.get(host, now)
                tokens = min(self.capacity, tokens + (now - last) * self.rate)
                if tokens >= 1.0:
                    self._tokens[host] = tokens - 1.0
                    self._stamp[host] = now
                    return
                need = (1.0 - tokens) / self.rate
                self._tokens[host] = tokens
                self._stamp[host] = now
            time.sleep(min(need, 1.0))


class NullRateLimiter:
    """No-op limiter for tests."""

    def acquire(self, host: str) -> None:  # noqa: D401
        return
