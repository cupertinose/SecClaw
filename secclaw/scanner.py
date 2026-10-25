from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable


SERVICE_NAMES = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 443: "https", 2375: "docker", 3306: "mysql", 5432: "postgresql", 6379: "redis", 8080: "http-admin", 8443: "https-admin", 9200: "elasticsearch"}


class FixedTemplateScanner:
    """Bounded TCP connect scanner. No user input is ever passed to a shell."""

    def __init__(self, timeout: float = 0.5, concurrency: int = 32, rate: float = 200.0):
        self.timeout = min(max(timeout, 0.05), 5.0)
        self.concurrency = min(max(concurrency, 1), 64)
        self.rate = min(max(rate, 1.0), 500.0)

    def scan(
        self,
        target: str,
        ports: list[int],
        cancelled: Callable[[], bool] = lambda: False,
        blocked: set[int] | None = None,
    ) -> dict:
        started = time.monotonic()
        blocked = blocked or set()
        observations: list[dict] = []

        def probe(port: int) -> dict:
            if port in blocked:
                return {"port": port, "state": "filtered", "service": SERVICE_NAMES.get(port, "unknown"), "source": "demo_firewall"}
            if cancelled():
                return {"port": port, "state": "cancelled", "service": SERVICE_NAMES.get(port, "unknown")}
            time.sleep(1 / self.rate)
            try:
                with socket.create_connection((target, port), timeout=self.timeout):
                    return {"port": port, "state": "open", "service": SERVICE_NAMES.get(port, "unknown"), "source": "tcp_connect"}
            except (ConnectionRefusedError, TimeoutError, socket.timeout, OSError) as exc:
                return {"port": port, "state": "closed", "service": SERVICE_NAMES.get(port, "unknown"), "source": "tcp_connect", "error_type": type(exc).__name__}

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = [pool.submit(probe, port) for port in sorted(set(ports))]
            for future in as_completed(futures):
                observations.append(future.result())
        return {
            "target": target,
            "observations": sorted(observations, key=lambda x: x["port"]),
            "scanner": "fixed_tcp_connect_v1",
            "duration_ms": round((time.monotonic() - started) * 1000),
        }

