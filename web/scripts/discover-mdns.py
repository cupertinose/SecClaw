#!/usr/bin/env python3
"""Collect resolved mDNS services from the host Avahi daemon."""

import argparse
import ipaddress
import json
import subprocess
from datetime import datetime, timezone


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", required=True)
    parser.add_argument("--seconds", type=int, default=8)
    args = parser.parse_args()
    if not 2 <= args.seconds <= 30:
        parser.error("--seconds must be 2–30")

    started = datetime.now(timezone.utc)
    # Avahi includes its cache and services forwarded from other network segments.
    process = subprocess.run(
        ["avahi-browse", "--all", "--terminate", "--resolve", "--parsable"],
        capture_output=True, text=True, timeout=args.seconds + 15, check=True,
    )
    devices = {}
    for line in process.stdout.splitlines():
        fields = line.split(";")
        if len(fields) < 9 or fields[0] != "=" or fields[1] != args.interface or fields[2] != "IPv4":
            continue
        _, _, _, name, service, _, hostname, ip, port_text, *_ = fields
        try:
            ipaddress.IPv4Address(ip)
            port = int(port_text)
            if not 1 <= port <= 65535:
                raise ValueError
        except (ipaddress.AddressValueError, ValueError):
            continue
        device = devices.setdefault(ip, {"ip": ip, "hostname": None, "names": set(), "services": set()})
        if hostname:
            device["hostname"] = hostname.rstrip(".")
        device["names"].add(name)
        device["services"].add((service, port))

    result = []
    for device in devices.values():
        device["names"] = sorted(device["names"])
        device["services"] = [
            {"name": service, "port": port}
            for service, port in sorted(device["services"])
        ]
        result.append(device)
    result.sort(key=lambda device: ipaddress.IPv4Address(device["ip"]))
    print(json.dumps({"source": "mDNS via Avahi", "interface": args.interface,
                      "started_at": started.isoformat(), "finished_at": datetime.now(timezone.utc).isoformat(),
                      "devices": result}, ensure_ascii=False))


if __name__ == "__main__":
    main()
