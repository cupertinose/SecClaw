#!/usr/bin/env bash
# Discover OpenAI-compatible vLLM servers on an authorized intranet range.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: vllm_scan.sh --targets TARGETS --ports PORTS [options]

Scan authorized intranet hosts for vLLM's unauthenticated /v1/models endpoint.

Required:
  -t, --targets VALUE    Comma-separated IPv4 addresses, hostnames, or CIDRs
                         (example: 10.20.0.0/24,server1.internal)
  -p, --ports VALUE      Comma-separated ports/ranges, or "all" for 1-65535
                         (example: 8000,8080-8082)

Options:
  -k, --api-key VALUE    Bearer token used to query /v1/models
  -j, --jobs N           Maximum concurrent checks (default: 32, max: 128)
  -w, --timeout SECONDS  TCP/HTTP timeout per check (default: 2)
  -o, --output FILE      JSON output path (default: scan_<timestamp>.json)
      --https            Probe HTTPS instead of HTTP
      --open-only        Print every open TCP port, even if it is not vLLM
      --discovery MODE   arp (default), ping, tshark, or none
                         ARP uses arp-scan and requires root access
      --interface NAME   Interface for ARP or tshark discovery
      --arp-interval MS  Minimum ARP packet interval (default: 20)
      --no-tcp-fallback  Skip common-port checks for hosts missed by discovery
      --capture-seconds N  Tshark capture duration (default: 15, max: 300)
      --no-ping          Alias for --discovery none
  -h, --help             Show this help

Hosts missed by discovery are checked on 100 common TCP ports before scanning.
The scan is capped at 4096 hosts. Full-port scans can be lengthy and noisy.
Only scan systems you own or are authorized to assess.
EOF
}

targets=""
ports=""
api_key="${VLLM_API_KEY:-}"
jobs=32
timeout_seconds=2
scheme=http
open_only=0
output=""
discovery_mode=arp
capture_interface=""
capture_seconds=15
arp_interval=20
tcp_fallback=1

while (($#)); do
  case "$1" in
    -t|--targets) [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }; targets=$2; shift 2 ;;
    -p|--ports) [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }; ports=$2; shift 2 ;;
    -k|--api-key) [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }; api_key=$2; shift 2 ;;
    -j|--jobs) [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }; jobs=$2; shift 2 ;;
    -w|--timeout) [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }; timeout_seconds=$2; shift 2 ;;
    -o|--output) [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }; output=$2; shift 2 ;;
    --https) scheme=https; shift ;;
    --open-only) open_only=1; shift ;;
    --discovery) [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }; discovery_mode=$2; shift 2 ;;
    --interface) [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }; capture_interface=$2; shift 2 ;;
    --arp-interval) [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }; arp_interval=$2; shift 2 ;;
    --no-tcp-fallback) tcp_fallback=0; shift ;;
    --capture-seconds) [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }; capture_seconds=$2; shift 2 ;;
    --no-ping) discovery_mode=none; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "$targets" && -n "$ports" ]] || { usage >&2; exit 2; }
case "$discovery_mode" in arp|ping|tshark|none) ;; *) echo "--discovery must be arp, ping, tshark, or none" >&2; exit 2 ;; esac
if [[ "$discovery_mode" == tshark && -z "$capture_interface" ]]; then
  echo "--interface is required for --discovery tshark" >&2; exit 2
fi
[[ "$capture_seconds" =~ ^[0-9]+$ ]] && ((capture_seconds >= 1 && capture_seconds <= 300)) || {
  echo "--capture-seconds must be an integer from 1 to 300" >&2; exit 2;
}
[[ "$arp_interval" =~ ^[0-9]+$ ]] && ((arp_interval >= 1 && arp_interval <= 1000)) || {
  echo "--arp-interval must be an integer from 1 to 1000" >&2; exit 2;
}
[[ "$jobs" =~ ^[0-9]+$ ]] && ((jobs >= 1 && jobs <= 128)) || {
  echo "--jobs must be an integer from 1 to 128" >&2; exit 2;
}
[[ "$timeout_seconds" =~ ^([0-9]+)(\.[0-9]+)?$ ]] || {
  echo "--timeout must be a positive number" >&2; exit 2;
}
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

export VLLM_SCAN_TARGETS="$targets" VLLM_SCAN_PORTS="$ports"
export VLLM_SCAN_API_KEY="$api_key" VLLM_SCAN_JOBS="$jobs"
export VLLM_SCAN_TIMEOUT="$timeout_seconds" VLLM_SCAN_SCHEME="$scheme"
export VLLM_SCAN_OPEN_ONLY="$open_only"
export VLLM_SCAN_OUTPUT="$output"
export VLLM_SCAN_DISCOVERY="$discovery_mode"
export VLLM_SCAN_INTERFACE="$capture_interface" VLLM_SCAN_CAPTURE_SECONDS="$capture_seconds"
export VLLM_SCAN_ARP_INTERVAL="$arp_interval"
export VLLM_SCAN_TCP_FALLBACK="$tcp_fallback"

python3 - <<'PY'
import concurrent.futures
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

MAX_HOSTS = 4096
MAX_PORTS = 65535
# A fixed, reproducible set for finding hosts that ignore ICMP/ARP discovery.
COMMON_PORTS = (
    7, 9, 13, 17, 19, 20, 21, 22, 23, 25, 26, 37, 42, 43, 49, 53, 67,
    68, 69, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 99, 100, 106, 110,
    111, 113, 119, 123, 135, 137, 138, 139, 143, 144, 161, 162, 179,
    199, 389, 427, 443, 444, 445, 465, 500, 512, 513, 514, 515, 548,
    554, 587, 623, 631, 636, 646, 873, 902, 989, 990, 993, 995, 1080,
    1194, 1433, 1521, 1723, 1883, 2049, 2375, 3000, 3306, 3389, 3690,
    4369, 5000, 5432, 5672, 5900, 6379, 6443, 7001, 8000, 8080, 8081,
    8443, 8888, 9000, 9090, 9200, 27017,
)


def expand_targets(value):
    result = []
    for item in (part.strip() for part in value.split(",")):
        if not item:
            continue
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError:
            result.append(item)
        else:
            result.extend(str(host) for host in network.hosts())
        if len(result) > MAX_HOSTS:
            raise ValueError(f"target set exceeds the {MAX_HOSTS}-host limit")
    if not result:
        raise ValueError("no valid targets supplied")
    return list(dict.fromkeys(result))


def expand_ports(value):
    if value.strip().lower() == "all":
        return list(range(1, 65536))
    result = []
    for item in (part.strip() for part in value.split(",")):
        if not item:
            continue
        try:
            if "-" in item:
                first, last = map(int, item.split("-", 1))
                if first > last:
                    raise ValueError
                result.extend(range(first, last + 1))
            else:
                result.append(int(item))
        except ValueError as exc:
            raise ValueError(f"invalid port or range: {item}") from exc
        if len(result) > MAX_PORTS:
            raise ValueError(f"port set exceeds the {MAX_PORTS}-port limit")
    if not result or any(port < 1 or port > 65535 for port in result):
        raise ValueError("ports must be in the range 1-65535")
    return list(dict.fromkeys(result))


def port_ranges(values):
    ranges = []
    ordered = sorted(set(values))
    start = end = ordered[0]
    for port in ordered[1:]:
        if port == end + 1:
            end = port
            continue
        ranges.append(str(start) if start == end else f"{start}-{end}")
        start = end = port
    ranges.append(str(start) if start == end else f"{start}-{end}")
    return ranges


try:
    hosts = expand_targets(os.environ["VLLM_SCAN_TARGETS"])
    ports = expand_ports(os.environ["VLLM_SCAN_PORTS"])
except ValueError as exc:
    print(f"vllm_scan: {exc}", file=sys.stderr)
    raise SystemExit(2)

timeout = float(os.environ["VLLM_SCAN_TIMEOUT"])
workers = int(os.environ["VLLM_SCAN_JOBS"])
scheme = os.environ["VLLM_SCAN_SCHEME"]
api_key = os.environ["VLLM_SCAN_API_KEY"]
show_open = os.environ["VLLM_SCAN_OPEN_ONLY"] == "1"
discovery_mode = os.environ["VLLM_SCAN_DISCOVERY"]
capture_interface = os.environ["VLLM_SCAN_INTERFACE"]
capture_seconds = int(os.environ["VLLM_SCAN_CAPTURE_SECONDS"])
discovery_method = discovery_mode
tls_context = ssl.create_default_context()
started_at = datetime.now(timezone.utc)

if not 0 < timeout <= 60:
    print("vllm_scan: --timeout must be greater than 0 and at most 60", file=sys.stderr)
    raise SystemExit(2)

requested_hosts = hosts
discovery_started = time.monotonic()
primary_hosts = []
fallback_open_ports = {}
fallback_checks = 0
if discovery_method == "arp":
    arp_program = shutil.which("arp-scan")
    if not arp_program:
        print("vllm_scan: arp-scan is not installed; install it (sudo apt install arp-scan)", file=sys.stderr)
        raise SystemExit(1)
    if os.geteuid() != 0:
        print("vllm_scan: ARP discovery needs root access; run this command with sudo", file=sys.stderr)
        raise SystemExit(1)
    interval = int(os.environ["VLLM_SCAN_ARP_INTERVAL"])
    print(f"Host discovery: arp-scan of {len(requested_hosts)} target(s), {interval} ms interval...", file=sys.stderr)

    def run_arp_scan(packet_interval):
        command = [arp_program, "--quiet", "--plain", "--retry=1",
                   f"--interval={packet_interval}", "--file=-"]
        if capture_interface:
            command.insert(1, f"--interface={capture_interface}")
        return subprocess.run(
            command, input="\n".join(requested_hosts) + "\n",
            text=True, capture_output=True, check=False,
        )

    scan = run_arp_scan(interval)
    if scan.returncode and "Resource temporarily unavailable" in scan.stderr and interval < 100:
        print("ARP send queue busy; retrying at 100 ms interval...", file=sys.stderr)
        scan = run_arp_scan(100)
    if scan.returncode:
        print(f"vllm_scan: arp-scan host discovery failed: {scan.stderr.strip()}", file=sys.stderr)
        raise SystemExit(1)
    hosts = sorted({
        line.split()[0]
        for line in scan.stdout.splitlines()
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}\s+", line)
    })
    print(
        f"Host discovery complete (arp-scan): {len(hosts)} online, "
        f"{len(requested_hosts) - len(hosts)} offline/unresponsive.",
        file=sys.stderr,
    )
elif discovery_method == "ping":
    ping_program = shutil.which("ping")
    if not ping_program:
        print("vllm_scan: ping is required; install it or use --no-ping", file=sys.stderr)
        raise SystemExit(1)

    print(f"Host discovery: pinging {len(requested_hosts)} target(s)...", file=sys.stderr)

    def ping_host(host):
        result = subprocess.run(
            [ping_program, "-n", "-c", "1", "-W", "1", "--", host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return host if result.returncode == 0 else None

    online_hosts = []
    discovered = 0
    last_discovery_progress = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as discovery_pool:
        discovery_futures = {
            discovery_pool.submit(ping_host, host): host for host in requested_hosts
        }
        for future in concurrent.futures.as_completed(discovery_futures):
            discovered += 1
            online_host = future.result()
            if online_host:
                online_hosts.append(online_host)
            now = time.monotonic()
            if now - last_discovery_progress >= 1 or discovered == len(requested_hosts):
                percent = discovered * 100 / len(requested_hosts)
                print(
                    f"Host discovery: {discovered}/{len(requested_hosts)} "
                    f"({percent:.2f}%) | online {len(online_hosts)}",
                    end="\r",
                    file=sys.stderr,
                    flush=True,
                )
                last_discovery_progress = now
    print(file=sys.stderr)
    hosts = sorted(online_hosts)
    print(
        f"Host discovery complete: {len(hosts)} online, "
        f"{len(requested_hosts) - len(hosts)} offline/unresponsive.",
        file=sys.stderr,
    )
elif discovery_method == "tshark":
    tshark_program = shutil.which("tshark")
    if not tshark_program:
        print("vllm_scan: tshark is not installed; install it to use --discovery tshark", file=sys.stderr)
        raise SystemExit(1)
    print(
        f"Host discovery: capturing on {capture_interface} for {capture_seconds}s...",
        file=sys.stderr,
    )
    try:
        capture = subprocess.run(
            [
                tshark_program, "-i", capture_interface,
                "-a", f"duration:{capture_seconds}",
                "-f", "arp or (udp and (port 67 or port 68 or port 5353 or port 137))",
                "-T", "fields", "-e", "arp.src.proto_ipv4", "-e", "ip.src",
            ],
            text=True,
            capture_output=True,
            timeout=capture_seconds + 15,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print("vllm_scan: tshark capture timed out", file=sys.stderr)
        raise SystemExit(1)
    if capture.returncode:
        detail = capture.stderr.strip()
        if "dumpcap" in detail and "Permission denied" in detail:
            print(
                "vllm_scan: dumpcap permission denied. Run the scan with sudo, "
                "or add your user to the wireshark group and log in again.",
                file=sys.stderr,
            )
        else:
            print(f"vllm_scan: tshark capture failed: {detail}", file=sys.stderr)
        raise SystemExit(1)
    requested_host_set = set(requested_hosts)
    observed = set()
    for line in capture.stdout.splitlines():
        for field in line.replace("\t", ",").split(","):
            address = field.strip()
            if address in requested_host_set:
                observed.add(address)
    hosts = sorted(observed)
    print(f"Host discovery complete (tshark): {len(hosts)} in-scope IP(s) observed.", file=sys.stderr)
else:
    print(f"Host discovery skipped; scanning all {len(requested_hosts)} target(s).", file=sys.stderr)

if discovery_method != "none":
    primary_hosts = hosts
    primary_host_set = set(primary_hosts)
    missing_hosts = ([host for host in requested_hosts if host not in primary_host_set]
                     if os.environ["VLLM_SCAN_TCP_FALLBACK"] == "1" else [])
    if missing_hosts:
        print(
            f"TCP fallback: checking {len(COMMON_PORTS)} common ports on "
            f"{len(missing_hosts)} unresponsive host(s)...",
            file=sys.stderr,
        )

        def check_common_port(host, port):
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    return host, port
            except OSError:
                return None

        combinations = (
            (host, port) for port in COMMON_PORTS for host in missing_hosts
        )
        pending = set()
        last_fallback_progress = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            def queue_next():
                for host, port in combinations:
                    if host not in fallback_open_ports:
                        pending.add(pool.submit(check_common_port, host, port))
                        return True
                return False

            for _ in range(workers * 4):
                if not queue_next():
                    break
            while pending:
                done, pending = concurrent.futures.wait(
                    pending, return_when=concurrent.futures.FIRST_COMPLETED
                )
                for future in done:
                    fallback_checks += 1
                    found = future.result()
                    if found:
                        host, port = found
                        fallback_open_ports.setdefault(host, port)
                    queue_next()
                now = time.monotonic()
                if now - last_fallback_progress >= 1 or not pending:
                    print(
                        f"TCP fallback: {fallback_checks} checks | "
                        f"{len(fallback_open_ports)} additional host(s) found",
                        end="\r",
                        file=sys.stderr,
                        flush=True,
                    )
                    last_fallback_progress = now
        print(file=sys.stderr)
    hosts = sorted(set(primary_hosts) | set(fallback_open_ports))
    print(
        f"Host discovery total: {len(hosts)} online "
        f"({len(primary_hosts)} initial, {len(fallback_open_ports)} TCP fallback).",
        file=sys.stderr,
    )

discovery_seconds = round(time.monotonic() - discovery_started, 3)

if not hosts:
    print("No responsive hosts found; no ports will be scanned.", file=sys.stderr)


def probe(host, port):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except (OSError, socket.timeout):
        return None

    display_host = f"[{host}]" if ":" in host else host
    url = f"{scheme}://{display_host}:{port}/v1/models"
    headers = {"Accept": "application/json", "User-Agent": "SecClaw-vLLM-scan/1"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(url, headers=headers)
    try:
        kwargs = {"timeout": timeout}
        if scheme == "https":
            kwargs["context"] = tls_context
        with urllib.request.urlopen(request, **kwargs) as response:
            body = json.load(response)
        data = body.get("data") if isinstance(body, dict) else None
        if isinstance(data, list):
            models = [item["id"] for item in data if isinstance(item, dict) and isinstance(item.get("id"), str)]
            return {
                "host": host,
                "port": port,
                "status": "vllm",
                "models": models,
                "detail": None,
            }
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return {
                "host": host,
                "port": port,
                "status": "protected",
                "models": [],
                "detail": f"HTTP {exc.code} on /v1/models",
            }
    except (OSError, ValueError, http.client.HTTPException):
        pass
    if show_open:
        return {"host": host, "port": port, "status": "open", "models": [], "detail": None}
    return None


def format_duration(seconds):
    if seconds == float("inf"):
        return "unknown"
    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h{minutes:02d}m"
    if minutes:
        return f"{minutes}m{seconds:02d}s"
    return f"{seconds}s"


results = []
total_checks = len(hosts) * len(ports)
completed_checks = 0
progress_started = time.monotonic()
last_progress = progress_started
if total_checks:
    print(
        f"Port scan: 0/{total_checks} (0.00%) | 0 checks/s | ETA unknown",
        end="\r",
        file=sys.stderr,
        flush=True,
    )
with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
    combinations = ((host, port) for host in hosts for port in ports)
    pending = set()

    # Keep only a small window of work queued instead of materializing every
    # host/port combination, which is essential for full-port CIDR scans.
    for _ in range(workers * 4):
        try:
            host, port = next(combinations)
        except StopIteration:
            break
        pending.add(pool.submit(probe, host, port))

    while pending:
        done, pending = concurrent.futures.wait(
            pending, return_when=concurrent.futures.FIRST_COMPLETED
        )
        for future in done:
            completed_checks += 1
            result = future.result()
            if result:
                results.append(result)
            try:
                host, port = next(combinations)
            except StopIteration:
                continue
            pending.add(pool.submit(probe, host, port))

        now = time.monotonic()
        if now - last_progress >= 1 or completed_checks == total_checks:
            elapsed = max(now - progress_started, 0.001)
            rate = completed_checks / elapsed
            remaining = total_checks - completed_checks
            eta = remaining / rate if rate else float("inf")
            percent = completed_checks * 100 / total_checks
            print(
                f"Port scan: {completed_checks}/{total_checks} ({percent:.2f}%) | "
                f"{rate:,.0f} checks/s | ETA {format_duration(eta)}",
                end="\r",
                file=sys.stderr,
                flush=True,
            )
            last_progress = now

if total_checks:
    print(file=sys.stderr)

results.sort(key=lambda item: (item["host"], item["port"]))
finished_at = datetime.now(timezone.utc)
timestamp = started_at.astimezone().strftime("%Y%m%d_%H%M%S")
output = os.environ["VLLM_SCAN_OUTPUT"] or f"scan_{timestamp}.json"
document = {
    "scan": {
        "tool": "SecClaw vLLM scanner",
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
        "scanner_hostname": socket.gethostname(),
        "input": {
            "targets": os.environ["VLLM_SCAN_TARGETS"],
            "ports": os.environ["VLLM_SCAN_PORTS"],
            "scheme": scheme,
            "jobs": workers,
            "timeout_seconds": timeout,
            "open_only": show_open,
            "ping_discovery": discovery_method == "ping",
            "discovery_mode": discovery_mode,
            "capture_interface": capture_interface if discovery_method == "tshark" else None,
            "capture_seconds": capture_seconds if discovery_method == "tshark" else None,
            "api_key_provided": bool(api_key),
        },
        "host_discovery": {
            "enabled": discovery_method != "none",
            "method": discovery_method,
            "duration_seconds": discovery_seconds,
            "target_count": len(requested_hosts),
            "online_count": len(hosts) if discovery_method != "none" else None,
            "offline_or_unresponsive_count": (
                len(requested_hosts) - len(hosts) if discovery_method != "none" else None
            ),
            "online_hosts": hosts if discovery_method != "none" else [],
            "initial_online_count": len(primary_hosts) if discovery_method != "none" else None,
            "tcp_fallback": {
                "port_set": "common_100_v1" if discovery_method != "none" and os.environ["VLLM_SCAN_TCP_FALLBACK"] == "1" else None,
                "port_count": len(COMMON_PORTS) if discovery_method != "none" and os.environ["VLLM_SCAN_TCP_FALLBACK"] == "1" else 0,
                "host_count": len(fallback_open_ports),
                "hosts_and_open_ports": fallback_open_ports,
                "checks_completed": fallback_checks,
            },
        },
        "scope": {
            "expanded_host_count": len(requested_hosts),
            "scanned_host_count": len(hosts),
            "expanded_port_count": len(ports),
            "expanded_ports": port_ranges(ports),
        },
        "result_count": len(results),
    },
    "results": results,
}
with open(output, "w", encoding="utf-8") as output_file:
    json.dump(document, output_file, indent=2, ensure_ascii=False)
    output_file.write("\n")

print(
    f"Scanned {len(hosts)} host(s) x {len(ports)} port(s); "
    f"reported {len(results)} result(s). JSON: {output}",
    file=sys.stderr,
)
PY
