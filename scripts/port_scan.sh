#!/usr/bin/env bash
# Find hosts with a TCP port open on authorized intranet networks.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: port_scan.sh [options] [TARGET ...]

Scan every address in one or more intranet IPv4 networks. When no TARGET is
given, directly connected RFC 1918 networks are detected automatically.

Options:
  -p, --port PORT       TCP port to scan (default: 22)
  -t, --target TARGET   IPv4 address or CIDR; may be repeated or comma-separated
  -i, --interface NAME  Only auto-detect networks on this interface
      --discovery       Skip hosts that do not respond to Nmap host discovery
  -h, --help            Show this help

Examples:
  ./scripts/port_scan.sh
  ./scripts/port_scan.sh --port 443
  ./scripts/port_scan.sh --target 192.168.10.0/24
  ./scripts/port_scan.sh -p 22 10.20.0.0/24 10.20.1.0/24

The default mode checks every address (-Pn), including hosts that ignore ping.
Only scan networks you own or are authorized to assess.
EOF
}

port=22
interface=""
skip_discovery=1
declare -a raw_targets=()

while (($#)); do
  case "$1" in
    -p|--port)
      [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
      port=$2
      shift 2
      ;;
    -t|--target)
      [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
      raw_targets+=("$2")
      shift 2
      ;;
    -i|--interface)
      [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
      interface=$2
      shift 2
      ;;
    --discovery)
      skip_discovery=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      raw_targets+=("$@")
      break
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      raw_targets+=("$1")
      shift
      ;;
  esac
done

[[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)) || {
  echo "Port must be an integer from 1 to 65535" >&2
  exit 2
}
[[ -z "$interface" || "$interface" =~ ^[[:alnum:]_.:-]+$ ]] || {
  echo "Invalid interface name: $interface" >&2
  exit 2
}

command -v nmap >/dev/null || {
  echo "nmap is required (on Debian/Ubuntu: sudo apt install nmap)" >&2
  exit 1
}
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

if ((${#raw_targets[@]} == 0)); then
  command -v ip >/dev/null || { echo "iproute2 is required for automatic target detection" >&2; exit 1; }
  ip_args=(-o -4 addr show scope global)
  if [[ -n "$interface" ]]; then
    ip_args+=(dev "$interface")
  fi
  mapfile -t raw_targets < <(ip "${ip_args[@]}" | awk '{print $4}')
  ((${#raw_targets[@]} > 0)) || {
    echo "No active private IPv4 network found; supply one with --target" >&2
    exit 1
  }
fi

# Normalize, validate, de-duplicate, and keep automatic discovery on RFC 1918
# networks. Explicit targets are also restricted to non-public IPv4 space.
target_text=$(IFS=,; printf '%s' "${raw_targets[*]}")
if ! target_output=$(python3 - "$target_text" <<'PY'
import ipaddress
import sys

private_networks = tuple(map(ipaddress.ip_network, (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
)))
seen = set()
for value in sys.argv[1].split(","):
    value = value.strip()
    if not value:
        continue
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        print(f"Invalid IPv4 address or CIDR: {value}", file=sys.stderr)
        raise SystemExit(2)
    if network.version != 4:
        print(f"IPv6 targets are not supported: {value}", file=sys.stderr)
        raise SystemExit(2)
    if not any(network.subnet_of(private) for private in private_networks):
        print(f"Refusing public target: {network}", file=sys.stderr)
        raise SystemExit(2)
    normalized = str(network)
    if normalized not in seen:
        seen.add(normalized)
        print(normalized)
PY
); then
  exit 2
fi
mapfile -t targets <<<"$target_output"

((${#targets[@]} > 0)) || {
  echo "No private IPv4 targets found; supply one with --target" >&2
  exit 1
}

echo "Scanning ${targets[*]} for open TCP/$port ..." >&2
nmap_args=(-n --open -sT -p "$port")
if ((skip_discovery)); then
  nmap_args+=(-Pn)
fi
nmap "${nmap_args[@]}" "${targets[@]}"
