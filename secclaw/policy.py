from __future__ import annotations

import ipaddress
import re
from datetime import datetime


HOSTNAME = re.compile(r"(?=^.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


class PolicyDenied(ValueError):
    pass


def validate_policy(policy: dict) -> None:
    if not policy.get("owner", "").strip():
        raise PolicyDenied("task owner is required")
    if not policy.get("business_justification", "").strip():
        raise PolicyDenied("business justification is required")
    if not policy.get("targets"):
        raise PolicyDenied("at least one target is required")
    if not policy.get("ports"):
        raise PolicyDenied("at least one port is required")
    if len(policy["ports"]) > 1024 or any(not isinstance(p, int) or p < 1 or p > 65535 for p in policy["ports"]):
        raise PolicyDenied("ports must contain at most 1024 values in 1..65535")
    for value in policy["targets"]:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            if not HOSTNAME.fullmatch(value):
                raise PolicyDenied(f"invalid target: {value}")
            continue
        if network.version != 4:
            raise PolicyDenied("MVP supports IPv4 only")
        if not network.is_private and network.prefixlen < 24:
            raise PolicyDenied("public network ranges broader than /24 are prohibited")


def _active(policy: dict) -> bool:
    current = datetime.now().astimezone()
    for key, before in (("not_before", True), ("not_after", False)):
        if value := policy.get(key):
            boundary = datetime.fromisoformat(value)
            if boundary.tzinfo is None:
                boundary = boundary.astimezone()
            if (before and current < boundary) or (not before and current > boundary):
                return False
    return True


def authorize(policy: dict, target: str, ports: list[int], remediation: bool = False) -> None:
    validate_policy(policy)
    if not _active(policy):
        raise PolicyDenied("authorization policy is outside its active time window")
    if remediation and not policy.get("allow_remediation"):
        raise PolicyDenied("policy does not allow remediation")
    if any(port not in policy["ports"] for port in ports):
        raise PolicyDenied("one or more ports are outside the allowlist")

    allowed = False
    try:
        address = ipaddress.ip_address(target)
        allowed = any(
            address in ipaddress.ip_network(entry, strict=False)
            for entry in policy["targets"]
            if _is_network(entry)
        )
    except ValueError:
        allowed = target.lower() in {entry.lower() for entry in policy["targets"] if not _is_network(entry)}
    if not allowed:
        raise PolicyDenied(f"target {target!r} is outside the authorization policy")


def _is_network(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False

