from __future__ import annotations

import hashlib

from .models import Finding


RULES = {
    21: ("Exposed FTP service", "high", "FTP commonly exposes credentials and data without transport encryption."),
    23: ("Exposed Telnet service", "critical", "Telnet transmits administrative sessions without encryption."),
    2375: ("Unauthenticated Docker API may be exposed", "critical", "A reachable Docker API can permit control of containers and the host."),
    3306: ("Database service is network-accessible", "high", "Direct database exposure increases data and credential risk."),
    5432: ("Database service is network-accessible", "high", "Direct database exposure increases data and credential risk."),
    6379: ("Redis service is network-accessible", "high", "An exposed data store can permit unauthorized data access."),
    8080: ("Administrative HTTP port is exposed", "medium", "An administrative interface increases the externally reachable attack surface."),
    8443: ("Administrative HTTPS port is exposed", "medium", "An administrative interface increases the externally reachable attack surface."),
    9200: ("Elasticsearch service is network-accessible", "high", "Direct search cluster exposure can disclose or alter indexed data."),
}


def findings_for(task: dict, scan: dict) -> list[Finding]:
    findings: list[Finding] = []
    for observation in scan["observations"]:
        port = observation["port"]
        if observation["state"] != "open" or port not in RULES:
            continue
        title, severity, impact = RULES[port]
        finding_id = "fnd_" + hashlib.sha256(f"{task['policy_id']}|{task['target']}|{port}|exposure-v1".encode()).hexdigest()[:20]
        findings.append(Finding(
            id=finding_id,
            task_id=task["id"],
            policy_id=task["policy_id"],
            asset=task["target"],
            port=port,
            title=title,
            severity=severity,
            status="open",
            evidence={"fact": observation, "source_scan_id": scan["id"]},
            impact=impact,
            confidence=0.95,
            recommendation=f"Restrict TCP/{port} to approved management sources or disable the service.",
            verification=f"Rescan {task['target']} TCP/{port} and confirm it is not open.",
            rollback=f"Restore the previous access rule for TCP/{port} if service health is affected.",
        ))
    return findings

