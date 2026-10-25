from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


def now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class Policy:
    id: str
    name: str
    owner: str
    business_justification: str
    targets: list[str]
    ports: list[int]
    allow_remediation: bool = False
    not_before: str | None = None
    not_after: str | None = None
    created_at: str = field(default_factory=now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanTask:
    id: str
    policy_id: str
    target: str
    ports: list[int]
    owner: str
    status: str = "queued"
    created_at: str = field(default_factory=now)
    started_at: str | None = None
    completed_at: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    id: str
    task_id: str
    policy_id: str
    asset: str
    port: int
    title: str
    severity: str
    status: str
    evidence: dict[str, Any]
    impact: str
    confidence: float
    recommendation: str
    verification: str
    rollback: str
    observed_at: str = field(default_factory=now)
    updated_at: str = field(default_factory=now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Plan:
    id: str
    finding_id: str
    policy_id: str
    target: str
    port: int
    adapter: str
    prechecks: list[str]
    changes: list[dict[str, Any]]
    verification: list[str]
    rollback: list[dict[str, Any]]
    summary: str
    plan_hash: str
    status: str = "pending_approval"
    created_at: str = field(default_factory=now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

