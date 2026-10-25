from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .models import now


KINDS = {"policies", "tasks", "scans", "findings", "plans", "approvals"}


class Store:
    """Small durable JSON document store backed by SQLite."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS documents (kind TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(kind,id))"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, object_type TEXT NOT NULL, object_id TEXT NOT NULL, result TEXT NOT NULL, correlation_id TEXT, details TEXT NOT NULL)"
        )
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    def put(self, kind: str, item: dict[str, Any]) -> dict[str, Any]:
        if kind not in KINDS or not item.get("id"):
            raise ValueError("invalid document")
        payload = json.dumps(item, sort_keys=True, separators=(",", ":"))
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO documents(kind,id,data) VALUES(?,?,?) ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                (kind, item["id"], payload),
            )
        return item

    def get(self, kind: str, item_id: str) -> dict[str, Any] | None:
        row = self._db.execute(
            "SELECT data FROM documents WHERE kind=? AND id=?", (kind, item_id)
        ).fetchone()
        return json.loads(row["data"]) if row else None

    def list(self, kind: str, **filters: Any) -> list[dict[str, Any]]:
        if kind not in KINDS:
            raise ValueError("invalid kind")
        rows = self._db.execute(
            "SELECT data FROM documents WHERE kind=? ORDER BY rowid DESC", (kind,)
        ).fetchall()
        items = [json.loads(row["data"]) for row in rows]
        return [x for x in items if all(x.get(k) == v for k, v in filters.items())]

    def update(self, kind: str, item_id: str, **changes: Any) -> dict[str, Any]:
        item = self.get(kind, item_id)
        if item is None:
            raise KeyError(f"{kind}/{item_id} not found")
        item.update(changes)
        return self.put(kind, item)

    def audit(
        self,
        actor: str,
        action: str,
        object_type: str,
        object_id: str,
        result: str,
        correlation_id: str | None = None,
        **details: Any,
    ) -> None:
        # Only explicitly supplied structured metadata is logged; request headers,
        # prompts, environment variables, and credentials never reach this method.
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO audit(timestamp,actor,action,object_type,object_id,result,correlation_id,details) VALUES(?,?,?,?,?,?,?,?)",
                (now(), actor, action, object_type, object_id, result, correlation_id, json.dumps(details, sort_keys=True)),
            )

    def audit_events(self, correlation_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM audit"
        args: tuple[Any, ...] = ()
        if correlation_id:
            sql += " WHERE correlation_id=?"
            args = (correlation_id,)
        sql += " ORDER BY seq"
        rows = self._db.execute(sql, args).fetchall()
        return [{**dict(row), "details": json.loads(row["details"])} for row in rows]

