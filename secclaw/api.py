from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .model import ModelUnavailable
from .policy import PolicyDenied
from .service import Conflict, SecClaw


class Handler(BaseHTTPRequestHandler):
    server_version = "SecClaw/0.1"

    @property
    def app(self) -> SecClaw:
        return self.server.app  # type: ignore[attr-defined]

    def _actor(self) -> str:
        return self.headers.get("X-SecClaw-Actor", "local-admin")[:128]

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1_000_000:
            raise ValueError("request body too large")
        return json.loads(self.rfile.read(length) or b"{}")

    def _send(self, status: int, body: object) -> None:
        payload = json.dumps(body, ensure_ascii=False, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/health":
                return self._send(200, {"status": "ok", "mode": "local", "remediation_adapter": "demo_firewall_v1"})
            if parsed.path == "/api/audit":
                correlation = parse_qs(parsed.query).get("correlation_id", [None])[0]
                return self._send(200, self.app.store.audit_events(correlation))
            for route, kind in (("/api/policies", "policies"), ("/api/tasks", "tasks"), ("/api/findings", "findings"), ("/api/plans", "plans")):
                if parsed.path == route:
                    filters = {k: v[0] for k, v in parse_qs(parsed.query).items() if k in {"asset", "severity", "status", "policy_id"}}
                    return self._send(200, self.app.store.list(kind, **filters))
            self._send(404, {"error": "not found"})
        except Exception as exc:
            self._error(exc)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            body, actor = self._body(), self._actor()
            if path == "/api/policies":
                return self._send(201, self.app.create_policy(body, actor))
            if path == "/api/tasks":
                return self._send(201, self.app.create_task(body, actor))
            if path == "/api/summary":
                filters = {k: body[k] for k in ("asset", "severity", "status", "policy_id") if k in body}
                return self._send(200, self.app.summarize(actor, **filters))
            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[:2] == ["api", "tasks"] and parts[3] in {"run", "cancel"}:
                result = self.app.run_task(parts[2], actor) if parts[3] == "run" else self.app.cancel_task(parts[2], actor)
                return self._send(200, result)
            if len(parts) == 4 and parts[:2] == ["api", "findings"] and parts[3] == "plan":
                return self._send(201, self.app.create_plan(parts[2], actor))
            if len(parts) == 4 and parts[:2] == ["api", "plans"]:
                if parts[3] == "decision":
                    return self._send(201, self.app.approve(parts[2], actor, body.get("decision", ""), int(body.get("ttl_minutes", 30))))
                if parts[3] == "execute":
                    return self._send(200, self.app.execute(parts[2], actor))
                if parts[3] == "rollback":
                    return self._send(200, self.app.rollback(parts[2], actor))
            self._send(404, {"error": "not found"})
        except Exception as exc:
            self._error(exc)

    def _error(self, exc: Exception) -> None:
        if isinstance(exc, KeyError):
            status = HTTPStatus.NOT_FOUND
        elif isinstance(exc, (Conflict, ModelUnavailable)):
            status = HTTPStatus.CONFLICT
        elif isinstance(exc, (ValueError, PolicyDenied, json.JSONDecodeError)):
            status = HTTPStatus.BAD_REQUEST
        else:
            status = HTTPStatus.INTERNAL_SERVER_ERROR
        self._send(status, {"error": str(exc)})

    def log_message(self, format: str, *args: object) -> None:
        pass


def serve(app: SecClaw, host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), Handler)
    server.app = app  # type: ignore[attr-defined]
    print(f"SecClaw listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

