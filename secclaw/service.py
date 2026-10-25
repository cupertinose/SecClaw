from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .analyzer import findings_for
from .model import OllamaModel
from .models import Plan, Policy, ScanTask, now
from .notifications import DiscordNotifier
from .policy import PolicyDenied, authorize, validate_policy
from .scanner import FixedTemplateScanner
from .store import Store


class Conflict(RuntimeError):
    pass


class SecClaw:
    def __init__(self, data_dir: str | Path = ".secclaw", scanner: FixedTemplateScanner | None = None, model=None, notifier=None):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.store = Store(self.data_dir / "secclaw.db")
        self.scanner = scanner or FixedTemplateScanner()
        self.model = model or OllamaModel()
        self.notifier = notifier or DiscordNotifier()
        self.firewall_path = self.data_dir / "demo_firewall.json"

    @staticmethod
    def _id(prefix: str) -> str:
        return f"{prefix}_{secrets.token_hex(8)}"

    def create_policy(self, body: dict, actor: str) -> dict:
        policy = Policy(
            id=self._id("pol"), name=body.get("name", "Authorization policy"),
            owner=body.get("owner", ""), business_justification=body.get("business_justification", ""),
            targets=list(body.get("targets", [])), ports=sorted(set(body.get("ports", []))),
            allow_remediation=bool(body.get("allow_remediation", False)),
            not_before=body.get("not_before"), not_after=body.get("not_after"),
        ).to_dict()
        try:
            validate_policy(policy)
        except PolicyDenied as exc:
            self.store.audit(actor, "policy.create", "policy", policy["id"], "denied", reason=str(exc))
            raise
        self.store.put("policies", policy)
        self.store.audit(actor, "policy.create", "policy", policy["id"], "success")
        return policy

    def create_task(self, body: dict, actor: str) -> dict:
        task = ScanTask(id=self._id("scan"), policy_id=body.get("policy_id", ""), target=body.get("target", ""), ports=sorted(set(body.get("ports", []))), owner=actor).to_dict()
        policy = self.store.get("policies", task["policy_id"])
        try:
            if not policy:
                raise PolicyDenied("authorization policy does not exist")
            authorize(policy, task["target"], task["ports"])
        except PolicyDenied as exc:
            self.store.audit(actor, "scan.authorize", "task", task["id"], "denied", task["id"], reason=str(exc), target=task["target"])
            raise
        duplicate = next((x for x in self.store.list("tasks", status="queued") if x["target"] == task["target"] and x["ports"] == task["ports"] and x["policy_id"] == task["policy_id"]), None)
        if duplicate:
            self.store.audit(actor, "scan.deduplicate", "task", duplicate["id"], "success", duplicate["id"])
            return duplicate
        self.store.put("tasks", task)
        self.store.audit(actor, "task.create", "task", task["id"], "success", task["id"], target=task["target"], ports=task["ports"])
        return task

    def cancel_task(self, task_id: str, actor: str) -> dict:
        task = self._required("tasks", task_id)
        if task["status"] not in {"queued", "running"}:
            raise Conflict("only queued or running tasks can be cancelled")
        task = self.store.update("tasks", task_id, status="cancelled", completed_at=now())
        self.store.audit(actor, "task.cancel", "task", task_id, "success", task_id)
        return task

    def run_task(self, task_id: str, actor: str) -> dict:
        task = self._required("tasks", task_id)
        if task["status"] != "queued":
            raise Conflict("task is not queued")
        policy = self._required("policies", task["policy_id"])
        try:
            authorize(policy, task["target"], task["ports"])
            self.store.audit(actor, "scan.authorize", "task", task_id, "success", task_id)
        except PolicyDenied as exc:
            self.store.update("tasks", task_id, status="denied", error=str(exc), completed_at=now())
            self.store.audit(actor, "scan.authorize", "task", task_id, "denied", task_id, reason=str(exc))
            raise
        self.store.update("tasks", task_id, status="running", started_at=now())
        self.store.audit("scanner", "tool.invoke", "task", task_id, "started", task_id, template="fixed_tcp_connect_v1")
        try:
            result = self.scanner.scan(task["target"], task["ports"], cancelled=lambda: self.store.get("tasks", task_id)["status"] == "cancelled", blocked=self._blocked_ports(task["target"]))
            scan = {"id": self._id("raw"), "task_id": task_id, "kind": "initial", "created_at": now(), **result}
            self.store.put("scans", scan)
            generated = findings_for(task, scan)
            for finding in generated:
                old = self.store.get("findings", finding.id)
                if old and old["status"] in {"accepted_risk", "awaiting_approval", "remediating"}:
                    finding.status = old["status"]
                self.store.put("findings", finding.to_dict())
            task = self.store.update("tasks", task_id, status="completed", completed_at=now())
            self.store.audit("scanner", "tool.invoke", "task", task_id, "success", task_id, raw_scan_id=scan["id"], findings=len(generated))
            return {"task": task, "scan": scan, "findings": [x.to_dict() for x in generated]}
        except Exception as exc:
            self.store.update("tasks", task_id, status="failed", completed_at=now(), error=str(exc))
            self.store.audit("scanner", "tool.invoke", "task", task_id, "failed", task_id, error_type=type(exc).__name__)
            raise

    def create_plan(self, finding_id: str, actor: str) -> dict:
        finding = self._required("findings", finding_id)
        if finding["status"] not in {"open", "failed"}:
            raise Conflict("finding is not eligible for planning")
        plan_data = {
            "finding_id": finding_id, "policy_id": finding["policy_id"], "target": finding["asset"], "port": finding["port"],
            "adapter": "demo_firewall_v1", "prechecks": ["Revalidate authorization policy", "Confirm port is still open", "Confirm rollback is present"],
            "changes": [{"operation": "deny", "protocol": "tcp", "port": finding["port"], "target": finding["asset"]}],
            "verification": [f"Rescan TCP/{finding['port']} using the fixed scanner template"],
            "rollback": [{"operation": "allow", "protocol": "tcp", "port": finding["port"], "target": finding["asset"]}],
            "summary": f"Demo firewall diff: ALLOW -> DENY {finding['asset']} tcp/{finding['port']}",
        }
        canonical = json.dumps(plan_data, sort_keys=True, separators=(",", ":"))
        plan = Plan(id=self._id("plan"), plan_hash=hashlib.sha256(canonical.encode()).hexdigest(), **plan_data).to_dict()
        self.store.put("plans", plan)
        self.store.update("findings", finding_id, status="awaiting_approval", updated_at=now())
        self.store.audit(actor, "plan.create", "plan", plan["id"], "success", finding["task_id"], finding_id=finding_id, plan_hash=plan["plan_hash"], summary=plan["summary"])
        if self.notifier.configured:
            try:
                self.notifier.send_plan(plan, finding)
                self.store.audit("secclaw", "notification.send", "plan", plan["id"], "success", finding["task_id"], channel="discord")
            except Exception as exc:
                self.store.audit("secclaw", "notification.send", "plan", plan["id"], "failed", finding["task_id"], channel="discord", error_type=type(exc).__name__)
        return plan

    def approve(self, plan_id: str, approver: str, decision: str, ttl_minutes: int = 30) -> dict:
        if decision not in {"approved", "rejected", "deferred", "accepted_risk"}:
            raise ValueError("invalid decision")
        plan = self._required("plans", plan_id)
        finding = self._required("findings", plan["finding_id"])
        approval = {"id": self._id("approval"), "plan_id": plan_id, "finding_id": finding["id"], "approver": approver, "decision": decision, "plan_hash": plan["plan_hash"], "command_summary": plan["summary"], "created_at": now(), "expires_at": (datetime.now(UTC) + timedelta(minutes=min(max(ttl_minutes, 1), 1440))).isoformat()}
        self.store.put("approvals", approval)
        status = {"approved": "approved", "rejected": "rejected", "deferred": "pending_approval", "accepted_risk": "accepted_risk"}[decision]
        self.store.update("plans", plan_id, status=status)
        self.store.update("findings", finding["id"], status="accepted_risk" if decision == "accepted_risk" else ("open" if decision == "rejected" else finding["status"]), updated_at=now())
        self.store.audit(approver, "plan.decision", "plan", plan_id, decision, finding["task_id"], finding_id=finding["id"], plan_hash=plan["plan_hash"], command_summary=plan["summary"])
        return approval

    def execute(self, plan_id: str, actor: str) -> dict:
        plan = self._required("plans", plan_id)
        finding = self._required("findings", plan["finding_id"])
        policy = self._required("policies", plan["policy_id"])
        approvals = [x for x in self.store.list("approvals", plan_id=plan_id) if x["decision"] == "approved"]
        if not approvals:
            raise Conflict("an explicit remediation approval is required")
        approval = approvals[0]
        if datetime.fromisoformat(approval["expires_at"]) < datetime.now(UTC):
            raise Conflict("approval has expired")
        if approval["plan_hash"] != plan["plan_hash"]:
            raise Conflict("approved plan hash does not match the execution plan")
        hash_fields = {key: plan[key] for key in ("finding_id", "policy_id", "target", "port", "adapter", "prechecks", "changes", "verification", "rollback", "summary")}
        actual_hash = hashlib.sha256(json.dumps(hash_fields, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if actual_hash != plan["plan_hash"]:
            raise Conflict("execution plan changed after approval")
        if plan["adapter"] != "demo_firewall_v1" or plan["changes"] != [{"operation": "deny", "protocol": "tcp", "port": plan["port"], "target": plan["target"]}]:
            raise Conflict("plan is not accepted by the controlled adapter")
        authorize(policy, plan["target"], [plan["port"]], remediation=True)
        # FR-07: never change state when the configured local reasoning service
        # is unavailable, even though this adapter executes a deterministic plan.
        self.model.ensure_available()
        self.store.update("findings", finding["id"], status="remediating", updated_at=now())
        self.store.audit(actor, "remediation.authorize", "plan", plan_id, "success", finding["task_id"], plan_hash=plan["plan_hash"])
        self._set_blocked(plan["target"], plan["port"], True)
        self.store.audit("openshell-demo", "remediation.execute", "plan", plan_id, "success", finding["task_id"], adapter=plan["adapter"])

        result = self.scanner.scan(plan["target"], [plan["port"]], blocked=self._blocked_ports(plan["target"]))
        scan = {"id": self._id("raw"), "task_id": finding["task_id"], "kind": "verification", "created_at": now(), **result}
        self.store.put("scans", scan)
        state = result["observations"][0]["state"]
        resolved = state != "open"
        self.store.update("findings", finding["id"], status="resolved" if resolved else "failed", updated_at=now(), verification_scan_id=scan["id"])
        self.store.update("plans", plan_id, status="completed" if resolved else "failed")
        self.store.audit("scanner", "remediation.verify", "finding", finding["id"], "resolved" if resolved else "failed", finding["task_id"], verification_scan_id=scan["id"], observed_state=state)
        return {"resolved": resolved, "finding": self.store.get("findings", finding["id"]), "verification_scan": scan}

    def summarize(self, actor: str, **filters) -> dict:
        findings = self.store.list("findings", **filters)
        summary = self.model.summarize(findings)
        self.store.audit(actor, "model.summarize", "findings", "selection", "success", count=len(findings), model=getattr(self.model, "model", "local"))
        return {"summary": summary, "finding_ids": [item["id"] for item in findings], "model_location": "local"}

    def rollback(self, plan_id: str, actor: str) -> dict:
        plan = self._required("plans", plan_id)
        authorize(self._required("policies", plan["policy_id"]), plan["target"], [plan["port"]], remediation=True)
        self._set_blocked(plan["target"], plan["port"], False)
        self.store.update("plans", plan_id, status="rolled_back")
        self.store.update("findings", plan["finding_id"], status="open", updated_at=now())
        self.store.audit(actor, "remediation.rollback", "plan", plan_id, "success", details_summary=plan["summary"])
        return self.store.get("plans", plan_id)

    def _required(self, kind: str, item_id: str) -> dict:
        item = self.store.get(kind, item_id)
        if not item:
            raise KeyError(f"{kind}/{item_id} not found")
        return item

    def _blocked_ports(self, target: str) -> set[int]:
        if not self.firewall_path.exists():
            return set()
        state = json.loads(self.firewall_path.read_text())
        return set(state.get(target, []))

    def _set_blocked(self, target: str, port: int, blocked: bool) -> None:
        state = json.loads(self.firewall_path.read_text()) if self.firewall_path.exists() else {}
        ports = set(state.get(target, []))
        ports.add(port) if blocked else ports.discard(port)
        state[target] = sorted(ports)
        temporary = self.firewall_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(state, sort_keys=True))
        temporary.replace(self.firewall_path)

