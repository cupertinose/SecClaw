from __future__ import annotations

import tempfile
import unittest

from secclaw.policy import PolicyDenied
from secclaw.service import Conflict, SecClaw


class FakeScanner:
    def scan(self, target, ports, cancelled=lambda: False, blocked=None):
        blocked = blocked or set()
        return {
            "target": target,
            "scanner": "fake_fixed_template",
            "duration_ms": 1,
            "observations": [
                {
                    "port": port,
                    "state": "filtered" if port in blocked else "open",
                    "service": "http-admin",
                    "source": "test",
                }
                for port in ports
            ],
        }


class FakeModel:
    model = "test-local-model"

    def ensure_available(self):
        return None

    def summarize(self, findings):
        return f"Local summary: {len(findings)} findings"


class SecClawTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = SecClaw(self.temp.name, scanner=FakeScanner(), model=FakeModel())
        self.policy = self.app.create_policy(
            {
                "name": "demo",
                "owner": "alice",
                "business_justification": "isolated lab",
                "targets": ["10.20.0.0/24"],
                "ports": [8080],
                "allow_remediation": True,
            },
            "alice",
        )

    def tearDown(self):
        self.app.store.close()
        self.temp.cleanup()

    def test_complete_approval_gated_workflow(self):
        task = self.app.create_task(
            {"policy_id": self.policy["id"], "target": "10.20.0.5", "ports": [8080]},
            "alice",
        )
        result = self.app.run_task(task["id"], "alice")
        finding = result["findings"][0]
        self.assertEqual(finding["status"], "open")
        self.assertEqual(finding["evidence"]["fact"]["state"], "open")

        plan = self.app.create_plan(finding["id"], "alice")
        with self.assertRaises(Conflict):
            self.app.execute(plan["id"], "alice")

        approval = self.app.approve(plan["id"], "bob", "approved")
        self.assertEqual(approval["plan_hash"], plan["plan_hash"])
        execution = self.app.execute(plan["id"], "alice")
        self.assertTrue(execution["resolved"])
        self.assertEqual(execution["finding"]["status"], "resolved")
        self.assertEqual(execution["verification_scan"]["kind"], "verification")

        actions = [event["action"] for event in self.app.store.audit_events(task["id"])]
        self.assertIn("scan.authorize", actions)
        self.assertIn("remediation.execute", actions)
        self.assertIn("remediation.verify", actions)

    def test_unauthorized_target_is_denied_and_audited(self):
        with self.assertRaises(PolicyDenied):
            self.app.create_task(
                {"policy_id": self.policy["id"], "target": "192.0.2.10", "ports": [8080]},
                "alice",
            )
        events = self.app.store.audit_events()
        self.assertEqual(events[-1]["result"], "denied")
        self.assertEqual(events[-1]["action"], "scan.authorize")

    def test_public_scope_too_broad_is_rejected(self):
        with self.assertRaises(PolicyDenied):
            self.app.create_policy(
                {
                    "owner": "alice",
                    "business_justification": "invalid broad range",
                    "targets": ["8.0.0.0/8"],
                    "ports": [443],
                },
                "alice",
            )

    def test_plan_tampering_invalidates_approval(self):
        task = self.app.create_task(
            {"policy_id": self.policy["id"], "target": "10.20.0.6", "ports": [8080]},
            "alice",
        )
        finding = self.app.run_task(task["id"], "alice")["findings"][0]
        plan = self.app.create_plan(finding["id"], "alice")
        self.app.approve(plan["id"], "bob", "approved")
        self.app.store.update("plans", plan["id"], plan_hash="tampered")
        with self.assertRaises(Conflict):
            self.app.execute(plan["id"], "alice")

    def test_local_summary_keeps_finding_references(self):
        task = self.app.create_task(
            {"policy_id": self.policy["id"], "target": "10.20.0.7", "ports": [8080]}, "alice"
        )
        finding = self.app.run_task(task["id"], "alice")["findings"][0]
        result = self.app.summarize("alice", severity="medium")
        self.assertEqual(result["finding_ids"], [finding["id"]])
        self.assertEqual(result["model_location"], "local")


if __name__ == "__main__":
    unittest.main()

