from __future__ import annotations

import argparse
import json
import sys

from .api import serve
from .service import SecClaw


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="SecClaw local security operations MVP")
    root.add_argument("--data-dir", default=".secclaw")
    sub = root.add_subparsers(dest="command", required=True)
    server = sub.add_parser("serve", help="start the local JSON API")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8787)
    policy = sub.add_parser("create-policy")
    policy.add_argument("--name", default="Demo policy")
    policy.add_argument("--owner", required=True)
    policy.add_argument("--reason", required=True)
    policy.add_argument("--target", action="append", required=True)
    policy.add_argument("--ports", required=True, help="comma-separated ports")
    policy.add_argument("--allow-remediation", action="store_true")
    scan = sub.add_parser("scan")
    scan.add_argument("--policy", required=True)
    scan.add_argument("--target", required=True)
    scan.add_argument("--ports", required=True)
    sub.add_parser("audit")
    return root


def _ports(value: str) -> list[int]:
    return [int(x) for x in value.split(",") if x]


def main() -> int:
    args = parser().parse_args()
    app = SecClaw(args.data_dir)
    try:
        if args.command == "serve":
            serve(app, args.host, args.port)
            return 0
        if args.command == "create-policy":
            result = app.create_policy({"name": args.name, "owner": args.owner, "business_justification": args.reason, "targets": args.target, "ports": _ports(args.ports), "allow_remediation": args.allow_remediation}, args.owner)
        elif args.command == "scan":
            task = app.create_task({"policy_id": args.policy, "target": args.target, "ports": _ports(args.ports)}, "local-admin")
            result = app.run_task(task["id"], "local-admin")
        else:
            result = app.store.audit_events()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

