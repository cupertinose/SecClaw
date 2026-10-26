from __future__ import annotations

import json
import os
import urllib.request


class DiscordNotifier:
    """Optional Discord webhook channel; the secret URL is never persisted."""

    def __init__(self, webhook_url: str | None = None):
        self.webhook_url = webhook_url or os.environ.get("SECCLAW_DISCORD_WEBHOOK")

    @property
    def configured(self) -> bool:
        return bool(self.webhook_url)

    def send_plan(self, plan: dict, finding: dict) -> bool:
        if not self.webhook_url:
            return False
        content = (
            f"SecClaw finding **{finding['severity']}** `{finding['id']}`\n"
            f"{finding['title']} — `{finding['asset']}:{finding['port']}`\n"
            f"Proposed change: {plan['summary']}\n"
            f"Plan hash: `{plan['plan_hash']}`\n"
            "Review the evidence in the local SecClaw API, then approve, reject, defer, or accept the risk."
        )
        request = urllib.request.Request(
            self.webhook_url,
            data=json.dumps({"content": content}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5):
            return True

