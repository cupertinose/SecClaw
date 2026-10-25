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
            f"SecClaw 发现项 **{finding['severity']}** `{finding['id']}`\n"
            f"{finding['title']} — `{finding['asset']}:{finding['port']}`\n"
            f"拟执行变更：{plan['summary']}\n"
            f"计划哈希：`{plan['plan_hash']}`\n"
            "请在本地 SecClaw API 中查看证据并批准、拒绝、延后或接受风险。"
        )
        request = urllib.request.Request(
            self.webhook_url,
            data=json.dumps({"content": content}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5):
            return True

