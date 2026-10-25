from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


class ModelUnavailable(RuntimeError):
    pass


class OllamaModel:
    """Minimal local-only Ollama client used for grounded risk summaries."""

    def __init__(self, host: str | None = None, model: str | None = None):
        self.host = (host or os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")).rstrip("/")
        self.model = model or os.environ.get("OLLAMA_MODEL", "local-gpt-oss-120b:latest")
        if not self.host.startswith(("http://127.0.0.1", "http://localhost", "http://[::1]")):
            raise ValueError("the model endpoint must be local")

    def ensure_available(self) -> None:
        try:
            with urllib.request.urlopen(f"{self.host}/api/tags", timeout=2) as response:
                models = json.load(response).get("models", [])
            if self.model not in {entry.get("name") for entry in models}:
                raise ModelUnavailable(f"local model {self.model!r} is not installed")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ModelUnavailable("local model service is unavailable") from exc

    def summarize(self, findings: list[dict]) -> str:
        self.ensure_available()
        facts = [
            {
                "id": item["id"], "asset": item["asset"], "port": item["port"],
                "severity": item["severity"], "observed_fact": item["evidence"]["fact"],
                "rule_assessment": item["impact"],
            }
            for item in findings
        ]
        prompt = (
            "用中文简洁总结以下授权安全扫描结果。必须把工具观测事实与推断分开，"
            "不得声称已利用漏洞，不得建议攻击行为。数据：" + json.dumps(facts, ensure_ascii=False)
        )
        payload = json.dumps({"model": self.model, "stream": False, "messages": [{"role": "user", "content": prompt}]}).encode()
        request = urllib.request.Request(f"{self.host}/api/chat", data=payload, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return json.load(response)["message"]["content"]
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError) as exc:
            raise ModelUnavailable("local model inference failed") from exc

