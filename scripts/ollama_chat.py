#!/usr/bin/env python3
"""Small dependency-free client for a local Ollama server."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


DEFAULT_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
DEFAULT_MODEL = os.environ.get("OLLAMA_MODEL", "local-gpt-oss-120b:latest")


def request_json(url: str, payload: dict | None = None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="GET" if payload is None else "POST",
    )
    return urllib.request.urlopen(request, timeout=600)


def available_models(host: str) -> list[str]:
    with request_json(f"{host}/api/tags") as response:
        body = json.load(response)
    return [model["name"] for model in body.get("models", [])]


def read_prompt(parts: list[str]) -> str:
    if parts:
        return " ".join(parts).strip()
    if not sys.stdin.isatty():
        return sys.stdin.read().strip()
    return input("You: ").strip()


def chat(host: str, model: str, prompt: str, system: str | None, stream: bool) -> None:
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    payload = {"model": model, "messages": messages, "stream": stream}
    with request_json(f"{host}/api/chat", payload) as response:
        if not stream:
            body = json.load(response)
            print(body.get("message", {}).get("content", ""))
            return

        for raw_line in response:
            if not raw_line.strip():
                continue
            event = json.loads(raw_line)
            if error := event.get("error"):
                raise RuntimeError(error)
            text = event.get("message", {}).get("content", "")
            print(text, end="", flush=True)
        print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Chat with a local Ollama model")
    parser.add_argument("prompt", nargs="*", help="Question; stdin is used when omitted")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Ollama base URL")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Installed Ollama model name")
    parser.add_argument("--system", help="Optional system message")
    parser.add_argument("--no-stream", action="store_true", help="Wait for one JSON response")
    parser.add_argument("--list-models", action="store_true", help="List local models and exit")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    host = args.host.rstrip("/")

    try:
        models = available_models(host)
        if args.list_models:
            print("\n".join(models))
            return 0
        if args.model not in models:
            print(
                f"Model {args.model!r} is not installed. Available: "
                + (", ".join(models) if models else "none"),
                file=sys.stderr,
            )
            return 2

        prompt = read_prompt(args.prompt)
        if not prompt:
            print("Prompt cannot be empty.", file=sys.stderr)
            return 2

        chat(host, args.model, prompt, args.system, not args.no_stream)
        return 0
    except urllib.error.URLError as exc:
        print(f"Cannot reach Ollama at {host}: {exc.reason}", file=sys.stderr)
        print("Start it with: ollama serve", file=sys.stderr)
        return 1
    except (json.JSONDecodeError, RuntimeError) as exc:
        print(f"Ollama request failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
