#!/usr/bin/env python3
"""Small dependency-free client for a local OpenAI-compatible vLLM server."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


DEFAULT_HOST = os.environ.get("VLLM_HOST", "http://127.0.0.1:8000")
DEFAULT_MODEL = os.environ.get("VLLM_MODEL", "gpt-oss-120b")
DEFAULT_API_KEY = os.environ.get("VLLM_API_KEY")


def request_json(
    url: str,
    payload: dict | None = None,
    api_key: str | None = None,
):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method="GET" if payload is None else "POST",
    )
    return urllib.request.urlopen(request, timeout=600)


def available_models(host: str, api_key: str | None) -> list[str]:
    with request_json(f"{host}/v1/models", api_key=api_key) as response:
        body = json.load(response)
    return [model["id"] for model in body.get("data", [])]


def read_prompt(parts: list[str]) -> str:
    if parts:
        return " ".join(parts).strip()
    if not sys.stdin.isatty():
        return sys.stdin.read().strip()
    return input("You: ").strip()


def stream_chat(
    host: str,
    model: str,
    prompt: str,
    system: str | None,
    api_key: str | None,
    max_tokens: int,
    temperature: float,
    stream: bool,
) -> None:
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    payload = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "stream": stream,
    }
    with request_json(f"{host}/v1/chat/completions", payload, api_key) as response:
        if not stream:
            body = json.load(response)
            print(body["choices"][0]["message"].get("content", ""))
            return

        for raw_line in response:
            line = raw_line.decode("utf-8").strip()
            if not line or line.startswith(":") or not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            event = json.loads(data)
            if error := event.get("error"):
                raise RuntimeError(error.get("message", str(error)))
            choices = event.get("choices", [])
            if not choices:
                continue
            text = choices[0].get("delta", {}).get("content") or ""
            print(text, end="", flush=True)
        print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Chat with a local vLLM model")
    parser.add_argument("prompt", nargs="*", help="Question; stdin is used when omitted")
    parser.add_argument("--host", default=DEFAULT_HOST, help="vLLM base URL")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Served model name")
    parser.add_argument("--api-key", default=DEFAULT_API_KEY, help="Optional API key")
    parser.add_argument("--system", help="Optional system message")
    parser.add_argument("--max-tokens", type=int, default=1024, help="Maximum output tokens")
    parser.add_argument("--temperature", type=float, default=0.7, help="Sampling temperature")
    parser.add_argument("--no-stream", action="store_true", help="Wait for one JSON response")
    parser.add_argument("--list-models", action="store_true", help="List served models and exit")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    host = args.host.rstrip("/")

    try:
        models = available_models(host, args.api_key)
        if args.list_models:
            print("\n".join(models))
            return 0
        if args.model not in models:
            print(
                f"Model {args.model!r} is not served. Available: "
                + (", ".join(models) if models else "none"),
                file=sys.stderr,
            )
            return 2

        prompt = read_prompt(args.prompt)
        if not prompt:
            print("Prompt cannot be empty.", file=sys.stderr)
            return 2
        if args.max_tokens < 1:
            print("--max-tokens must be at least 1.", file=sys.stderr)
            return 2

        stream_chat(
            host,
            args.model,
            prompt,
            args.system,
            args.api_key,
            args.max_tokens,
            args.temperature,
            not args.no_stream,
        )
        return 0
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        print(f"vLLM returned HTTP {exc.code}: {detail}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"Cannot reach vLLM at {host}: {exc.reason}", file=sys.stderr)
        return 1
    except (json.JSONDecodeError, KeyError, RuntimeError) as exc:
        print(f"vLLM request failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
