#!/usr/bin/env python3
"""Render a timestamped Markdown transcript to an MP3 with OpenAI TTS."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "docs" / "transcripts.md"
DEFAULT_OUTPUT = ROOT / "transcript.mp3"
TIMESTAMP = re.compile(r"^`?\[\d{2}:\d{2}(?::\d{2})?\]`?\s*")


def load_env(path: Path) -> None:
    """Load simple KEY=VALUE entries without overriding the process environment."""
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if value[:1] == value[-1:] and value[:1] in {'"', "'"}:
            value = value[1:-1]
        if key:
            os.environ.setdefault(key, value)


def transcript_text(path: Path) -> str:
    """Remove Markdown structure and timestamps so they are not spoken aloud."""
    sentences: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        line = TIMESTAMP.sub("", line)
        line = re.sub(r"[*_`]", "", line).strip()
        if line:
            sentences.append(line)
    return "\n\n".join(sentences)


def synthesize(text: str, output: Path, *, voice: str, instructions: str) -> None:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is missing from the environment or .env")
    if len(text) > 4096:
        raise RuntimeError(f"Transcript is {len(text)} characters; the Speech API limit is 4096")

    payload = json.dumps(
        {
            "model": "gpt-4o-mini-tts",
            "voice": voice,
            "input": text,
            "instructions": instructions,
            "response_format": "mp3",
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        "https://api.openai.com/v1/audio/speech",
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            audio = response.read()
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenAI Speech API returned HTTP {error.code}: {detail}") from error

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(audio)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("output", nargs="?", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--voice", default="marin")
    parser.add_argument(
        "--instructions",
        default=(
            "Speak as a confident, natural enterprise technology presenter. "
            "Use a warm, conversational tone, clear diction, and brief pauses between paragraphs."
        ),
    )
    args = parser.parse_args()

    load_env(ROOT / ".env")
    try:
        text = transcript_text(args.input.resolve())
        if not text:
            raise RuntimeError("The transcript contains no speakable text")
        synthesize(text, args.output.resolve(), voice=args.voice, instructions=args.instructions)
    except (OSError, RuntimeError) as error:
        print(f"tts: {error}", file=sys.stderr)
        return 1

    print(f"Wrote {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
