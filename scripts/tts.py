#!/usr/bin/env python3
"""Render a timestamped Markdown transcript to an MP3 with OpenAI TTS."""

from __future__ import annotations

import argparse
import asyncio
import base64
import os
import re
import shutil
import subprocess
import sys
import tempfile
import wave
from pathlib import Path

from openai import AsyncOpenAI


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


async def synthesize(text: str, output: Path, *, voice: str, instructions: str) -> None:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is missing from the environment or .env")
    client = AsyncOpenAI(api_key=api_key)
    pcm = bytearray()
    async with client.realtime.connect(model="gpt-realtime-2.1-mini") as connection:
        await connection.session.update(session={
            "type": "realtime",
            "model": "gpt-realtime-2.1-mini",
            "output_modalities": ["audio"],
            "instructions": instructions,
            "audio": {
                "output": {
                    "format": {"type": "audio/pcm", "rate": 24000},
                    "voice": voice,
                },
            },
        })
        await connection.conversation.item.create(item={
            "type": "message",
            "role": "user",
            "content": [{
                "type": "input_text",
                "text": f"Read the following transcript verbatim. Do not add or omit any words.\n\n{text}",
            }],
        })
        await connection.response.create()
        async for event in connection:
            if event.type == "response.output_audio.delta":
                pcm.extend(base64.b64decode(event.delta))
            elif event.type == "error":
                raise RuntimeError(f"Realtime API error: {event.error.message}")
            elif event.type == "response.done":
                if getattr(event.response, "status", None) == "failed":
                    raise RuntimeError("Realtime audio generation failed")
                break

    if not pcm:
        raise RuntimeError("Realtime API returned no audio")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="secclaw-tts-") as temp_dir:
        wav_path = Path(temp_dir) / "transcript.wav"
        with wave.open(str(wav_path), "wb") as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(24000)
            wav_file.writeframes(pcm)
        ffmpeg = shutil.which("ffmpeg")
        bundled = Path("/tmp/secclaw-ffmpeg/node_modules/ffmpeg-static/ffmpeg")
        if not ffmpeg and bundled.is_file():
            ffmpeg = str(bundled)
        if not ffmpeg:
            raise RuntimeError("ffmpeg is required to encode transcript.mp3")
        subprocess.run(
            [ffmpeg, "-y", "-loglevel", "error", "-i", str(wav_path), "-codec:a", "libmp3lame", "-b:a", "128k", str(output)],
            check=True,
        )


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
        asyncio.run(synthesize(text, args.output.resolve(), voice=args.voice, instructions=args.instructions))
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"tts: {error}", file=sys.stderr)
        return 1

    print(f"Wrote {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
