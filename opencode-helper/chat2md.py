#!/usr/bin/env python3
"""Convert an `opencode export` JSON dump into a readable Markdown transcript.

Usage:
    chat2md.py <input.json> <output.md> [--reasoning]

Each user prompt becomes a `##` section; the assistant answer is its content.
Use `--reasoning` to include the assistant's internal reasoning as a
`### thinking` subsection (with the answer under `### final answer`).
Tool calls, steps and other implementation details are hidden.
"""

import argparse
import json
import re
from datetime import datetime, timezone

URL_RE = re.compile(r"(?<!\()(https?://[^\s)\]]+)")


def ts_to_str(ms):
    try:
        return datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    except (TypeError, ValueError):
        return ""


def linkify(text):
    return URL_RE.sub(lambda m: f"[{m.group(0)}]({m.group(0)})", text)


def text_parts(parts):
    return [p for p in parts if p.get("type") == "text" and p.get("text")]


def reasoning_parts(parts):
    return [p for p in parts if p.get("type") == "reasoning" and p.get("text")]


def heading(text):
    return re.sub(r"\s+", " ", text).strip()


def metadata_table(info):
    tokens = info.get("tokens", {})
    cache = tokens.get("cache", {})
    model = info.get("model", {})
    rows = [
        ("Session", info.get("id", "")),
        ("Title", info.get("title", "")),
        ("Project", info.get("directory", "")),
        ("Agent", info.get("agent", "")),
        ("Model", model.get("id", "")),
        ("Provider", model.get("providerID", "")),
        ("Tokens in/out", f"{tokens.get('input', 0)} / {tokens.get('output', 0)}"),
        ("Cache read/write", f"{cache.get('read', 0)} / {cache.get('write', 0)}"),
        ("Cost", info.get("cost", 0)),
    ]
    rows = [(k, str(v)) for k, v in rows if v]
    if not rows:
        return ""
    lines = ["| Field | Value |", "| --- | --- |"]
    for k, v in rows:
        lines.append(f"| {k} | {linkify(v)} |")
    return "\n".join(lines)


def build_sections(messages, include_reasoning):
    sections = []
    current = None
    for msg in messages:
        parts = msg.get("parts", [])
        role = (msg.get("info") or {}).get("role", "unknown")
        if role == "user":
            texts = [p["text"].rstrip() for p in text_parts(parts)]
            if not texts:
                continue
            current = {"prompt": "\n\n".join(texts), "reasoning": [], "answer": []}
            sections.append(current)
        elif role == "assistant" and current is not None:
            if include_reasoning:
                current["reasoning"].extend(p["text"].rstrip() for p in reasoning_parts(parts))
            current["answer"].extend(p["text"].rstrip() for p in text_parts(parts))
    return sections


def main():
    parser = argparse.ArgumentParser(
        description="Convert an opencode export JSON dump into a readable Markdown transcript."
    )
    parser.add_argument("input", help="input chat.json exported with `opencode export`")
    parser.add_argument("output", help="output Markdown file")
    parser.add_argument(
        "--reasoning",
        action="store_true",
        help="include the assistant's internal reasoning as a `### thinking` subsection",
    )
    args = parser.parse_args()

    with open(args.input, encoding="utf-8") as fh:
        data = json.load(fh)
    info = data.get("info", {}) if isinstance(data, dict) else {}
    messages = data.get("messages", []) if isinstance(data, dict) else data

    out = []
    out.append(f"# {info.get('title') or 'Chat transcript'}\n")
    table = metadata_table(info)
    if table:
        out.append(table + "\n")
    out.append("---\n")

    for current in build_sections(messages, args.reasoning):
        out.append(f"## {heading(current['prompt'])}\n")
        if args.reasoning and current["reasoning"]:
            out.append("### thinking\n")
            out.append("\n\n".join(linkify(t) for t in current["reasoning"]) + "\n")
            out.append("### final answer\n")
        if current["answer"]:
            out.append("\n\n".join(linkify(t) for t in current["answer"]) + "\n")
        out.append("---\n")

    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()