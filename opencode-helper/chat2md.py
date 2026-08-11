#!/usr/bin/env python3
"""Convert an `opencode export` JSON dump into a readable Markdown transcript.

Usage:
    chat2md.py --input <input.json> --output <output.md> [--reasoning]

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


def detect_mcps_used(messages):
    """Scan messages for tool calls to detect which MCPs were used."""
    mcps = set()
    for msg in messages:
        for part in msg.get("parts", []):
            # Check both "tool_use" parts and "tool" field in the part
            tool_name = part.get("name") or part.get("tool") or ""
            if tool_name:
                # Extract MCP name from tool name (e.g., "jeb_decompile_code_item" -> "jeb")
                parts = tool_name.split("_")
                if parts:
                    mcp_name = parts[0]
                    mcps.add(mcp_name)
    return sorted(mcps) if mcps else []


def metadata_table(info, messages=None):
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
    if messages:
        mcps = detect_mcps_used(messages)
        if mcps:
            rows.append(("Tools enabled", ", ".join(mcps)))
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


def json_to_markdown(data, include_reasoning=False, output_file=None):
    """Convert opencode export JSON data to Markdown.

    Args:
        data: Parsed JSON from opencode export.
        include_reasoning: Whether to include assistant reasoning sections.
        output_file: Path to write Markdown, or None to return string.

    Returns:
        The Markdown string if output_file is None, else None.
    """
    info = data.get("info", {}) if isinstance(data, dict) else {}
    messages = data.get("messages", []) if isinstance(data, dict) else data

    out = []
    out.append(f"# {info.get('title') or 'Chat transcript'}\n")
    table = metadata_table(info, messages)
    if table:
        out.append(table + "\n")
    for current in build_sections(messages, include_reasoning):
        out.append(f"## {heading(current['prompt'])}\n")
        if include_reasoning and current["reasoning"]:
            reasoning = [t for t in current["reasoning"] if t.strip()]
            if reasoning:
                out.append("### thinking\n")
                out.append("\n\n".join(linkify(t) for t in reasoning) + "\n")
                out.append("### final answer\n")
        answer = [t for t in current["answer"] if t.strip()]
        if answer:
            out.append("\n\n".join(linkify(t) for t in answer) + "\n")

    md = "\n".join(out) + "\n"
    if output_file:
        with open(output_file, "w", encoding="utf-8") as fh:
            fh.write(md)
    return md


def list_sessions_and_select(days=-1):
    """Query opencode's SQLite DB for sessions and let the user pick one. Returns session ID.

    Args:
        days: Only show sessions from the last `days` days. Use -1 for all sessions (default).
    """
    import sqlite3
    from pathlib import Path

    db_path = Path.home() / ".local" / "share" / "opencode" / "opencode.db"
    if not db_path.is_file():
        print("No opencode database found.")
        return None

    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    if days == -1:
        query = "SELECT id, title, time_created FROM session WHERE time_archived IS NULL ORDER BY time_created DESC"
    else:
        cutoff = now_ms - (days * 24 * 3600 * 1000)
        query = "SELECT id, title, time_created FROM session WHERE time_archived IS NULL AND time_created >= ? ORDER BY time_created DESC"
        with sqlite3.connect(str(db_path)) as conn:
            cur = conn.execute(query, (cutoff,))
            sessions = [{"id": r[0], "title": r[1] or "(untitled)", "created": r[2]} for r in cur.fetchall()]
        return _present_and_select(sessions)

    with sqlite3.connect(str(db_path)) as conn:
        sessions = [{"id": r[0], "title": r[1] or "(untitled)", "created": r[2]} for r in conn.execute(query).fetchall()]
    return _present_and_select(sessions)


def _present_and_select(sessions):
    """Display sessions and let the user pick one. Returns session ID."""
    if not sessions:
        print("No sessions found.")
        return None

    print("Available sessions:")
    for i, s in enumerate(sessions):
        print(f"  {i + 1}. {s['title']} ({ts_to_str(s['created'])})")

    while True:
        choice = input("\nSelect session number: ").strip()
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(sessions):
                return sessions[idx]["id"]
            print(f"Please enter a number between 1 and {len(sessions)}.")
        except ValueError:
            print("Invalid input.")


def export_session(session_id):
    """Export a session by ID, returning parsed JSON."""
    import subprocess
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    subprocess.run(
        ["opencode", "export", session_id],
        stdout=open(tmp_path, "w"), stderr=subprocess.PIPE
    )
    with open(tmp_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    import os
    os.unlink(tmp_path)
    return data


def main():
    import subprocess

    parser = argparse.ArgumentParser(
        description="Convert an opencode export JSON dump into a readable Markdown transcript."
    )
    parser.add_argument("--input", help="input chat.json exported with `opencode export`")
    parser.add_argument("--output", required=True, help="output Markdown file")
    parser.add_argument(
        "--reasoning",
        action="store_true",
        help="include the assistant's internal reasoning as a `### thinking` subsection",
    )
    parser.add_argument(
        "--days",
        type=int, default=1,
        help="only show sessions from the last X days (-1 for all, default 1)",
    )
    args = parser.parse_args()

    if args.input:
        with open(args.input, encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        session_id = list_sessions_and_select(days=args.days)
        if not session_id:
            return
        data = export_session(session_id)

    json_to_markdown(data, args.reasoning, args.output)


if __name__ == "__main__":
    main()