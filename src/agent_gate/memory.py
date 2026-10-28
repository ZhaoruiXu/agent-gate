"""Three-layer memory for the agent.

Layers (kept deliberately small for the skeleton; no vector DB):

  1. working  - the current run's message list. ``compress_messages`` trims
     it when it grows past a char budget: keep system + first user turn +
     last 2 turns, replace the middle with a one-line summary. This is the
     cheap, deterministic alternative to "just append forever".
  2. episodic - one JSONL line per finished run (request, final answer,
     tools used). ``recall`` does keyword + recency retrieval: score each
     episode by word overlap with the query, break ties by recency.
     Upgrade path: replace keyword scoring with embedding cosine.
  3. semantic - a small key -> value fact store (e.g. user preferences,
     stable business facts). Explicit ``set_fact`` / ``forget``; nothing is
     inferred silently, so a wrong fact can be corrected and stays corrected.

All files live under ``paths.memory_dir()`` and respect ``paths.set_root``
so evals (which use a temp root) stay isolated.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from . import paths
from .policy import scrub_pii


def _words(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+|[\u4e00-\u9fff]", text.lower()))


class MemoryStore:
    def __init__(self, root: Path | None = None):
        self.dir = (root or paths.memory_dir())
        self.dir.mkdir(parents=True, exist_ok=True)
        self.episodic_path = self.dir / "episodic.jsonl"
        self.semantic_path = self.dir / "semantic.json"
        if not self.semantic_path.exists():
            self.semantic_path.write_text("{}", encoding="utf-8")

    # --- episodic ---
    def remember_episode(self, run_id: str, request: str, final: str,
                         tools_used: list[str]) -> dict:
        entry = {
            "ts": time.time(),
            "run_id": run_id,
            "request": scrub_pii(request)[:500],
            "final": scrub_pii(final)[:500],
            "tools_used": tools_used,
        }
        with open(self.episodic_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def _read_episodes(self) -> list[dict]:
        if not self.episodic_path.exists():
            return []
        out = []
        for line in self.episodic_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out

    def recall(self, query: str, limit: int = 3) -> list[str]:
        """Keyword + recency retrieval over episodic memory."""
        if not query.strip():
            return []
        qwords = _words(query)
        scored: list[tuple[float, dict]] = []
        for i, ep in enumerate(self._read_episodes()):
            hay = f"{ep.get('request','')} {ep.get('final','')}"
            overlap = len(qwords & _words(hay))
            if overlap == 0:
                continue
            # recency tie-break: later episodes score slightly higher
            score = overlap + i * 0.01
            scored.append((score, ep))
        scored.sort(key=lambda t: t[0], reverse=True)
        return [
            f"[past run {ep['run_id']}] {ep['request']} -> {ep['final'][:200]}"
            for _, ep in scored[:limit]
        ]

    # --- semantic ---
    def _read_facts(self) -> dict[str, str]:
        try:
            return json.loads(self.semantic_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def set_fact(self, key: str, value: str) -> None:
        facts = self._read_facts()
        facts[key] = scrub_pii(value)
        self.semantic_path.write_text(
            json.dumps(facts, ensure_ascii=False, indent=2), encoding="utf-8")

    def get_fact(self, key: str) -> str | None:
        return self._read_facts().get(key)

    def forget(self, key: str) -> bool:
        facts = self._read_facts()
        if key not in facts:
            return False
        del facts[key]
        self.semantic_path.write_text(
            json.dumps(facts, ensure_ascii=False, indent=2), encoding="utf-8")
        return True

    def all_facts(self) -> dict[str, str]:
        return self._read_facts()


def _msg_chars(messages: list[dict]) -> int:
    total = 0
    for m in messages:
        c = m.get("content", "")
        total += len(c) if isinstance(c, str) else len(str(c))
        for tc in m.get("tool_calls", []) or []:
            total += len(str(getattr(tc, "arguments", tc)))
    return total


def compress_messages(messages: list[dict], max_chars: int = 8000) -> tuple[list[dict], bool]:
    """Trim working memory when it exceeds max_chars.

    Keeps system + first user turn + last 2 turns, replaces the middle with
    a summary placeholder. Returns (new_messages, did_compress).
    """
    if _msg_chars(messages) <= max_chars or len(messages) <= 4:
        return messages, False
    head = messages[:2]
    tail = messages[-2:]
    dropped = len(messages) - len(head) - len(tail)
    summary = {
        "role": "system",
        "content": f"[working-memory compressed: {dropped} middle turns "
                   f"summarised to keep context under {max_chars} chars]",
    }
    return head + [summary] + tail, True
