"""Idempotency: same logical tool call executed N times == executed once.

Why the agent needs it: execution is at-least-once. The model may repeat a
tool call, a timeout triggers a retry, or the process restarts mid-run.
You cannot guarantee "execute exactly once", so you make the receiver
idempotent: ``at-least-once delivery + idempotent receiver == effectively once``.

Mechanism: ``make_key`` hashes (run_id + tool + canonical args). The store
maps key -> cached result. The agent checks the store *after* policy +
approval (so the audit trail still shows the decision) and *before*
``tool.run``. On a hit it returns the cached result without re-executing,
so a retried ``send_email`` sends one email, not two.

Scope: keys include ``run_id``, so two separate runs that happen to call
the same tool with the same args are *not* deduped against each other --
that would be surprising (e.g. sending the same summary twice on purpose).
There is no cross-run explicit key: an explicit key was removed because
a caller-supplied key is a collision hazard (two different calls sharing
one explicit key would incorrectly dedup), and it is not a valid tool
argument -- policy denies unknown arguments, including that key.

Only successful results are cached. Errors are *not* cached, so a retry
after a transient failure can still succeed.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from . import paths


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str)


def make_key(run_id: str, tool_name: str, args: dict) -> str:
    # Per-run key only: run_id + tool + canonical args. No explicit
    # override (see module docstring for why it was removed).
    raw = f"{run_id}:{tool_name}:{_canonical(args or {})}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


class IdempotencyStore:
    def __init__(self, root: Path | None = None):
        self.dir = (root or paths.data_dir())
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "idempotency.json"
        self._cache: dict[str, dict] = self._load()

    def _load(self) -> dict[str, dict]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}

    def _save(self) -> None:
        self.path.write_text(
            json.dumps(self._cache, ensure_ascii=False, indent=2),
            encoding="utf-8")

    def lookup(self, key: str) -> dict | None:
        entry = self._cache.get(key)
        if entry is None:
            return None
        return entry.get("result")

    def store(self, key: str, tool_name: str, result: Any) -> None:
        self._cache[key] = {
            "tool": tool_name,
            "ts": time.time(),
            "result": result,
        }
        self._save()

    def hits(self) -> int:
        return len(self._cache)
