"""Append-only, hash-chained audit log.

Every model turn, policy decision, approval, tool execution and final answer
is recorded. Each entry commits to the previous entry's hash, so tampering
with history is detectable via verify().

Scope, stated plainly: this is tamper-*evident* against editing an entry
without recomputing the chain. It is NOT tamper-*proof* against an attacker
who already has write access to the file and recomputes the hashes, or
who truncates the tail: a truncated or fully rewritten chain still
verifies, because no terminal hash or entry count is anchored anywhere
else. That threat model needs an external anchor (signed terminal hash,
append-only store, or a hash published elsewhere), which is out of scope
for this skeleton.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any

from . import paths
from .policy import ActorContext, scrub_value


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str)


def _actor_json(actor: ActorContext | str | dict | None) -> Any:
    """Serialize the actor for the audit log. Stored as given (attribution
    requires the identifier) - unlike payloads, it is NOT PII-scrubbed."""
    if isinstance(actor, ActorContext):
        return {"user_id": actor.user_id, "role": actor.role}
    return actor


class AuditLog:
    def __init__(self, run_id: str, path: Path | None = None,
                 actor: ActorContext | str | dict | None = None):
        self.run_id = run_id
        self.path = path or (paths.audit_dir() / f"{run_id}.jsonl")
        self.actor = actor
        self._seq = 0
        self._prev_hash = "GENESIS"
        # MCP 2.x runs sync tools in threads, so concurrent calls share
        # one AuditLog. Without this lock, two threads can read the same
        # _prev_hash / _seq, and verify() then reports a seq gap or a
        # broken chain. The whole seq/hash/append step must be atomic.
        self._lock = threading.Lock()

    def record(self, event_type: str, payload: dict) -> dict:
        # Scrub and serialise the payload OUTSIDE the lock: scrubbing
        # runs regexes over free text, so a large payload used to stall
        # every other thread sharing this log for seconds. Only the
        # seq/hash/append step, which is quick, needs the lock.
        scrubbed = scrub_value(payload)
        # Verify the payload serialises before touching _seq, so a
        # serialisation failure cannot leave a seq gap in the chain.
        _canonical(scrubbed)
        actor_json = _actor_json(self.actor)
        _canonical(actor_json)
        with self._lock:
            seq = self._seq + 1
            entry = {
                "seq": seq,
                "ts": time.time(),
                "run_id": self.run_id,
                "actor": actor_json,
                "type": event_type,
                # Scrub by value, not by editing JSON text (see policy.scrub_value).
                "payload": scrubbed,
                "prev_hash": self._prev_hash,
            }
            entry["hash"] = hashlib.sha256(
                (entry["prev_hash"] + _canonical({k: v for k, v in entry.items()
                                                 if k != "hash"})).encode()
            ).hexdigest()
            # Serialise the full entry before committing _seq /
            # _prev_hash: only after this line succeeds do we advance.
            line = _canonical(entry) + "\n"
            self._seq = seq
            self._prev_hash = entry["hash"]
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line)
            return entry

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in
                self.path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def verify(self) -> tuple[bool, str]:
        prev = "GENESIS"
        for i, e in enumerate(self.read_all(), start=1):
            if e.get("seq") != i:
                return False, f"seq gap at entry {i}: got {e.get('seq')}"
            if e["prev_hash"] != prev:
                return False, f"chain broken at seq {e['seq']}"
            recomputed = hashlib.sha256(
                (e["prev_hash"] + _canonical({k: v for k, v in e.items()
                                             if k != "hash"})).encode()
            ).hexdigest()
            if recomputed != e["hash"]:
                return False, f"hash mismatch at seq {e['seq']}"
            prev = e["hash"]
        return True, f"ok ({len(self.read_all())} entries)"
