"""Run observability: per-run metrics + a CLI summary.

What it records (alongside, not inside, the audit log):
  - per-tool: calls, ok / error / denied / cached, total latency ms
  - per-run: total latency, approvals granted/denied, estimated tokens + cost
  - run outcome: final answer (truncated), whether it hit max_iters

Token / cost numbers are *estimates* for the skeleton: char count / 4
approximates tokens, and cost uses a fixed Haiku-class price table.
With a real provider, replace ``estimate_tokens`` with the API's
``usage`` block (Anthropic returns input/output tokens per call) -- the
collector interface stays the same, so the upgrade is a one-line change.
This is the "observable" half of the audit story: audit answers "what
happened, in order, and was it tampered with"; metrics answers "how often,
how slow, how expensive, how often denied".
"""
from __future__ import annotations

import json
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from . import paths

# Rough Haiku-class pricing, USD per 1M tokens. Estimates only.
PRICE_INPUT_PER_M = 0.80
PRICE_OUTPUT_PER_M = 4.00


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


class MetricsCollector:
    def __init__(self, run_id: str, policy_mode: str = "standard",
                 root: Path | None = None):
        self.run_id = run_id
        self.policy_mode = policy_mode
        self.dir = (root or paths.metrics_dir())
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "metrics.jsonl"
        self.start = time.time()
        self.per_tool: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"calls": 0, "ok": 0, "error": 0, "denied": 0,
                     "cached": 0, "latency_ms": 0})
        self.approvals_granted = 0
        self.approvals_denied = 0
        self.input_chars = 0
        self.output_chars = 0
        self.hit_max_iters = False

    def record_tool(self, tool: str, status: str, latency_ms: int,
                    cached: bool = False) -> None:
        s = self.per_tool[tool]
        s["calls"] += 1
        s["latency_ms"] += latency_ms
        if cached:
            s["cached"] += 1
        elif status == "ok":
            s["ok"] += 1
        elif status == "denied":
            s["denied"] += 1
        else:
            s["error"] += 1

    def record_approval(self, granted: bool) -> None:
        if granted:
            self.approvals_granted += 1
        else:
            self.approvals_denied += 1

    def record_tokens(self, input_text: str, output_text: str) -> None:
        self.input_chars += len(input_text)
        self.output_chars += len(output_text)

    def finish(self, final: str = "", hit_max_iters: bool = False) -> dict:
        self.hit_max_iters = hit_max_iters
        in_tokens = max(1, self.input_chars // 4)
        out_tokens = max(1, self.output_chars // 4)
        cost = (in_tokens * PRICE_INPUT_PER_M
                + out_tokens * PRICE_OUTPUT_PER_M) / 1_000_000
        rec = {
            "ts": time.time(),
            "run_id": self.run_id,
            "policy_mode": self.policy_mode,
            "total_latency_ms": round((time.time() - self.start) * 1000),
            "input_tokens_est": in_tokens,
            "output_tokens_est": out_tokens,
            "cost_usd_est": round(cost, 6),
            "approvals_granted": self.approvals_granted,
            "approvals_denied": self.approvals_denied,
            "hit_max_iters": hit_max_iters,
            "final_chars": len(final),
            "per_tool": dict(self.per_tool),
        }
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return rec

    @staticmethod
    def load_all(root: Path | None = None) -> list[dict]:
        d = root or paths.metrics_dir()
        p = d / "metrics.jsonl"
        if not p.exists():
            return []
        out = []
        for line in p.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out

    @staticmethod
    def summary_text(records: list[dict]) -> str:
        if not records:
            return "no metrics yet (run demo first)"
        runs = len(records)
        total_cost = sum(r.get("cost_usd_est", 0) for r in records)
        avg_lat = sum(r.get("total_latency_ms", 0) for r in records) / runs
        lines = [
            f"runs: {runs}  avg latency: {avg_lat:.0f}ms  "
            f"total cost (est): ${total_cost:.4f}",
        ]
        agg: dict[str, dict] = defaultdict(
            lambda: {"calls": 0, "ok": 0, "denied": 0, "cached": 0})
        for r in records:
            for tool, s in r.get("per_tool", {}).items():
                for k in ("calls", "ok", "denied", "cached"):
                    agg[tool][k] += s.get(k, 0)
        for tool, s in sorted(agg.items()):
            lines.append(
                f"  {tool:12s} calls={s['calls']} ok={s['ok']} "
                f"denied={s['denied']} cached={s['cached']}")
        return "\n".join(lines)
