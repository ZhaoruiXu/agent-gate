"""Approval policy: every tool call goes through decide() before execution.

Modes:
  permissive - approve everything (dev only; hard-rule violations still denied)
  standard   - auto-approve low risk, prompt on medium/high
  strict     - auto-approve low, prompt on medium, deny high

Hard rules apply in every mode (defense in depth - the tool handlers also
enforce their own constraints):
  - db_query must be a SELECT (no writes/DDL through the read-only tool)
  - file tools cannot escape the sandbox
"""
from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass

from .tools import Tool

ALLOWED_ROLES = frozenset({"intern", "user", "manager", "admin"})

# Named limit for a recipient: RFC 5321 caps a path at 256 chars, so
# 320 is generous. Longer than this is denied, never silently truncated
# in the approval prompt (see CLIAprover).
MAX_TO_LEN = 320


def _normalise_role(role) -> str | None:
    """Lower-case and strip a role, so Intern/INTERN are not a bypass."""
    if isinstance(role, str):
        return role.strip().lower()
    if role is None:
        return None
    return str(role).strip().lower()


def _actor_role(actor) -> str | None:
    if actor is None:
        return None
    if isinstance(actor, dict):
        return _normalise_role(actor.get("role"))
    return _normalise_role(getattr(actor, "role", None))

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b")


def scrub_text(text: str) -> str:
    """Redact obvious PII in a single string."""
    text = _EMAIL_RE.sub("[EMAIL_REDACTED]", text)
    text = _PHONE_RE.sub("[PHONE_REDACTED]", text)
    return text


def scrub_pii(text: str) -> str:
    """Backwards-compatible alias: redact PII in a string."""
    return scrub_text(text)


def scrub_value(value, *, _in_args: bool = False):
    """Redact PII value-by-value, never by editing a JSON string.

    The old approach (dump to JSON, regex-replace the text, re-parse)
    crashed on bare 10-digit numbers: the replacement is not valid JSON
    as a bare value. Walking the value keeps numbers, bools and strings
    typed, and a bare 10-digit int is turned into a redaction *string*,
    which stays valid JSON.

    Coverage, fixed in this round: dict keys are scrubbed too (a key
    can itself be an email), sets are scrubbed element-wise, and bytes
    are decoded and scrubbed to a string (audit JSON cannot hold raw
    bytes anyway). The one exemption is narrow, not at any depth: a
    "to" field is kept only inside an "args" dict, where it is the
    destination attribution for a send_email. A "to" field anywhere
    else (for example, inside a free-text body dict) is scrubbed like
    any other PII, because exempting "to" at any depth would leak
    addresses that are not destinations.
    """
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            new_key = scrub_text(k) if isinstance(k, str) else k
            if k == "args" and isinstance(v, dict):
                out[new_key] = scrub_value(v, _in_args=True)
            elif _in_args and k == "to":
                out[new_key] = v
            else:
                out[new_key] = scrub_value(v, _in_args=False)
        return out
    if isinstance(value, (list, tuple)):
        return [scrub_value(v, _in_args=False) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted((scrub_value(v, _in_args=False) for v in value),
                      key=lambda x: str(x))
    if isinstance(value, (bytes, bytearray)):
        return scrub_text(bytes(value).decode("utf-8", errors="replace"))
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if re.fullmatch(r"\d{10}", str(value)):
            return "[PHONE_REDACTED]"
        return value
    if isinstance(value, str):
        return scrub_text(value)
    return value


@dataclass
class Decision:
    action: str  # "allow" | "prompt" | "deny"
    reason: str


@dataclass
class ActorContext:
    """Who is on whose behalf the agent is acting.

    user_id identifies the human (e.g. an email); role grades what the
    agent may do for them. Roles: "intern" | "user" | "manager" | "admin".
    Only "intern" currently gets extra restriction (no high-risk tools);
    everyone else follows the normal mode logic.
    """
    user_id: str
    role: str = "user"

    def __post_init__(self):
        # Normalise here so every caller (CLI, MCP, run_agent) sees the
        # same role: "Intern" and "INTERN" must not slip past the check.
        normalised = _normalise_role(self.role)
        self.role = normalised if normalised is not None else "user"


class PolicyEngine:
    def __init__(self, mode: str = "standard", max_tool_calls: int = 20,
                 max_calls_per_tool: int = 10,
                 actor: ActorContext | None = None,
                 budget_window_seconds: float | None = None):
        if mode not in ("permissive", "standard", "strict"):
            raise ValueError(f"unknown policy mode: {mode}")
        self.mode = mode
        self.max_tool_calls = max_tool_calls
        self.max_calls_per_tool = max_calls_per_tool
        self.actor = actor
        # Budget decision: by default (None) the budget is per
        # PolicyEngine lifetime, which is per agent run for the CLI /
        # agent loop. A long-lived MCP server must pass an explicit
        # window (server.py passes 60s) so it recovers after a burst
        # instead of denying everything until restart. Applying the
        # window to every engine was a regression: a CLI run lasting
        # over 60s silently got a fresh budget.
        self.budget_window_seconds = budget_window_seconds
        self._total = 0
        self._per_tool: dict[str, int] = {}
        self._window_start = time.monotonic()
        # Same lock pattern as AuditLog: MCP threads share one engine,
        # and _total += 1 is not atomic, so concurrent decides could
        # lose increments or allow past the cap.
        self._lock = threading.Lock()

    def _maybe_reset_window(self) -> None:
        if self.budget_window_seconds is None:
            return
        now = time.monotonic()
        if now - self._window_start >= self.budget_window_seconds:
            self._total = 0
            self._per_tool = {}
            self._window_start = now

    def decide(self, tool: Tool, args: dict,
               actor: ActorContext | None = None) -> Decision:
        # Badly typed args must be a deny, never a crash: decide() runs
        # outside the tool-execution try block in the agent loop, so an
        # AttributeError here used to kill the whole run.
        if not isinstance(args, dict):
            return Decision("deny", "tool args must be a dict")
        # --- schema keys only: an extra key is not just ignored, it
        # is a denial. Otherwise a model could smuggle a key whose
        # printed name contains ANSI/cursor codes and draws a fake
        # "to: ..." line in the approval prompt, or flood the prompt
        # with junk keys. The allowed set is the tool's JSON schema.
        try:
            allowed_keys = set(tool.parameters.get("properties", {}).keys())
        except Exception:  # noqa: BLE001 - a broken schema is a deny
            return Decision("deny", "tool schema unavailable")
        unknown = [k for k in args.keys() if k not in allowed_keys]
        if unknown:
            unknown_sorted = sorted(unknown, key=lambda x: str(x))
            return Decision(
                "deny",
                f"unknown argument(s): {[repr(k) for k in unknown_sorted]}")
        # --- recipient length: never truncate "to" silently ---
        to_val = args.get("to")
        if isinstance(to_val, str) and len(to_val) > MAX_TO_LEN:
            return Decision(
                "deny",
                f"recipient too long ({len(to_val)} chars, limit {MAX_TO_LEN})")
        # --- hard rules (apply in every mode) ---
        if tool.name == "db_query":
            sql = args.get("sql")
            if not isinstance(sql, str):
                return Decision("deny", "db_query sql must be a string")
            if not sql.strip().lstrip("(").upper().startswith("SELECT"):
                return Decision("deny", "db_query is read-only: only SELECT allowed")
        if tool.name in ("write_file", "delete_file"):
            rel = args.get("path", "")
            if not isinstance(rel, str):
                return Decision("deny", "file path must be a string")
            if ".." in rel.replace("\\", "/").split("/") or rel.startswith("/"):
                return Decision("deny", f"path escapes sandbox: {rel!r}")
        if tool.name == "write_file" and "content" in args:
            if not isinstance(args["content"], str):
                return Decision("deny", "write_file content must be a string")
        if tool.name == "send_email":
            for field in ("to", "subject", "body"):
                if field in args and not isinstance(args[field], str):
                    return Decision("deny", f"send_email {field} must be a string")

        # --- role gating (actor-aware, applies in every mode) ---
        actor = actor or self.actor
        role = _actor_role(actor)
        if actor is not None and role not in ALLOWED_ROLES:
            return Decision("deny", f"unknown role {role!r}")
        if actor is not None and role == "intern" and tool.risk == "high":
            return Decision("deny",
                            f"role {role!r} may not use high-risk tool "
                            f"{tool.name}")

        # --- rate limits (per window, see __init__) ---
        with self._lock:
            self._maybe_reset_window()
            self._total += 1
            self._per_tool[tool.name] = self._per_tool.get(tool.name, 0) + 1
            if self._total > self.max_tool_calls:
                return Decision("deny", f"run budget exceeded ({self.max_tool_calls} tool calls)")
            if self._per_tool[tool.name] > self.max_calls_per_tool:
                return Decision("deny", f"per-tool limit exceeded for {tool.name}")

        # --- risk tiers ---
        if self.mode == "permissive":
            return Decision("allow", "permissive mode")
        if tool.risk == "low":
            return Decision("allow", "low-risk read-only tool")
        if self.mode == "strict" and tool.risk == "high":
            return Decision("deny", "strict mode denies high-risk tools")
        return Decision("prompt", f"{tool.risk}-risk tool requires approval ({self.mode} mode)")
