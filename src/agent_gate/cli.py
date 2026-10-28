"""agent-gate CLI.

  python -m agent_gate.cli demo            # scripted demo (no API key needed)
  python -m agent_gate.cli run "request"    # interactive agent (needs ANTHROPIC_API_KEY,
                                           # falls back to a scripted mock otherwise)
  # --mode is a global flag: it must come BEFORE the subcommand.
  python -m agent_gate.cli --mode permissive run "request" --yes
  python -m agent_gate.cli audit            # show + verify the latest audit log
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import paths
from .agent import (AnthropicClient, AutoApprover, CLIAprover, MockClient,
                    _safe_terminal_text, new_run_id, run_agent)
from .audit import AuditLog
from .metrics import MetricsCollector
from .policy import ActorContext, PolicyEngine

DEMO_SCRIPT = [
    {"text": "I'll check your inbox first.",
     "tool_calls": [{"name": "read_inbox", "arguments": {"n": 3}}]},
    {"text": ("Found 3 emails, including an invoice and a message that tried to "
              "inject instructions (flagged, ignored). Writing a summary file."),
     "tool_calls": [{"name": "write_file",
                     "arguments": {"path": "inbox-summary.md",
                                   "content": "# Inbox summary\n\n- Invoice #1042 ($1,200) due Friday\n- Standup moved to 10am\n" }}]},
    {"text": "Summary written to sandbox/inbox-summary.md. No external actions taken."},
]


def _latest_audit() -> AuditLog | None:
    files = sorted(paths.audit_dir().glob("*.jsonl"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        return None
    log = AuditLog(run_id="__view__", path=files[0])
    return log


def _actor_from_args(args: argparse.Namespace) -> ActorContext | None:
    # Fail closed on an explicit role: --role intern without --actor used
    # to be silently dropped, leaving no restriction at all. Now it is
    # kept as an unknown user with that role, so intern gating applies
    # and the audit trail shows the role that was claimed.
    role = getattr(args, "role", None) or "user"
    if getattr(args, "actor", None):
        return ActorContext(user_id=args.actor, role=role)
    if role != "user":
        print(f"(no --actor given: treating caller as unknown user "
              f"with role {role!r})", file=sys.stderr)
        return ActorContext(user_id="unknown", role=role)
    return None


def cmd_demo(args: argparse.Namespace) -> int:
    audit = AuditLog(run_id=new_run_id())
    policy = PolicyEngine(mode=args.mode)
    client = MockClient(DEMO_SCRIPT)
    run_agent("Summarize my inbox and save the summary to a file.",
              client, policy, audit, AutoApprover(True), verbose=True,
              actor=_actor_from_args(args))
    ok, msg = audit.verify()
    print(f"audit verify: {msg}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    audit = AuditLog(run_id=new_run_id())
    policy = PolicyEngine(mode=args.mode)
    approver = AutoApprover(True) if args.yes else CLIAprover()
    if os.environ.get("ANTHROPIC_API_KEY"):
        client: AnthropicClient | MockClient = AnthropicClient()
    else:
        print("(no ANTHROPIC_API_KEY - using scripted mock client)", file=sys.stderr)
        client = MockClient(DEMO_SCRIPT)
    run_agent(args.request, client, policy, audit, approver, verbose=True,
              actor=_actor_from_args(args))
    ok, msg = audit.verify()
    print(f"audit verify: {msg}")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    log = _latest_audit()
    if log is None:
        print("no audit logs yet")
        return 1
    print(f"--- {log.path} ---")
    for e in log.read_all():
        p = e["payload"]
        detail = ""
        if e["type"] == "policy_decision":
            detail = f"{p['tool']} -> {p['action']} ({p['reason']})"
        elif e["type"] == "tool_result":
            detail = (f"{p['tool']} [{p['status']}]"
                      + (" INJECTION_SUSPECTED" if p.get("injection_suspected") else ""))
        elif e["type"] == "approval":
            detail = f"{p['tool']} granted={p['granted']}"
        elif e["type"] in ("run_start", "run_end", "model_turn"):
            detail = str(p)[:120]
        print(f"#{e['seq']:02d} {e['type']:15s} {_safe_terminal_text(detail)}")
    ok, msg = log.verify()
    print(f"verify: {msg}")
    return 0 if ok else 2


def cmd_metrics(args: argparse.Namespace) -> int:
    records = MetricsCollector.load_all()
    print(MetricsCollector.summary_text(records))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="agent-gate")
    ap.add_argument("--mode", default="standard",
                    choices=["permissive", "standard", "strict"])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo")
    r = sub.add_parser("run")
    r.add_argument("request")
    r.add_argument("--yes", action="store_true",
                   help="auto-approve policy prompts (non-interactive)")
    for p in (sub.choices["demo"], r):
        p.add_argument("--actor", default=None,
                       help="who the agent acts for (e.g. user@example.com); "
                            "carried on every audit entry")
        p.add_argument("--role", default=None,
                       choices=["intern", "user", "manager", "admin"],
                       help="actor role: intern is denied high-risk tools. "
                            "An explicit role without --actor is kept as "
                            "an unknown user with that role, never dropped.")
    sub.add_parser("audit")
    sub.add_parser("metrics")
    args = ap.parse_args()
    if args.cmd == "demo":
        return cmd_demo(args)
    if args.cmd == "run":
        return cmd_run(args)
    if args.cmd == "metrics":
        return cmd_metrics(args)
    return cmd_audit(args)


if __name__ == "__main__":
    raise SystemExit(main())
