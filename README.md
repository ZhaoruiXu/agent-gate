# agent-gate

[![evals](https://github.com/ZhaoruiXu/agent-gate/actions/workflows/evals.yml/badge.svg)](https://github.com/ZhaoruiXu/agent-gate/actions/workflows/evals.yml)

A safe tool-calling harness.

A **safe tool-calling agent** skeleton: the "tooling layer" that lets an LLM
agent take real actions (send email, write files, query a DB) without letting
it go rogue.

```
                    ┌─────────────┐
  user request ───▶ │  agent loop │ ◀── model (Anthropic API or scripted mock)
                    │  (ReAct)    │
                    └──────┬──────┘
                           │ every tool call
              ┌────────────▼────────────┐
              │  policy engine          │── allow / prompt / deny
              │  risk tiers + hard rules│── actor role gating
              │  low: read-only → auto  │   (intern: no high-risk)
              │  medium: writes → ask   │
              │  high: external → ask / │
              │         deny in strict  │
              └────────────┬────────────┘
              ┌────────────▼────────────┐
              │  tool registry (MCP)    │── read_inbox · db_query ·
              │  5 tools, sandboxed     │   write_file · delete_file ·
              └────────────┬────────────┘   send_email
                           │
              ┌────────────▼────────────┐
              │  audit log (hash-chained│── every turn, decision,
              │  JSONL, PII-scrubbed)   │   approval & result
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │  memory (3 layers)      │── working compress ·
              │  episodic + semantic    │   episodic recall ·
              └────────────┬────────────┘   semantic facts
                           │
              ┌────────────▼────────────┐
              │  idempotency store      │── key = hash(run + tool
              │  key -> cached result   │   + args); retry returns
              └────────────┬────────────┘   cached, never re-executes
                           │
              ┌────────────▼────────────┐
              │  metrics (observability)│── per-tool latency / ok /
              │  metrics.jsonl + CLI    │   denied / cached, tokens,
              └─────────────────────────┘   est. cost
```

## Quickstart

```bash
cd agent-gate
python3 -m venv .venv && .venv/bin/pip install -e .
cp .env.example .env   # optional: add ANTHROPIC_API_KEY for a real model

# scripted demo, no API key needed (shows approval + injection flagging)
.venv/bin/python -m agent_gate.cli demo

# interactive agent (uses Anthropic if key is set, else scripted mock)
.venv/bin/python -m agent_gate.cli run "Summarize my inbox"

# non-interactive / strict mode (--mode is global, before the subcommand)
.venv/bin/python -m agent_gate.cli --mode strict run "Email the summary to me" --yes

# inspect + verify the audit chain of the latest run
.venv/bin/python -m agent_gate.cli audit

# show aggregated observability across runs (latency, cost, per-tool stats)
.venv/bin/python -m agent_gate.cli metrics

# run the eval suite (51 checks, no API key needed)
.venv/bin/python evals/run_evals.py

# expose the tools as an MCP server (stdio) for Claude Code / Claude Desktop
# MCP calls go through the same policy engine and audit log as the agent
# loop. No approver exists over MCP, so "prompt" decisions are denied;
# mode/actor come from AGENT_GATE_MCP_MODE / _ACTOR / _ROLE (default strict).
# An explicit ROLE without ACTOR is kept as unknown+role, never dropped.
# The policy budget is per 60-second window, not per process lifetime,
# so a long-lived MCP server recovers after a burst instead of denying
# everything until restart. The SDK validates arguments against the tool
# schema and silently drops unknown keys before our code runs, so a
# raw-argument guard inspects the wire arguments first (middleware on
# mcp 2.x, an overridden call_tool on 1.x): unknown tools, unknown
# argument keys and malformed envelopes are rejected with isError
# ("Error executing tool X:" prefix, like policy denials) and the raw
# arguments are audited. Every rejection is charged to the rate budget.
# Advertised schemas carry additionalProperties: false.
.venv/bin/python -m agent_gate.server
```

## Design decisions

**Risk tiers, not blocklists.** Each tool declares `low` / `medium` / `high`.
Policy modes (`permissive` / `standard` / `strict`) map tiers to
allow / prompt / deny. Adding a new tool means declaring its tier — the
rest is automatic.

**Defense in depth.** The policy engine *and* the tool handlers enforce
constraints independently: `db_query` is checked by policy and then by
SQLite itself (a read-only connection plus an authorizer that only
allows SELECT/READ/FUNCTION, never hand-parsed SQL text, which comments
can bypass), file tools are confined to `sandbox/` at both layers.

**Approvals are first-class.** Medium/high-risk calls pause for approval
(CLI prompt, or programmatic `Approver`). Every approval/denial is audited.
The CLI prompt is local-only and shows the full call, including the
recipient of a `send_email`: scrubbing the prompt was a bug, because the
approver could not see what they were approving. The audit log still
scrubs free-text PII, but keeps the recipient as attribution. Prompt
output uses repr(), so control characters in a recipient cannot forge
the displayed address. Over MCP, denied/errored calls raise, so MCP
reports them with isError=True instead of as successful results.

**Actor attribution + role gating.** `run_agent(..., actor="user@example.com")`
(or `ActorContext(user_id, role)`, CLI: `--actor / --role`). Every audit
entry carries the actor, so the trail answers *who* did what, not just what
happened. Policy grades by role: `intern` is denied high-risk tools
(send_email, delete_file) in every mode; `manager` / `admin` / `user`
follow the normal mode logic. Note the tradeoff: the actor identifier is
stored as given for attribution, unlike payloads which are PII-scrubbed —
don't put secrets in `user_id`. An explicit `--role` without `--actor`
is kept as an unknown user with that role, never silently dropped.

**Tamper-evident audit log.** Each entry hash-chains to the previous one;
`cli audit` runs verify(), which detects an edited entry and a seq gap. Args/results are
PII-scrubbed by value before writing (never by editing JSON text, which
used to crash on bare 10-digit numbers). Recording is locked, so
concurrent MCP threads sharing one log cannot corrupt the chain.
Scope: tamper-evident, not tamper-proof. An attacker with write access
who recomputes the chain, or who truncates the tail, still passes
verification; that threat model needs an externally anchored terminal
hash, which is out of scope here.

**Tool output is untrusted data.** The mock inbox contains a prompt
injection. The harness detects injection patterns in tool output, flags
them in the audit log, and appends a system note so the model treats the
output as data — never as instructions. The loop itself can only execute
tool calls the *model* issues, never instructions found in tool output.
Detection is regex heuristics, not a guarantee, and unknown tool names
are surfaced as errors instead of crashing the run without a run_end.

**Soft deletes.** `delete_file` moves files to `sandbox/.trash` instead of
unlinking — reversible, still audited.

**Three-layer memory (`memory.py`).** Working memory compresses the message
list past a char budget (keep system + first + last 2 turns, middle replaced
by a summary placeholder). Episodic memory persists one JSONL line per run
and recalls by keyword + recency. Semantic memory is an explicit key-value
fact store (`set_fact` / `forget`) — nothing inferred silently, so a wrong
fact can be corrected. Upgrade path: swap keyword recall for embedding
cosine; interface stays the same.

**Idempotency (`idempotency.py`).** Key = `hash(run_id + tool + canonical
args)`, checked *after* policy + approval, *before* execution. First call
executes and caches the result; a retry with the same key returns the cached
result without re-executing, so a retried `send_email` sends once. Only
successes are cached (errors retry cleanly). Keys are per-run, so two
intentional runs with identical args are not merged. There is no
cross-run explicit key: it was removed as a collision hazard, and
policy denies it as an unknown argument if a caller tries to pass it.

**Observability (`metrics.py`).** Per run: total latency, per-tool
calls / ok / error / denied / cached, approvals granted/denied, estimated
tokens + cost (char/4 approximation, Haiku-class price table — replace with
the provider's `usage` block for exact numbers). Written to
`metrics/metrics.jsonl`; `cli metrics` aggregates across runs. Audit
answers "what happened, in order"; metrics answers "how often, how slow,
how expensive".

## Eval results

`evals/run_evals.py` runs 51 checks (no API key needed):

| case | what it proves | result |
|---|---|---|
| `read_only_auto` | read-only tools auto-approved | ✅ PASS |
| `write_requires_approval` | medium-risk write pauses for approval | ✅ PASS |
| `permissive_allows_medium` | policy modes change behavior predictably | ✅ PASS |
| `send_denied_strict` | high-risk email denied in strict mode, no side effect | ✅ PASS |
| `injection_ignored` | injected instruction flagged in audit, never executed | ✅ PASS |
| `destructive_sql_denied` | non-SELECT denied by hard rule in *any* mode | ✅ PASS |
| `idempotency_dedup` | same `send_email` twice → 1 outbox line, 2nd is cache hit | ✅ PASS |
| `metrics_recorded` | metrics.jsonl gets 1 record per run | ✅ PASS |
| `memory_persists` | episodic.jsonl gets 1 episode per run | ✅ PASS |
| `working_memory_compress` | long context compresses to summary placeholder | ✅ PASS |
| `intern_denied_high_risk` | intern role denied send_email, no side effect, actor on all audit entries | ✅ PASS |
| `manager_prompt_high_risk` | manager role follows normal mode logic (prompt → send), actor on all audit entries | ✅ PASS |
| `unknown_tool_continues` | unknown tool name is an audited error, run still ends cleanly | ✅ PASS |
| `audit_bare_number` | bare 10-digit audit payload does not crash, is redacted as a string | ✅ PASS |
| `sql_tool_layer` | tool handler itself rejects DROP, table survives | ✅ PASS |
| `injection_two_qualifier` | two-qualifier injection phrase is detected | ✅ PASS |
| `cli_role_without_actor` | `--role intern` without `--actor` is kept, not dropped | ✅ PASS |

| `server_handlers` | server.py dispatch core via a stubbed mcp module: allow, deny-as-ToolError, permissive intern role without actor, signature, advertised additionalProperties:false, raw-arg guard (unknown key/tool rejected with isError and audited with raw args), audit entries, MCP injection flag/note | ✅ PASS |
| `recipient_display` | approval prompt shows recipient with repr(), no raw carriage return | ✅ PASS |
| `cache_hit_note` | cached injected tool result still carries the system note | ✅ PASS |
| `comment_bypass_sql` | comment-hidden DROP is denied by SQLite, table survives | ✅ PASS |
| `concurrent_audit_writes` | 20 threads sharing one AuditLog still verify, no seq gap | ✅ PASS |
| `policy_role_normalisation` | Intern/INTERN normalised, unknown roles denied | ✅ PASS |
| `policy_budget_window` | budget resets after its window, not only on restart | ✅ PASS |
| `policy_nonstring_deny` | non-string sql/path/args are denied, not AttributeError | ✅ PASS |
| `write_file_symlink_root` | write under a symlinked root reports success correctly | ✅ PASS |
| `injection_qualifier_variants` | "your previous" and "the above" injection phrases detected | ✅ PASS |

| `server_real_session` | real MCP ClientSession when mcp is installed, else SKIP (not PASS) | ✅ PASS |
| `mcp_unknown_arg_rejected` | T10 regression: extra key over a real ClientSession is rejected with isError (not dropped), raw args audited, schema advertises additionalProperties:false, unknown tool audited; SKIP without mcp | ✅ PASS |
| `mcp_guard_malformed` | malformed tools/call envelopes (string args, non-string name, list-of-pairs args) are clean isError rejections with the Error-executing prefix, never leaked Python exceptions, and audited | ✅ PASS |
| `mcp_guard_budget_charged` | guard rejections count against the rate budget: 25 unknown-tool rejections exhaust the budget of 20, the next legitimate call is denied | ✅ PASS |
| `policy_single_statement` | multi-statement SQL denied by policy itself (deny, not allow-then-error); trailing semicolon stays allowed | ✅ PASS |
| `no_skip_validation` | --no-skip with no names or an unknown name exits non-zero instead of silently doing nothing | ✅ PASS |
| `policy_unknown_arg` | unknown argument keys are denied by policy | ✅ PASS |
| `approver_key_repr_and_to_full` | approval keys are repr()d, long recipient shown in full or denied over limit | ✅ PASS |
| `terminal_c1_bidi_strip` | C1 controls and bidi overrides stripped from terminal output | ✅ PASS |
| `mcp_prompt_not_allow` | standard-mode prompt is a denial over MCP, not an allow | ✅ PASS |
| `audit_seq_on_serialisation_failure` | failed audit record does not consume a seq number | ✅ PASS |
| `run_agent_weird_arg` | non-dict tool arguments deny and continue, run does not die | ✅ PASS |
| `mcp_audit_truncated` | MCP audit results are truncated before scrubbing/writing | ✅ PASS |
| `idempotency_key_dropped` | explicit key no longer overrides the derived key, policy denies it | ✅ PASS |
| `injection_case_insensitive` | uppercase/mixed-case injection phrases detected | ✅ PASS |
| `terminal_strip` | ANSI/control chars stripped from model terminal output | ✅ PASS |
| `approver_per_field` | approval shows each arg on its own line, path not hidden by long content | ✅ PASS |
| `policy_default_budget_lifetime` | default budget is per-engine lifetime, window only in server | ✅ PASS |
| `policy_counters_thread_safe` | concurrent decides do not lose counter increments | ✅ PASS |
| `policy_lock_used` | decide actually acquires the budget lock | ✅ PASS |
| `authorizer_temp_table` | authorizer denies temp tables that a read-only file allows | ✅ PASS |
| `ro_connection_mode` | user query opens with uri=True and mode=ro | ✅ PASS |
| `delete_file_symlink_root` | delete under a symlinked root resolves both sides | ✅ PASS |
| `scrub_value_narrow_to` | "to" kept only inside args; keys, sets and bytes scrubbed | ✅ PASS |

51 checks, updated 2026-10-29 after the live MCP test follow-ups (guard rejects malformed envelopes cleanly, guard rejections charge the rate budget, Error-executing prefix on guard denials). The idempotency explicit-key feature was removed in an earlier round; see the idempotency section. The server tests run real MCP ClientSessions when the `mcp` package is installed (verified locally on mcp 1.30.0 and 2.3.0), and report SKIP when it is not.

## Requirements

Python >= 3.10 (see `pyproject.toml`, `requires-python = ">=3.10"`).

## Known gaps (not fixed, listed honestly)

- `db_query` time is bounded (5s progress handler), but row count is
  not: a fast SELECT returning millions of rows is still fetched in
  full with `fetchall()`. Do not point this tool at a large production
  table without a LIMIT.
- PII scrubbing is regex-based, not Presidio: it can miss unusual
  formats, and the email/phone regexes run over the full free-text
  input, so very large bodies (MB-scale) can be slow to scrub for
  that one call. Scrubbing now happens outside the audit lock, and
  MCP tool results are truncated to 2000 chars before audit, so a
  large result no longer stalls other MCP calls, but policy-decision
  args are not truncated.
- The audit chain is tamper-evident, not tamper-proof (see above):
  truncation or a full rewrite with recomputed hashes still verifies
  without an externally anchored terminal hash.
- Injection detection is regex heuristics: it flags suspicious tool
  output, it does not prove a sentence is or is not an instruction.
- `scrub_value` now covers dict keys, sets and bytes, and keeps "to"
  only inside an "args" dict, but the underlying email/phone patterns
  are still the simple regexes above.

## What's next (deliberately out of scope for the skeleton)

- Real mailer (SMTP / Resend / Gmail API) behind `send_email`
- Approval UX over MCP (elicitation / webhooks) instead of CLI-only
- `Agent playground`: Next.js UI to compose/test agent chains without local setup
- Telemetry: LangSmith / Langfuse / Sentry traces per run (exact provider
  token usage instead of the char/4 estimate)
- PII scrubbing with Presidio instead of regexes; full RBAC matrix
  (per-tool role permissions, team scopes) beyond the intern/high-risk rule
- Red-team eval set: more injection/JB exfiltration scenarios
- Memory upgrade: embedding recall for episodic memory, TTL + conflict
  resolution for semantic facts

## Design highlights

What the eval suite in `evals/run_evals.py` actually checks:

- Policy modes change tool behaviour predictably: high-risk email is denied in strict mode with no side effect, and medium-risk writes pause for approval in standard mode.
- Role gating is enforced in every mode: an intern is denied high-risk tools, while a manager follows the normal mode logic.
- Unknown tool names become audited errors; the run still ends cleanly.
- Injection phrases in tool output are flagged in the audit log and not executed as instructions; detection is regex heuristics, not a guarantee.
- The audit chain is verified in the evals: edited entries and sequence gaps are detected. The chain is tamper-evident, not tamper-proof.
- Concurrent audit writes from 20 threads still verify, with no sequence gap.
- The database tool is read-only in two layers: a read-only connection and a SQLite authorizer that only allows SELECT and related reads, so DROP and similar statements do not execute.
- Idempotency is per run: the same send_email call twice produces one outbox line, the second call is a cache hit.
- Approval prompts show every field (recipient in full, other fields truncated per field) with repr(), so control characters cannot forge the displayed address.
