# Design notes

Why agent-gate is built the way it is, what it deliberately does not do, and where it could go next.
For setup and usage, start with the [README](../README.md).

## Design decisions

**Risk tiers, not blocklists.** Each tool declares `low` / `medium` / `high`.
Policy modes (`permissive` / `standard` / `strict`) map tiers to
allow / prompt / deny. Adding a new tool means declaring its tier - the
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

**Role labels, not identity.** `run_agent(..., actor="user@example.com")`
(or `ActorContext(user_id, role)`, CLI: `--actor / --role`, MCP:
`AGENT_GATE_MCP_ACTOR` / `AGENT_GATE_MCP_ROLE`) attaches caller-supplied
labels to every audit entry, and the policy grades by role label: `intern`
is denied high-risk tools (send_email, delete_file) in every mode;
`manager` / `admin` / `user` follow the normal mode logic. These labels are
declared, not authenticated: anyone invoking the CLI or the MCP server can
claim any actor or role, so this is not an identity layer. Verifying who the
caller really is (authentication) is a separate layer above this harness and
is not built here. Note the tradeoff: the actor identifier is stored as
given for attribution, unlike payloads which are PII-scrubbed, so don't put
secrets in `user_id`. An explicit `--role` without `--actor` is kept as an
unknown user with that role, never silently dropped.

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
output as data - never as instructions. The loop itself can only execute
tool calls the *model* issues, never instructions found in tool output.
Detection is regex heuristics, not a guarantee, and unknown tool names
are surfaced as errors instead of crashing the run without a run_end.

**Soft deletes.** `delete_file` moves files to `sandbox/.trash` instead of
unlinking - reversible, still audited.

**Three-layer memory (`memory.py`).** Working memory compresses the message
list past a char budget (keep system + first + last 2 turns, middle replaced
by a summary placeholder). Episodic memory persists one JSONL line per run
and recalls by keyword + recency. Semantic memory is an explicit key-value
fact store (`set_fact` / `forget`) - nothing inferred silently, so a wrong
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
tokens + cost (char/4 approximation, Haiku-class price table - replace with
the provider's `usage` block for exact numbers). Written to
`metrics/metrics.jsonl`; `cli metrics` aggregates across runs. Audit
answers "what happened, in order"; metrics answers "how often, how slow,
how expensive".

**MCP server.** MCP calls go through the same policy engine and audit log as the agent loop.
No approver exists over MCP, so "prompt" decisions are denied.
Mode and actor come from `AGENT_GATE_MCP_MODE`, `AGENT_GATE_MCP_ACTOR` and `AGENT_GATE_MCP_ROLE` (default mode strict), so a client cannot change its own policy.
An explicit role without an actor is kept as unknown plus that role, never dropped.
The policy budget is per 60-second window, not per process lifetime, so a long-lived server recovers after a burst instead of denying everything until restart.
The MCP SDK validates arguments against the tool schema and silently drops unknown keys before application code runs, so a raw-argument guard inspects the wire arguments first (middleware on mcp 2.x, an overridden `call_tool` on 1.x).
Unknown tools, unknown argument keys and malformed envelopes are rejected with `isError` (with the same "Error executing tool X:" prefix as policy denials), and the raw arguments are audited.
Every rejection is charged to the rate budget, and advertised schemas carry `additionalProperties: false`.

## RAG (role-filtered doc search)

The `search_docs` tool lets the agent answer from company documents instead
of guessing: keyword search over a small demo doc set, returning
paragraph-level hits with doc id, paragraph id and score.

- Retrieval is hand-rolled BM25 (k1 1.5, b 0.75, stdlib only, no new
  dependencies). A query that scores 0 against every paragraph comes back
  as `no_match` with no hits.
- Permissions are per document and checked before retrieval, with default
  deny. Each document lists explicit `allowed_roles`; the token `"all"`
  means every role, and no hierarchy is inferred. A missing or unknown
  caller role only sees `"all"` documents.
- Filtered-out documents are named in the audit trail
  (`doc_access_filtered`) and never appear in the result the model sees,
  so the model cannot learn that a restricted document exists from the
  search itself.

What this is not:

- Semantic search. Paraphrases with no shared terms score 0. Embeddings
  are a possible upgrade, deliberately not added (no new dependency).
- Authenticated access control. Roles are caller-declared labels with no
  authentication, the same known gap documented below: whoever can set
  the role gets the documents.
- A guarantee against hallucination. The system prompt tells the model to
  cite doc and paragraph ids and to say it does not know when nothing
  matches, but that is a prompt-level instruction, not an enforced check.

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
- Permissive mode performs no recipient check on `send_email`: if the
  model decides to mail an arbitrary external address, the harness
  allows it (policy judges risk tiers, not destinations). Shown by a
  positive control: haiku, asked directly by the user to email
  attacker@example.org, had the message denied in strict mode but
  written to the outbox in permissive mode.
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
- Embedding-based retrieval for `search_docs` (replacing BM25)
- Memory upgrade: embedding recall for episodic memory, TTL + conflict
  resolution for semantic facts
