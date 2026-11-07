# agent-gate

[![evals](https://github.com/ZhaoruiXu/agent-gate/actions/workflows/evals.yml/badge.svg)](https://github.com/ZhaoruiXu/agent-gate/actions/workflows/evals.yml)

**A checkpoint between an AI agent and the tools it can use.**
Every tool call is checked against a policy, held for a human's approval (or denied) when it is risky, and written to an audit log that detects edited entries.

You want an agent that can read your inbox, query a database or send an email.
You do not want it to send that email because a stranger's message told it to.
agent-gate sits in the middle and decides, call by call, what goes through.

## When you would use it

- **You are giving an agent real actions** (email, files, a database) and need a hard stop that does not depend on the model behaving.
- **You need to show what an agent did**: which tool it called, with what arguments, who approved it and what came back, in order, in a log you can check for edits.
- **You connect an MCP client** such as Claude Code or Claude Desktop and want those tool calls to pass through the same rules.
- **You are learning how agent guardrails work** and want a small, readable codebase with tests for every rule.

## What you get

- **Risk-tiered policy.** Each tool is `low`, `medium` or `high` risk. A mode (`permissive`, `standard`, `strict`) decides whether each tier is allowed, needs approval, or is denied. Some rules hold in every mode: SQL is read-only, files stay inside a sandbox folder, and an `intern` role never sends email or deletes files.
- **Human approval.** Risky calls stop and show you the full call, recipient included, before anything happens.
- **Tamper-evident audit log.** Each entry is hash-chained to the one before, so an edited entry is detected. Personal data is masked before writing.
- **Prompt-injection handling.** Tool output is treated as data. Suspected injections are flagged in the log and the model is warned.
- **Role-filtered document search.** A `search_docs` tool removes documents the caller's role may not see before searching, so restricted text never reaches the model.
- **Retry safety.** A retried `send_email` sends once.
- **Tested.** 58 deterministic evals run in CI on every push. A [red-team run with real models](docs/evals.md#red-team-real-model-injection-tests) is written up with its limits.

Only calls that go through agent-gate are gated. If your agent also has other tools, such as a client's own file or shell tools, agent-gate does not see those.

All six tools are safe demos: email goes to a local file, the inbox is fake and the database is a small SQLite file.
You can try everything without risk, then replace a tool with a real one.

## How it works

```
  your request ─▶ agent loop or MCP client ─▶ every tool call
                                                   │
                                       ┌───────────▼───────────┐
                                       │ policy                │  allow / ask / deny
                                       │ hard rules, roles,    │
                                       │ risk tier x mode      │
                                       └───────────┬───────────┘
                                       ┌───────────▼───────────┐
                                       │ approval (if "ask")   │  y / n in the terminal
                                       └───────────┬───────────┘
                                       ┌───────────▼───────────┐
                                       │ tool runs, sandboxed  │  read_inbox, db_query,
                                       │ output checked for    │  write_file, delete_file,
                                       │ injection             │  send_email, search_docs
                                       └───────────┬───────────┘
                                       ┌───────────▼───────────┐
                                       │ audit log             │  hash-chained JSONL
                                       └───────────────────────┘
```

## Quickstart (about 5 minutes, no API key)

You need **Python 3.10 or newer** and **git**.
Check your Python version first:

```bash
python3 --version
```

If it prints 3.9 or lower (macOS ships 3.9), install a newer one, for example `brew install python@3.12`, and use `python3.12` in place of `python3` in step 2.

The quickstart assumes `ANTHROPIC_API_KEY` is not set. If you have it in your shell, step 5 would call the real, billed API, so clear it for this terminal:

```bash
unset ANTHROPIC_API_KEY
```

1. Clone the repository and enter it.

   ```bash
   git clone https://github.com/ZhaoruiXu/agent-gate.git
   ```

   ```bash
   cd agent-gate
   ```

   `ls` should now show `README.md`, `pyproject.toml` and a `src` folder.

2. Create a virtual environment and install agent-gate into it.

   ```bash
   python3 -m venv .venv
   ```

   ```bash
   .venv/bin/pip install -e .
   ```

   It should end with `Successfully installed agent-gate-0.1.0` and its dependencies.

   On Windows, use `.venv\Scripts\pip` and `.venv\Scripts\python` wherever this README says `.venv/bin/pip` and `.venv/bin/python`. The other commands are written for a macOS or Linux shell: on Windows, replace `"$(pwd)/.venv/bin/python"` with the full path to `.venv\Scripts\python.exe`, and `export NAME=value` with `$env:NAME="value"` in PowerShell.

3. Run the scripted demo.
   It uses a built-in mock model, so it needs no key and costs nothing.

   ```bash
   .venv/bin/python -m agent_gate.cli demo
   ```

   You should see the agent read the inbox, a warning that one email contains a prompt injection, and a file write that needed approval (the demo approves it for you):

   ```
     -> read_inbox [allow] low-risk read-only tool
        !! possible prompt injection in tool output - flagged
     -> write_file [prompt] medium-risk tool requires approval (standard mode)
        approval: granted
   audit verify: ok (10 entries)
   ```

   The file it wrote is `sandbox/inbox-summary.md`.

4. Read the audit log of that run.

   ```bash
   .venv/bin/python -m agent_gate.cli audit
   ```

   Each numbered line is one event: the request, each model turn, each policy decision, each approval and each tool result.
   The last line, `verify: ok (10 entries)`, means the hash chain is intact; an edited or missing entry would print `verify: hash mismatch at seq N` or similar instead.

5. Try approving a call yourself.

   ```bash
   .venv/bin/python -m agent_gate.cli run "Summarize my inbox"
   ```

   It shows the `write_file` call it wants to make, with every argument, then asks `approve? [y/N]`.
   Type `n` and press Enter: the line `approval: denied` appears and the call does not run.
   Without an API key this command replays the same scripted conversation as the demo, whatever you type as the request.
   The script's last line still says "Summary written" because it is fixed text, not a real model reacting.
   Run `.venv/bin/python -m agent_gate.cli audit` to see the truth: `write_file granted=False`, then `write_file [denied]`.
   (The `sandbox/inbox-summary.md` you still see is the one step 3 wrote.)

6. Run the eval suite.

   ```bash
   .venv/bin/python evals/run_evals.py
   ```

   The last line should read `58/58 passed, 0 skipped`.

You have now seen the policy, the approval step, injection flagging and the audit log working.
The next two sections connect a real model.

## Use it from an MCP client

agent-gate also runs as an [MCP](https://modelcontextprotocol.io) server, so a client such as Claude Code or Claude Desktop calls its tools through the same policy and audit log.
Your client's own subscription pays for the model, so you need no API key here either.

The client starts the server for you; you never run it by hand.
The server reads these settings from its environment (plus `AGENT_GATE_ROOT`, described under the command reference, which you normally leave unset):

| Variable | Values | Default |
| --- | --- | --- |
| `AGENT_GATE_MCP_MODE` | `strict`, `standard`, `permissive` | `strict` |
| `AGENT_GATE_MCP_ROLE` | `intern`, `user`, `manager`, `admin` | none: no role rule applies, and `search_docs` returns only documents open to everyone |
| `AGENT_GATE_MCP_ACTOR` | any label, such as `alice@example.com` | none |

There is no approval prompt over MCP, so any call that would ask for approval is denied.
In practice: `strict` and `standard` allow only the read-only tools, and `permissive` allows everything the hard rules do not forbid.

### Claude Code

Run this from inside the `agent-gate` folder, so `$(pwd)` expands to its full path:

```bash
claude mcp add agent-gate -e AGENT_GATE_MCP_MODE=strict -e AGENT_GATE_MCP_ROLE=intern -- "$(pwd)/.venv/bin/python" -m agent_gate.server
```

By default this registers the server for the current folder only, so start Claude Code in this same folder:

```bash
claude
```

To check it from the terminal first, run `claude mcp list` in the same folder; it should show `agent-gate: ... ✔ Connected`.
Inside Claude Code, type `/mcp`. It should list `agent-gate` as connected, with 6 tools.
Then ask it something, for example:

> Use the agent-gate tools to read my inbox and summarise it, then search the docs for salary bands.

The inbox summary works.
The salary search comes back with no match, because an `intern` may not see that document.
To see the difference, remove the server, add it again with `AGENT_GATE_MCP_ROLE=manager`, and ask the same question: the salary-bands paragraphs now come back, each with its document and paragraph id.
Every call is in the newest file under `audit/`; run `.venv/bin/python -m agent_gate.cli audit` to read it.

To change the mode or role, remove the server and add it again with new values:

```bash
claude mcp remove agent-gate
```

### Claude Desktop

Open the config file (on macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`, on Windows: `%APPDATA%\Claude\claude_desktop_config.json`) and add the server.
Use the full path to your clone; `~` and `$(pwd)` are not expanded in this file.
On Windows, point `command` at `.venv\Scripts\python.exe` and write each backslash twice, as JSON requires (`C:\\Users\\you\\agent-gate\\.venv\\Scripts\\python.exe`).

```json
{
  "mcpServers": {
    "agent-gate": {
      "command": "/full/path/to/agent-gate/.venv/bin/python",
      "args": ["-m", "agent_gate.server"],
      "env": { "AGENT_GATE_MCP_MODE": "strict", "AGENT_GATE_MCP_ROLE": "user" }
    }
  }
}
```

Do Quickstart steps 1 and 2 first, so `.venv` exists.
Quit and reopen Claude Desktop, then open the connectors menu (the plus icon in the chat box) and check that `agent-gate` is listed and switched on.
If it is missing or shows an error, read `~/Library/Logs/Claude/mcp-server-agent-gate.log` (Windows: `%APPDATA%\Claude\logs`).
The audit log still lands in the clone's `audit/` folder, whatever folder Claude Desktop starts the server in.

## Use the built-in agent loop with a real model

The `run` command can drive a real Claude model through the Anthropic API instead of the mock.
This needs an API key from [console.anthropic.com](https://console.anthropic.com), which is billed separately from a Claude subscription.

```bash
export ANTHROPIC_API_KEY=your-key-here
```

```bash
.venv/bin/python -m agent_gate.cli --mode strict run "Read my inbox and email a summary to me@example.com"
```

In `strict` mode the email is denied whatever the model wants.
Try `--mode standard` to be asked instead, or put `--role intern` after the request to see the role rule deny it in any mode:

```bash
.venv/bin/python -m agent_gate.cli --mode permissive run "Email a summary to me@example.com" --role intern
```

## Command reference

| Command | What it does |
| --- | --- |
| `.venv/bin/python -m agent_gate.cli demo` | Scripted run with the mock model and auto-approval. |
| `.venv/bin/python -m agent_gate.cli run "<request>"` | Agent run. Uses the Anthropic API if `ANTHROPIC_API_KEY` is set, otherwise the mock. Asks you to approve risky calls. |
| `... run "<request>" --yes` | Same, approving every prompt automatically. Denials still apply. |
| `.venv/bin/python -m agent_gate.cli audit` | Prints the most recently modified audit log in `audit/` and verifies its hash chain. |
| `.venv/bin/python -m agent_gate.cli metrics` | Per-tool call counts, latency and estimated cost across all runs. |
| `.venv/bin/python evals/run_evals.py` | The 58 deterministic evals. |
| `.venv/bin/python -m agent_gate.server` | The MCP server on stdio. Normally started by your MCP client. |

Options for `demo` and `run`: `--actor <label>` and `--role intern|user|manager|admin` (written on every audit entry).
`--mode permissive|standard|strict` goes **before** the subcommand, for example `cli --mode strict run "..."`.
The default mode is `standard` for the CLI and `strict` for the MCP server.

What each mode does with each risk tier:

| Tool risk | Tools | `permissive` | `standard` | `strict` |
| --- | --- | --- | --- | --- |
| low | `read_inbox`, `db_query`, `search_docs` | allow | allow | allow |
| medium | `write_file` | allow | ask | ask |
| high | `send_email`, `delete_file` | allow | ask | deny |

Hard rules apply first, in every mode: only single `SELECT` statements, file paths inside `sandbox/`, no unknown arguments, a budget of 20 calls per run (per minute on the MCP server) and 10 per tool, and no high-risk tools for `intern`.

Everything a run writes stays in the repository folder and is ignored by git: `audit/`, `sandbox/`, `data/`, `memory/` and `metrics/`.
Delete those folders to start fresh.
Set `AGENT_GATE_ROOT=/some/other/folder` to keep them somewhere else.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `pip install -e .` fails with `requires a different Python`, or with `File "setup.py" or "setup.cfg" not found` | The venv was made with Python 3.9 or older. Delete `.venv` and recreate it with `python3.12 -m venv .venv`. |
| `python3 -m venv .venv` fails with `ensurepip is not available` | On Debian or Ubuntu the venv module is a separate package. Install it with `sudo apt install python3-venv` (or `python3.12-venv`), delete `.venv`, and repeat step 2. |
| `No module named agent_gate` | You are using a Python outside the venv. Run commands through `.venv/bin/python`, or re-run step 2. |
| `zsh: no such file or directory: .venv/bin/python` | You are not in the `agent-gate` folder. `cd` into it first. |
| `run` prints `(no ANTHROPIC_API_KEY - using scripted mock client)` although you have a key | The key is not exported in this shell. Run `export ANTHROPIC_API_KEY=...` in the same terminal. A `.env` file is not read automatically. |
| `run` seems to wait forever | It is asking `approve? [y/N]` and waiting for you. Type `y` or `n`, or pass `--yes`. |
| `python -m agent_gate.server` prints nothing and does not return | That is normal. It is waiting for an MCP client on stdin. Press Ctrl+C and let the client start it instead. |
| `/mcp` shows `agent-gate` as failed | The command path is wrong. Run `claude mcp get agent-gate` and check that the path ends in `agent-gate/.venv/bin/python` and that the file exists. Use the full path, not `.venv/...`. |
| `/mcp` does not list `agent-gate` at all | It was added in a different folder. Start `claude` in the folder where you ran `claude mcp add`, or add it again with `-s user` to make it available everywhere. |
| Every write or email is denied over MCP | Expected in `strict` and `standard`: there is no approval prompt over MCP, so "ask" becomes "deny". Use `AGENT_GATE_MCP_MODE=permissive` to allow them. |
| A call is denied with `run budget exceeded` or `per-tool limit exceeded` | The budget is spent: 20 calls in total, or 10 to one tool. On the MCP server both refill every 60 seconds; for the CLI, start a new run. |
| `audit` prints `no audit logs yet` | No run has happened in this folder (or in `AGENT_GATE_ROOT`). Run the demo first. |
| `audit` ends with `verify: hash mismatch at seq N`, `chain broken at seq N` or `seq gap at entry N`, and exit code 2 | An audit entry was edited or removed after it was written. That is the tamper check working. |
| `search_docs` returns `no_match` for something you know is there | Either your role may not see that document, or your words do not appear in it. Search is keyword-based, so use words from the document, not synonyms. |

## Questions and answers

**Do I need an API key or a paid account?**
No for the quickstart, the evals and the MCP route (your MCP client pays for its own model).
Yes only for `run` with a real model, which uses the Anthropic API.

**Is anything real sent or deleted?**
No. `send_email` appends to `sandbox/outbox.jsonl`, `delete_file` moves files to `sandbox/.trash`, and the inbox and database are demo data.

**Can I use my own tools?**
Yes. Tools are registered in `src/agent_gate/tools.py`: give a new tool a name, a description, a risk tier and a handler, and the policy, approval and audit apply to it automatically.

**Does it stop every prompt injection?**
No. Detection is pattern matching, so it flags and warns but cannot prove intent.
What it does guarantee is the policy: in `strict` mode a high-risk tool is denied whatever the model was talked into.
In the red-team run the models refused every attack themselves, so the policy was never needed; the [results and their limits](docs/evals.md#reading-the-results) are written up honestly.

**Are roles a login system?**
No. A role is a label the caller supplies, and anyone who can start the CLI or server can claim any role.
Authentication belongs in a layer above this one.

**Can someone rewrite the audit log without being noticed?**
Editing or deleting an entry is detected.
Someone with write access who rewrites the whole chain, or cuts entries off the end, is not.
That needs an external copy of the latest hash, which is out of scope.

**Which model does `run` use?**
A Haiku-class Claude model, set as the `model` default of `AnthropicClient` in `src/agent_gate/agent.py`.
There is no flag for it; edit that default to use another model, for example if the API reports the model as not found or retired.

**Which Python and MCP versions are supported?**
Python 3.10 and newer.
CI runs Python 3.10 and 3.12 against MCP SDK 1.30.0 and 2.3.0.

**How do I remove it?**
Run `claude mcp remove agent-gate` in the folder where you added it, or delete the `agent-gate` entry from the Claude Desktop config (copy the file first if you are unsure) and restart the app.
Then delete the cloned folder; agent-gate installs nothing outside it.

**Where is the design reasoning?**
[docs/design.md](docs/design.md) covers each design decision, the known gaps and what comes next.
[docs/evals.md](docs/evals.md) lists every eval and the red-team method and results.

## License

[MIT](LICENSE)
