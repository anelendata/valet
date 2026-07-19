# valet

A narrow local broker that lets an AI agent validate the behavior of
credential-using commands **without ever putting raw secrets into model
context**.

The name *valet*: it holds your keys, brings the car around, and hands you back
only what you asked for — never the keys.

Built for the [handoff](https://github.com/anelendata/handoff) `cloud schedule
list` use case, but the core is command-agnostic: point it at any read-only
command that touches secrets.

---

## Threat model

**Actors**

- **The agent (e.g. Codex)** runs inside a sandbox that *denies* filesystem
  reads of `~/.aws`, `.secrets`, `.env`. This is correct and stays in place —
  secrets must not enter model context.
- **valet** runs *outside* that sandbox, started by a human in a normal shell.
  It **can** read those credentials at runtime.

**The problem.** The agent sometimes needs to *check the effect* of a
credential-using command — e.g. "does `schedule list` with `scope=prefix`
over-match sibling tasks?" — to review a PR. Running the command itself would
pull AWS ARNs, account IDs, rule names, and possibly secret values into the
model's context.

**The boundary valet creates.**

```
┌────────────────────────────┐        ┌───────────────────────────────────┐
│  Agent sandbox (the model) │        │  valet daemon (normal shell)      │
│  • CANNOT read ~/.aws       │  UDS   │  • CAN read ~/.aws, .secrets, .env │
│  • CANNOT read .secrets     │ ─────▶ │  • runs ONE allowlisted read-only  │
│  • sees only derived facts: │ ◀───── │    command with a fixed argv       │
│    counts, booleans, hashes │        │  • redacts known secret VALUES     │
└────────────────────────────┘        │    from all output before replying │
      request {op,alias,stage,scope}   └───────────────────────────────────┘
```

**What crosses the boundary back to the agent** — only derived, sanitized data:

- success / failure and the command exit code
- count of schedules, and count by scope
- whether `prefix` scope over-matches `declared` (issue #134), on request
- **redacted** rule/project identifiers as stable salted hashes
  (`h:xxxxxxxx`) so identity can be *compared* across runs without being
  *revealed*
- a high-level error class (`CredentialsError`, `Timeout`, `ConfigError`,
  `HandoffError`, `ValidationError`) if execution failed

**What never crosses** — raw stdout/stderr, ARNs, 12-digit account IDs, access
keys, secret file paths, and above all the **literal contents of any secret**.

### Why this is stronger than a regex scrubber

valet can read the credential files the agent cannot, so it loads the *actual
secret values* and blocks those exact strings from every byte of output
(`valet/secrets.py` → `valet/sanitize.py`). A guessing scrubber can miss a
weird-looking token; valet cannot miss a value it already holds. A generic
pattern backstop (account IDs, ARNs, `AKIA…` keys, PEM blocks, home-dir
credential paths, emails) is layered on top as defense in depth for the
free-text error channel.

### Structural guarantees (not blocklists)

- **No arbitrary execution.** valet builds the entire argv itself; the caller
  supplies only `alias`, `stage`, `scope`, each checked against an allowlist
  *before* use. `subprocess` runs with `shell=False`. There is no code path
  that turns caller input into a command.
- **No mutations.** Exactly one operation is registered — `schedule_list`,
  read-only. `create` / `delete` / `deploy` are not implemented, so they cannot
  be called.
- **Fail-closed redaction.** Every string returned is passed through the
  redactor and asserted secret-free; if a known value somehow survived, the
  field is dropped rather than returned.

---

## Transport

**Unix domain socket** (primary). The socket file is `0600`, owned by the user
who started the daemon, so the OS is the access-control layer — no port, no
bearer token, no network surface, no DNS-rebinding risk. Protocol is
newline-delimited JSON: one request object per line, one response object per
line.

*Why not a WebSocket "virtual terminal"?* A terminal is generic command
execution by definition (breaks the allowlist), and streaming "redacted"
stdout is best-effort — a secret split across two chunks defeats a stream
scrubber. valet returns **structured derived facts, not a stream**, so there is
nothing to stream. A loopback-HTTP adapter (token-protected) is a possible
future addition for sandboxes that permit localhost TCP but not the socket
path; the core (`valet/broker.py`) is transport-agnostic.

---

## Install & run

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[yaml]"          # yaml lets it parse handoff's output

cp config.example.toml config.toml   # config.toml is git-ignored
$EDITOR config.toml                  # set real project dirs + AWS profiles
valet init                           # generate a random fingerprint_salt

valet serve                          # start the daemon (keep this shell open)
```

Then, from anywhere (including the agent):

```bash
valet schedule-list --alias demo_billing --stage prod --scope declared
valet schedule-list --alias demo_billing --scope prefix --compare   # over-match check
valet call --json '{"op":"schedule_list","project_alias":"demo_billing","scope":"all"}'
```

### Interactive mode

Run `valet` with no subcommand (like running `python` bare) to open a REPL that
holds one persistent connection to the daemon:

```
$ valet
valet 0.1.0 interactive client. Type 'help' for commands, 'quit' to exit.
valet> schedule-list demo_billing --scope prefix --compare
{ ... sanitized response ... }
valet> sl demo_billing            # 'sl' is an alias for schedule-list
valet> call {"op":"schedule_list","project_alias":"demo_billing"}
valet> quit
```

`help` lists commands, `ops` lists allowlisted operations, Ctrl-D exits. A bad
line (unknown command, invalid scope) is reported without dropping the session,
and the same allowlist/redaction rules apply — the REPL is just another client.

Example response:

```json
{
  "op": "schedule_list", "ok": true, "exit_code": 0,
  "project_alias": "demo_billing", "stage": "prod", "scope": "prefix",
  "count": 6,
  "by_scope": { "declared": 4, "prefix": 6 },
  "prefix_over_match": { "over_matches": true, "extra_beyond_declared": 2 },
  "rule_fingerprints": ["h:3f9a1c8b", "h:77b2e0d4"],
  "broker_version": "0.1.0"
}
```

Every value above is safe to paste into a public PR review.

---

## Config

`config.toml` (never committed) maps public **aliases** to real project dirs
and AWS profiles, and lists the secret sources valet loads so it can redact
their values. See [`config.example.toml`](config.example.toml). The alias is
the only project identifier the agent ever sends or sees.

---

## Tests

```bash
pip install -e ".[test,yaml]"
pytest
```

The suite proves: arbitrary/mutating commands can't run, unknown aliases are
rejected, invalid scopes are rejected, known secret values and sensitive
patterns are redacted, and the handoff command is built with exactly the
expected read-only arguments.

---

## Adding another operation

Register a read-only op in `valet/operations.py` (build a fixed argv, run it,
summarize into derived facts) and dispatch it in `valet/broker.py`. Keep the
two invariants: valet builds the whole argv, and every returned string goes
through the redactor. Never add an op that mutates state or that accepts a
caller-supplied command.

See [`docs/codex_usage.md`](docs/codex_usage.md) for how an agent uses valet
during PR validation.
