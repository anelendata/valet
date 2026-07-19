# valet

A local **secret-redacting command runner**. valet runs a command on your
behalf and returns the output with every known secret **value** scrubbed out —
so an AI agent can see what a command actually did without the secrets entering
model context.

The name *valet*: it holds your keys, brings the car around, and hands you back
only what you asked for — never the keys.

> **v0.2 is intentionally permissive.** valet will run (almost) any command; the
> guarantee it makes today is about *output* (secrets are redacted), not about
> *which commands may run*. Command allow/deny lists and a workspace write-jail
> are the next step and already have their hook in [`valet/policy.py`](valet/policy.py).

---

## Threat model

**Actors**

- **The agent (e.g. Codex)** runs inside a sandbox that *denies* filesystem
  reads of `~/.aws`, `.secrets`, `.env`. This stays in place — secrets must not
  enter model context.
- **valet** runs *outside* that sandbox, started by a human in a normal shell.
  It **can** read those credential files at runtime.

**The problem.** The agent often needs to see the *result* of a command that
uses credentials (`aws s3 ls`, `terraform plan`, a project script) to do its
job. Running it directly would pull ARNs, account IDs, tokens, and possibly
secret values straight into the model's context.

**What valet does.**

```
┌────────────────────────────┐        ┌───────────────────────────────────┐
│  Agent sandbox (the model) │        │  valet daemon (normal shell)      │
│  • CANNOT read ~/.aws       │  UDS   │  • CAN read ~/.aws, .secrets, .env │
│  • CANNOT read .secrets     │ ─────▶ │  • runs the command                │
│  • sees output with secret  │ ◀───── │  • loads the real secret VALUES    │
│    values already scrubbed  │        │    and scrubs them from the output │
└────────────────────────────┘        └───────────────────────────────────┘
      request {op:"exec", cmd, cwd}      response {exit_code, stdout, stderr}
```

### Why this is stronger than a regex scrubber

valet can read the credential files the agent cannot, so for each file listed in
`secret_sources` it redacts **the entire file content as one blob** *and* the
individual structured values ([`valet/secrets.py`](valet/secrets.py) →
[`valet/sanitize.py`](valet/sanitize.py)):

- **Whole-file blob** — a `cat`, `less`, or any full dump of a declared secret
  file is masked wholesale, regardless of format (ini, `.env`, JSON, a bare
  one-line token, a PEM key). You never rely on the parser recognizing the
  format.
- **Individual values** — a single secret leaking on its own (`echo $KEY`, a
  `grep` of one line) is caught even without the surrounding file.

A guessing scrubber can miss a weird-looking token; valet cannot miss content it
already holds. A generic pattern backstop (account IDs, ARNs, `AKIA…` keys, PEM
blocks, home-dir credential paths, emails) is layered on top as defense in
depth. Redaction is **fail-closed**: if a known secret value somehow survives a
pass, the whole field is withheld rather than returned.

### Heuristic redaction (for secrets valet doesn't know)

Some secrets never sit in a file valet can pre-load — a tool may fetch them from
a parameter store and print them at runtime (e.g. `handoff secrets print`). For
those, valet also runs **heuristic** redaction (on by default,
`redact_suspected`, [`valet/heuristics.py`](valet/heuristics.py)): it masks the
*value* of an assignment whose *key name* looks sensitive
(`AWS_SECRET_ACCESS_KEY=…`, `password: …`, `"api_key": "…"`), the `value:` field
of a `key:`/`value:` object pair (the secrets-dump shape), and known token
shapes (AWS, GitHub/GitLab, Slack, Stripe, Google, JWT, PEM). The key name stays
visible; only the value is masked, so `export AWS_PROFILE=tiny; … secrets print`
returns with `AWS_PROFILE=tiny` intact and every secret value replaced by
`[REDACTED:suspected]`.

This is precision-first: a secret with a non-suggestive key name *and* a
non-standard shape can still slip through, which is exactly why the exact
value-firewall and the `deny_read_paths` bans exist. Set `redact_suspected =
false` to keep output verbatim.

**Known limit.** Redaction matches secret values *literally*. If a command
*transforms* a secret before printing it (uppercases it, base64-encodes it,
splits it), the transformed form won't match and won't be redacted. valet
defends against secrets appearing verbatim (an accidental `cat .env`, `env`,
error dumps) — not against a command deliberately obfuscating one.

---

## Transport

**Unix domain socket** (primary). The socket file is `0600`, owned by the user
who started the daemon, so the OS is the access-control layer — no port, no
token, no network surface, no DNS-rebinding risk. Protocol is newline-delimited
JSON: one request object per line, one response per line. The core
([`valet/broker.py`](valet/broker.py)) is transport-agnostic; a token-protected
loopback-HTTP adapter is a possible future addition.

---

## Install & run

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .

cp config.example.toml config.toml     # config.toml is git-ignored
$EDITOR config.toml                     # set workspace + secret_sources
valet init                              # optional: stable redaction tags

valet serve                             # start the daemon (keep this shell open)
```

Then, from anywhere (including the agent):

```bash
valet run -- aws s3 ls                   # argv, no shell (exact)
valet sh 'aws s3 ls | grep prod'         # shell: pipes, globs, redirection
valet call --json '{"op":"exec","cmd":"env"}'
```

`run`/`sh` print redacted stdout/stderr and exit with the command's code, so
they drop into scripts like the real command would.

### Interactive mode — a redacting shell

Run `valet` with no subcommand (like `python` bare) to open a prompt. **Any line
you type is run as a command**, and the output comes back redacted:

```
$ valet
valet 0.2.0 — redacting shell. Type a command to run it; ':help' for meta-commands, ':quit' to exit.
valet> cat .secrets
DB_PASSWORD=[REDACTED:secret:h:38673aad]
API_TOKEN=[REDACTED:secret:h:3bc13a30]
valet> aws s3 ls | head
valet> :cwd /path/to/project      # change working dir for the session
valet> :shell off                 # run following lines as argv, not shell
valet> :secrets                   # how many values are being redacted here
valet> :quit
```

Meta-commands are `:`-prefixed (`:help`, `:cwd`, `:shell`, `:secrets`, `:call`,
`:quit`); everything else runs. Ctrl-D also exits.

---

## Config

`config.toml` (never committed) sets the socket, the default workspace, and the
secret sources valet loads so it can redact their values. See
[`config.example.toml`](config.example.toml). Per command, valet also
auto-loads `.env`/`.secrets` from the command's working directory, so a
project's own secrets are redacted when you run there.

---

## Roadmap (the constraints coming next)

The [`[policy]`](config.example.toml) section and [`valet/policy.py`](valet/policy.py)
carry the constraints. Available now:

- **command deny list** (`deny`) — refuse commands by program name.
- **wildcard file bans** (`deny_read_paths`) — glob patterns (`**`, `*`, `?`) of
  files a command may not reference; valet refuses to run a command that names
  an existing matching file, so its content is never revealed. `**/.env` bans
  reading any `.env` anywhere; `~/.aws/**` bans anything under `~/.aws`. The
  analyzer is shell-aware: it splits on operators (`;` `&&` `||` `|` `&`,
  newlines) and tracks `cd`/`pushd`, so `cd some/dir; cat .env` is caught the
  same as `cat some/dir/.env`.

  It is still **best-effort static analysis of the command line**: it catches
  the realistic reveals (`cat`/`less`/`grep` a path, including after a `cd`), but
  cannot see through a computed path (`eval`, `$(...)`, variable expansion,
  base64) or a program that reads the file internally without naming it. Content
  redaction is the backstop for those; only OS-level sandboxing would stop a
  determined reader.

Still to come:

- **command allow list** (`allow`, empty = allow all today) becomes a strict
  allowlist when populated.
- **workspace write-jail** (`enforce_workspace_writes`) will forbid writes
  outside the configured `workspace`.

`Policy.check` is the single choke point; new constraints go there and stay
fail-closed.

---

## Tests

```bash
pip install -e ".[test]"
pytest
```

The suite covers: commands run and their output is captured; known secret
values (from `secret_sources`, cwd `.env`/`.secrets`, and `extra_values`) are
redacted from stdout and stderr; the pattern backstop masks ARNs/account
IDs/keys; nonzero exits and missing binaries are reported; unknown ops, missing
`cmd`, and bad `cwd` are rejected; the deny list blocks a command; and the REPL
runs lines and handles meta-commands.

See [`docs/codex_usage.md`](docs/codex_usage.md) for how an agent uses valet.
