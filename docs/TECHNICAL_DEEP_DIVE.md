# Technical deep dive

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
┌────────────────────────────┐         ┌────────────────────────────────────┐
│  Agent sandbox (the model) │         │  valet daemon (normal shell)       │
│  • CANNOT read ~/.aws      │  UDS    │  • CAN read ~/.aws, .secrets, .env │
│  • CANNOT read .secrets    │ ─────▶  │  • runs the command                │
│  • sees output with secret │ ◀─────  │  • loads the real secret VALUES    │
│    values already scrubbed │         │    and scrubs them from the output │
└────────────────────────────┘         └────────────────────────────────────┘
 request {op:"exec", cmd, cwd}          response {exit_code, stdout, stderr}
 request {op:"exec", stream:true, ...}  exec_chunk* then final response
```

## Why this is stronger than a regex scrubber

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
blocks, home-dir credential paths, and email addresses) is layered on top as
defense in depth; email addresses are always replaced with `[REDACTED:email]`,
including when they are not in a configured secret source. Redaction is
**fail-closed**: if a known secret value somehow survives a
pass, the whole field is withheld rather than returned.

## Heuristic redaction (for secrets valet doesn't know)

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

For the remaining case — a **bare** unknown secret with no key name and no known
shape (a token a command just prints on its own) — there is an opt-in,
**off-by-default** high-entropy scan (`redact_high_entropy`): it masks long
high-entropy tokens anywhere in output, skipping git SHAs/hashes (hex), UUIDs,
decimal ids, and filesystem paths. It is deliberately off because entropy is the
only signal left and it will sometimes mask base64 blobs or random-looking ids
that aren't secrets. Enable it per environment when the extra coverage is worth
the noise.

**Known limit.** Redaction matches secret values *literally*. If a command
*transforms* a secret before printing it (uppercases it, base64-encodes it,
splits it), the transformed form won't match and won't be redacted. valet
defends against secrets appearing verbatim (an accidental `cat .env`, `env`,
error dumps) — not against a command deliberately obfuscating one.

## Transport

Today the primary transport is a local Unix domain socket, with an optional
trusted-LAN WebSocket RPC host for clients on another machine. The broker core
is transport-agnostic: the same request/response shape is carried over UDS and
WebSocket today and, with careful authentication and authorization design, over
other networked transports in the future. The long-term idea is not limited to
one machine; it is to let sandboxed agents request approved capabilities from a
trusted valet service wherever that service is safely deployed.

**Unix domain socket** (primary). The socket file is `0600`, owned by the user
who started the daemon, so the OS is the access-control layer — no port, no
token, no network surface, no DNS-rebinding risk. Protocol is newline-delimited
JSON: one request object per line, followed by one response line. If an exec
request sets `"stream": true`, the daemon may send zero or more `exec_chunk`
events before the final response. The core ([`valet/broker.py`](valet/broker.py))
is transport-agnostic.

**WebSocket RPC host** (optional). For clients on another machine, run
`valet serve-lan`. It carries the same JSON request/response contract over a
Level 1 trusted-LAN WebSocket connection, with challenge-response authentication
against approved client identities. It is disabled unless `[host].lan = true`;
bind `[host].listen` to `127.0.0.1` for local testing, or a LAN interface only
on a trusted network.

