# Threat model

## Actors

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

## What valet stops — and what it doesn't

valet is layered defense, not a single guarantee. The layers, strongest first:

1. **The sandbox boundary (structural).** The agent cannot read `~/.aws`,
   `.env`, `.secrets` at all — those paths are denied in its sandbox, and valet
   holds the credentials on the other side. The agent never receives raw
   credential files or un-redacted output; there is nothing "pre-redaction" on
   the agent's side to exfiltrate. This blocks the common case outright: an
   agent (or a prompt-injected one) that naively `cat`s a credentials file, or a
   tool that dumps a key into stdout that would otherwise flow into a cloud
   model's context. It is a structural block, not a pattern match.
2. **Policy / allowlist (guardrails).** valet decides whether a requested action
   may run *before* it runs. A tightly scoped allowlist (`aws s3 ls`-shaped
   read-only lookups, not arbitrary `bash -c`) is what keeps an adversary from
   issuing a request crafted to smuggle a secret past redaction. See
   [Guardrails](../README.md#guardrails).
3. **Audit log.** Every request is recorded (`audit.jsonl`), so even a leak that
   slips through is detectable and attributable after the fact. See
   [Audit logging](../README.md#audit-logging).
4. **Redaction (best-effort).** For output that legitimately contains
   secret-shaped values, valet scrubs known and suspected secrets before
   returning. This is the softest layer: it catches accidental verbatim
   leakage, not an adversary who controls the request.

**What valet does not stop.** Redaction matches secret values *literally*. An
*actively adversarial* request can transform a secret before printing it —
`aws configure get aws_secret_access_key | base64`, uppercase it, split it — so
the output no longer matches and redaction misses it. Redaction is not the
barrier in that case; policy (the command never being allowed to run) and audit
(it being recorded) are.

State the guarantee precisely: **a compromised-but-not-request-crafting agent
cannot leak secrets; a request-crafting adversary is contained by policy and
audit, not by redaction.** Treat valet as a large, auditable increase in the
cost and conspicuousness of a leak — not an airtight seal.

## Why redaction is stronger than a regex scrubber

valet can read the credential files the agent cannot, so for each file matched by
`secret_file_paths` it redacts **the entire file content as one blob** *and* the
individual structured values ([`valet/secrets.py`](../valet/secrets.py) →
[`valet/sanitize.py`](../valet/sanitize.py)):

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
**fail-closed**: if a known secret value somehow survives a pass, the whole
field is withheld rather than returned.

## Heuristic redaction (for secrets valet doesn't know)

Some secrets never sit in a file valet can pre-load — a tool may fetch them from
a parameter store and print them at runtime (e.g. `aws secretsmanager
get-secret-value`). For
those, valet also runs **heuristic** redaction (on by default,
`redact_suspected`, [`valet/heuristics.py`](../valet/heuristics.py)): it masks
the *value* of an assignment whose *key name* looks sensitive
(`AWS_SECRET_ACCESS_KEY=…`, `password: …`, `"api_key": "…"`), the `value:` field
of a `key:`/`value:` object pair (the secrets-dump shape), and known token
shapes (AWS, GitHub/GitLab, Slack, Stripe, Google, JWT, PEM). The key name stays
visible; only the value is masked, so `export AWS_PROFILE=tiny; … secrets print`
returns with `AWS_PROFILE=tiny` intact and every secret value replaced by
`[REDACTED:suspected]`.

This is precision-first: a secret with a non-suggestive key name *and* a
non-standard shape can still slip through, which is exactly why the exact
value-firewall and the `deny_read` bans exist. Set `redact_suspected =
false` to keep output verbatim.

For the remaining case — a **bare** unknown secret with no key name and no known
shape (a token a command just prints on its own) — there is an opt-in,
**off-by-default** high-entropy scan (`redact_high_entropy`): it masks long
high-entropy tokens anywhere in output, skipping git SHAs/hashes (hex), UUIDs,
decimal ids, and filesystem paths. It is deliberately off because entropy is the
only signal left and it will sometimes mask base64 blobs or random-looking ids
that aren't secrets. Enable it per environment when the extra coverage is worth
the noise.

This is the concrete mechanism behind the "what valet does not stop" limit
above: redaction matches secret values verbatim, so a command that *transforms*
a secret before printing it defeats it. valet defends against secrets appearing
verbatim (an accidental `cat .env`, `env`, error dumps) — not against a command
deliberately obfuscating one.

## Transport attack surface

**Unix domain socket** (primary). The socket file is `0600`, owned by the user
who started the daemon, so the OS is the access-control layer — no port, no
token, no network surface, no DNS-rebinding risk.

**WebSocket RPC host** (optional, off by default). Enabling `[host].lan` opens a
trusted-LAN WebSocket for clients on another machine, authenticated by
challenge-response against approved client identities. It is disabled unless
`[host].lan = true`; bind `[host].listen` to `127.0.0.1` for local testing, or a
LAN interface only on a trusted network. Setup is covered in
[Running from a node in the local network](../README.md#running-from-a-node-in-the-local-network).
