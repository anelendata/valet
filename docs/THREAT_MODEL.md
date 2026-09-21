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
  format. *Caveat:* the blob is capped at ~1 MB; a **larger** secret file is not
  masked wholesale — only its extracted structured values are — so a full dump of
  a multi-MB secret file may leak the parts no value-extractor caught. For files
  that big (e.g. a `.har` session capture), prefer `deny_read` over redaction.
- **Individual values** — a single secret leaking on its own (`echo $KEY`, a
  `grep` of one line) is caught even without the surrounding file.

A file matched by `policy.deny_read` is **not indexed for redaction**: it cannot
be read, so there is nothing to scrub. Do not rely on redaction as a backstop for
a `deny_read` file reached by a computed path (a gap the policy static analysis
can miss) — that is the OS sandbox's job, not redaction's.

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

## Allowlist and environment (`allow_exec`, per-request env)

`allow_exec` matches a program's **basename**, and an agent that can write files
(push, or any allowed program that writes) chooses names. Two ways that used to
turn an allowlist such as `["aws", "git", "python3"]` into running the agent's
own code, and what now stops them:

| Attempt | Stopped by |
|---|---|
| `valet run -- tools/aws`, after `git mv tools/x tools/aws` | a path-qualified program must be the same file its name finds on `PATH`, and outside the workspace |
| `/tmp/aws` (outside the workspace, but agent-writable) | same-file-as-`PATH` requirement |
| `tools/aws` symlink to another host binary; host symlink into the workspace | both the directory-resolved path and the final target are checked; case-insensitive |
| `tools/env aws`, `env tools/aws` | every program in an `env` wrapper is checked |
| `--env PATH=./tools:…` then bare `aws` | `PATH` is refused per request |
| `PYTHONPATH`/`PYTHONSTARTUP`, `NODE_OPTIONS`, `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES`, `GIT_CONFIG_*`/`GIT_EXEC_PATH`, `BASH_ENV`, `PERL5OPT`, `HOME`, `PAGER`, … | refused per request, in every policy mode (`RESTRICTED_ENV`) |

**A redirect's target is a file, not a command.** `echo hi > out.txt` lexes
into two sub-commands, and treating the second as a program denied every
redirect under an allowlist — for a filename that was never going to run. The
target is now checked as what it is: the path rules (`deny_read`, the workspace
jail, `config.toml`) still apply to it, the allow/deny lists do not. The same
goes for a heredoc's body, which is the command's input. Only a *pure* redirect
operator qualifies: `<(` is process substitution, whose first word really is a
command, and an unbalanced-quote line is not trusted to say which token is
which — both keep the stricter reading.

**The workspace `bin/` is trusted.** It is prepended to `PATH`, so a bare name
runs `bin/<name>` before the host's program. That is the admin's hook for
workspace tools; it assumes the agent cannot write `bin/`. Push refuses a `bin/`
name that shadows a `PATH` program, but an allowed program that can move files
(`git mv`, `python3`) can still place one there.

**Env restrictions apply in every mode**, not only under an allowlist. Without an
allowlist the agent can already run a workspace file directly, so this mostly
buys consistency; under a sandbox profile that restricts which files may be
executed it also stops code arriving by library or module path, which needs only
a read. The admin's
`[exec].env` is not restricted.

**Command stdin is not analysed.** `--stdin-file` hands a command bytes that
policy never inspects — but that is not new ground: `python3 -c` and a heredoc
already put arbitrary program text past static analysis, and an allowlist that
includes an interpreter is a decision to allow that. What stdin changes is that
the text no longer has to survive two shell parses, and no longer has to be
written to the host to be run. It is capped at 1 MiB, never logged (the audit
records `stdin_bytes` only), and reaches the child through an unlinked temp file
that no other process can open by name. Without it a command's stdin is empty:
before, the child inherited the daemon's, so on a daemon started in a terminal a
command reading stdin consumed the operator's keystrokes.

**What this does not stop:**

- **An allowed program that runs code by design.** `python3 script.py`,
  `python3 -c`, `git -c core.pager=…`, `git` reading a workspace `.git/config` or
  hooks, `make`, `npm run`: allowing the program allows that. Only list
  interpreters and build tools you are willing to let run workspace code.
- **Tool-specific config variables.** `AWS_CONFIG_FILE` (a `credential_process`
  runs a command), `KUBECONFIG` (exec credential plugins), `DOCKER_CONFIG`
  (credential helpers) and similar are not on the list; a request can point
  them at a workspace file. Pin the ones your allowed tools read in
  `[exec].env` if that matters.
- **Shell mode beyond static analysis.** A variable set by `read`, `eval`,
  `printf -v`, or a computed name is not seen. Shell mode is off by default.
- **A race.** The program path is checked, then executed by name; a directory on
  the way that the agent can swap in between could redirect it. The OS sandbox is
  the hard boundary.

## File transfer (`files push` / `files pull` / `files patch`)

**Push** writes agent bytes into the workspace. The jail keeps it inside the
root, but inside the root some files are trust anchors, so push also refuses:
secret sources (overwriting `.env` swaps the credentials trusted tools use, and a
new file there feeds values into the redaction index), `deny_read` paths, VCS
internals (a `.git` hook or `core.pager` runs on the next trusted `git`), valet's
own state, a workspace `bin/` entry that would shadow a PATH program, and any file
named like an `allow_exec` entry. The write walks the path with `O_NOFOLLOW` so a
directory swapped for a symlink after the check cannot redirect it.

**Pull** is the one op whose result is *not* redacted — a redacted file is a
corrupted file — so it must refuse whenever redaction would have mattered. It is
off by default (`allow_pull`), separately gated for LAN clients
(`allow_pull_lan`), and refuses, in order:

| Breach attempt | Stopped by |
|---|---|
| pull `.secrets/key`, `.ENV`, a `deny_read` file, `.git/objects/…` | case-insensitive path rules on the lexical and resolved path |
| symlink to a secret or out of the jail; swap a component mid-request | `realpath` jail + `O_NOFOLLOW` walk |
| `ln .secrets/key notes.txt` (or a link to `~/.aws/credentials`) | single-link (`st_nlink == 1`) requirement + inode match |
| `cp .secrets/key out.txt` (text, binary, or >1 MB) | byte-for-byte comparison with same-size secret files |
| a command writes a token or credential dump to a file | text refused if the redactor would change anything |
| FIFO / device / socket | regular-file requirement (opened non-blocking) |
| compressed or binary copy | binary refused unless `allow_pull_binary`; then still scanned for known values and key shapes |

**Patch** reads a workspace file and writes it back, so it takes both rule sets:
the push destination rules (it must not edit `bin/ls`, a `.git` hook, or a secret
source any more than push may create one) and the pull identity checks (the file
must not *be* a secret source by inode, or a copy of one). Two further limits are
its own: a setuid/setgid file is refused outright, since its content would become
agent-supplied while staying privileged, and a file that changed between the read
and the write is refused rather than silently reverted.

The disclosure question for patch is the diff it returns. At the default
`context = 0` every line of that diff is one the agent supplied — the removed
lines are its anchors, the added lines its replacements — so the reply discloses
only line numbers. Context lines are unseen file content, which is `files pull`'s
question, so they take `allow_pull` (plus `allow_pull_lan` off-machine) and pass
through the same content gate; the check runs before the write, so a refusal
leaves the file untouched. The count assertion is an oracle of sorts — "does this
exact string occur once in this file?" — but a narrower one than the `grep` that
`exec` already allows, and it is subject to the same path rules and audit trail.

**What pull does not stop:** a secret *transformed* into a workspace file by a
command — `base64`, `gzip`, `openssl enc` — then pulled. This is the same limit
exec already has (see above), except that pull returns binary losslessly, which
is why binary pulls are a separate opt-in. Policy (`deny_exec`, `allow_exec`) and
the audit log (every pull records path, size, and sha256) contain it.

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
