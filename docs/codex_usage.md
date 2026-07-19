# How Codex should call valet during PR validation

valet exists so an agent can *check the runtime effect* of a credential-using
command while reviewing a handoff PR, without any secret entering model context.

## One-time human setup (outside the sandbox)

A human, in a normal shell that has the AWS profiles and project `.secrets`:

```bash
cp config.example.toml config.toml
$EDITOR config.toml        # map aliases → real project dirs + AWS profiles
valet init                # generate fingerprint_salt
valet serve               # leave running; listens on ~/.valet/broker.sock (0600)
```

The agent's sandbox keeps denying `~/.aws` / `.secrets`. Nothing about that
changes. The agent only ever talks to the socket.

## What the agent runs

The agent shells out to the thin client (it reads no secrets itself — it just
talks to the daemon):

```bash
valet schedule-list --alias demo_billing --stage prod --scope declared
```

To answer the specific question behind issue **#134** ("does `scope=prefix`
over-match sibling tasks?"), ask for the comparison:

```bash
valet schedule-list --alias demo_billing --scope prefix --compare
```

Response (safe to read into context and to paste into a public PR):

```json
{
  "ok": true, "exit_code": 0, "scope": "prefix",
  "count": 6,
  "by_scope": { "declared": 4, "prefix": 6 },
  "prefix_over_match": { "over_matches": true, "extra_beyond_declared": 2 },
  "rule_fingerprints": ["h:3f9a1c8b", "h:77b2e0d4"]
}
```

## How the agent should use the result in a review

- `prefix_over_match.over_matches == true` with `extra_beyond_declared == 2`
  confirms the bug the PR addresses: `scope=prefix` matches 2 rules that are
  **not** declared for this project (a sibling task whose name extends this
  one). The agent can state this in the PR review with the numbers, since they
  carry no secret.
- After the fix, re-running with `--scope declared` should show `count` equal
  to the number of locally declared schedules, and `by_scope.prefix` should no
  longer exceed it.
- `rule_fingerprints` are stable salted hashes: the agent can assert "the same
  N rules appear before and after" by comparing fingerprint sets across runs,
  without ever learning a real rule name.

## Rules the agent must follow

- Only `schedule_list` exists. Requests for any other `op` (create, delete,
  deploy, or an arbitrary command) return `ValidationError` — do not try to
  work around this; there is no generic-exec path by design.
- Use only aliases the human configured (`demo_billing`, …). An unknown alias
  is rejected.
- Never ask valet for raw output or to "print the ARN / account id / secret."
  valet does not expose them; that is the point.
- If a call returns `ok: false`, report the `error_class` (e.g.
  `CredentialsError`, `Timeout`) — not a guess at the underlying message, which
  valet deliberately withholds.
```
