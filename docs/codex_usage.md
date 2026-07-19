# How Codex should use valet

valet lets an agent see the *result* of a credential-using command without any
secret entering model context. valet runs the command outside the sandbox,
where it can read `~/.aws` / `.secrets` / `.env`, and returns the output with
those secret values scrubbed.

## One-time human setup (outside the sandbox)

In a normal shell that has the AWS profiles and project secrets:

```bash
cp config.example.toml config.toml
$EDITOR config.toml        # set [exec].workspace and [redaction].secret_sources
valet init                # optional: stable redaction tags
valet serve               # leave running; socket at ~/.valet/broker.sock (0600)
```

The agent's sandbox keeps denying `~/.aws` / `.secrets`. The agent only talks to
the socket.

## What the agent runs

The agent shells out to the client (it reads no secrets itself):

```bash
valet run -- aws s3 ls                 # exact argv, no shell
valet sh 'terraform plan | tail -40'   # shell features
```

Both print redacted stdout/stderr and exit with the command's own code. Example:

```
$ valet run -- cat .env
DB_PASSWORD=[REDACTED:secret:h:38673aad]
API_TOKEN=[REDACTED:secret:h:3bc13a30]
```

The `[REDACTED:secret:h:xxxx]` tags are stable salted hashes: the agent can tell
two occurrences are the *same* secret without learning its value.

## Rules the agent should follow

- Treat all valet output as safe to reason over, but remember redaction is
  **literal**: do not ask valet to transform a secret (base64, uppercase, split)
  and then trust the result — the transformed form is not redacted.
- If a call returns `ok: false` with an `error_class` (e.g. `Timeout`,
  `CommandError`, `PolicyDenied`), report that class rather than guessing at the
  underlying message, which valet withholds.
- Do not try to exfiltrate secrets through valet (e.g. writing `.env` to a
  world-readable path and reading it back). valet redacts known values wherever
  they appear in output; the human's policy settings govern what may run.

## Programmatic use

One request per line of newline-delimited JSON over the socket:

```json
{"op": "exec", "cmd": "aws sts get-caller-identity", "cwd": "/path", "shell": true}
```

Response:

```json
{"ok": true, "exit_code": 0, "stdout": "...redacted...", "stderr": "",
 "redacted_value_count": 4, "broker_version": "0.2.0"}
```
