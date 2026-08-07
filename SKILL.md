---
name: valet-client
description: Use Valet from a client environment to run local or trusted-LAN commands through the redacting broker. Use when Codex needs host-side credentials or tools without reading secrets directly, needs to choose between Unix-socket local mode and WebSocket LAN mode, needs to run valet run/sh/repl/ping/hosts, or needs to troubleshoot client.toml, HTTP proxy, or reconnect behavior.
---

# Valet Client Usage

Use `valet` when a task needs privileged host-side tools or credentials that the
client sandbox must not read directly. Valet runs commands on the trusted host,
redacts known and suspected secret values, and returns only the sanitized result.

## Core Rules

- Do not read credential files directly, including `.env`, `.secrets`, `~/.aws`,
  or other configured secret sources.
- Prefer narrow, read-only diagnostic commands. Avoid using Valet as a generic
  secret printer or broad data tunnel.
- Use `valet run -- ...` for exact argv execution. Shell is disabled by default;
  use `valet sh '...'` only when the trusted host explicitly enables
  `[exec] shell = true`.
- Use `valet run --cwd DIR -- ...` to run a one-shot command in a directory.
  This is the shell-free replacement for patterns like `cd DIR; command`.
- Use `valet --env NAME=value run -- ...` for per-command environment variables
  instead of shell assignment syntax.
- Do not use host process tools such as `ps`, `kill`, `pkill`, or `killall`.
  Use `valet processes list` and `valet processes kill <pid>` for subprocesses
  that Valet itself started.
- For interactive work, use `valet repl` or bare `valet`.
- If a WebSocket command fails after it was already sent, do not assume it was
  not executed. Valet reconnects for the next prompt but does not silently
  replay in-flight commands.

## Choose Transport

Local mode uses the Unix-domain socket started by `valet serve` on the same
machine. It is selected by default when no remote host is configured.

```bash
valet ping
valet run -- aws sts get-caller-identity --profile prod-readonly
valet run --cwd projects/app -- cat text.txt
valet --env AWS_PROFILE=prod-readonly run -- aws sts get-caller-identity
valet --env AWS_PROFILE=prod-readonly run --cwd projects/app -- aws s3 ls
valet repl
```

Force local mode even when a client config has a default LAN host:

```bash
valet --local ping
valet --local run -- pwd
```

LAN mode uses a client-only `client.toml` and WebSocket RPC to a trusted host:

```bash
valet hosts
valet --host my-main-laptop ping
valet --host my-main-laptop run -- handoff status
valet --host my-main-laptop run --cwd projects/app -- cat text.txt
valet --host my-main-laptop --env AWS_PROFILE=prod-readonly run -- aws s3 ls
valet --host my-main-laptop --env AWS_PROFILE=prod-readonly run --cwd projects/app -- aws s3 ls
valet --host my-main-laptop processes list
valet --host my-main-laptop repl
```

Use a non-default client config when needed:

```bash
valet --client-config client.toml --host my-main-laptop ping
```

## Client Config

The client config contains only the client identity and remote host URLs. It
must not contain host-side secret sources, redaction salts, audit paths, or
policy.

```toml
[client]
id = "client-local-ai-box"
key = "client-shared-key"
default_host = "my-main-laptop"
reconnect_max_retries = 5
reconnect_backoff_seconds = 0.25
reconnect_backoff_max_seconds = 3.0

[hosts.my-main-laptop]
url = "ws://192.168.1.25:8766/rpc"
host_id = "my-main-laptop"
```

Per-host reconnect overrides can be placed under `[hosts.<name>]` with the same
three reconnect keys.

## Host Prerequisites

For local mode, the trusted host must be running:

```bash
valet serve
```

For LAN mode, the trusted host must approve the client and enable LAN serving in
its host-side `config.toml`:

```toml
[host]
id = "my-main-laptop"
lan = true
listen = "0.0.0.0:8766"
```

Then the same host-side command starts both local and LAN listeners:

```bash
valet serve
```

Client keys are generated on the trusted host:

```bash
valet clients add local-ai-box --url ws://192.168.1.25:8766/rpc
valet clients list
valet clients remove local-ai-box
```

Copy the printed client-only TOML to the client machine or pass it with
`--client-config`.

The running `valet serve` process reloads changes to policy, redaction, audit
settings, and approved LAN client identities from `config.toml`. Restart the
server after changing listener bind settings such as `broker.socket_path`,
`[host].lan`, or `[host].listen`.

## Interactive REPL

The REPL keeps a session cwd and shell mode on the trusted host:

```bash
valet --host my-main-laptop repl
```

Inside the REPL, `cd` sticks only when it is a standalone line. With shell mode
off, do not use shell separators such as `cd DIR; cat file`; use two REPL lines
or one-shot `run --cwd`:

```text
valet> cd projects/app
app valet> cat text.txt
```

```bash
valet --host my-main-laptop run --cwd projects/app -- cat text.txt
```

Useful meta-commands:

```text
:help
:cwd
:cwd path
:shell on
:shell off
:secrets
:processes list
:processes kill <pid>
:jobs
:kill <pid>
:quit
```

Tab completion, history navigation, and command execution use the same client
transport as one-shot commands. In LAN mode, completion candidates come from the
host, not from the client sandbox.

Shell mode starts off unless the selected local host config explicitly enables
it. Built-in dangerous command bans apply in every transport, including local
mode, LAN WebSocket mode, and future relays.

## Proxy And Reconnect

For `ws://`, Valet honors `HTTP_PROXY` and `http_proxy`. For `wss://`, it
honors `HTTPS_PROXY` and `https_proxy`, with HTTP proxy fallback. It also honors
`NO_PROXY` and `no_proxy` for exact hosts/IPs, optional ports, domain suffixes,
and `*`.

WebSocket clients reconnect with exponential backoff during initial connection
and when an idle socket is discovered to be stale. Defaults:

```toml
reconnect_max_retries = 5
reconnect_backoff_seconds = 0.25
reconnect_backoff_max_seconds = 3.0
```

If a command was already sent and the socket drops before a response arrives,
Valet reports a connection error, reconnects for the next request, and requires
the caller to decide whether retrying is safe.

## Troubleshooting

- `no daemon at socket`: start `valet serve` on the trusted host, or use
  `--host` to select LAN mode.
- `unknown host`: run `valet hosts` and check `default_host` and `[hosts.*]`
  names in the client config.
- WebSocket timeout from a sandbox: check `HTTP_PROXY`/`HTTPS_PROXY` and
  `NO_PROXY`; Valet tunnels WebSocket connections through HTTP CONNECT when a
  proxy is configured.
- Authentication failed: regenerate or rotate the client key on the trusted host
  with `valet clients add <name> --yes`, then update the client config.
