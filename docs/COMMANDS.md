# valet command reference

Every valet subcommand, its arguments, and where it runs. For the `config.toml`
keys these commands read and write, see
[Configuration](CONFIGURATION.md); for the bigger picture, the
[README](../README.md).

```
valet [GLOBAL OPTIONS] <command> [ARGS]
```

Run `valet <command> -h` for the built-in help of any command.

- [Global options](#global-options)
- [Command index](#command-index)
- [Running commands](#running-commands)
  - [`run`](#run) · [`sh`](#sh) · [`call`](#call)
- [Interactive & orientation](#interactive--orientation)
  - [`valet` (no command)](#valet-no-command) · [`repl`](#repl) · [`status`](#status) · [`info`](#info) · [`ping`](#ping) · [`hosts`](#hosts)
- [Host setup & lifecycle](#host-setup--lifecycle)
  - [`init`](#init) · [`doctor`](#doctor) · [`serve`](#serve) · [`serve-lan`](#serve-lan)
- [Workspaces (host-side)](#workspaces-host-side)
  - [`workspaces list`](#workspaces-list) · [`workspaces add`](#workspaces-add) · [`workspaces remove`](#workspaces-remove)
- [Client identities (host-side)](#client-identities-host-side)
  - [`clients list`](#clients-list) · [`clients add`](#clients-add) · [`clients block`](#clients-block) · [`clients unblock`](#clients-unblock) · [`clients remove`](#clients-remove)
- [Client configuration (client-side)](#client-configuration-client-side)
  - [`client init`](#client-init) · [`client default_workspace`](#client-default_workspace)
- [Processes](#processes)
  - [`processes list`](#processes-list) · [`processes kill`](#processes-kill)
- [Exit codes](#exit-codes)
- [REPL meta-commands](#repl-meta-commands)

## Global options

These come **before** the subcommand (e.g. `valet --host box run -- ls`). They
select which host/workspace a command targets and shape the execution
environment for `run`/`sh`/`repl`.

| Option | Argument | Default | What it does |
|---|---|---|---|
| `-c`, `--config` | `PATH` | `$VALET_CONFIG`, else `~/.valet/config.toml`, else the repo `config.toml` | Path to `config.toml`. Holds both the server and `[client]`/`[hosts]` sections. |
| `--host` | `NAME` | — | Configured remote host (`[hosts.<name>]`) to use for client commands. |
| `-w`, `--workspace` | `ID` | host default | Workspace to run in. Applies to `run`, `sh`, and the REPL. |
| `--local` | — | off | Force the local Unix-domain socket transport (ignore any configured remote host). |
| `-e`, `--env` | `NAME=VALUE` | — | Set an environment variable for `run`/`sh` without shell syntax. Repeatable. (`-env` is accepted too.) |
| `--cwd` | `DIR` | workspace root | Working directory for `run`/`sh` without shell syntax. |

## Command index

| Command | Runs on | Purpose |
|---|---|---|
| [`run`](#run) | client | Run an argv with no shell; print redacted output. |
| [`sh`](#sh) | client | Run a shell command line; print redacted output. |
| [`call`](#call) | client | Send a raw JSON request to the daemon. |
| [`repl`](#repl) | client | Interactive redacting shell. |
| [`status`](#status) | client | Connection status + agent orientation. |
| [`info`](#info) | client | Show the selected workspace's README guide. |
| [`ping`](#ping) | client | Check the selected host. |
| [`hosts`](#hosts) | client | List configured remote hosts. |
| [`init`](#init) | host | Create `config.toml` (and, on macOS, the sandbox profile). |
| [`doctor`](#doctor) | host | Check config and the OS sandbox setup. |
| [`serve`](#serve) | host | Run the configured host daemon. |
| [`serve-lan`](#serve-lan) | host | Run the trusted-LAN WebSocket RPC host. |
| [`workspaces`](#workspaces-host-side) | host | `list` / `add` / `remove` workspaces. |
| [`clients`](#client-identities-host-side) | host | `list` / `add` / `block` / `unblock` / `remove` approved client identities. |
| [`client`](#client-configuration-client-side) | client | `init` a client config; manage `default_workspace`. |
| [`processes`](#processes) | client | `list` / `kill` valet subprocesses. |

"Client" commands talk to a daemon — the local Unix socket by default, or a
remote host over WebSocket when `--host` (or a client `default_host`) is set.
"Host" commands act on the local `config.toml` and daemon directly.

## Running commands

### `run`

```
valet [-w ID] [--env NAME=VALUE] run [--cwd DIR] [--timeout N] -- <cmd> [args…]
```

Run a command as an **argv** — no shell, so no pipes, globs, or redirection.
This is the exact, safest mode and the one to prefer. valet runs the command with
the host's credentials, redacts the echoed command plus stdout/stderr, and exits
with the command's own exit code.

| Argument | Default | Notes |
|---|---|---|
| `<cmd> [args…]` | — | The command and its arguments. A leading `--` separates them from valet's own flags and is stripped. |
| `--cwd DIR` | workspace root | Working directory for this command. |
| `--timeout N` | `60` | Hard wall-clock limit in seconds. |

```bash
valet run -- aws s3 ls s3://my-bucket/
valet --cwd projects/app run -- ls
valet --env AWS_PROFILE=prod run -- aws s3 ls
```

### `sh`

```
valet [-w ID] [--env NAME=VALUE] sh [--cwd DIR] [--timeout N] "<command line>"
```

Run a **shell command line**, so pipes, globs, redirection, and `&&` work.
Requires `[exec].shell = true` for the workspace (off by default); otherwise the
request is refused. Same redaction and exit-code behavior as `run`.

| Argument | Default | Notes |
|---|---|---|
| `"<command line>"` | — | The line to run via the shell. Quote it as one argument. |
| `--cwd DIR` | workspace root | Working directory for this command. |
| `--timeout N` | `60` | Hard wall-clock limit in seconds. |

```bash
valet sh 'aws s3 ls | grep prod'
valet sh 'psql "$DATABASE_URL" --csv -c "select count(*) from jobs"'
```

### `call`

```
valet call --json '<request object>'
```

Send a raw JSON request straight to the daemon — an escape hatch for debugging
and scripting against the wire protocol. Prints the JSON response.

```bash
valet call --json '{"op":"ping"}'
valet call --json '{"op":"exec","cmd":"echo hi","shell":false}'
```

## Interactive & orientation

### `valet` (no command)

A bare `valet` dispatches by who is on the other end:

- **At a terminal** (TTY) → the interactive [`repl`](#repl).
- **Over a pipe** (no TTY) → [`status`](#status), so an agent that "just runs
  `valet`" gets non-interactive orientation instead of a shell it can't type
  into.

### `repl`

```
valet [-w ID] repl
```

Open the interactive redacting shell. Any line you type is run as a command and
the output comes back redacted; `cd` sticks for the session and is jailed to the
workspace. See [REPL meta-commands](#repl-meta-commands) for the `:`-prefixed
controls.

### `status`

```
valet status
```

Orient an agent with no prior context: prints the connection status, the command
vocabulary, the workspaces on offer, and the next step (`valet -w <id> info`).
Degrades cleanly when no host is reachable — the unreachable state is itself the
status. Also produced by a bare `valet` over a pipe.

### `info`

```
valet [-w ID] info
```

Print the selected workspace's `README.md` guide (the one scaffolded by
`workspaces add`), so an agent can read the layout and conventions of the tree it
is working in.

### `ping`

```
valet [--host NAME] ping
```

Check that the selected host's daemon is reachable.

### `hosts`

```
valet hosts
```

List the remote hosts configured under `[hosts.<name>]` in the client config.

## Host setup & lifecycle

### `init`

```
valet init
```

Create `~/.valet/config.toml` from the bundled example (use `-c PATH` to write it
elsewhere) with a stable redaction salt, and — on macOS — offer to install the
`sandbox-exec` profile. Prompts (y/n) for the macOS OS sandbox and the LAN host.
If you enable the LAN host, it then asks whether another computer on your LAN
should be able to connect: **yes** sets `[host].listen` to `0.0.0.0:8766`, **no**
leaves it at `127.0.0.1:8766` (this machine only) — either way you can change it
later in the `[host]` section. It defines **no** workspace and won't overwrite an
existing config; add your first workspace with
[`workspaces add`](#workspaces-add). Ends with a health check.

### `doctor`

```
valet doctor
```

Re-check config health and the OS sandbox setup anytime. Warns when the config,
sandbox profile, audit log, or secret sources resolve **inside** a workspace
(where the agent could read them), and flags a workspace that is your home
directory or broader as very high risk.

### `serve`

```
valet serve
```

Run the configured host daemon on the Unix domain socket (`[broker].socket_path`,
`0600`, owned by you). Keep the terminal open while agents work; stop with
Ctrl-C. It hot-reloads `[policy]`, `[redaction]`, `[audit]`, workspaces, and
approved clients on config change; restart it after changing
`[broker].socket_path`, `[host].lan`, or `[host].listen`. Refuses to start until
at least one workspace exists.

### `serve-lan`

```
valet serve-lan
```

Run the Level-1 trusted-LAN WebSocket RPC host so clients on another machine can
reach this daemon (see [`clients`](#client-identities-host-side)). Requires
`[host].lan = true` and a `[host].listen` address. Intended for trusted networks
only.

## Workspaces (host-side)

A workspace is a directory jail with its own `[exec]`/`[policy]`/`[redaction]`
settings. These commands edit the host `config.toml`. `workspace` is an accepted
alias for `workspaces`.

### `workspaces list`

```
valet workspaces list
```

List configured workspaces; `*` marks the default. Run **locally** it reads the
config and shows paths; run as a **client** (remote `--host` or a client
`default_host`) it lists the remote host's workspaces over RPC — ids, default
marker, and shell mode, but never paths, which the host doesn't disclose.

### `workspaces add`

```
valet workspaces add <id> <path> [--make-default] [--yes]
```

Add a `[workspaces.<id>]` section pointing at `<path>` and scaffold the directory
(`bin/`, `tools/`, `skills/`, `projects/`, `tmp/`, a `.secrets/demo.yaml`, and a
`README.md`). Existing files are never overwritten.

| Argument | Notes |
|---|---|
| `<id>` | Workspace id (spaces become hyphens). |
| `<path>` | Directory the workspace confines commands to. Point at a project dir, never `~`. |
| `--make-default` | Set this as `[exec].default_workspace`. The **first** workspace added becomes default anyway. |
| `--yes`, `-y` | Assume yes to prompts (replace an existing workspace, create the directory). |

### `workspaces remove`

```
valet workspaces remove <id>
```

Remove the `[workspaces.<id>]` section (and clear the default pointer if it
pointed there). **Leaves the directory on disk** — it prints the path so you can
delete it yourself.

## Client identities (host-side)

Approve and manage the LAN clients allowed to reach this host. Edits
`[identity.clients]` in the host config; `valet serve` reloads changes
automatically.

### `clients list`

```
valet clients list
```

List approved client identities.

### `clients add`

```
valet clients add <id> [--host-name NAME] [--url ws://HOST:PORT/rpc] [--yes]
```

Generate and approve a client key, then print a client-only config snippet to
copy to the client machine.

| Argument | Notes |
|---|---|
| `<id>` | Client id (the identity's section name; spaces become hyphens). |
| `--host-name NAME` | Host profile name to print in the client snippet. |
| `--url ws://…` | WebSocket URL to print in the client snippet. |
| `--yes`, `-y` | Replace an existing client key without prompting. |

### `clients block`

```
valet clients block <id>
```

Temporarily deny a client without removing its key. A blocked client can't
authenticate and any live connection is dropped on reload.

### `clients unblock`

```
valet clients unblock <id>
```

Restore access for a blocked client.

### `clients remove`

```
valet clients remove <id>
```

Permanently remove an approved client key (revokes access for good).

## Client configuration (client-side)

Manage the `[client]` / `[hosts.<name>]` sections on a machine that acts as a
client of a remote host.

### `client init`

```
valet client init --url ws://HOST:PORT/rpc [--host-name NAME] [--force]
```

Create a client-only config pointing at a host.

| Argument | Default | Notes |
|---|---|---|
| `--url ws://…` | *(required)* | The host's WebSocket RPC endpoint. |
| `--host-name NAME` | `lan-host` | Name for the `[hosts.<name>]` section. |
| `--force` | off | Overwrite an existing client config. |

### `client default_workspace`

```
valet client default_workspace show
valet client default_workspace set <id>
valet client default_workspace unset
```

Show, set, or clear `[client].default_workspace` — the workspace this client uses
when a command names none. It takes priority over the host's own default; an
explicit `valet -w <id> …` still overrides it. If it points at a workspace the
host no longer offers, `run`/`sh` fail with a clear message and the REPL declines
to start.

## Processes

Inspect and stop subprocesses **started by valet** — use these instead of host
process tools like `kill`/`ps` (which valet bans). Only subprocesses valet
currently tracks can be killed this way.

### `processes list`

```
valet processes list
```

List running valet subprocesses.

### `processes kill`

```
valet processes kill <pid>
```

Terminate a running valet subprocess by pid.

## Exit codes

| Code | Meaning |
|---|---|
| *command's own code* | `run`/`sh` exit with the wrapped command's exit code. |
| `0` | Success (or a request the daemon reported `ok` with no exit code). |
| `1` | The daemon reported failure with no specific exit code. |
| `2` | Usage error, or a `ValetError` (e.g. policy denial, bad config, no command given). Printed as `valet: <error_class>: <message>` on stderr. |

## REPL meta-commands

Inside `valet repl` (or a bare `valet` at a TTY), lines starting with `:` are
meta-commands; everything else is run as a command. Type `:` then Tab to list
them.

| Meta-command | Aliases | What it does |
|---|---|---|
| `:help` | `:?` | Show the meta-command help. |
| `:cwd [dir]` | — | Show the working directory, or change it (same as `cd`). |
| `:shell [on\|off]` | — | Show or toggle shell mode for the session (default off). |
| `:workspaces [list]` | `:ws`, `:workspace` | List workspaces (active marked `*`). |
| `:workspaces set <id>` | `:ws set <id>` | Switch workspace, resetting cwd to its root and adopting its shell default. |
| `:secrets` | — | How many secret values are being redacted for the current cwd. |
| `:processes [list]` | `:procs`, `:jobs` | List subprocesses started by valet. |
| `:processes kill <pid>` | `:kill <pid>` | Terminate a valet subprocess. |
| `:call <json>` | — | Send a raw request object to the daemon and print the response. |
| `:quit` | `:exit`, Ctrl-D | Leave the REPL. |

Beyond meta-commands, the prompt shows `(workspace) <dir>`; `cd` sticks and is
jailed to the workspace (`..` and symlinks can't climb above it); Up/Down (or
Ctrl-P/Ctrl-N) recall past commands; and Tab completes commands and files.
