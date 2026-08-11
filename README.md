# valet: Let agents use privileged tools without seeing secrets

valet is a broker between an AI agent and the tools the agent should not run
directly.

The name *valet*: it holds your keys, brings the car around, and hands you back
only what you asked for, never the keys.

The agent stays in a sandbox where it cannot read credential files like
`~/.aws`, `.env`, `.secrets`, etc. valet runs outside that sandbox, where it
can use those credentials on the agent's behalf. Before valet returns anything,
it scrubs known and suspected secret values from stdout, stderr, and the echoed
command.

In simple terms:

1. the agent asks valet to do something;
2. valet decides whether the request is allowed;
3. valet runs the approved action with the credentials available to it;
4. valet redacts sensitive values from the result;
5. the agent gets the useful result, while raw credentials and secret
   files stay on valet's side of the sandbox.

Benefits:

1. Safeguard secrets while moving fast with agents
2. Keep agents lightweight without loading apps and keys
3. Manage and audit multi-agent host access and tool usage

![Valet-mediated agent interaction](images/valet-interaction.svg)

## Table of contents

- [Quick demo](#quick-demo)
- [Motivating examples](#motivating-examples)
  - [Example 1: Running AWS CLI commands in a hardened sandbox](#example-1-running-aws-cli-commands-in-a-hardened-sandbox)
  - [Example 2: Database query](#example-2-database-query)
- [Features](#features)
  - [Valet serve](#valet-serve)
  - [REPL mode](#repl-mode)
  - [Audit logging](#audit-logging)
  - [Multi-transport: one host, many agents](#multi-transport-one-host-many-agents)
- [Valet is not...](#valet-is-not)
- [Before getting started](#before-getting-started)
  - [Recommended architecture](#recommended-architecture)
  - [Sandbox hardening](#sandbox-hardening)
- [Install & run](#install--run)
  - [Interactive mode — a redacting shell](#interactive-mode--a-redacting-shell)
- [Config](#config)
  - [Choosing what to configure](#choosing-what-to-configure)
- [Guardrails](#guardrails)
- [Development](#development)
  - [Tests](#tests)

More...
- [Roadmap](./docs/ROADMAP.md)
- [Threat model](./docs/THREAT_MODEL.md)
- [Google Workspace CLI (`gws`) through valet](./docs/google-workspace-cli.md)
- [Set up a workspace-wide Python venv](./docs/workspace-python-venv.md)


## Quick demo

Install, set up a workspace, and read a secret file *through* valet:

```bash
git clone https://github.com/anelendata/valet.git
cd valet
python -m venv venv
. venv/bin/activate
pip install -e .                           # PyPI release pending

valet init                                 # writes ~/.valet/config.toml
valet workspace add demo ~/ai-workspace    # scaffolds the workspace + a demo secret
valet serve                                # leave this running
```

In another terminal:

```bash
# Read the demo secret directly — you see the value:
cat ~/ai-workspace/.secrets/demo.yaml
# -> secret_key: "demo-only-not-meaningful-fiRzDlOBbSwF8qCgKlWulH35wNbKH"

# Read it THROUGH valet — the secret is scrubbed:
valet run -- grep secret_key .secrets/demo.yaml
# -> secret_key: "[REDACTED:secret:h:…]"
```

`valet workspace add` scaffolds a fake secret at `.secrets/demo.yaml`. valet masks
its value from the output an agent would get, yet the file stays usable — a trusted
tool can still receive it as an argument (`my_command --key-file ./.secrets/demo.yaml`).

## Motivating examples

### Example 1: Running AWS CLI commands in a hardened sandbox

With a hardened Codex or Claude Code sandbox (see
[Sandbox hardening](#sandbox-hardening)), commands that need host-side
credentials should fail non-negotiably when the agent runs them directly. For
example, the AWS CLI usually needs `~/.aws/config` or `~/.aws/credentials`, but
those paths should be denied to the agent:

```bash
aws s3 ls s3://my-prod-bucket/releases/ --profile prod-readonly
```

Run through valet, the same credentialed command can succeed **without putting
credential files or secret values into model context**:

```bash
valet run -- aws s3 ls s3://my-prod-bucket/releases/ --profile prod-readonly

2026-08-04 10:12:31   18422913 app-2026-08-04T1012Z.tar.gz
2026-08-04 10:18:44        512 app-2026-08-04T1012Z.sha256
2026-08-04 11:03:09   18425102 app-2026-08-04T1103Z.tar.gz
2026-08-04 11:09:02        512 app-2026-08-04T1103Z.sha256
...
```

Other good valet-shaped commands are credentialed, read-only operational
lookups whose useful signal is not the secret itself:

```bash
valet run -- aws cloudformation list-stacks --profile prod-readonly

{
    "StackSummaries": [
        {
            "StackId": "[REDACTED:arn]",
            "StackName": "my-stack",
            "CreationTime": "2026-07-18T05:36:45.760000+00:00",
            "StackStatus": "CREATE_COMPLETE",
            "DriftInformation": {
                "StackDriftStatus": "NOT_CHECKED"
            }
        },
        ...
```

The returned output is still useful after redaction: the agent can see release
artifact names, timestamps, sizes, and missing checksum files, while account
IDs, ARNs, access keys, emails, tokens, and configured **secret values are
scrubbed before the response reaches the agent**.

### Example 2: Database query

The same pattern applies to database diagnostics. A hardened agent sandbox
should not be able to read the `.env` or `.secrets` file that contains
`DATABASE_URL`, but a trusted host-side command can use it and return a narrow,
non-secret result:

```bash
sandbox$ valet sh 'psql "$DATABASE_URL" --csv -c \
  "select status, count(*) from jobs group by status order by status"'
```

These examples let an agent inspect deployment state, failed stack updates,
service rollout progress, recent application errors, and aggregate database
state without gaining direct access to the credentials used to make the request.
Avoid using valet as a generic secret printer or unrestricted database tunnel;
secret-value reads and broad data queries should become narrow, typed
capabilities with explicit policy and approval, not raw shell habits.

## Features

### Valet serve

`valet serve` is the normal way to make privileged tools available to a
sandboxed agent. Start it yourself in a regular terminal that has the profiles,
tokens, and environment the trusted tools already use:

```bash
valet serve
```

Leave that terminal running while the agent works. The agent still runs inside
its hardened Codex or Claude Code sandbox, where it cannot read `.env`,
`.secrets`, `~/.aws`, or other denied credential locations. When it needs the
result of an approved privileged command, it calls valet instead:

```bash
sandbox$ valet --env AWS_PROFILE=prod-readonly run -- aws s3 ls s3://my-prod-bucket/releases/
sandbox$ valet run -- psql --csv -c "select status, count(*) from jobs group by status"
```

From the user's point of view, this gives the agent useful operational output
while keeping the credential material on the trusted side of the boundary.
Valet loads the configured secret sources, runs the command, redacts the echoed
command plus stdout/stderr, and only then returns output to the agent. For
`valet run`, `valet sh`, and the REPL, safe line-oriented output streams as it
arrives; structured JSON/YAML/PEM-shaped output is buffered until valet has
enough context to redact it safely.

Use `valet serve` for day-to-day local agent sessions. Stop it with Ctrl-C when
the session is over. If a client reports that no daemon is running, start
`valet serve` again from the trusted terminal.

While `valet serve` is running it watches `config.toml` and reloads changes to
policy, redaction, audit settings, and approved LAN client identities. Listener
bind settings such as `broker.socket_path`, `[host].lan`, and `[host].listen`
are read when the server starts; restart `valet serve` after changing those.

### REPL mode

REPL (Read-Eval-Print Loop) is available to examine valet's behavior
interactively while `valet serve` is running. This is particularly useful
validating a policy.

```
$ valet
valet 0.2.0 — redacting shell. Type a command to run it; ':help' for meta-commands, ':quit' to exit.

valet> aws logs tail mystack/some-task --since 60m --profile prod-readonly

2026-08-05T04:00:17.166000+00:00 states/mystack-some-task-1/2026-08-05-04/00000000 {"details":{"roleArn":"[REDACTED:arn]"},"redrive_count":"0","id":"1","type":"ExecutionStarted","previous_event_id":"0","event_timestamp":"1785902417166","execution_arn":"[REDACTED:arn]"}
2026-08-05T04:00:17.192000+00:00 states/mystack-some-task-1/2026-08-05-04/00000000 {"details":{"name":"RunTask"},"redrive_count":"0","id":"2","type":"TaskStateEntered","previous_event_id":"0","event_timestamp":"1785902417192","execution_arn":"[REDACTED:arn]"}
2026-08-05T04:00:17.192000+00:00 states/mystack-some-task-1/2026-08-05-04/00000000 {"details":{"region":"[REDACTED:secret:h:52a3d849]","resource":"runTask.sync","resourceType":"ecs"},"redrive_count":"0","id":"3","type":"TaskScheduled","previous_event_id":"2","event_timestamp":"1785902417192","execution_arn":"[REDACTED:arn]"}
...
```

### Audit logging

Audit logging makes valet's privileged boundary inspectable after the fact.
When an agent asks valet to run something, the log helps a human
answer: who asked, what command or capability was requested, which working
directory was used, whether policy allowed or denied it, whether approval was
required, how long it ran, whether it succeeded, and how much redaction happened
before output returned to the agent.

Configure the JSON log path in `config.toml`:

```toml
[audit]
log_path = "~/.valet/audit.jsonl"
console = true
```

The file is newline-delimited JSON. Non-streaming requests append one final
JSON object. Streamed exec requests append a `phase = "started"` event as soon
as policy allows the command and the process is about to run, then append a
final event when the command finishes. When `console = true`, `valet serve` and
`valet serve-lan` also print readable server-console entries:

```text
2026-08-05T12:31:03Z INFO: codex uds allowed started aws ecs describe-services ...
2026-08-05T12:31:04Z INFO: codex uds allowed aws ecs describe-services ...
   {
     "caller": "codex",
     "transport": "uds",
     "decision": "allowed",
     "phase": null,
     "command": "aws ecs describe-services ...",
     ...
   }
```

The audit log is meant to be safe to keep. It records metadata
such as request IDs, caller identity, command shape, policy decision, exit code,
duration, byte counts, redaction counts, and fail-closed events. It should not
store raw stdout, raw stderr, credential values, or unredacted command material;
otherwise the log becomes another secret sink.

For example, an audit event might say that `codex` requested an
`aws ecs describe-services ... --profile prod-readonly` command, valet allowed
it under policy, loaded several configured secret sources, redacted six values,
and returned a zero exit code after 1.8 seconds. A denied event might say that a
command referenced `**/.env` and was refused before execution. The point is
accountability: redaction protects model context, policy controls execution,
and audit logging lets an operator reconstruct what happened without exposing
the secrets valet was built to protect.

### Multi-transport: one host, many agents

valet speaks two transports behind the same request/response contract, so the
same `valet run` / `valet sh` / REPL commands work whether the agent is on the
host or on another machine:

- **Unix domain socket** (default) — `valet serve`. The socket file is `0600`,
  owned by the user who started the daemon, so the OS is the access-control
  layer: no port, no token, no network surface.
- **Trusted-LAN WebSocket RPC** — `valet serve-lan`. A client on a second
  computer on the same trusted network reaches the host over WebSocket, with
  challenge-response authentication against approved client identities. It stays
  off unless `[host].lan = true`; setup is in
  [Running from a node in the local network](#running-from-a-node-in-the-local-network).

The payoff is **one credentialed host, many agents**. Point every agent — the
REPL on your laptop, a coding agent in a hardened sandbox, a second workstation
running another model — at the same valet host, and they all get the same
policy-gated, redacted tool access. You install and configure the credentials,
cloud CLIs, and secret sources **once, on the host**, instead of standing up and
securing a separate stack of MCP servers and application installs inside every
agent. Agents stay lightweight and hold no secrets; the host is the single place
where privileged tools live and where policy and audit are enforced. Each
request's transport (`uds` or `lan`) is recorded in the audit log, so a shared
host stays accountable.

## Valet is not...

valet sits near several popular security and agent-infrastructure products, but
it is a different layer:

| Valet is not... | What that product or layer does | How valet is different |
|---|---|---|
| **a password manager or vault like 1Password** | Stores, shares, rotates, and governs secrets for humans, services, and teams. | valet does not want to become the source of truth for secrets. It uses credentials that already exist at runtime and focuses on approved actions plus redacted results. |
| **a compute platform or sandbox runtime like Modal** | Runs code in managed infrastructure with scaling, isolation, images, jobs, and service deployment. | valet does not provide general compute. It is the broker a sandboxed agent calls when it needs a trusted tool or host-side capability. |
| **a network gateway** | Controls which networks, hosts, ports, services, or private resources a workload can reach. | valet does not primarily route packets. It decides whether a requested action may run, executes approved actions, and redacts the response before the agent sees it. |
| **an MCP proxy or tool gateway** | Mediates model access to MCP tools and can centralize tool discovery, auth, logging, and request filtering. | valet can expose or sit behind MCP-shaped tools later, but its core primitive is broader: policy-controlled host actions with secret-aware output redaction. |

Those layers are complementary. A mature deployment may use a vault for storing
credentials, a sandbox or compute runtime for the agent, a network gateway for
egress control, an MCP proxy for tool routing, and valet for the policy,
redaction, and approval boundary around privileged actions.

## Before getting started

valet is defense-in-depth, not a guarantee — see
[Threat model](./docs/THREAT_MODEL.md) for what it does and doesn't stop.

### Recommended architecture

valet is meant to be one layer in a larger agent safety design:

1. **Sandboxed agents** — the model runs where it cannot directly read secret
   files or freely reach privileged host resources.
2. **Least-privilege credentials on the host** — the credentials available to
   the broker can do only the work the agent is meant to request.
3. **Policy** — a broker decides which actions are allowed before anything
   runs.
4. **Redaction** — every response is scrubbed before it reaches model context.
5. **Audit/approval** — sensitive or mutating actions are logged and, when
   appropriate, require a human or higher-trust approval path.

valet's current implementation focuses on **3. policy**, **4. redaction**, and
the audit part of **5. audit/approval**. Human approval flows are still future
work.

Valet relies on **1. agent sandboxes** and **2. least-privilege credentials** as
complementary layers. Those layers are the operator's responsibility. Valet can
help enforce an authorization and redaction boundary, but it cannot protect
against negligent setup, over-broad host credentials, disabled sandboxes, or
approving a dangerous action without understanding its blast radius.

**WARNING:** valet is intentionally permissive today. Raw command execution is
dangerously powerful when the host has credentials with write, delete, deploy,
or payment privileges.

### Sandbox hardening

The agent runtime should be hardened before Valet is added. Treat Valet as the
privileged broker, not as the only safety control.

**IMPROTANT**: Follow [Sandbox Hardening Guide](./docs/SANDBOX_HARDENING.md)
before installing valet!

## Install & run

### Running from the a sandbox inside the host

Install valet in the host and sandbox:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```
(You can also use uv)

In the host,
```
valet init                              # create ~/.valet/config.toml
                                        # (macOS: + OS sandbox), then a health check. y/n prompts.
valet workspaces add work ~/work/project  # add your first workspace (becomes default)
$EDITOR ~/.valet/config.toml            # set secret_file_paths, tune policy, etc.

valet serve                             # start the daemon (keep this shell open)
valet doctor                            # re-check config health anytime
```

`valet init` and workspace creation are two separate steps. `valet init` copies
`config.example.toml` into `~/.valet/config.toml` (use `-c PATH` to write it
elsewhere), gives it a stable redaction salt, and on macOS offers to install and
activate the OS sandbox profile. It defines **no** workspace — it ends by
reminding you to run `valet workspaces add <id> <dir>`, which creates the first
workspace (making it the default) and scaffolds its directory. `valet serve`
refuses to start until at least one workspace exists. `init` refuses to
overwrite an existing `config.toml`/`workspace.sb` — remove or rename them to
re-run.

Keep the config, the sandbox profile, the audit log, and your secret sources
**outside** the workspace: the agent can read (and, when jailed there, write)
anything inside it, so any of these placed under the workspace is exposed to the
very agent it hides secrets from. `valet doctor` (also run at the end of `valet
init`) warns when any of them resolve inside a workspace path, and separately
flags a workspace path that is your home directory (or broader) as very
high risk — the agent's blast radius would be your whole home.

#### Multiple workspaces under one host

A host can serve several workspaces, each a separate directory jail with its own
settings. `[exec]`, `[policy]`, and `[redaction]` are the **defaults** for every
workspace; each `[workspaces.<id>]` names a `path` and may override those defaults
per key. `[exec].default_workspace` picks the one used when a command names none.

```toml
[exec]
default_workspace = "default"      # used when no workspace is named
shell = false                      # default for all workspaces

[policy]
deny_exec = ["curl"]               # denied in every workspace

[workspaces.default]
path = "~/work/project"

[workspaces.personal]
path = "~/personal"
[workspaces.personal.exec]
shell = true                       # overrides the [exec] default, personal only
[workspaces.personal.policy]
deny_exec = ["rm"]                 # replaces the shared deny list for personal
```

Manage them from the host:

```bash
valet workspaces add personal ~/personal   # add a [workspaces.personal] section
valet workspaces add personal ~/personal --make-default   # ...and make it the default
valet workspaces list                      # list workspaces (* marks the default)
```

`valet workspaces add` edits the host config, so it is a host-side command.
`valet workspaces list` adapts to context: run locally it reads the config
(showing paths); run as a client (a remote `--host` or a client config's
`default_host`) it lists the **remote** host's workspaces over RPC — ids, the
default marker, and shell mode, but not paths, which the host never discloses.

The first workspace added becomes `[exec].default_workspace` automatically; pass
`--make-default` to point the default at a later one.

When the target directory does not exist, `valet workspaces add` offers to
create it. Either way it scaffolds a standard layout — `bin/` (executables put
on `PATH`), `tools/` (local tools installed outside `/usr/local/bin`, e.g.
`handoff`), and `skills/` (skills for agents) — and writes a `README.md`
explaining them (an existing `README.md` is never overwritten, so your own notes
are safe).

Select a workspace per command with `-w/--workspace`, or switch inside the REPL
with `:workspaces set <id>` (see below). `valet serve` reloads workspace changes
automatically.

```bash
valet -w personal run -- ls
valet -w personal sh 'ls | grep foo'
```

From a sandbox running in the same machine,

```bash
# Lists files in the host's workspace root
valet run -- ls
```

Run privileged commands according to host's environment:

```bash
valet repl # (or simply valet) to start REPL mode
valet run -- aws s3 ls                   # argv, no shell (exact)
valet --cwd projects/app run -- ls       # cwd without shell syntax
valet --env AWS_PROFILE=prod run -- aws s3 ls
valet sh 'aws s3 ls | grep prod'         # requires [exec] shell = true
```

`run`/`sh` print redacted stdout/stderr and exit with the command's code, so
they drop into scripts like the real command would.

### Running from a node in the local network

For trusted-LAN RPC, approve a client on the trusted host:

```bash
$ valet clients add my-ai-box
valet: added client 'my-ai-box' in ./config.toml

Client config:
[client]
id = "my-ai-box"
key = "xxxxxxxxxxxxxxxxxxxxxxxx"
default_host = "my-computer"
# default_workspace = "<id>"  # optional; overrides the host default
reconnect_max_retries = 5
reconnect_backoff_seconds = 0.25
reconnect_backoff_max_seconds = 3.0

[hosts.my-computer]
url = "ws://<host-lan-ip>:8766/rpc"
```

`[client].default_workspace` (optional) sets which workspace this client runs in
when a command names none. It takes priority over the host's own default; an
explicit `valet -w <id> ...` still overrides it. Manage it with `valet client
default_workspace set <id>` / `show` / `unset`. If it points at a workspace the
host no longer offers, `valet run`/`sh` fail with a clear message and the REPL
declines to start — update or `unset` it (or run `valet workspaces list`).

This writes a new `[identity.clients.<id>]` entry to the host's `config.toml`
and prints a client-only TOML snippet. (If the id already exists, valet asks
before rotating its key.) valet hot-reloads the config if the server is already
running.

Put the printed client config on the second machine (i.e. agent),
set `[host].lan = true` and `[host].listen` on the trusted host.

The client can then use the same commands through the default host:

```bash
valet ping
valet --env AWS_PROFILE=prod run -- aws s3 ls
valet sh 'aws s3 ls | head'
valet repl
```

You can select host with `--host` option:
```bash
valet --host my-computer -- run ls
```

To revoke a LAN client, remove it from the trusted host config:

```bash
valet clients remove local-ai-box
```

The running `valet serve` process reloads the updated client registry
automatically.

The client config only contains host URLs and that client's identity key. Host
secret sources, redaction salts, policy, and audit settings stay in the trusted
host config. `ws://` is for trusted development LANs. (public internet relay
support belongs to the future `wss://` transport in the future development.)

WebSocket clients reconnect automatically with exponential backoff. The defaults
are conservative and can be tuned in the client-only config:

```toml
[client]
reconnect_max_retries = 5
reconnect_backoff_seconds = 0.25
reconnect_backoff_max_seconds = 3.0

[hosts.my-computer]
# Optional per-host overrides use the same keys.
```

If the socket drops while a command is already in flight, valet reconnects for
the next prompt but does not silently replay that command.

### Interactive mode — a redacting shell

Run `valet` with no subcommand (like `python` bare) to open a prompt. **Any line
you type is run as a command**, and the output comes back redacted:

```
$ valet
valet 0.2.0 — redacting shell. Type a command to run it; ':help' for meta-commands, ':quit' to exit.
(default) ws valet> cat .secrets
DB_PASSWORD=[REDACTED:secret:h:38673aad]
API_TOKEN=[REDACTED:secret:h:3bc13a30]
(default) ws valet> cd projects/x-com       # cd sticks for the session
(default) x-com valet> aws s3 ls | head     # runs in projects/x-com
(default) x-com valet> cd ../../..          # cd: cannot cd above the workspace
(default) x-com valet> :workspaces set personal   # switch workspace (resets cwd)
(personal) personal valet> :shell off       # run following lines as argv, not shell
(personal) personal valet> :quit
```

The prompt shows `(workspace) <dir>`. **`cd` sticks** for the session,
and is **jailed to the workspace** — `..` and symlinks can't climb above
the workspace path (a bare `cd` returns to the workspace root). A compound line
(`cd x && y`) is not intercepted: the `cd` there applies only to that
subprocess, as in a real shell. Meta-commands are `:`-prefixed (`:help`, `:cwd`,
`:shell`, `:workspaces`, `:secrets`, `:processes`, `:call`, `:quit`); everything
else runs. `:workspaces` (or `:ws`) lists workspaces; `:workspaces set <id>`
switches to another, resetting the cwd to its root and adopting its shell
default.
Use `:processes list` (or `:jobs`) to list subprocesses started by Valet, and
`:processes kill <pid>` (or `:kill <pid>`) to terminate one of them. Ctrl-D
also exits. Up/Down and Ctrl-P/Ctrl-N recall previously submitted commands.
Press Tab to complete commands from `PATH` (and shell builtins) or files from the
current directory. File candidates include a trailing `/` for directories. When
there is more than one match, valet displays them in two columns; lists taller
than the terminal are shown through `more`, where `q` returns to the prompt.

## Config

`config.toml` (never committed) sets the socket, the default workspace, and the
secret sources valet loads so it can redact their values. See
[`config.example.toml`](config.example.toml). Per command, valet also
auto-loads `.env`/`.secrets` from the command's working directory, so a
project's own secrets are redacted when you run there.

### Choosing what to configure

The knobs split into two families that do fundamentally different things:

- **`[redaction]`** — *let the command run, scrub its **output**.* (masks content)
- **`[policy]`** — *decide whether the command **runs at all**.* (blocks execution)

| Knob | What it does | Use it when | Example |
|---|---|---|---|
| `redaction.secret_file_paths` | Loads secret files matching **glob patterns** and masks their content + values in *any* command's output. **Absolute** patterns (`~/.aws/**`) apply everywhere; **relative** ones (`.env`, `.secrets/**`) resolve against each command's cwd | Files/dirs trusted tools legitimately **use** — both fixed host creds and per-project secrets, in one list | `["~/.aws/**", ".env", ".secrets/**"]` |
| `policy.deny_exec` | Refuses a command **by program name** (`allow_exec` flips to default-deny; empty = allow all) | You want to forbid a **whole tool** | `["curl", "rm"]` |
| `policy.deny_read` | Refuses a command that **names an existing file** matching a **glob** — nothing runs (also blocks a trusted tool that *receives* the file as an argument) | You want a file no tool should even **receive** — opt-in, **empty by default** | `["**/.env", "~/.aws/**"]` |
| `policy.enforce_workspace_reads` | Refuses existing command-line paths or an explicit `cwd` outside the workspace path | Commands should stay within one project tree | `true` |
| `audit.log_path` | Appends metadata-only JSON objects for requests; streamed execs get an immediate `started` event plus a final event | You want a durable record of what valet allowed, denied, or rejected | `~/.valet/audit.jsonl` |

By default, `[exec].shell` is `false`; `valet sh`, REPL shell mode, and direct
shell executables such as `sh -c` are refused unless the host explicitly sets
`shell = true`.

**How a `secret_file_paths` pattern is located** — one list, but the pattern's
form decides where it matches. An **absolute** or `~`-rooted pattern (`~/.aws/**`)
is matched against the filesystem and applies to **every** command. A **relative**
pattern (`.env`, `.secrets/**`, `**/.env`) is resolved **against each command's
cwd**, so one line covers every project. A pattern may name a file, a directory
(all files under it load), or a glob.

**`secret_file_paths` vs `deny_read`** — the important pairing. A credentialed
tool like the AWS CLI needs redaction, not a deny:

| | `aws cloudformation list-stacks` (reads creds **internally**, output safe) | `cat ~/.aws/credentials` (a reveal) |
|---|---|---|
| `secret_file_paths = ["~/.aws/**"]` | ✅ runs; any leak masked | ✅ runs, content masked |
| `deny_read = ["~/.aws/**"]` | ✅ runs (doesn't *name* the file) | ⛔ refused before running |

Use **`secret_file_paths`** for files trusted commands must **use** (keeps them
working, scrubs incidental leaks, and catches a program that opens the file
without naming it) — this is the default, and it's the whole point of valet: *let
an agent use privileged tools without seeing the secrets.* **`deny_read`**
is a **hard block** — it refuses the command outright, so it also stops a trusted
tool that takes the file as an argument (e.g. `mytool --creds .env`). That's why
it is **empty by default**. Reach for it only when you would rather a command
*fail* than trust redaction — for a value that a hijacked command could transform
(e.g. base64-encode) before printing, which literal redaction cannot follow.

> **Rule of thumb:** "a tool should *use* this secret, the agent shouldn't *see*
> it" → `secret_file_paths` (the common case). "no tool should
> even *receive* this file" → `deny_read` (opt-in). "this program shouldn't
> run" → `policy.deny_exec`.

### Default environment variables

valet exports VALET_WORKSPACE=<real workspace root> into every command's
environment (exactly like it already sets PWD and prepends <workspace>/bin).
You can use it like:

```
# shell=true mode
AWS_SHARED_CREDENTIALS_FILE=$VALET_WORKSPACE/.aws/credentials aws s3 ls
```

For the recurring case, set it once in config so you never retype it. Add an [exec].env table that valet applies to every command, expanding $VALET_WORKSPACE:

```
[exec.env]
AWS_SHARED_CREDENTIALS_FILE = "$VALET_WORKSPACE/.aws/credentials"
AWS_CONFIG_FILE = "$VALET_WORKSPACE/.aws/config"
```

## Guardrails

Valet also starts with built-in dangerous command bans for
environment/process/system-control commands such as `env`, `printenv`, `kill`,
`pkill`, `killall`, `ps`, `sudo`, `reboot`, `halt`, `launchctl`, `osascript`,
and `valet` itself.

When a command launched by Valet needs to be inspected or stopped, use Valet's
own process registry instead of host process tools:

```bash
valet processes list
valet processes kill <pid>
```

Only subprocesses started and currently tracked by Valet can be killed this way.

For per-command environment variables, prefer shell-free argv mode:

```bash
valet --env AWS_PROFILE=prod-readonly run -- aws s3 ls
```

## Development

### Tests

```bash
pip install -e ".[test]"
pytest
```

The suite covers: commands run and their output is captured; known secret
values (from `secret_file_paths` and `extra_values`) are
redacted from stdout and stderr; the pattern backstop masks ARNs/account
IDs/keys; nonzero exits and missing binaries are reported; unknown ops, missing
`cmd`, and bad `cwd` are rejected; the deny list blocks a command; streamed
exec output arrives as redacted chunks with structured-output buffering; audit
logging records streamed exec start and final events; and the REPL runs lines
and handles meta-commands.
