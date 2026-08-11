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

<!-- Absolute raw URL + PNG so the image renders on PyPI too (PyPI's image proxy
     rejects SVG and does not resolve relative paths). SVG source is in images/. -->
![Valet-mediated agent interaction](https://raw.githubusercontent.com/anelendata/valet/main/images/valet-interaction.png)

## Table of contents

- [Quick demo](#quick-demo)
- [Use cases](#use-cases)
  - [Use case 1: Running AWS CLI commands in a hardened sandbox](#use-case-1-running-aws-cli-commands-in-a-hardened-sandbox)
  - [Use case 2: Database query](#use-case-2-database-query)
- [Features](#features)
  - [Valet serve](#valet-serve)
  - [Interactive shell (REPL)](#interactive-shell-repl)
  - [Audit logging](#audit-logging)
  - [Multi-transport: one host, many agents](#multi-transport-one-host-many-agents)
- [Valet is not...](#valet-is-not)
- [Before getting started](#before-getting-started)
  - [Recommended architecture](#recommended-architecture)
  - [Sandbox hardening](#sandbox-hardening)
- [Install & run](#install--run)
  - [On the host](#on-the-host)
  - [Run commands through valet](#run-commands-through-valet)
  - [Interactive mode — a redacting shell](#interactive-mode--a-redacting-shell)
  - [Multiple workspaces under one host](#multiple-workspaces-under-one-host)
  - [Running from a node in the local network](#running-from-a-node-in-the-local-network)
- [Configuration](#configuration)
- [Guardrails](#guardrails)
- [Development](#development)
  - [Tests](#tests)

More...
- [Configuration reference](https://github.com/anelendata/valet/blob/main/docs/CONFIGURATION.md)
- [Roadmap](https://github.com/anelendata/valet/blob/main/docs/ROADMAP.md)
- [Threat model](https://github.com/anelendata/valet/blob/main/docs/THREAT_MODEL.md)
- [Google Workspace CLI (`gws`) through valet](https://github.com/anelendata/valet/blob/main/docs/google-workspace-cli.md)
- [Set up a workspace-wide Python venv](https://github.com/anelendata/valet/blob/main/docs/workspace-python-venv.md)


## Quick demo

Install, set up a workspace, and read a secret file *through* valet:

```bash
python -m venv venv
. venv/bin/activate
pip install valet-ai

valet init                                 # writes ~/.valet/config.toml
valet workspace add demo ~/ai-workspace    # scaffolds the workspace + a demo secret
valet serve                                # leave this running
```

In another terminal:

```bash
. venv/bin/activate

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

## Use cases

### Use case 1: Running AWS CLI commands in a hardened sandbox

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

### Use case 2: Database query

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

The broker runs in a trusted terminal that already has your profiles, tokens,
and cloud CLIs, and hands a sandboxed agent the *results* of privileged commands
without ever handing over the credentials. The agent can't read `.env`,
`.secrets`, or `~/.aws` from inside its sandbox — it asks valet instead:

```bash
sandbox$ valet --env AWS_PROFILE=prod-readonly run -- aws s3 ls s3://my-prod-bucket/releases/
sandbox$ valet run -- psql --csv -c "select status, count(*) from jobs group by status"
```

Valet loads the secret sources, runs the command, and redacts the echoed command
plus stdout/stderr **before a single byte reaches model context**. Safe
line-oriented output streams as it arrives; structured JSON/YAML/PEM is buffered
just long enough to redact it safely. Edit `config.toml` while it runs and
policy, redaction, and audit changes reload live.

### Interactive shell (REPL)

Run bare `valet` for a redacting shell — type any command and watch the output
come back scrubbed. It's the fastest way to *see* your policy and redaction
rules at work before you trust an agent to them:

```
$ valet
valet 0.2.0 — redacting shell. Type a command to run it; ':help' for meta-commands, ':quit' to exit.

valet> aws logs tail mystack/some-task --since 60m --profile prod-readonly

2026-08-05T04:00:17 … {"details":{"roleArn":"[REDACTED:arn]"}, … "execution_arn":"[REDACTED:arn]"}
2026-08-05T04:00:17 … {"details":{"region":"[REDACTED:secret:h:52a3d849]","resource":"runTask.sync"}, …}
...
```

### Audit logging

Every request through valet can land in an append-only JSON log, so the
privileged boundary stays accountable: who asked, what command ran, in which
workspace, whether policy allowed or denied it, how long it took, and how many
values were redacted.

```toml
[audit]
log_path = "~/.valet/audit.jsonl"
console = true
```

The log is **safe to keep** — it records metadata (request IDs, caller, command
shape, decision, exit code, redaction counts, fail-closed events), never raw
stdout/stderr or credential values, so it can't become another secret sink. With
`console = true`, `valet serve` also prints readable entries as commands run:

```text
2026-08-05T12:31:03Z INFO: codex uds allowed started aws ecs describe-services ...
2026-08-05T12:31:04Z INFO: codex uds allowed aws ecs describe-services ...
```

Denied requests read the same way — e.g. a command that referenced `**/.env` and
was refused before execution — so an operator can reconstruct exactly what
happened without ever touching the secrets valet protects.

### Multi-transport: one host, many agents

Configure credentials, cloud CLIs, and secret sources **once, on the host**, then
point every agent at it — the REPL on your laptop, a coding agent in a hardened
sandbox, a second workstation running another model. They all get the same
policy-gated, redacted tool access, and none of them hold a secret. No separate
stack of MCP servers and app installs to stand up and secure inside every agent.

The same `valet run` / `valet sh` / REPL commands work over either transport:

- **Unix domain socket** (default) — the socket is `0600`, owned by the user who
  started the daemon, so the OS *is* the access control: no port, no token, no
  network surface.
- **Trusted-LAN WebSocket** — reach the host from another machine on the trusted
  network, with challenge-response auth against approved client identities. Off
  unless you opt in with `[host].lan = true`
  ([setup](#running-from-a-node-in-the-local-network)).

Every request records its transport (`uds` or `lan`) in the audit log, so a
shared host stays accountable.

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
[Threat model](https://github.com/anelendata/valet/blob/main/docs/THREAT_MODEL.md) for what it does and doesn't stop.

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

**valet is not a sandbox for itself.** It is a broker the agent calls, running as
the same user from the same binary — so it cannot stop an agent with native host
access from reading its config (`~/.valet/config.toml`, which holds the LAN
client keys) or running its admin subcommands (`serve`, `doctor`, `clients`,
`workspaces`). That boundary is the agent sandbox's job: deny reads of `~/.valet`
and allow only `valet run`/`sh` (see the hardening guide). The agent reaches the
daemon over the broker socket, so it never needs to read `~/.valet` directly.

**IMPROTANT**: Follow [Sandbox Hardening Guide](https://github.com/anelendata/valet/blob/main/docs/SANDBOX_HARDENING.md)
before installing valet!

## Install & run

Install from PyPI — on the host, and inside the agent's sandbox:

```bash
pip install valet-ai
```

Or from source for development (you can also use `uv`):

```bash
git clone https://github.com/anelendata/valet.git
cd valet
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```

### On the host

Set up the daemon once, in a trusted terminal:

```bash
valet init                                # create ~/.valet/config.toml + health check
                                          # (y/n prompts: macOS OS sandbox, LAN host)
valet workspaces add work ~/work/project  # add your first workspace (becomes default)
$EDITOR ~/.valet/config.toml              # point secret_file_paths at your secrets, etc.

valet serve                               # start the daemon (keep this shell open)
valet doctor                              # re-check config health anytime
```

- **`valet init`** writes the example config with a stable redaction salt and
  prompts for the macOS sandbox and LAN host. It defines **no** workspace and
  won't overwrite an existing config.
- **`valet workspaces add <id> <dir>`** creates the first workspace and scaffolds
  its directory. `valet serve` won't start until one exists.

Keep the config, sandbox profile, audit log, and secret sources **outside** the
workspace — anything inside it is readable (and, when jailed there, writable) by
the agent. `valet doctor` warns when they aren't. Full setup of secrets, policy,
and redaction lives in [Configuration](docs/CONFIGURATION.md).

### Run commands through valet

From the agent's sandbox on the same machine, call valet instead of the tool
directly. You get redacted output and the command's own exit code, so it drops
into scripts like the real command would:

```bash
valet run -- ls                          # list the host's workspace root
valet run -- aws s3 ls                    # argv, no shell (exact)
valet --cwd projects/app run -- ls        # set cwd without shell syntax
valet --env AWS_PROFILE=prod run -- aws s3 ls
valet sh 'aws s3 ls | grep prod'          # pipes/globs — needs [exec] shell = true
```

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

The prompt shows `(workspace) <dir>`. A few behaviors worth knowing:

- **`cd` sticks** for the session and is **jailed to the workspace** — `..` and
  symlinks can't climb above it (a bare `cd` returns to the root). A compound
  line (`cd x && y`) isn't intercepted; that `cd` applies only to the subprocess,
  as in a real shell.
- **Meta-commands** are `:`-prefixed: `:help`, `:cwd`, `:shell`, `:workspaces`
  (`:ws`; `set <id>` switches, resetting cwd and adopting that workspace's shell
  default), `:secrets`, `:processes` (`:jobs` to list, `:kill <pid>` to stop a
  valet subprocess), `:call`, `:quit`. Everything else runs.
- **History & completion** — Up/Down (or Ctrl-P/Ctrl-N) recall past commands; Tab
  completes commands and files. **Ctrl-D** exits.

### Multiple workspaces under one host

One host can serve several workspaces, each its own directory jail with its own
policy and redaction. Manage them from the host:

```bash
valet workspaces add personal ~/personal                  # add a workspace
valet workspaces add personal ~/personal --make-default   # ...and make it default
valet workspaces list                                     # * marks the default
valet workspaces remove personal                          # drop the entry, keep the dir
```

Select one per command with `-w`, or switch inside the REPL with
`:workspaces set <id>`:

```bash
valet -w personal run -- ls
valet -w personal sh 'ls | grep foo'
```

Per-workspace overrides of the shared `[exec]`/`[policy]`/`[redaction]` defaults,
and the `[client].default_workspace` setting, are in
[Configuration → Workspaces](docs/CONFIGURATION.md#workspaces-and-per-workspace-overrides).

### Running from a node in the local network

Agents on another machine on a trusted LAN can use the host over WebSocket.

**On the host** — enable LAN and restart, then approve a client. `valet clients
add` prints a client snippet and hot-reloads the daemon:

```toml
[host]
lan = true
listen = "0.0.0.0:8766"
```

```bash
valet clients add my-ai-box     # prints the snippet below
valet clients list              # also: block / unblock / remove <id>
```

```toml
[client]
id = "my-ai-box"
key = "xxxxxxxxxxxxxxxxxxxxxxxx"
default_host = "my-computer"     # reconnect_* tuning keys omitted

[hosts.my-computer]
url = "ws://<host-lan-ip>:8766/rpc"
```

**On the client** — drop that snippet into the client's config, then run the same
commands, resolved through the default host:

```bash
valet ping
valet --env AWS_PROFILE=prod run -- aws s3 ls
valet sh 'aws s3 ls | head'
valet --host my-computer run -- ls         # target a host explicitly
```

Reconnect tuning and the full client-config reference are in
[Configuration](docs/CONFIGURATION.md#client-and-hostsname--client-side).

## Configuration

`config.toml` (git-ignored, written by `valet init`) holds the socket, secret
sources, policy, workspaces, and audit settings. Per command, valet also
auto-loads `.env`/`.secrets` from the working directory, so a project's own
secrets are redacted when you run there — no config change needed.

The mental model is two families of knobs:

- **`[redaction]`** — *let the command run, scrub its **output**.* (the default;
  the whole point of valet)
- **`[policy]`** — *decide whether the command **runs at all**.* (opt-in blocks)

**→ Full reference: [docs/CONFIGURATION.md](docs/CONFIGURATION.md)** — every
section and key, plus the annotated
[`config.example.toml`](https://github.com/anelendata/valet/blob/main/valet/config.example.toml).

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
