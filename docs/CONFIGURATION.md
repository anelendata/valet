# valet configuration

Complete reference for `config.toml` — every section, every key, and the mental
model for choosing between them.

- [Where config lives](#where-config-lives)
- [The mental model: two control families](#the-mental-model-two-control-families)
  - [`secret_file_paths` vs `deny_read`](#secret_file_paths-vs-deny_read)
  - [Rule of thumb](#rule-of-thumb)
- [Reference by section](#reference-by-section)
  - [`[broker]`](#broker)
  - [`[host]` — trusted-LAN WebSocket](#host--trusted-lan-websocket)
  - [`[client]` and `[hosts.<name>]` — client side](#client-and-hostsname--client-side)
  - [`[identity.clients]`](#identityclients)
  - [`[audit]`](#audit)
  - [`[exec]`](#exec)
  - [`[exec.env]` and `VALET_WORKSPACE`](#execenv-and-valet_workspace)
  - [`[redaction]`](#redaction)
  - [`[policy]`](#policy)
- [Workspaces and per-workspace overrides](#workspaces-and-per-workspace-overrides)

The shipped [`config.example.toml`](../valet/config.example.toml) is annotated
and authoritative; this document explains the same keys in prose. `valet init`
writes it to `~/.valet/config.toml` for you.

## Where config lives

- **Host config** — `~/.valet/config.toml`, written by `valet init` (use
  `-c PATH` to place it elsewhere). It is git-ignored and holds the socket path,
  redaction salt, secret sources, policy, workspaces, audit settings, and the
  approved LAN client identities. Keep it — and the sandbox profile, audit log,
  and secret sources — **outside** any workspace directory, so the agent it
  guards can't read them.
- **Client config** — the *same file format*. Every command except `valet serve`
  reads `[client]` and `[hosts.<name>]` from `~/.valet/config.toml` (override
  with `-c` or `$VALET_CLIENT_CONFIG`). With no `[hosts]` table, client commands
  talk to the local daemon over the Unix socket.
- **Per-command auto-load** — for every command, valet also auto-loads
  `.env`/`.secrets` from the command's working directory, so a project's own
  secrets are redacted when you run there, with no config change.

`valet serve` watches the config and hot-reloads changes to `[policy]`,
`[redaction]`, `[audit]`, workspaces, and approved clients. Listener bind
settings (`[broker].socket_path`, `[host].lan`, `[host].listen`) are read at
startup only — restart the daemon after changing those.

## The mental model: two control families

Two families of knobs do fundamentally different things:

- **`[redaction]`** — *let the command run, scrub its **output**.* (masks content)
- **`[policy]`** — *decide whether the command **runs at all**.* (blocks execution)

Valet is permissive by default: it runs almost any command and relies on
redaction to keep secret *values* out of model context. Policy is the opt-in
layer for the cases where you'd rather a command never run.

### `secret_file_paths` vs `deny_read`

The pairing that trips people up. A credentialed tool like the AWS CLI needs
redaction, **not** a deny — a deny would break it:

| | `aws cloudformation list-stacks` (reads creds **internally**, output safe) | `cat ~/.aws/credentials` (a reveal) |
|---|---|---|
| `secret_file_paths = ["~/.aws/**"]` | ✅ runs; any leak masked | ✅ runs, content masked |
| `deny_read = ["~/.aws/**"]` | ✅ runs (doesn't *name* the file) | ⛔ refused before running |

Use **`secret_file_paths`** for files trusted commands must **use**: it keeps
them working, scrubs incidental leaks, and even catches a program that opens the
file without naming it on the command line. This is the default, and it is the
whole point of valet — *let an agent use privileged tools without seeing the
secrets.*

**`deny_read`** is a **hard block**: it refuses the command outright, so it also
stops a trusted tool that takes the file as an argument (e.g. `mytool --creds
.env`) — the opposite of what valet is usually for. That's why it is **empty by
default**. Reach for it only when you'd rather a command *fail* than trust
redaction — for a value a hijacked command could transform (e.g. base64-encode)
before printing, which literal redaction can't follow.

### Rule of thumb

> - "a tool should *use* this secret, the agent shouldn't *see* it" →
>   `secret_file_paths` (the common case)
> - "no tool should even *receive* this file" → `deny_read` (opt-in)
> - "this program shouldn't run" → `policy.deny_exec`

## Reference by section

### `[broker]`

The daemon's transport and global limits.

| Key | Default | What it does |
|---|---|---|
| `socket_path` | `~/.valet/broker.sock` | Unix socket the daemon listens on. Created `0600`, owned by you — the OS is the access control: no port, no token, no network surface. Read at startup; restart after changing. |
| `timeout_seconds` | `60` | Hard wall-clock limit per command. |
| `fingerprint_salt` | *(unset)* | Salt for redaction fingerprint tags (`[REDACTED:secret:h:…]`). Set a stable value to keep tags consistent across restarts; left as `CHANGE_ME` or unset, valet generates an ephemeral salt at startup. `valet init` sets one for you. |

### `[host]` — trusted-LAN WebSocket

A Level-1 trusted-LAN WebSocket host so agents on another machine can reach this
daemon. Disabled unless `lan = true`. Read at startup — restart after changing
`lan` or `listen`.

```toml
[host]
id = "my-computer"
lan = false
listen = "127.0.0.1:8766"
```

| Key | Default | What it does |
|---|---|---|
| `id` | `"my-computer"` | Host identifier. `[hosts.<name>]` on a client is matched against this. |
| `lan` | `false` | Turn the WebSocket listener on. Leave off for socket-only local use. |
| `listen` | `127.0.0.1:8766` | Bind address. `127.0.0.1` for local testing; a LAN interface (e.g. `0.0.0.0`) **only on a trusted network**. |

`ws://` is for trusted development LANs only; public-internet relay awaits a
future `wss://` transport.

### `[client]` and `[hosts.<name>]` — client side

Present only on machines that act as a **client** of a remote host. valet writes
this snippet for you when the host approves the client (`valet clients add`);
copy it to the client machine.

```toml
[client]
id = "my-ai-box"
key = "<shared key approved under [identity.clients] on the host>"
default_host = "my-computer"
# default_workspace = "<id>"          # optional; overrides the host default
reconnect_max_retries = 5
reconnect_backoff_seconds = 0.25
reconnect_backoff_max_seconds = 3.0

[hosts.my-computer]                    # name it after the host's [host].id
url = "ws://192.168.1.25:8766/rpc"
```

| Key | Default | What it does |
|---|---|---|
| `client.id` | — | This client's identity, approved on the host. |
| `client.key` | — | Shared key for challenge-response auth. Lives only in the client config. |
| `client.default_host` | — | Which `[hosts.<name>]` to use when `--host` is omitted. |
| `client.default_workspace` | *(unset)* | Workspace this client runs in when a command names none. Takes priority over the host's own default; an explicit `valet -w <id> …` still overrides it. Manage with `valet client default_workspace set <id>` / `show` / `unset`. If it points at a workspace the host no longer offers, `run`/`sh` fail with a clear message and the REPL declines to start. |
| `client.reconnect_max_retries` | `5` | Reconnect attempts after a dropped socket. |
| `client.reconnect_backoff_seconds` | `0.25` | Initial backoff between attempts. |
| `client.reconnect_backoff_max_seconds` | `3.0` | Backoff ceiling (exponential). |
| `hosts.<name>.url` | — | WebSocket RPC endpoint of the host. Defaults its `host_id` to `<name>`. |

`[hosts.<name>]` may repeat the `reconnect_*` keys to override the `[client]`
defaults per host. Reconnection is transparent, but valet never silently replays
a command that was in flight when the socket dropped — you re-issue it.

The client config holds **only** host URLs and this client's identity key. Secret
sources, redaction salts, policy, and audit settings stay on the trusted host and
are never disclosed to clients.

### `[identity.clients]`

The host's registry of approved Level-1 clients. Let valet manage it rather than
editing by hand:

```bash
valet clients add my-ai-box --url ws://192.168.1.25:8766/rpc
valet clients list
valet clients block my-ai-box      # temporarily deny (drops any live connection)
valet clients unblock my-ai-box
valet clients remove my-ai-box     # revoke the key permanently
```

`valet serve` reloads client changes automatically; a blocked client can't
authenticate and any live connection is dropped on reload. Restart the daemon
only when you change `[host].lan` or `[host].listen`.

### `[audit]`

Optional append-only JSON audit log — the record of what valet allowed, denied,
or rejected.

```toml
[audit]
log_path = "~/.valet/audit.jsonl"
console = true
```

| Key | Default | What it does |
|---|---|---|
| `log_path` | *(unset)* | Newline-delimited JSON file (one object per line). Unset disables file logging. |
| `console` | `false` | Also print each event to the server console (human-readable) under `valet serve` / `valet serve-lan`. |

**Format.** Non-streaming requests append one final JSON object. Streamed exec
requests append a `phase = "started"` event as soon as policy allows the command
and the process is about to run, then a final event when it finishes. Each object
records metadata only: request ID, caller identity, transport (`uds`/`lan`),
command shape, working directory, policy decision, whether approval was required,
duration, exit code, byte counts, redaction counts, and fail-closed events.

**It never stores** raw stdout, raw stderr, credential values, or unredacted
command material — so the log stays safe to keep and can't become another secret
sink.

### `[exec]`

Execution defaults for every workspace (each `[workspaces.<id>]` can override any
key — see [Workspaces](#workspaces-and-per-workspace-overrides)).

| Key | Default | What it does |
|---|---|---|
| `default_workspace` | *(unset)* | Workspace used when a command names none. Set by `valet workspaces add` (first workspace wins; `--make-default` re-points it). |
| `shell` | `false` | Whether `valet sh`, REPL shell mode, and shell executables like `sh -c` are allowed. Off by default: they're refused unless you set `shell = true`. Enable only if you trust all clients and need pipes/globs/redirects/`&&`; prefer `valet --env NAME=value run …` for env vars. |
| `sandbox_profile` | *(unset)* | Path to a macOS `sandbox-exec` (`.sb`) profile. When set, every command runs under `sandbox-exec` — a real kernel boundary that policy alone can't provide. Needs the workspace path set and `sandbox-exec` on `PATH`; a ready profile ships in [`contrib/sandbox-exec/workspace.sb`](../contrib/sandbox-exec/workspace.sb). |

### `[exec.env]` and `VALET_WORKSPACE`

Every command's environment includes `VALET_WORKSPACE` = the real workspace root
(valet also sets `PWD` and prepends `<workspace>/bin` to `PATH`). Reference
workspace files from any subdirectory without `../../..` paths:

```bash
# shell = true mode
AWS_SHARED_CREDENTIALS_FILE=$VALET_WORKSPACE/.aws/credentials aws s3 ls
```

For the recurring case, set it once with an `[exec.env]` table that valet applies
to every command, expanding `$VALET_WORKSPACE`. Per-command env (an inline
`NAME=value` or `--env`) wins over these defaults:

```toml
[exec.env]
AWS_SHARED_CREDENTIALS_FILE = "$VALET_WORKSPACE/.aws/credentials"
AWS_CONFIG_FILE = "$VALET_WORKSPACE/.aws/config"
```

### `[redaction]`

Family 1 — the command runs; its **output** is scrubbed.

```toml
[redaction]
secret_file_paths = [
    "~/.aws/**", "~/.config/**",
    "**/.env", "**/.config/**", "**/.secrets/**", "**/secrets/**",
    "**/.passwords/**", "**/passwords/**", "**/.ssh/**", "**/.aws/**",
]
extra_values = []
redact_suspected = true
redact_high_entropy = true
```

| Key | Default | What it does |
|---|---|---|
| `secret_file_paths` | AWS/ssh/secrets globs (see above) | Globs (`**` / `*` / `?`) naming secret files or dirs that trusted commands legitimately **use**; their contents are masked from **every** command's output. See [pattern matching](#how-secret_file_paths-patterns-are-matched) below. |
| `extra_values` | `[]` | Extra literal strings to always redact — e.g. a token not stored in any file. |
| `redact_suspected` | `true` | Mask values that *look* secret even when valet doesn't know the exact value (fetched at runtime): the value of a sensitively-named key, the `value:` of a key/value pair, and known token shapes (AWS/GitHub/Slack/Stripe/Google, JWT, PEM). Key **names** stay visible. Set `false` for verbatim output. |
| `redact_high_entropy` | `true` | Mask long high-entropy tokens **anywhere**, even a bare string with no key name or known shape. Skips git SHAs/hashes, UUIDs, decimal IDs, and paths, but may still mask base64 blobs or random-looking non-secrets. Noisy — turn off if it over-masks. |

#### How `secret_file_paths` patterns are matched

One list, but the pattern's **form** decides where it matches:

- An **absolute** or `~`-rooted pattern (`~/.aws/**`) is matched against the
  filesystem and applies to **every** command.
- A **relative** pattern (`**/.secrets/**`, `**/.env`) is resolved **against
  each command's cwd**, so one line covers every project.

**Depth matters — this is a common footgun.** A bare `.secrets/**` matches only a
`.secrets/` directory *directly at the cwd*; a **nested** one (say
`skills/foo/.secrets/token`) is **not** covered, so its contents would leak in
output. Prefix with `**/` (`**/.secrets/**`) to match `.secrets/` at **any**
depth — this is why the shipped defaults use `**/`.

To keep `**/` cheap, valet **caches** the scan per workspace (reused across
commands until an indexed secret file changes, and refreshed at least every few
seconds so new files are still picked up) and **prunes** well-known huge
non-secret directories (`.git`, `node_modules`, `.venv`, `__pycache__`, caches,
…) from the walk. A directory you name explicitly in a pattern is never pruned.
For an enormous tree you can still narrow patterns to specific subtrees.

A pattern may name a file, a directory (all files under it load), or a glob. For
each match valet masks the whole file content (so any full dump is caught) **plus**
its structured values (`KEY=VALUE` / ini / json / yaml). Missing paths are
skipped; files larger than 1 MB skip the whole-blob step.

### `[policy]`

Family 2 — decide whether a command **runs at all**. Permissive by default except
valet's built-in bans (see [Guardrails in the README](../README.md#guardrails)).
Command-line policy is best-effort static analysis, **not** a real boundary — for
a hard guarantee use the OS sandbox (`[exec].sandbox_profile`).

```toml
[policy]
allow_exec = []
deny_exec = []
deny_read = []
enforce_workspace_reads = true
enforce_workspace_writes = true
```

| Key | Default | What it does |
|---|---|---|
| `allow_exec` | `[]` | Empty = allow everything not otherwise denied. A **non-empty** list flips to **default-deny**: only these basenames run (`cd`/`pushd`/`popd` still allowed), e.g. `["python", "ls", "cat"]`. |
| `deny_exec` | `[]` | Extra program-name bans (by basename) on top of the built-ins, e.g. `["rm", "npm"]`. |
| `deny_read` | `[]` | Globs of files a command may not name — valet refuses to **run** it. A hard block that also stops a trusted tool from *using* the file. Shell-aware (splits on `;` `&&` `||` `|`, tracks `cd`). Empty by default; see [`secret_file_paths` vs `deny_read`](#secret_file_paths-vs-deny_read). Examples: `["**/.env", "**/.secrets/**", "~/.aws/**"]`. |
| `enforce_workspace_reads` | `true` | Refuse a command whose existing path argument or `cwd` resolves outside the workspace (`../` and symlinks included). Best-effort, not a sandbox. |
| `enforce_workspace_writes` | `true` | Refuse a command whose path-like argument resolves outside the workspace **even if it doesn't exist yet**, so nothing is written outside. |

## Workspaces and per-workspace overrides

A workspace is a dedicated directory that commands are confined to, and the
REPL's `cd` jail: `cd` cannot climb above it (`..` and symlinks are resolved
first). It appears as the virtual root `./`, and the real parent path is stripped
from all output. A `bin/` at the workspace root is prepended to `PATH`.

Point each workspace at a **project** directory, never your home (`~` would put
your whole home in the agent's blast radius).

**Add workspaces with the CLI** (recommended) — each `add` writes a section and
scaffolds the directory (`bin/`, `tools/`, `skills/`, `projects/`, `tmp/`,
`.secrets/demo.yaml`, `README.md`); existing files are never overwritten:

```bash
valet workspaces add work ~/work/project             # first one becomes default
valet workspaces add personal ~/personal --make-default
valet workspaces list                                # * marks the default
valet workspaces remove personal                     # drop the entry, keep the dir
```

`[exec]`, `[policy]`, and `[redaction]` at the top level are the **defaults** for
every workspace. Each `[workspaces.<id>]` names a `path` and may override any of
those defaults in a sub-table:

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
[workspaces.personal.redaction]
extra_values = ["a-token-only-this-workspace-uses"]
```

Select a workspace per command with `-w/--workspace`, or switch inside the REPL
with `:workspaces set <id>`. `valet serve` reloads workspace changes
automatically.

```bash
valet -w personal run -- ls
valet -w personal sh 'ls | grep foo'
```

`valet workspaces remove <id>` deletes the config entry (and clears the default
pointer if it pointed there) but **leaves the directory on disk** — it prints the
path so you can delete it yourself. `valet workspaces list` adapts to context:
run locally it reads the config and shows paths; run as a client (remote `--host`
or a client `default_host`) it lists the **remote** host's workspaces over RPC —
ids, default marker, and shell mode, but never paths, which the host doesn't
disclose.
