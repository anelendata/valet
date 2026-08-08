# Using the Google Workspace CLI (`gws`) through valet

[`gws`](https://www.npmjs.com/package/@googleworkspace/cli) (the
`@googleworkspace/cli` npm package) works fine when you run it directly, but
under valet's OS sandbox (`[exec].sandbox_profile`) it fails with a discovery
error:

```
error[discovery]: File exists (os error 17)
{ "error": { "code": 500, "message": "File exists (os error 17)", "reason": "discoveryError" } }
[exit 4]
```

This page explains why and how to make it work while keeping the sandbox on.

## Why it fails under the sandbox

`gws` keeps everything under a single **config directory**, `~/.config/gws`:

```
~/.config/gws/
├── cache/                 # cached API discovery docs: gmail_v1.json, drive_v3.json, ...
├── client_secret.json     # OAuth client
├── credentials.enc        # encrypted credentials
└── token_cache.json       # cached OAuth token
```

That directory is **outside the workspace**, so the sandbox's read-jail blocks
it. When `gws` checks whether a cached discovery doc exists, the blocked `stat`
makes it look absent — so `gws` tries to (re)create it, and the kernel returns
`EEXIST` ("File exists") because it is actually there. Same story for the
credentials.

Setting `XDG_CACHE_HOME` / `XDG_CONFIG_HOME` does **not** help: `gws` uses its
own override, `GOOGLE_WORKSPACE_CLI_CONFIG_DIR`, not the XDG variables.

## Fix: move `gws`'s config dir into the workspace

Point `GOOGLE_WORKSPACE_CLI_CONFIG_DIR` at a path inside the workspace, where
the sandbox allows both read and write. `$VALET_WORKSPACE` (which valet sets on
every command, and expands in argv mode) is the stable way to name the root.

### 1. One-time auth — do this **outside** valet

`gws auth login` is an interactive browser/OAuth flow, and valet runs commands
non-interactively (no TTY, no browser). So authenticate once by hand, in a
normal terminal, writing the token into the workspace config dir with the
**file** keyring backend (the default `keyring` backend is the macOS Keychain,
which the sandbox blocks):

```bash
GOOGLE_WORKSPACE_CLI_CONFIG_DIR="$HOME/path/to/workspace/.config/gws" \
GOOGLE_WORKSPACE_CLI_KEYRING_BACKEND=file \
"$HOME/path/to/workspace/bin/gws" auth login
```

(If you already have a working `~/.config/gws`, you can instead copy it in —
`cp -R ~/.config/gws "$HOME/path/to/workspace/.config/gws"` — but you will still
need the `file` backend, and the Keychain-encrypted `credentials.enc` may not
decrypt without a fresh `auth login`.)

### 2. Point valet at it — `~/.valet/config.toml`

```toml
[exec.env]
GOOGLE_WORKSPACE_CLI_CONFIG_DIR      = "$VALET_WORKSPACE/.config/gws"
GOOGLE_WORKSPACE_CLI_KEYRING_BACKEND = "file"
```

valet applies these to every command and expands `$VALET_WORKSPACE` to the
workspace root. (Per-command env still overrides them.)

### 3. Run it in the REPL

```
valet> gws gmail users messages list --params '{"userId": "me"}' --format table
```

The discovery cache and token are now read/written inside the jail, so no more
`EEXIST`.

## Non-interactive alternative to `auth login`

`gws` also reads a pre-obtained token from the environment (highest priority):

```toml
[exec.env]
GOOGLE_WORKSPACE_CLI_TOKEN = "..."   # expires; needs refreshing
```

Useful for automation, but the token is short-lived — the file-backend login
above is usually less hassle.

## Security note

Putting `client_secret.json`, `credentials.enc`, and `token_cache.json` inside
the workspace means **any command valet runs can read them**. valet still scrubs
known secret values from *output*, but this is broad Google Workspace access
(Gmail, Drive, …). Prefer a **separate, minimal-scope** credential set for the
sandboxed agent over your personal `gws` login.

## The general pattern

This applies to any CLI that caches or stores state under `$HOME` (outside the
workspace) while the OS sandbox is on:

1. Find the tool's config/cache location and its override (an env var or a
   `--config-dir`/`--cache-dir` flag). Its `--help` usually lists it.
2. Point that override at `$VALET_WORKSPACE/...` via `[exec.env]`.
3. Do any interactive setup (login, key generation) **outside** valet, once,
   writing into that in-workspace location.
4. Avoid backends that need the macOS Keychain — the sandbox blocks it; prefer a
   file-based store.
