# Google Workspace CLI (`gws`) with valet

A complete guide to installing and authenticating
[`gws`](https://github.com/googleworkspace/cli) (the `@googleworkspace/cli`,
"one CLI for all of Google Workspace"), and the gotchas that matter when you run
it through valet — especially under the OS sandbox.

> `gws` is **not** an officially supported Google product and is pre-1.0; expect
> breaking changes. Details here are distilled from the project's README and may
> drift — check `gws --help` and the repo for the current surface.

---

## 1. Install

Pick one (pre-built binary is easiest):

```bash
# Pre-built binary — download for your OS/arch from GitHub Releases, add to PATH
#   https://github.com/googleworkspace/cli/releases

npm install -g @googleworkspace/cli        # npm (Node 18+)
brew install googleworkspace-cli           # Homebrew
cargo install --git https://github.com/googleworkspace/cli --locked   # from source
nix run github:googleworkspace/cli         # Nix
```

Verify: `gws --help`.

**Prerequisites:** a Google account with Workspace access, and a Google Cloud
project (created by `gws auth setup`, the `gcloud` CLI, or the Cloud Console).

---

## 2. Authenticate

`gws` supports several credential sources. Precedence (highest first):

| # | Source | How |
|---|--------|-----|
| 1 | Access token | `GOOGLE_WORKSPACE_CLI_TOKEN` |
| 2 | Credentials file | `GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE` (OAuth **or** service account JSON) |
| 3 | Encrypted credentials from `gws auth login` | stored in the config dir |
| 4 | Plaintext `~/.config/gws/credentials.json` | — |

### Interactive login (personal account, has `gcloud`)

```bash
gws auth setup                 # one-time: create project, enable APIs, log in
gws auth login                 # subsequent logins / scope selection
gws drive files list --params '{"pageSize": 5}'
```

**Scopes:** unverified (testing-mode) OAuth apps are capped at ~25 scopes, so the
`recommended` preset (85+ scopes) fails. Request only what you need:

```bash
gws auth login -s drive,gmail,sheets
```

### Manual OAuth (no `gcloud`)

1. OAuth consent screen → App type **External** (testing mode is fine) → add your
   email under **Test users** (skipping this causes "Access blocked").
2. **Credentials** → create OAuth client → type **Desktop app** → download the
   client JSON to `~/.config/gws/client_secret.json`.
3. `gws auth login`.

### Service account (server-to-server; best for org automation)

```bash
export GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE=/path/to/service-account.json
gws drive files list           # no login needed
```

(User data like Gmail/Drive needs domain-wide delegation set by a Workspace
admin. Not available for personal `@gmail.com` accounts.)

### Headless / export (portable, keyring-free)

On a machine with a browser, log in, then export a self-contained credentials
file — this is the key to sandboxed/headless use:

```bash
gws auth export --unmasked > credentials.json
export GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE=/path/to/credentials.json
gws drive files list           # authenticates without a browser or keyring
```

### Where credentials live

`gws` encrypts credentials at rest (AES-256-GCM). The encryption **key** is kept
in your OS keyring by default, or in `<config-dir>/.encryption_key` when
`GOOGLE_WORKSPACE_CLI_KEYRING_BACKEND=file`. The config directory holds it all:

```
~/.config/gws/                 # override: GOOGLE_WORKSPACE_CLI_CONFIG_DIR
├── cache/                     # API discovery docs, cached 24h (gmail_v1.json, ...)
├── client_secret.json         # OAuth client
├── credentials.enc            # encrypted credentials
├── .encryption_key            # only with KEYRING_BACKEND=file
└── token_cache.json           # cached OAuth token
```

---

## 3. Configuration & environment

Default config dir is `~/.config/gws`. Useful variables (all optional; also
loadable from a `.env`):

| Variable | Purpose |
|----------|---------|
| `GOOGLE_WORKSPACE_CLI_CONFIG_DIR` | Config directory (default `~/.config/gws`) |
| `GOOGLE_WORKSPACE_CLI_KEYRING_BACKEND` | `keyring` (OS keyring, default) or `file` |
| `GOOGLE_WORKSPACE_CLI_TOKEN` | Pre-obtained OAuth2 access token (highest priority) |
| `GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE` | OAuth or service-account JSON |
| `GOOGLE_WORKSPACE_CLI_CLIENT_ID` / `_CLIENT_SECRET` | OAuth client (instead of `client_secret.json`) |
| `GOOGLE_WORKSPACE_PROJECT_ID` | GCP project for quota/billing |
| `GOOGLE_WORKSPACE_CLI_SANITIZE_TEMPLATE` / `_MODE` | Model Armor template; `warn`/`block` |
| `GOOGLE_WORKSPACE_CLI_LOG` / `_LOG_FILE` | stderr log level (e.g. `gws=debug`) / JSON log dir |

---

## 4. Running commands

Commands are generated dynamically from Google's Discovery Service:

```
gws <service> <resource> [sub-resource] <method> [flags]
```

```bash
gws drive files list --params '{"pageSize": 10}'
gws sheets spreadsheets create --json '{"properties": {"title": "Q1 Budget"}}'
gws gmail users messages list --params '{"userId": "me"}' --format table
gws schema drive.files.list                       # inspect a method's schema
```

- `--params <JSON>` query params · `--json <JSON>` request body · `--upload <PATH>`
  media · `--format json|table|yaml|csv` · `--dry-run` preview.
- Pagination: `--page-all` (NDJSON), `--page-limit N`, `--page-delay MS`.
- Sheets ranges contain `!`; always single-quote params: `'{"range": "Sheet1!A1:C10"}'`.
- Helper shortcuts are prefixed with `+`: `gws gmail +send`, `gws calendar +agenda`, etc.

**Exit codes:** `0` ok · `1` API error · `2` auth error · `3` validation ·
`4` discovery error · `5` internal.

---

## 5. Using `gws` with valet — the gotchas

valet runs commands **non-interactively** and (when `[exec].sandbox_profile` is
set) **inside an OS sandbox** that confines file access to the workspace. Three
things follow.

### Gotcha 1 — Interactive setup can't run through valet

`gws auth setup` and `gws auth login` open a browser/console. valet captures
stdout/stderr and has no TTY or browser to proxy, so **do all auth by hand,
outside valet, once.** valet then runs only the non-interactive `gws` commands.

### Gotcha 2 — The sandbox blocks `~/.config/gws`

Everything `gws` needs — the discovery `cache/`, the OAuth client, the encrypted
credentials, and (default) the keyring — lives under `~/.config/gws`, which is
outside the workspace. Under the sandbox:

- **Discovery fails** with `error[discovery]: File exists (os error 17)` /
  `exit 4`. The blocked `stat` makes a cached doc look absent, so `gws` tries to
  recreate it and the kernel returns `EEXIST` because it is actually there.
- **Auth fails** (`exit 2`) because the OS keyring (macOS Keychain) that holds
  the encryption key is blocked, and the credential files can't be read.

`XDG_CACHE_HOME` / `XDG_CONFIG_HOME` do **not** help — `gws` uses its own
`GOOGLE_WORKSPACE_CLI_CONFIG_DIR`.

**Fix:** move `gws`'s state into the workspace and avoid the keyring. Two clean
options.

#### Option A — credentials file (recommended: non-interactive, no keyring)

Priority-2 credentials bypass the keyring entirely. One-time, **outside valet**:

```bash
WS="$HOME/path/to/workspace"                 # your [exec].workspace
mkdir -p "$WS/.config/gws"

# log in (interactive) into the workspace config dir, minimal scopes
GOOGLE_WORKSPACE_CLI_CONFIG_DIR="$WS/.config/gws" gws auth login -s gmail,drive

# export a portable, keyring-free credentials file into the workspace
GOOGLE_WORKSPACE_CLI_CONFIG_DIR="$WS/.config/gws" \
  gws auth export --unmasked > "$WS/.config/gws/credentials.json"
```

Then in `~/.valet/config.toml` (`$VALET_WORKSPACE` is set on every command and
expands to the workspace root):

```toml
[exec.env]
GOOGLE_WORKSPACE_CLI_CONFIG_DIR       = "$VALET_WORKSPACE/.config/gws"
GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE = "$VALET_WORKSPACE/.config/gws/credentials.json"
```

Now, in the REPL under the sandbox:

```
valet> gws gmail users messages list --params '{"userId": "me"}' --format table
```

#### Option B — file keyring backend

Keep `gws`'s encrypted-credentials flow, but put the encryption key in the
workspace instead of the Keychain. One-time, **outside valet**:

```bash
GOOGLE_WORKSPACE_CLI_CONFIG_DIR="$WS/.config/gws" \
GOOGLE_WORKSPACE_CLI_KEYRING_BACKEND=file \
  gws auth login -s gmail,drive
```

```toml
[exec.env]
GOOGLE_WORKSPACE_CLI_CONFIG_DIR      = "$VALET_WORKSPACE/.config/gws"
GOOGLE_WORKSPACE_CLI_KEYRING_BACKEND = "file"
```

#### Option C — service account (Workspace domains)

No login, no keyring, no browser. Drop the service-account JSON in the workspace
and point at it:

```toml
[exec.env]
GOOGLE_WORKSPACE_CLI_CONFIG_DIR       = "$VALET_WORKSPACE/.config/gws"
GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE = "$VALET_WORKSPACE/.config/gws/service-account.json"
```

### Gotcha 3 — Network must be allowed

`gws` talks to Google's APIs, so the sandbox profile must permit network (the
shipped `contrib/sandbox-exec/workspace.sb` allows it by default). If you
uncommented `(deny network*)`, `gws` will fail DNS/HTTPS.

---

## 6. Security notes

- **Credentials in the workspace are readable by any command valet runs.** That
  is the price of the sandbox seeing them. valet redacts known secret *values*
  from output, but the OAuth material itself is broad Workspace access
  (Gmail, Drive, …). Prefer a **separate, minimal-scope** login or a scoped
  **service account** for the agent — not your personal `gws` credentials.
- Log in with only the scopes the agent needs (`-s gmail,drive`), not the
  `recommended` preset.
- `gws` can pipe API responses through **Model Armor** to scan for prompt
  injection before they reach an agent (`--sanitize <template>`, or
  `GOOGLE_WORKSPACE_CLI_SANITIZE_TEMPLATE` / `_MODE`). That is complementary to
  valet's output redaction and worth enabling for untrusted mailboxes.

---

## 7. Troubleshooting (valet-specific)

| Symptom | Cause | Fix |
|---------|-------|-----|
| `error[discovery]: File exists (os error 17)`, `exit 4` | Sandbox blocks the discovery cache under `~/.config/gws` | Set `GOOGLE_WORKSPACE_CLI_CONFIG_DIR` into the workspace (§5) |
| Auth error, `exit 2`, under sandbox but fine unsandboxed | Keyring (Keychain) / credential files blocked | Use a credentials file (Option A) or `KEYRING_BACKEND=file` (Option B) |
| `gws auth login` hangs / no browser in the REPL | Interactive flow, valet is non-interactive | Run auth outside valet (§5, Gotcha 1) |
| DNS / connection failures | `(deny network*)` in the sandbox profile | Allow network (§5, Gotcha 3) |
| "Access blocked" during login | Account not in OAuth **Test users** | Add your email to Test users |
| Consent error / too many scopes | Unverified app capped at ~25 scopes | `gws auth login -s <services>` |

## General pattern for other CLIs

Any tool that stores state under `$HOME` hits Gotcha 2. The recipe generalizes:

1. Find the tool's config/cache override (`--help`; an env var or `--config-dir`).
2. Point it at `$VALET_WORKSPACE/...` via `[exec.env]`.
3. Do interactive setup (login, keygen) **outside** valet, once, into that path.
4. Avoid the macOS Keychain — prefer a file-based credential store.
