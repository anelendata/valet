# Separate credentials from your workspaces

By default, the tools an agent drives through valet read *your* personal
credentials — `~/.aws`, `~/.config/gh`, `~/.ssh`, and so on. That is your whole
account's worth of access. This guide shows how to give **each workspace its own
scoped credential set** instead, so an agent only ever uses least-privilege
credentials dedicated to that workspace, never your personal ones.

The mechanism is one valet feature: every command runs with `VALET_WORKSPACE` set
to the workspace root, and `[exec.env]` in the config lets you point each tool's
config/credential path *into* the workspace.

- [When to use this](#when-to-use-this)
- [The trade-off — read this first](#the-trade-off--read-this-first)
- [How it works](#how-it-works)
- [Step by step](#step-by-step)
- [Environment variables by tool](#environment-variables-by-tool)
- [Blunt option: relocate `HOME` / `XDG_CONFIG_HOME`](#blunt-option-relocate-home--xdg_config_home)
- [Verify](#verify)

## When to use this

Reach for per-workspace credentials when you want:

- **Least privilege per agent** — a workspace's AWS profile, GitHub token, or
  git identity can be scoped to exactly what that agent needs, so a mistake or a
  hijacked command can't reach the rest of your account.
- **Clean multiple identities** — different workspaces use different AWS
  profiles, GitHub accounts, or commit identities without colliding.
- **OS-sandbox compatibility** — with the macOS sandbox enabled (see
  [SANDBOX_HARDENING.md](SANDBOX_HARDENING.md)), reads of `~` are blocked, so a
  tool hardcoded to `~/.aws` can't reach it. Pointing it into the workspace makes
  it work with scoped credentials.

## The trade-off — read this first

Anything **inside** a workspace is readable by the agent — the workspace *is* the
agent's tree. So workspace-local credentials are **not** the place for your most
powerful keys. Put only **least-privilege, revocable, workspace-scoped**
credentials there. valet still redacts their *values* from command output (keep
`secret_file_paths` covering the workspace's config dir — the shipped default
already includes the relative `.config/**` pattern), but the files themselves are
reachable by the agent.

Two models, pick per credential:

| | Host-side (valet default) | Workspace-local (this guide) |
|---|---|---|
| Where the file lives | outside the workspace (`~/.aws`, …) | inside it (`$VALET_WORKSPACE/.config/aws`, …) |
| Can the agent read the file? | **No** — sandbox denies it | Yes — it's in the agent's tree |
| Values redacted in output? | Yes | Yes |
| Best for | a single powerful credential you want fully hidden | scoped, per-workspace, least-privilege credentials |

Use host-side when you want to *hide* a high-value key. Use workspace-local when
you want *isolation and least privilege* — a dedicated credential the agent may
touch but that can do little harm.

## How it works

Every command valet runs gets `VALET_WORKSPACE` = the real workspace root in its
environment (valet also sets `PWD` and prepends `<workspace>/bin` to `PATH`). An
`[exec.env]` table sets default environment variables for **every** command,
expanding `$VALET_WORKSPACE`; a per-command value (inline `NAME=value` or
`--env`) still wins. See
[Configuration → `[exec.env]`](CONFIGURATION.md#execenv-and-valet_workspace).

So you redirect each tool from its default home location to a workspace-local
one:

```toml
[exec.env]
AWS_SHARED_CREDENTIALS_FILE = "$VALET_WORKSPACE/.config/aws/credentials"
AWS_CONFIG_FILE             = "$VALET_WORKSPACE/.config/aws/config"
GIT_CONFIG_GLOBAL           = "$VALET_WORKSPACE/.config/git/.gitconfig"
GH_CONFIG_DIR               = "$VALET_WORKSPACE/.config/gh"
GOOGLE_WORKSPACE_CLI_CONFIG_DIR      = "$VALET_WORKSPACE/.config/gws"
GOOGLE_WORKSPACE_CLI_KEYRING_BACKEND = "file"
```

Put this under the top-level `[exec.env]` to apply it to every workspace, or
under `[workspaces.<id>.exec.env]` to scope it to one workspace (see
[per-workspace overrides](CONFIGURATION.md#workspaces-and-per-workspace-overrides)).
Because the paths are relative to `$VALET_WORKSPACE`, the *same* lines give each
workspace its *own* credentials.

## Step by step

1. **Create the credential directories inside the workspace.** They aren't part
   of the standard scaffold, so make them yourself:

   ```bash
   ws=~/ai-workspace
   mkdir -p "$ws"/.config/{aws,git,gh,gws} "$ws"/.ssh
   chmod 700 "$ws/.ssh"
   ```

2. **Point the tools at them** with `[exec.env]` in `~/.valet/config.toml` (the
   block above). Restart or let `valet serve` hot-reload the config.

3. **Populate the directories with least-privilege credentials** — a scoped IAM
   user/role in `aws/credentials`, a fine-grained GitHub token in `gh`, a
   dedicated commit identity in `git/.gitconfig`, a per-workspace SSH key in
   `.ssh/`, a service account for `gws`. Grant each only what that workspace's
   agent needs.

4. **Confirm redaction covers them.** The default `secret_file_paths` includes
   the relative pattern `.config/**` (and `.ssh/**`), which resolves against each
   command's cwd and so matches `$VALET_WORKSPACE/.config/**`. If you changed
   that list, make sure your workspace credential dirs are still covered so their
   values are masked from output. See
   [pattern matching](CONFIGURATION.md#how-secret_file_paths-patterns-are-matched).

## Environment variables by tool

The general rule: find the tool's "config file" or "config directory" environment
variable and point it into `$VALET_WORKSPACE`. Common ones:

| Tool | Variable(s) | Points at |
|---|---|---|
| AWS CLI | `AWS_SHARED_CREDENTIALS_FILE`, `AWS_CONFIG_FILE` | credential + config files |
| Git | `GIT_CONFIG_GLOBAL` | the global `.gitconfig` file |
| GitHub CLI (`gh`) | `GH_CONFIG_DIR` (and `GH_TOKEN` for a bare token) | config directory |
| SSH (via Git) | `GIT_SSH_COMMAND = "ssh -F $VALET_WORKSPACE/.ssh/config -i $VALET_WORKSPACE/.ssh/id_ed25519"` | key + config for git remotes |
| Google Workspace CLI (`gws`) | `GOOGLE_WORKSPACE_CLI_CONFIG_DIR`, `GOOGLE_WORKSPACE_CLI_KEYRING_BACKEND = "file"`, `GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE` | config dir + on-disk keyring ([details](google-workspace-cli.md)) |
| gcloud | `CLOUDSDK_CONFIG` | config directory |
| kubectl | `KUBECONFIG` | kubeconfig file |
| Docker | `DOCKER_CONFIG` | config directory |
| npm | `NPM_CONFIG_USERCONFIG` | `.npmrc` file |

Plain `ssh` (outside Git) has no config-dir env var; pass `-F`/`-i` explicitly, or
use the `HOME` override below. When a tool isn't listed, check its docs for an
`*_CONFIG*`, `*_HOME`, or XDG variable — the same pattern applies.

## Blunt option: relocate `HOME` / `XDG_CONFIG_HOME`

Instead of one variable per tool, you can move the *whole* config root into the
workspace:

```toml
[exec.env]
XDG_CONFIG_HOME = "$VALET_WORKSPACE/.config"   # XDG-compliant tools
# HOME = "$VALET_WORKSPACE"                     # catch-all — see caveats
```

- **`XDG_CONFIG_HOME`** relocates every tool that honors the XDG spec (git, gh,
  and many others) in one line. Tools that ignore XDG (AWS CLI, ssh) still need
  their own variable.
- **`HOME`** catches almost everything, since `~` expands to it — but it's a big
  hammer: tools also write caches, state, and history under `$HOME`, some resolve
  paths at startup, and anything expecting your real home may misbehave. Test
  before relying on it, and prefer per-tool variables when you can.

## Verify

Check that a command sees the workspace paths, not your home:

```bash
valet run -- sh -c 'echo "$AWS_SHARED_CREDENTIALS_FILE"'
# -> /…/ai-workspace/.config/aws/credentials

valet run -- aws sts get-caller-identity     # should use the scoped identity
```

In the REPL, `:secrets` reports how many secret values valet is redacting for the
current directory — a quick confirmation that your workspace credential files are
being picked up for masking.
