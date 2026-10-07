# Run Node.js, npm, and npx in a workspace

Run `node`, `npm`, and `npx` through valet — `valet run`, `valet sh`, or the
REPL — so an agent can install and use npm packages inside a workspace.

valet does not block npm (it is not a built-in `deny_exec` ban, and network is
allowed by default), but the OS sandbox shapes how Node has to be set up:

- **Only the workspace is readable under `/Users`.** The sandbox profile
  (`valet/workspace.sb`) denies reads of every home directory except the
  workspace. A Node installed under `~/` — nvm, fnm, volta, asdf — cannot be
  found or loaded.
- **Writes are jailed to the workspace** (plus the temp directories). npm's
  default cache (`~/.npm`) and global prefix are outside it.
- **A request cannot set `PATH`, `HOME`, or `NPM_CONFIG_*`** (see
  [`[exec.env]`](CONFIGURATION.md#execenv-and-valet_workspace)). Only the
  `[exec.env]` table in `~/.valet/config.toml` can.

Pick the section that matches how Node is installed on the host:

- [Method A: Node outside your home (Homebrew, installer)](#method-a-node-outside-your-home-homebrew-installer)
- [Method B: Node from nvm](#method-b-node-from-nvm)

Then follow [Install and run packages](#install-and-run-packages), which is the
same for both.

## The symptom

If Node lives under your home directory (the usual nvm setup), every Node
command fails inside the sandbox:

```
$ valet run -- npm init -y
sandbox-exec: execvp() of 'npm' failed: No such file or directory
```

`which npm` in your own terminal finds it (e.g.
`~/.nvm/versions/node/v24.20.0/bin/npm`), but the sandbox cannot see that path.

## Method A: Node outside your home (Homebrew, installer)

A Node installed to a system location is readable inside the sandbox:

| Install | Location |
|---|---|
| Homebrew (Apple silicon) | `/opt/homebrew/bin/node` |
| Homebrew (Intel) | `/usr/local/bin/node` |
| nodejs.org `.pkg` installer | `/usr/local/bin/node` |

```sh
brew install node
```

This can coexist with nvm — your own shell keeps using nvm's Node; valet uses
the system one.

`valet serve` passes its own `PATH` to commands, so start it from a shell where
`which node` finds the system Node, or pin `PATH` in the config so it doesn't
depend on how the daemon was launched. Point npm's cache into the workspace at
the same time:

```toml
# ~/.valet/config.toml
[exec.env]
PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
npm_config_cache = "$VALET_WORKSPACE/.npm-cache"
```

`[exec.env]` values expand only `$VALET_WORKSPACE`, not `$PATH`, so spell the
full `PATH` out. valet still prepends `<workspace>/bin` to it. To scope this to
one workspace, put the same keys under `[workspaces.<id>.exec.env]` instead.
`valet serve` hot-reloads the change.

Check:

```sh
valet run -- node --version
valet run -- npm --version
```

## Method B: Node from nvm

nvm installs each version under `~/.nvm/versions/node/<version>`, which the
sandbox cannot read. Symlinking it into the workspace does not help: the
sandbox checks the resolved path, which is still under `~/.nvm`. Instead,
**copy** the version you want into the workspace:

```sh
cp -R ~/.nvm/versions/node/v24.20.0 "$VALET_WORKSPACE/tools/node"
```

(`nvm which current` prints the active version's `node`; its grandparent
directory is the one to copy.)

Then put its `bin` on `PATH` via `[exec.env]`:

```toml
# ~/.valet/config.toml
[exec.env]
PATH = "$VALET_WORKSPACE/tools/node/bin:/usr/local/bin:/usr/bin:/bin"
npm_config_cache = "$VALET_WORKSPACE/.npm-cache"
```

Check:

```sh
valet run -- node --version       # -> v24.20.0
valet run -- npm --version
```

### Why `PATH`, not a `bin/` wrapper?

For Python, a wrapper script in `<workspace>/bin` is enough (see
[workspace-python-venv.md](workspace-python-venv.md)). For npm it is not:
`npm` and `npx` are symlinks to JavaScript files whose first line is

```
#!/usr/bin/env node
```

so they look up `node` on `PATH` themselves. A `bin/npm` wrapper would start
`npm-cli.js`, which then fails to find `node`. Putting `tools/node/bin` on `PATH`
makes `node`, `npm`, `npx`, and anything installed with `npm install -g` all
resolve.

### Upgrading

To switch versions, replace the copy (`rm -rf tools/node` then copy the new
version in). The `PATH` entry stays the same. Globally installed packages live
inside the copy, so reinstall them afterwards.

## Install and run packages

### Local install (recommended)

From the workspace root:

```sh
valet run -- npm init -y
valet run -- npm install cowsay
```

Packages land in `<workspace>/node_modules`. Run them with `npx`, which finds
the local copy first:

```sh
valet run -- npx cowsay hello
```

### One-off with npx

`npx` downloads a package it can't find locally into the npm cache (which
`npm_config_cache` points into the workspace) and runs it:

```sh
valet run -- npx -y cowsay hello
```

### Call a package by name

valet prepends `<workspace>/bin` to `PATH`, so a small wrapper makes a locally
installed CLI callable without `npx`:

```sh
cat > bin/cowsay <<'EOF'
#!/bin/sh
here=$(cd "$(dirname "$0")" && pwd)
exec "$here/../node_modules/.bin/cowsay" "$@"
EOF
chmod +x bin/cowsay
```

```sh
valet run -- cowsay hello
```

Keep the `#!/bin/sh` line — without it `valet run` (argv mode, no shell) fails
with `Exec format error`. See
[Why the wrapper needs `#!/bin/sh`](workspace-python-venv.md#why-the-wrapper-needs-binsh).

### Global install (`-g`)

- **Method A:** `npm install -g` writes to the system prefix (e.g.
  `/opt/homebrew/lib/node_modules`), outside the workspace, so the sandbox and
  `enforce_workspace_writes` refuse it. Install locally instead.
- **Method B:** npm's global prefix is the Node directory itself, which is now
  `tools/node` inside the workspace, so `npm install -g <pkg>` works and the
  package's command lands in `tools/node/bin`, already on `PATH`.

## Notes

- **Cache without editing config.** Instead of `npm_config_cache` in
  `[exec.env]`, you can put `cache=.npm-cache` in a `.npmrc` next to your
  `package.json`. It only applies when npm runs within that project.
- **`allow_exec`.** If `[policy].allow_exec` is non-empty (default-deny), add
  `node`, `npm`, `npx`, and any wrapper names from `bin/`. Make sure `npm` is not
  in `deny_exec`.
- **Install scripts run with valet's access.** `npm install` executes each
  package's `preinstall`/`postinstall` scripts on the host side of valet, where
  credentials are reachable. Use `npm install --ignore-scripts` for packages you
  don't trust.
- **Network.** npm needs the registry. If you uncommented `(deny network*)` in
  the sandbox profile, installs fail; already-installed packages still run.
- `valet doctor` shows whether the sandbox profile is active and whether network
  is allowed.
