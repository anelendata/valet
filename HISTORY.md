# Release history

Notable changes per release. Published to PyPI as
[`valet-ai`](https://pypi.org/project/valet-ai/).

## 0.0.6 — 2026-08-10

- Docs: fixed broken links on the PyPI project page. README links to `docs/*`
  and the bundled example config now use absolute GitHub URLs, since PyPI can't
  resolve relative repo paths.

## 0.0.5 — 2026-08-10

- **Fixed:** normal client commands (`valet`, `valet status`, `valet run`)
  crashed with an uncaught `PermissionError` inside a hardened agent sandbox that
  denies `stat()` on `~/.valet/config.toml`. Config discovery now treats a denied
  stat as "not visible", and local (UDS) client mode falls back to the default
  broker socket, so an unprivileged client connects without needing to read the
  host config. Host/admin subcommands stay blocked by the sandbox.
- Added `valet clients block <id>` / `unblock <id>` to temporarily deny a client
  without deleting its key, and documented `valet clients remove <id>`.
- Added `valet workspaces remove <id>` (removes the config entry; leaves the
  directory on disk for you to delete).
- `valet doctor` collapses the home prefix to `~` in reported paths.
- Docs: a sandbox-hardening section on protecting valet's own config and admin
  subcommands, ready-to-copy `contrib/claude-code` and `contrib/codex` configs,
  and an Install & run refresh for the PyPI release.

## 0.0.4 — 2026-08-10

- `valet workspaces list` now collapses the home prefix to `~` in local mode, so
  it no longer prints your full home path / username. Paths outside home are
  shown as-is; the remote lister already discloses no path at all.

## 0.0.3 — 2026-08-10

- Fixed: the README diagram did not render on PyPI. Replaced the relative-path
  SVG (which PyPI's image proxy can't display) with an absolute-URL PNG.

## 0.0.2 — 2026-08-10

- Fixed: `valet init` failed with "cannot find config.example.toml" when
  installed from PyPI. The example config and the macOS sandbox profile are now
  shipped inside the package so `init` works from an installed wheel.

## 0.0.1 — 2026-08-10

- Initial release: a local secret-redacting command runner. Runs a command and
  returns its output with known and suspected secret values scrubbed. Includes
  workspaces with a path jail, an execution policy (`allow_exec` / `deny_exec` /
  `deny_read`), per-command and per-directory secret redaction, an audit log, an
  interactive redacting REPL, an optional trusted-LAN WebSocket host, and an
  optional macOS OS sandbox.
