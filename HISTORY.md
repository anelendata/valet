# Release history

Notable changes per release. Published to PyPI as
[`valet-ai`](https://pypi.org/project/valet-ai/).

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
