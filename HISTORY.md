# Release history

Notable changes per release. Published to PyPI as
[`valet-ai`](https://pypi.org/project/valet-ai/).

## 0.0.11 — 2026-08-12

- **Improved:** the per-workspace secret index is now invalidated by directory
  mtime instead of a 5-second TTL, so a large workspace no longer re-walks the
  whole tree on nearly every command. A brand-new secret file is caught on the
  next command — with no polling window — via its parent directory's mtime; a
  300-second backstop covers filesystems that don't update directory mtimes.
- **Fixed:** binary files (images, archives) under a broad secret-source glob
  (e.g. `**/.config/**`) are no longer indexed and decoded into junk redaction
  values. valet skips any file with a NUL byte in its first 8 KB — a
  text-vs-binary test, so unicode-containing secret files are still indexed.
- **Added:** `valet doctor redact` inspects the redaction index for a workspace
  (which source files contribute which values; plaintext hidden unless
  `--show-values`), and `valet doctor redact --bench` benchmarks the index
  build — splitting the tree-walk cost from per-file parsing and breaking it down
  by directory to find a slow workspace's hot subtree or file.
- Docs: note that a broad `**/.config/**`-style glob can sweep in app cache files
  (e.g. `~/.config/<tool>/cache/*.json`), whose long contents then over-mask
  output; `deny_read` the cache subtree.

## 0.0.10 — 2026-08-12

- **Fixed:** REPL Tab-completion is fast again. Every request — including
  completion — was rebuilding the whole-workspace secret index while auditing;
  read-only ops now use a path-only redactor and skip the scan entirely.
- **Added:** files matched by `policy.deny_read` are excluded from the redaction
  index. A file that can't be read needs no redacting, and this keeps a big
  capture file (e.g. a multi-MB `.har`) from over-masking unrelated output. Put a
  file in `secret_file_paths` (redact it) *or* `deny_read` (never read it), not
  both.
- Docs: a new redaction internals reference,
  [`docs/redaction-internals.md`](https://github.com/anelendata/valet/blob/main/docs/redaction-internals.md).

## 0.0.9 — 2026-08-11

- **Fixed:** argv-mode commands now resolve the first `PATH` match before
  launching, so shebangless workspace-local scripts consistently use the shell
  fallback instead of being skipped for a later system binary on Linux.
- **Fixed:** relative secret-file patterns are resolved from the workspace root,
  so secret redaction remains consistent no matter which subdirectory a command
  runs in.
- **Improved:** the secret redaction index is warmed and cached per workspace,
  with `pyahocorasick` selected automatically when available for faster
  multi-pattern masking.
- CI now runs the test suite both with and without optional speedups installed.

## 0.0.8 — 2026-08-11

- Docs: fixed broken doc links on the PyPI project page. Five README links added
  in 0.0.7 (the Configuration and separate-credentials references) were relative
  paths, which PyPI can't resolve; they now use absolute GitHub URLs like the
  rest of the README.

## 0.0.7 — 2026-08-11

- **Added:** after you enable the LAN host, `valet init` now asks whether another
  computer on your LAN should be able to connect — setting `[host].listen` to
  `0.0.0.0:8766` on yes, or leaving it at `127.0.0.1:8766` (this machine only).
  Either way, you can change it later in the `[host]` section.
- **Fixed:** the runtime version (`__version__` and the REPL banner) was out of
  sync with the published package version; both now report the release version.
- Docs: added a full command reference (`docs/COMMANDS.md`) and a complete
  configuration reference (`docs/CONFIGURATION.md`, extracted from the README as
  a per-key guide); added a guide to separating credentials per workspace
  (`docs/separate-creds.md`); reworked "Guardrails" into "Agent orientation and
  guardrails", documenting how a bare `valet` / `valet status` self-orients an
  agent; and streamlined the Install & run section and the introduction.

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
