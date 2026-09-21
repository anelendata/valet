# Release history

Notable changes per release. Published to PyPI as
[`valet-ai`](https://pypi.org/project/valet-ai/).

## Unreleased

- **Added:** `--stdin-file FILE` on `run` and `sh` feeds a command its input as
  text (UTF-8, 1 MiB cap), and `valet sh -` reads the command line itself from
  stdin. Both exist because a `sh` command line is parsed twice — by the client's
  shell and by the host's — which is where quotes, `<`, `>` and heredocs get
  mangled. `valet run --stdin-file ./plan.py -- python3 -` runs a local script on
  the host without writing it there and without either shell touching it, and
  `valet sh - <<'VALET'` delivers a command line with no parsing at all. The
  audit records `stdin_bytes`, never the content.
- **Fixed:** a command no longer inherits the daemon's stdin. It used to, so on a
  daemon started in a terminal any command that reads stdin blocked on the
  operator's keyboard and returned what they typed to the agent; a command with
  no input now sees EOF immediately.

- **Added:** `valet files patch <path>` edits a workspace file in place on the
  host, so a small edit costs one round trip instead of pull-edit-push-verify.
  Edits are literal `--old`/`--new` text (or `--edits FILE` for a batch, plus
  `--append` for a trailing row) and each carries the number of occurrences it
  expects, default exactly one: if a count is off, nothing is written, so a
  drifted or ambiguous anchor fails loudly instead of editing the wrong line.
  The reply is a unified diff. A patch obeys every `files push` destination rule
  (it may not edit a secret source, a `deny_read` path, VCS internals, valet
  state, or a program-shadowing name) and the pull-side identity checks (not a
  secret file by inode, nor a copy of one); binary and setuid/setgid files are
  refused, other permission bits are kept, and a file that changed between the
  read and the write is refused rather than silently reverted. `--context N`
  returns unseen lines around each hunk, so it needs `[policy].allow_pull`
  (`allow_pull_lan` off-machine) and passes those lines through the pull content
  gate — checked before the write, so a refusal leaves the file untouched.
- **Added:** `valet files pull <src> [dst|-]` downloads a workspace file. Off by
  default (`[policy].allow_pull`), with separate opt-ins for WebSocket clients
  (`allow_pull_lan`) and binary files (`allow_pull_binary`). A pulled file is not
  redacted, so the host refuses it instead whenever redaction would matter: the
  push path rules (secret sources, `deny_read`, VCS internals, valet state), a
  symlink swap (`O_NOFOLLOW` walk), a hard link, a FIFO/device, the secret file
  itself by inode or a byte-for-byte copy of any secret file, text the workspace
  redactor would change (the error names the category, never the value), and
  binary content unless enabled — which is then still searched for known secret
  values and key shapes. Every pull is audited with path, size, and sha256.
- **Fixed:** the redactor no longer appends each command's env values to the
  secret index's cached value list, which grew with every command.
- **Security:** `valet files push` now refuses destinations that let an upload
  tamper with credentials or smuggle in code the host will run: secret sources
  (`redaction.secret_file_paths`), `policy.deny_read` paths, VCS internals
  (`.git/`, `.hg/`, `.svn/` — hooks and `core.*` config execute on the next
  trusted `git`), valet's own state (`~/.valet`, the socket, the audit log, the
  sandbox profile, any `config.toml`), a workspace `bin/` file that would shadow a
  program on PATH, and any file named like an `allow_exec` entry (so
  `valet run -- tools/aws` cannot pass an `aws` allowlist). Checks are
  case-insensitive and applied to both the lexical and symlink-resolved path.
- **Security:** a non-empty `allow_exec` no longer trusts a program's basename
  alone. A path-qualified argv[0] (`tools/aws`, `./aws`, `/usr/bin/git`, or the
  program after an `env` wrapper) is refused unless it is the same file its bare
  name finds on the host `PATH` (the `[exec].env` PATH, else the daemon's) and
  it lies outside the workspace, so a workspace file renamed to an allowed name
  (`git mv tools/x tools/aws`) or dropped in an agent-writable host directory
  such as `/tmp` cannot run as `aws`. A path with `$`, `~`, or glob characters
  is refused, and so is any path when no workspace is configured. The workspace
  `bin/` is admin-trusted and runs by bare name only; `bin/aws` as a path is
  refused like any other workspace file.
- **Security:** a request may no longer set environment variables that change
  which code runs, in any policy mode: `PATH`, `HOME`, `XDG_CONFIG_HOME`,
  `SHELL`, the dynamic loader (`LD_*`, `DYLD_*`), shell startup (`ENV`,
  `BASH_ENV`, `ZDOTDIR`, `PROMPT_COMMAND`, …), interpreter hooks (`PYTHONPATH`,
  `PYTHONSTARTUP`, `NODE_OPTIONS`, `PERL5OPT`, `RUBYOPT`, `JAVA_TOOL_OPTIONS`,
  …), git (`GIT_CONFIG*`, `GIT_EXEC_PATH`, `GIT_DIR`, `GIT_SSH_COMMAND`, …),
  `NPM_CONFIG_*`, and helper programs tools exec (`PAGER`, `EDITOR`,
  `LESSOPEN`, …). This covers `--env`, a `NAME=value` argv prefix,
  `env NAME=value`, and in shell mode a leading assignment, `NAME+=`, or
  `export`/`declare`. Matching is case-insensitive. The host admin can still set
  any of them in `[exec].env`. **Breaking:** a per-command `PYTHONPATH=src …` or
  `--env PATH=…` is now refused; move it to `[exec].env`.
- **Security:** the push path is no longer `$VAR`-expanded on the host (which
  could echo host environment values back in the returned path), the write walks
  the destination with `O_NOFOLLOW` so a directory swapped for a symlink after the
  check cannot redirect it outside the workspace, and pushed permission bits are
  capped at `0755` (no setuid/setgid/sticky, no group/other write). A refused push
  is audited with the requested path.

## 0.0.12 — 2026-09-05

- **Added:** `valet files push <src> <dst>` uploads a local file into a
  workspace over the existing UDS/WebSocket transport. Bytes are base64-encoded
  (the JSON transport carries only text, so any file type works) and written to a
  workspace-relative destination. The destination is jailed to the workspace root
  — `..` and symlinks are resolved before the containment check, `/` and `~` mean
  the root (never the host filesystem), and `config.toml` stays protected — so a
  push can never write outside the workspace. Deliberately one-directional: there
  is no pull/read op, so this adds a write channel without opening a path for host
  data to leave. The whole file travels in one message, capped at 8 MiB (the
  transport's per-frame limit); the source's permission bits are preserved (so a
  pushed `bin/` tool stays executable), overwrite is the default with
  `--no-clobber` to refuse it, and the client verifies the host's sha256 against
  the local file to catch a corrupted transfer. Every push is audited with its
  destination path and byte count.

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
