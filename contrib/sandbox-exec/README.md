# OS-level sandbox prototype (macOS `sandbox-exec`)

Confines a command to a single workspace directory using the macOS kernel
sandbox. You can use it two ways:

- **With `valet serve`** — set `[exec].sandbox_profile` in `config.toml` to the
  path of `workspace.sb`; valet then runs every command as
  `sandbox-exec -D WORKSPACE=<workspace> -f <profile> <command>`. See
  "Use it with valet" below.
- **Standalone** — the `run-sandboxed.sh` / `demo.sh` scripts here let you try
  the boundary directly, without valet.

## Why this exists

Valet's `[policy]` layer (deny lists, `deny_read_paths`, `enforce_workspace_*`)
is **best-effort static analysis of the command line**. It catches the obvious
reveals, but a determined client can bypass it — computed paths, variable
expansion, `eval`, base64, or a tool that opens a file it never names. The audit
log made this concrete: with the workspace jail off, a client read the whole
home directory with plain `ls -la /Users/<you>`.

The only thing that stops a *determined* reader is an **OS-level boundary**. This
prototype is that boundary on macOS: the kernel denies file reads/writes outside
the workspace regardless of what the command attempts internally. Network is
**allowed by default** (valet's job is running cloud tools like `aws`/`handoff`,
which need it); a commented `(deny network*)` line blocks it for offline-only
setups.

## Files

- `workspace.sb` — the Seatbelt (SBPL) profile. Uses `(allow default)` as the
  base (so programs launch reliably), then **blocks reads** of home directories,
  the login keychain, and root's home; and **jails writes** to the workspace and
  scratch temp. Network is left **allowed** (cloud tools need it) with a
  commented `(deny network*)` line to block it. This trade-off is deliberate —
  see "Caveats" for why a stricter `(deny default)` profile aborts programs.
- `run-sandboxed.sh` — resolves the workspace to an absolute path and launches
  `sandbox-exec -D WORKSPACE=... -f workspace.sb <command>`.
- `demo.sh` — creates a throwaway workspace and shows workspace access
  succeeding while home-dir reads, `~/.aws` reads, and outside writes all fail
  at the kernel (network is allowed by default).

## Try it

```bash
chmod +x contrib/sandbox-exec/run-sandboxed.sh contrib/sandbox-exec/demo.sh
contrib/sandbox-exec/demo.sh
```

Or directly:

```bash
# Succeeds — inside the workspace:
contrib/sandbox-exec/run-sandboxed.sh ~/work ls -la .

# Denied by the kernel — escapes the workspace:
contrib/sandbox-exec/run-sandboxed.sh ~/work sh -c 'cat ~/.aws/credentials'
contrib/sandbox-exec/run-sandboxed.sh ~/work sh -c 'ls -la /Users/$(whoami)'
```

## Caveats (read before trusting it)

- **macOS only.** On Linux the equivalent is `bubblewrap`/`nsjail` or a
  container with mount + network namespaces and seccomp.
- **`sandbox-exec` is deprecated by Apple.** It still works on current macOS and
  is widely used, but SBPL is undocumented and version-sensitive.
- **Reads outside `/Users` are still allowed.** The profile blocks the sensitive
  spots (home dirs, keychain, root) but not all of `/etc`, `/Library`, `/opt`,
  `/System`, `/usr`. If you want a true "only the workspace is readable" jail,
  that needs a `(deny default)` profile — which reliably **aborts programs at
  launch (exit -6 / SIGABRT)** unless you painstakingly enumerate every path the
  dynamic linker and each tool needs, per macOS version. That is why the shipped
  profile uses `(allow default)` with carve-outs. To attempt the strict variant,
  start from `(deny default (with report))`, run `valet doctor` (or the demo)
  repeatedly, and add each path the Console reports as denied until programs
  launch. Add more `(deny file-read* ...)` carve-outs (e.g. `/opt`, extra
  `/Library` subpaths) to tighten the shipped profile without that risk.
- **Network is allowed by default.** Cloud tools need it, and sandbox-exec
  can't filter by hostname (it's all-or-nothing), so a command *can* exfiltrate
  over the network. Uncomment `(deny network*)` for an offline-only jail.
- **Not a full jail.** This confines file access. It does not restrict
  CPU/memory, IPC, network (by default), or every mach service, and scratch
  temp dirs are writable. Treat it as a strong containment layer, not a VM.

## Use it with `valet serve`

Do **not** run the daemon itself under the sandbox — it needs to read
`~/.aws/credentials` (for redaction), read its config, and write
`~/.valet/audit.jsonl`, all outside the workspace. Valet wraps each *child
command* instead, via an opt-in config flag:

1. Copy the profile somewhere stable (not inside the workspace, so a client
   cannot edit it):

   ```bash
   cp contrib/sandbox-exec/workspace.sb ~/.valet/workspace.sb
   ```

2. In `config.toml`, set the workspace and point at the profile:

   ```toml
   [exec]
   workspace = "~/work"
   sandbox_profile = "~/.valet/workspace.sb"
   ```

3. Start the daemon normally:

   ```bash
   valet serve
   ```

Every command now runs as
`sandbox-exec -D WORKSPACE=<workspace> -f <profile> <command>`. The policy layer
still runs first (it analyzes the *real* command, not the wrapper); the sandbox
is the backstop that holds even when static analysis is fooled. On a non-macOS
host, or without `sandbox-exec` on PATH, commands fail to launch — the flag is
macOS-only by design.

Implementation seam: `Broker._maybe_sandbox` in `valet/broker.py` builds the
wrapper; the executor is unchanged.
