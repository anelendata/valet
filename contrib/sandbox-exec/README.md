# OS-level sandbox prototype (macOS `sandbox-exec`)

A **standalone prototype** that confines a command to a single workspace
directory using the macOS kernel sandbox. It is deliberately **not wired into
valet** — it lives here in `contrib/` so you can evaluate the approach without
changing valet's behavior.

## Why this exists

Valet's `[policy]` layer (deny lists, `deny_read_paths`, `enforce_workspace_*`)
is **best-effort static analysis of the command line**. It catches the obvious
reveals, but a determined client can bypass it — computed paths, variable
expansion, `eval`, base64, or a tool that opens a file it never names. The audit
log made this concrete: with the workspace jail off, a client read the whole
home directory with plain `ls -la /Users/<you>`.

The only thing that stops a *determined* reader is an **OS-level boundary**. This
prototype is that boundary on macOS: the kernel denies file reads/writes outside
the workspace and denies all network access, regardless of what the command
attempts internally.

## Files

- `workspace.sb` — the Seatbelt (SBPL) profile. Denies everything by default,
  then allows: process exec, read-only access to system locations needed to run
  binaries, full read/write **only** under `WORKSPACE` (and system temp dirs),
  and **no network**.
- `run-sandboxed.sh` — resolves the workspace to an absolute path and launches
  `sandbox-exec -D WORKSPACE=... -f workspace.sb <command>`.
- `demo.sh` — creates a throwaway workspace and shows workspace access
  succeeding while home-dir reads, `~/.aws` reads, outside writes, and network
  all fail at the kernel.

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
contrib/sandbox-exec/run-sandboxed.sh ~/work sh -c 'curl https://example.com'
```

## Caveats (read before trusting it)

- **macOS only.** On Linux the equivalent is `bubblewrap`/`nsjail` or a
  container with mount + network namespaces and seccomp.
- **`sandbox-exec` is deprecated by Apple.** It still works on current macOS and
  is widely used, but SBPL is undocumented and version-sensitive. The system
  read paths in `workspace.sb` cover recent macOS; if a program fails to launch,
  switch the profile's first line to `(deny default (with report))`, watch
  Console for the denied path, and add it.
- **Not a full jail.** This confines file and network access. It does not
  restrict CPU/memory, IPC, or every mach service, and system temp dirs are
  writable by default (tighten by removing that block). Treat it as a strong
  containment layer, not a VM.

## If you later integrate it into valet

The natural seam is `valet/executor.py:_popen` — prefix the argv with
`sandbox-exec -D WORKSPACE=<workspace> -f <profile>` when a sandbox is
configured and available, falling back (loudly) to unsandboxed execution on
non-macOS hosts. Keep it behind an explicit config flag so the dependency on a
deprecated tool is opt-in. Left out on purpose here.
