# Set up a workspace-wide Python venv

Give a valet workspace its own Python virtual environment so every `valet run` /
`valet sh` / REPL command that calls `python` (or `pip`) uses that venv — with no
`activate` step, and without touching the system Python.

The trick relies on one valet behaviour: **valet prepends `<workspace>/bin` to
`PATH`** for every command it runs in the workspace (see the workspace `bin/`
convention). So a `python` placed in `bin/` shadows the system `python`.

The catch is *what* you put there. A symlink does **not** work, and a naive
script only works in shell mode. Use a shebang'd wrapper script.

## Steps

From the workspace root (`$VALET_WORKSPACE`):

```sh
# 1. Create the venv inside the workspace (so it stays within the sandbox jail).
python3 -m venv venv

# 2. Add a wrapper on PATH that runs the venv's python.
cat > bin/python <<'EOF'
#!/bin/sh
# Resolve the workspace's venv relative to this script, so it works whether or
# not $VALET_WORKSPACE is set (e.g. run directly in a terminal, or via valet).
here=$(cd "$(dirname "$0")" && pwd)
exec "$here/../venv/bin/python" "$@"
EOF
chmod +x bin/python
```

Now `python` resolves to the venv everywhere in the workspace:

```sh
valet run -- python -c "import sys; print(sys.prefix)"     # -> .../<workspace>/venv
valet run -- python -m pip install httpx                   # installs into the venv
```

Installing with `python -m pip …` targets the venv, so you usually don't need a
separate `bin/pip`. If you want `pip` on `PATH` too, add the same wrapper for it:

```sh
cat > bin/pip <<'EOF'
#!/bin/sh
here=$(cd "$(dirname "$0")" && pwd)
exec "$here/../venv/bin/pip" "$@"
EOF
chmod +x bin/pip
```

> Simpler alternative for the wrapper body, since valet exports `VALET_WORKSPACE`:
> `exec "$VALET_WORKSPACE/venv/bin/python" "$@"`. It's shorter but only works when
> that variable is set (i.e. under valet), whereas the `dirname "$0"` form above
> also works if you run `bin/python` directly.

## Why not `ln -s bin/python venv/bin/python`?

A venv's own `python` is a symlink chain to the base interpreter:

```
venv/bin/python -> python3.11 -> /usr/local/.../python3.11   (system)
```

If you symlink `bin/python` to it, the OS resolves the **whole chain** to the
system interpreter. Python then looks for the venv marker (`pyvenv.cfg`) next to
that real path, finds none, and runs as the **system** Python — the venv is
silently lost:

```
$ ln -s "$VALET_WORKSPACE/venv/bin/python" bin/python
$ bin/python -c "import sys; print(sys.prefix != sys.base_prefix)"
False        # <- not in the venv
```

Python only detects the venv when `python` is invoked **as a path inside
`venv/bin/`** (Python special-cases the venv's own `python -> python3.11` link
and checks the launch directory for `pyvenv.cfg` before resolving further). The
wrapper script does exactly that — it `exec`s `venv/bin/python` directly:

```
$ bin/python -c "import sys; print(sys.prefix != sys.base_prefix)"
True         # <- in the venv
```

## Why the wrapper needs `#!/bin/sh`

A shebang-less script like the one below happens to work in **shell mode**
(`valet sh …`, or `[exec] shell = true`), because the shell falls back to running
an unrecognized file with `/bin/sh`:

```sh
# bin/python  — works in shell mode ONLY
exec "$VALET_WORKSPACE/venv/bin/python" "$@"
```

But `valet run -- python …` (argv mode, no shell) `execve()`s the file directly.
Without a shebang the kernel returns `ENOEXEC` and there's no shell to fall back
to:

```
OSError: [Errno 8] Exec format error: '.../bin/python'
```

Adding `#!/bin/sh` makes the wrapper an executable the kernel understands, so it
works in **both** argv and shell modes. Always include it.

## Notes

- Keep the venv **inside** the workspace (`<workspace>/venv`). Under the OS
  sandbox the workspace is the readable/writable jail, so packages install and
  load fine; a venv outside it would be unreadable.
- `bin/`, `tools/`, and `skills/` are scaffolded by `valet workspaces add`
  (see the generated workspace `README.md`). This tip just fills `bin/python`.
- This is per-workspace: a second workspace gets its own `venv` and wrapper, so
  different projects can pin different interpreters and dependency sets.
