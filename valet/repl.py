"""Interactive client — a redacting shell.

Running ``valet`` with no subcommand (or ``valet repl``) drops into a prompt.
Any line you type is run as a command by the daemon, and its output comes back
with secret values scrubbed. Meta-commands start with ``:``.

The line handler is factored into ``run_command`` (pure: line + session + send
-> (keep_going, output)) so it is testable without stdin or a live socket.
"""
from __future__ import annotations

import json
import os
import shlex
from dataclasses import dataclass
from typing import Callable, Optional

from . import __version__

Send = Callable[[dict], dict]

# Shell control characters; a line containing any of these is not a "pure cd".
_OPERATOR_CHARS = set(";&|()<>\n")

HELP = """\
Type any command to run it; output has secrets redacted.
`cd <dir>` sticks for the session (jailed to the workspace). Meta-commands:
  :help, :?            this help
  :cwd [dir]           show or change the working directory (same as `cd`)
  :shell [on|off]      show or toggle shell mode (default on)
  :secrets             how many secret values are being redacted for the cwd
  :call <json>         send a raw request object to the daemon
  :quit, :exit         leave (Ctrl-D also works)
"""

BANNER = (
    f"valet {__version__} — redacting shell. "
    "Type a command to run it; ':help' for meta-commands, ':quit' to exit."
)


@dataclass
class Session:
    cwd: Optional[str] = None      # None => daemon's configured workspace
    shell: bool = True


def _pure_cd_target(line: str) -> Optional[str]:
    """If ``line`` is a standalone `cd [dir]`, return its target ("" for bare
    `cd`); otherwise None. A compound line (`cd x && y`, pipes) is not a pure cd
    — it runs as an exec, where the cd applies only to that subprocess."""
    if any(ch in line for ch in _OPERATOR_CHARS):
        return None
    try:
        tokens = shlex.split(line)
    except ValueError:
        return None
    if tokens and tokens[0] == "cd":
        return tokens[1] if len(tokens) > 1 else ""
    return None


def _change_dir(target: str, session: Session, send: Send) -> tuple[bool, Optional[str]]:
    req = {"op": "chdir", "target": target}
    if session.cwd:
        req["cwd"] = session.cwd
    try:
        resp = send(req)
    except ConnectionError:
        return False, "connection to daemon lost. Exiting."
    if resp.get("ok"):
        session.cwd = resp.get("cwd")
        return True, None  # shell-like: silent on success, prompt shows the dir
    return True, f"cd: {resp.get('detail') or resp.get('error_class') or 'failed'}"


def run_command(line: str, session: Session, send: Send) -> tuple[bool, Optional[str]]:
    """Handle one REPL line. Returns ``(keep_going, output_text)``."""
    stripped = line.strip()
    if not stripped:
        return True, None

    if stripped.startswith(":"):
        return _meta(stripped[1:].strip(), session, send)

    # A standalone `cd` sticks for the session (handled by the daemon, jailed).
    cd_target = _pure_cd_target(stripped)
    if cd_target is not None:
        return _change_dir(cd_target, session, send)

    # Anything else is a command to run.
    req = {"op": "exec", "cmd": line, "shell": session.shell}
    if session.cwd:
        req["cwd"] = session.cwd
    try:
        resp = send(req)
    except ConnectionError:
        return False, "connection to daemon lost. Exiting."
    return True, format_exec(resp)


def _meta(body: str, session: Session, send: Send) -> tuple[bool, Optional[str]]:
    parts = body.split(None, 1)
    name = parts[0] if parts else ""
    arg = parts[1].strip() if len(parts) > 1 else ""

    if name in ("quit", "exit"):
        return False, None
    if name in ("help", "?", ""):
        return True, HELP
    if name == "cwd":
        if arg:
            return _change_dir(arg, session, send)
        return True, f"cwd: {session.cwd or '(daemon default)'}"
    if name == "shell":
        if arg in ("on", "true", "1"):
            session.shell = True
        elif arg in ("off", "false", "0"):
            session.shell = False
        elif arg:
            return True, "usage: :shell [on|off]"
        return True, f"shell: {'on' if session.shell else 'off'}"
    if name == "secrets":
        req = {"op": "redaction_info"}
        if session.cwd:
            req["cwd"] = session.cwd
        try:
            resp = send(req)
        except ConnectionError:
            return False, "connection to daemon lost. Exiting."
        n = resp.get("redacted_value_count", "?")
        return True, f"redacting {n} secret value(s) for {resp.get('cwd') or '(default)'}"
    if name == "call":
        if not arg:
            return True, ':usage: :call {"op":"exec","cmd":"echo hi"}'
        try:
            req = json.loads(arg)
        except json.JSONDecodeError as exc:
            return True, f"invalid JSON: {exc}"
        try:
            resp = send(req)
        except ConnectionError:
            return False, "connection to daemon lost. Exiting."
        return True, json.dumps(resp, indent=2)

    return True, f"unknown meta-command: :{name} (try :help)"


def format_exec(resp: dict) -> Optional[str]:
    """Render an exec response the way a shell would: stdout, stderr, exit note."""
    if not isinstance(resp, dict):
        return str(resp)
    if resp.get("op") != "exec" and "stdout" not in resp:
        # An error response or a non-exec op: show it as JSON.
        if resp.get("ok") is False:
            return f"[{resp.get('error_class', 'error')}] {resp.get('detail', '')}".strip()
        return json.dumps(resp, indent=2)
    parts = []
    out = (resp.get("stdout") or "").rstrip("\n")
    err = (resp.get("stderr") or "").rstrip("\n")
    if out:
        parts.append(out)
    if err:
        parts.append(err)
    code = resp.get("exit_code", 0)
    if code not in (0, None):
        parts.append(f"[exit {code}]")
    return "\n".join(parts) if parts else None


def prompt_for(session: Session) -> str:
    """`<lastdir> valet> `, or plain `valet> ` if the cwd is unknown."""
    if session.cwd:
        name = os.path.basename(session.cwd.rstrip("/")) or session.cwd
        return f"{name} valet> "
    return "valet> "


def interact(send: Send, *, session: Optional[Session] = None,
             input_fn: Callable[[str], str] = input) -> int:
    """Run the prompt loop. ``send`` performs one request/response."""
    session = session or Session()
    # Resolve the starting cwd (the workspace root) so the prompt and relative
    # `cd`s have a concrete base.
    if session.cwd is None:
        try:
            resp = send({"op": "chdir", "target": "."})
            if resp.get("ok"):
                session.cwd = resp.get("cwd")
        except (ConnectionError, OSError):
            pass

    try:  # arrow-key history/editing if available
        import readline  # noqa: F401
    except Exception:
        pass

    print(BANNER)
    while True:
        try:
            line = input_fn(prompt_for(session))
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print()
            continue
        keep_going, output = run_command(line, session, send)
        if output is not None:
            print(output)
        if not keep_going:
            break
    return 0
