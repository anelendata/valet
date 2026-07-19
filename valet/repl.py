"""Interactive client — a redacting shell.

Running ``valet`` with no subcommand (or ``valet repl``) drops into a prompt.
Any line you type is run as a command by the daemon, and its output comes back
with secret values scrubbed. Meta-commands start with ``:``.

The line handler is factored into ``run_command`` (pure: line + session + send
-> (keep_going, output)) so it is testable without stdin or a live socket.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Optional

from . import __version__

Send = Callable[[dict], dict]

HELP = """\
Type any command to run it; output has secrets redacted. Meta-commands:
  :help, :?            this help
  :cwd [dir]           show or set the working directory for this session
  :shell [on|off]      show or toggle shell mode (default on)
  :secrets             how many secret values are being redacted for :cwd
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


def run_command(line: str, session: Session, send: Send) -> tuple[bool, Optional[str]]:
    """Handle one REPL line. Returns ``(keep_going, output_text)``."""
    stripped = line.strip()
    if not stripped:
        return True, None

    if stripped.startswith(":"):
        return _meta(stripped[1:].strip(), session, send)

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
            session.cwd = arg
            return True, f"cwd set to {arg}"
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


def interact(send: Send, *, session: Optional[Session] = None,
             input_fn: Callable[[str], str] = input) -> int:
    """Run the prompt loop. ``send`` performs one request/response."""
    session = session or Session()
    try:  # arrow-key history/editing if available
        import readline  # noqa: F401
    except Exception:
        pass

    print(BANNER)
    while True:
        try:
            line = input_fn("valet> ")
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
