"""Interactive client REPL.

Running ``valet`` with no subcommand (or ``valet repl``) drops into a prompt,
much like running ``python`` bare. It holds one persistent connection to the
daemon and lets you issue operations without re-typing ``valet …`` each time.

The line handler is factored into ``run_command`` (pure: line + send callable
-> (keep_going, output)) so it is testable without stdin or a live socket.
"""
from __future__ import annotations

import argparse
import json
import shlex
from typing import Callable, Optional

from . import SCHEDULE_SCOPES, __version__

Send = Callable[[dict], dict]

HELP = """\
commands:
  schedule-list <alias> [--stage S] [--scope declared|prefix|all] [--compare]
      alias: sl
  call <json>                 send a raw request object, e.g.
                              call {"op":"schedule_list","project_alias":"demo_billing"}
  ops                         list allowlisted operations
  help, ?                     this help
  quit, exit                  leave (Ctrl-D also works)
"""

BANNER = (
    f"valet {__version__} interactive client. "
    "Type 'help' for commands, 'quit' to exit."
)


class _ReplArgError(Exception):
    """Raised instead of SystemExit so a bad line does not kill the REPL."""


class _ReplParser(argparse.ArgumentParser):
    def error(self, message):  # noqa: D401 - argparse hook
        raise _ReplArgError(message)

    def exit(self, status=0, message=None):  # keep --help from exiting the REPL
        raise _ReplArgError(message or "")


def _sl_parser() -> _ReplParser:
    p = _ReplParser(prog="schedule-list", add_help=True)
    p.add_argument("alias")
    p.add_argument("--stage", default="prod")
    p.add_argument("--scope", default="declared", choices=list(SCHEDULE_SCOPES))
    p.add_argument("--compare", action="store_true")
    return p


def run_command(line: str, send: Send) -> tuple[bool, Optional[str]]:
    """Handle one REPL line.

    Returns ``(keep_going, output_text)``. ``output_text`` is None when there is
    nothing to print. ``send`` is called with a request dict and returns the
    daemon's response dict.
    """
    line = line.strip()
    if not line:
        return True, None

    try:
        tokens = shlex.split(line)
    except ValueError as exc:
        return True, f"parse error: {exc}"
    cmd, rest = tokens[0], tokens[1:]

    if cmd in ("quit", "exit"):
        return False, None
    if cmd in ("help", "?"):
        return True, HELP
    if cmd == "ops":
        return True, "read-only operations:\n  schedule_list"

    if cmd in ("schedule-list", "sl"):
        try:
            ns = _sl_parser().parse_args(rest)
        except _ReplArgError as exc:
            return True, (str(exc).strip() or None) or "usage: schedule-list <alias> [...]"
        req = {
            "op": "schedule_list",
            "project_alias": ns.alias,
            "stage": ns.stage,
            "scope": ns.scope,
            "compare": ns.compare,
        }
        return _send_and_format(send, req)

    if cmd in ("call", "raw"):
        payload = line[len(cmd):].strip()
        if not payload:
            return True, 'usage: call <json>, e.g. call {"op":"schedule_list",...}'
        try:
            req = json.loads(payload)
        except json.JSONDecodeError as exc:
            return True, f"invalid JSON: {exc}"
        return _send_and_format(send, req)

    return True, f"unknown command: {cmd!r} (try 'help')"


def _send_and_format(send: Send, req: dict) -> tuple[bool, Optional[str]]:
    try:
        resp = send(req)
    except ConnectionError:
        return False, "connection to daemon lost. Exiting."
    except OSError as exc:
        return True, f"send failed: {exc}"
    return True, json.dumps(resp, indent=2)


def interact(send: Send, *, input_fn: Callable[[str], str] = input) -> int:
    """Run the prompt loop. ``send`` performs one request/response."""
    try:  # arrow-key history/editing if available; harmless if not
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
            print()  # abandon current line, keep going
            continue
        keep_going, output = run_command(line, send)
        if output is not None:
            print(output)
        if not keep_going:
            break
    return 0
