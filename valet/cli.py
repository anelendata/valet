"""``valet`` command-line entrypoint.

Subcommands:
  valet                 interactive redacting shell (default; like `python` bare)
  valet repl            same as above, explicitly
  valet serve           run the UDS broker daemon (outside the agent sandbox)
  valet serve-http      run the HTTP broker adapter with bearer auth
  valet run CMD...      run an argv (no shell) and print redacted output
  valet sh 'CMDLINE'    run a shell command line and print redacted output
  valet call --json ..  send a raw request object to the daemon
  valet init            generate a fingerprint_salt in config.toml

The agent uses `valet run` / `valet sh` / the REPL — they read no secrets
themselves; the daemon does the privileged work and redacts before replying.
"""
from __future__ import annotations

import argparse
import json
import secrets as _secrets
import sys
from pathlib import Path

from .config import default_config_path, load_config
from .errors import ValetError
from .repl import interact
from .server_http import serve as serve_http
from .server_uds import Connection, call_once, serve


def _cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.config) if args.config else default_config_path()
    if not path.exists():
        print(f"valet: {path} not found. Copy config.example.toml first:",
              file=sys.stderr)
        print(f"  cp config.example.toml {path}", file=sys.stderr)
        return 2
    import re
    text = path.read_text()
    salt = _secrets.token_urlsafe(32)
    new, n = re.subn(
        r'(?m)^(\s*fingerprint_salt\s*=\s*).*$',
        lambda m: f'{m.group(1)}"{salt}"',
        text,
    )
    if n == 0:
        print("valet: no fingerprint_salt line found to update.", file=sys.stderr)
        return 2
    path.write_text(new)
    print(f"valet: wrote a new fingerprint_salt to {path}")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    serve(load_config(args.config))
    return 0


def _cmd_serve_http(args: argparse.Namespace) -> int:
    serve_http(load_config(args.config))
    return 0


def _connect(args: argparse.Namespace) -> Connection:
    cfg = load_config(args.config)
    return Connection(cfg.socket_path)


def _cmd_repl(args: argparse.Namespace) -> int:
    try:
        conn = _connect(args)
    except (ConnectionRefusedError, FileNotFoundError):
        print("valet: no daemon at socket. Start it with `valet serve`.",
              file=sys.stderr)
        return 2
    try:
        return interact(conn.request)
    finally:
        conn.close()


def _one_shot(args: argparse.Namespace, request: dict) -> int:
    cfg = load_config(args.config)
    try:
        resp = call_once(cfg.socket_path, request)
    except (ConnectionRefusedError, FileNotFoundError):
        print("valet: no daemon at socket. Start it with `valet serve`.",
              file=sys.stderr)
        return 2
    return _print_response(resp)


def _print_response(resp: dict) -> int:
    if resp.get("op") == "exec":
        if resp.get("stdout"):
            print(resp["stdout"], end="" if resp["stdout"].endswith("\n") else "\n")
        if resp.get("stderr"):
            print(resp["stderr"], end="" if resp["stderr"].endswith("\n") else "\n",
                  file=sys.stderr)
        if resp.get("ok") is False and "exit_code" not in resp:
            print(f"valet: {resp.get('error_class')}: {resp.get('detail','')}",
                  file=sys.stderr)
        return int(resp.get("exit_code", 0) or (0 if resp.get("ok") else 1))
    print(json.dumps(resp, indent=2))
    return 0 if resp.get("ok") else 1


def _cmd_run(args: argparse.Namespace) -> int:
    command = list(args.command)
    if command and command[0] == "--":  # `valet run -- cmd ...`
        command = command[1:]
    if not command:
        print("valet run: no command given", file=sys.stderr)
        return 2
    req = {"op": "exec", "cmd": command, "shell": False,
           "timeout": args.timeout}
    if args.cwd:
        req["cwd"] = args.cwd
    return _one_shot(args, req)


def _cmd_sh(args: argparse.Namespace) -> int:
    req = {"op": "exec", "cmd": args.command, "shell": True,
           "timeout": args.timeout}
    if args.cwd:
        req["cwd"] = args.cwd
    return _one_shot(args, req)


def _cmd_call(args: argparse.Namespace) -> int:
    try:
        request = json.loads(args.json)
    except json.JSONDecodeError as exc:
        print(f"valet: --json is not valid JSON: {exc}", file=sys.stderr)
        return 2
    return _one_shot(args, request)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="valet", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-c", "--config", default=None,
                   help="path to config.toml (default: repo config.toml or $VALET_CONFIG)")
    p.set_defaults(func=_cmd_repl)  # no subcommand => REPL
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("init", help="generate a fingerprint_salt").set_defaults(func=_cmd_init)
    sub.add_parser("serve", help="run the UDS broker daemon").set_defaults(func=_cmd_serve)
    sub.add_parser("serve-http", help="run the HTTP broker adapter with bearer auth"
                   ).set_defaults(func=_cmd_serve_http)
    sub.add_parser("repl", help="interactive redacting shell (default)"
                   ).set_defaults(func=_cmd_repl)

    run = sub.add_parser("run", help="run an argv (no shell), print redacted output")
    run.add_argument("--cwd", default=None)
    run.add_argument("--timeout", type=int, default=60)
    run.add_argument("command", nargs=argparse.REMAINDER,
                     help="the command and its arguments")
    run.set_defaults(func=_cmd_run)

    sh = sub.add_parser("sh", help="run a shell command line, print redacted output")
    sh.add_argument("--cwd", default=None)
    sh.add_argument("--timeout", type=int, default=60)
    sh.add_argument("command", help="the command line to run via the shell")
    sh.set_defaults(func=_cmd_sh)

    call = sub.add_parser("call", help="send a raw JSON request to the daemon")
    call.add_argument("--json", required=True, help='e.g. \'{"op":"exec","cmd":"env"}\'')
    call.set_defaults(func=_cmd_call)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ValetError as exc:
        print(f"valet: {exc.error_class}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
