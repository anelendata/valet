"""``valet`` command-line entrypoint.

Subcommands:
  valet init            generate a fingerprint_salt in config.toml
  valet serve           run the UDS broker daemon (outside the agent sandbox)
  valet call ...        one-shot client: send a request to a running daemon
  valet schedule-list   convenience wrapper for the one operation

The agent (Codex) uses ``valet call`` / ``valet schedule-list`` — those read no
secrets themselves; they just talk to the daemon, which does the privileged work.
"""
from __future__ import annotations

import argparse
import json
import secrets as _secrets
import sys
from pathlib import Path

from .config import default_config_path, load_config
from .errors import ValetError
from .server_uds import call_once, serve


def _cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.config) if args.config else default_config_path()
    if not path.exists():
        print(f"valet: {path} not found. Copy config.example.toml first:",
              file=sys.stderr)
        print(f"  cp config.example.toml {path}", file=sys.stderr)
        return 2
    text = path.read_text()
    salt = _secrets.token_urlsafe(32)
    import re
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
    cfg = load_config(args.config)
    serve(cfg)
    return 0


def _one_shot(args: argparse.Namespace, request: dict) -> int:
    # Resolve socket path from config without loading secrets.
    cfg = load_config(args.config)
    try:
        response = call_once(cfg.socket_path, request)
    except (ConnectionRefusedError, FileNotFoundError):
        print("valet: no daemon at socket. Start it with `valet serve`.",
              file=sys.stderr)
        return 2
    print(json.dumps(response, indent=2))
    return 0 if response.get("ok") else 1


def _cmd_call(args: argparse.Namespace) -> int:
    try:
        request = json.loads(args.json)
    except json.JSONDecodeError as exc:
        print(f"valet: --json is not valid JSON: {exc}", file=sys.stderr)
        return 2
    return _one_shot(args, request)


def _cmd_schedule_list(args: argparse.Namespace) -> int:
    request = {
        "op": "schedule_list",
        "project_alias": args.alias,
        "stage": args.stage,
        "scope": args.scope,
        "compare": args.compare,
    }
    return _one_shot(args, request)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="valet", description=__doc__)
    p.add_argument("-c", "--config", default=None,
                   help="path to config.toml (default: repo config.toml or $VALET_CONFIG)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="generate a fingerprint_salt").set_defaults(func=_cmd_init)
    sub.add_parser("serve", help="run the UDS broker daemon").set_defaults(func=_cmd_serve)

    call = sub.add_parser("call", help="send a raw JSON request to the daemon")
    call.add_argument("--json", required=True, help='e.g. \'{"op":"schedule_list",...}\'')
    call.set_defaults(func=_cmd_call)

    sl = sub.add_parser("schedule-list", help="run the schedule_list operation")
    sl.add_argument("--alias", required=True)
    sl.add_argument("--stage", default="prod")
    sl.add_argument("--scope", default="declared", choices=["declared", "prefix", "all"])
    sl.add_argument("--compare", action="store_true",
                    help="also compute prefix-vs-declared over-match")
    sl.set_defaults(func=_cmd_schedule_list)
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
