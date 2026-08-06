"""``valet`` command-line entrypoint.

Subcommands:
  valet                 interactive redacting shell (default; like `python` bare)
  valet repl            same as above, explicitly
  valet serve           run the configured host daemon
  valet serve-http      run the HTTP broker adapter with bearer auth
  valet serve-lan       run the Level 1 WebSocket RPC host adapter
  valet run CMD...      run an argv (no shell) and print redacted output
  valet sh 'CMDLINE'    run a shell command line and print redacted output
  valet call --json ..  send a raw request object to the daemon
  valet ping            check the selected host
  valet hosts           list configured client hosts
  valet client init     create a client-only config.toml
  valet clients add     generate and approve a host-side client key
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

from .client_config import default_client_config_path, load_client_config, write_new_client_config
from .config import default_config_path, load_config
from .errors import ValetError
from .host_config import client_config_snippet, find_client_identity, upsert_client_identity
from .rpc import RpcError, ValetClient, resolve_target
from .repl import Session, interact
from .server_host import serve as serve_host
from .server_http import serve as serve_http
from .server_ws import serve as serve_lan


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
    serve_host(load_config(args.config))
    return 0


def _cmd_serve_http(args: argparse.Namespace) -> int:
    serve_http(load_config(args.config))
    return 0


def _cmd_serve_lan(args: argparse.Namespace) -> int:
    serve_lan(load_config(args.config))
    return 0


def _connect(args: argparse.Namespace) -> tuple[ValetClient, object, object | None]:
    target, _client_cfg = resolve_target(
        host_name=args.host,
        force_local=args.local,
        client_config_path=args.client_config,
    )
    cfg = load_config(args.config) if not target.is_remote else None
    return ValetClient(target, cfg), target, cfg


def _cmd_repl(args: argparse.Namespace) -> int:
    try:
        conn, target, cfg = _connect(args)
    except (ConnectionRefusedError, FileNotFoundError):
        print("valet: no daemon at socket. Start it with `valet serve`.",
              file=sys.stderr)
        return 2
    except (ConnectionError, RpcError) as exc:
        print(f"valet: could not connect: {exc}", file=sys.stderr)
        return 2
    try:
        session = Session(
            host_label=target.name if target.is_remote else None,
            completion_workspace=(cfg.exec.workspace
                                  if cfg and cfg.policy.enforce_workspace_reads else None),
        )
        def send(req: dict) -> dict:
            if req.get("op", "exec") == "exec" and req.get("stream", True):
                req = dict(req)
                req["stream"] = True
                return conn.request_stream(req, _print_stream_event)
            return conn.request(req)

        session.completion_send = send
        return interact(send, session=session)
    finally:
        conn.close()


def _one_shot(args: argparse.Namespace, request: dict) -> int:
    try:
        conn, _target, _cfg = _connect(args)
    except (ConnectionRefusedError, FileNotFoundError):
        print("valet: no daemon at socket. Start it with `valet serve`.",
              file=sys.stderr)
        return 2
    except (ConnectionError, RpcError) as exc:
        print(f"valet: could not connect: {exc}", file=sys.stderr)
        return 2
    try:
        resp = conn.request(request)
    finally:
        conn.close()
    return _print_response(resp)


def _streaming_one_shot(args: argparse.Namespace, request: dict) -> int:
    request = dict(request)
    request["stream"] = True
    try:
        conn, _target, _cfg = _connect(args)
    except (ConnectionRefusedError, FileNotFoundError):
        print("valet: no daemon at socket. Start it with `valet serve`.",
              file=sys.stderr)
        return 2
    except (ConnectionError, RpcError) as exc:
        print(f"valet: could not connect: {exc}", file=sys.stderr)
        return 2
    try:
        resp = conn.request_stream(request, _print_stream_event)
    finally:
        conn.close()
    return _print_response(resp)


def _print_stream_event(event: dict) -> None:
    text = event.get("data") or ""
    if event.get("stream") == "stderr":
        print(text, end="", file=sys.stderr)
    else:
        print(text, end="")


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
    return _streaming_one_shot(args, req)


def _cmd_sh(args: argparse.Namespace) -> int:
    req = {"op": "exec", "cmd": args.command, "shell": True,
           "timeout": args.timeout}
    if args.cwd:
        req["cwd"] = args.cwd
    return _streaming_one_shot(args, req)


def _cmd_call(args: argparse.Namespace) -> int:
    try:
        request = json.loads(args.json)
    except json.JSONDecodeError as exc:
        print(f"valet: --json is not valid JSON: {exc}", file=sys.stderr)
        return 2
    return _one_shot(args, request)


def _cmd_ping(args: argparse.Namespace) -> int:
    return _one_shot(args, {"op": "ping"})


def _cmd_hosts(args: argparse.Namespace) -> int:
    cfg = load_client_config(args.client_config)
    if not cfg.hosts:
        print(f"valet: no remote hosts configured in {cfg.path}")
        return 0
    for name, host in sorted(cfg.hosts.items()):
        marker = "*" if name == cfg.default_host else " "
        print(f"{marker} {name}\t{host.url}\tclient_id={host.client_id or cfg.id}")
    return 0


def _cmd_client_init(args: argparse.Namespace) -> int:
    path = Path(args.client_config) if args.client_config else default_client_config_path()
    if path.exists() and not args.force:
        print(f"valet: {path} already exists. Use --force to replace it.", file=sys.stderr)
        return 2
    cfg = write_new_client_config(path, host_name=args.host_name, url=args.url)
    host = cfg.hosts[args.host_name]
    print(f"valet: wrote client config to {path}")
    print("\nAdd this to the trusted host's config.toml:")
    print("[identity.clients.%s]" % host.client_id)
    print('name = "%s"' % host.client_id)
    print('key = "%s"' % host.key)
    return 0


def _cmd_clients_add(args: argparse.Namespace) -> int:
    path = Path(args.config) if args.config else default_config_path()
    if not path.exists():
        print(f"valet: {path} not found. Copy config.example.toml first:",
              file=sys.stderr)
        return 2

    name = args.name.strip()
    if not name:
        print("valet clients add: client name cannot be empty", file=sys.stderr)
        return 2

    existing_id = find_client_identity(path, name)
    if existing_id and not args.yes:
        answer = input(
            f"valet: client {name!r} already exists as {existing_id!r}. "
            "Replace its key? [y/N] "
        )
        if answer.strip().lower() not in ("y", "yes"):
            print("valet: client key unchanged.")
            return 1

    update = upsert_client_identity(path, name=name)
    cfg = load_config(path)
    host_name = args.host_name or cfg.host.id
    url = args.url or _default_lan_url(cfg.host.listen)

    action = "rotated" if update.existed else "added"
    print(f"valet: {action} client {update.name!r} in {path}")
    print("\nClient config:")
    print(client_config_snippet(update, host_name=host_name, url=url, host_id=cfg.host.id))
    return 0


def _default_lan_url(listen: str) -> str:
    host, port = listen.rsplit(":", 1) if ":" in listen else (listen, "8766")
    if host in ("", "0.0.0.0", "::"):
        host = "<host-lan-ip>"
    return f"ws://{host}:{port}/rpc"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="valet", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-c", "--config", default=None,
                   help="path to config.toml (default: repo config.toml or $VALET_CONFIG)")
    p.add_argument("--client-config", default=None,
                   help="path to client-only config.toml (default: ~/.valet/client.toml)")
    p.add_argument("--host", default=None,
                   help="configured remote host to use for client commands")
    p.add_argument("--local", action="store_true",
                   help="force the local Unix-domain socket transport")
    p.set_defaults(func=_cmd_repl)  # no subcommand => REPL
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("init", help="generate a fingerprint_salt").set_defaults(func=_cmd_init)
    sub.add_parser("serve", help="run the configured host daemon").set_defaults(func=_cmd_serve)
    sub.add_parser("serve-http", help="run the HTTP broker adapter with bearer auth"
                   ).set_defaults(func=_cmd_serve_http)
    sub.add_parser("serve-lan", help="run the Level 1 trusted-LAN WebSocket RPC host"
                   ).set_defaults(func=_cmd_serve_lan)
    sub.add_parser("repl", help="interactive redacting shell (default)"
                   ).set_defaults(func=_cmd_repl)
    sub.add_parser("ping", help="check the selected host").set_defaults(func=_cmd_ping)
    sub.add_parser("hosts", help="list configured remote hosts").set_defaults(func=_cmd_hosts)

    client = sub.add_parser("client", help="manage client-only configuration")
    client_sub = client.add_subparsers(dest="client_cmd", required=True)
    client_init = client_sub.add_parser("init", help="create a client-only config")
    client_init.add_argument("--host-name", default="lan-host")
    client_init.add_argument("--url", required=True, help="ws://HOST:PORT/rpc")
    client_init.add_argument("--force", action="store_true")
    client_init.set_defaults(func=_cmd_client_init)

    clients = sub.add_parser("clients", help="manage host-approved client identities")
    clients_sub = clients.add_subparsers(dest="clients_cmd", required=True)
    clients_add = clients_sub.add_parser("add", help="generate and approve a client key")
    clients_add.add_argument("name", help="friendly client name")
    clients_add.add_argument("--yes", "-y", action="store_true",
                             help="replace an existing client key without prompting")
    clients_add.add_argument("--host-name", default=None,
                             help="host profile name to print in the client snippet")
    clients_add.add_argument("--url", default=None,
                             help="WebSocket URL to print in the client snippet")
    clients_add.set_defaults(func=_cmd_clients_add)

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
