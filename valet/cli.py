"""``valet`` command-line entrypoint.

Subcommands:
  valet                 interactive redacting shell (default; like `python` bare)
  valet repl            same as above, explicitly
  valet doctor          check config and the OS sandbox setup
  valet serve           run the configured host daemon
  valet serve-lan       run the Level 1 WebSocket RPC host adapter
  valet run CMD...      run an argv (no shell) and print redacted output
  valet sh 'CMDLINE'    run a shell command line when [exec].shell=true
  valet call --json ..  send a raw request object to the daemon
  valet ping            check the selected host
  valet hosts           list configured client hosts
  valet processes list  list subprocesses started by valet
  valet processes kill  terminate a subprocess started by valet
  valet client init     create a client-only config.toml
  valet clients add     generate and approve a host-side client key
  valet clients list    list host-approved client identities
  valet clients remove  remove a host-approved client identity
  valet init            create config.toml (+ macOS sandbox profile) and check it

The agent uses `valet run` / `valet sh` / the REPL — they read no secrets
themselves; the daemon does the privileged work and redacts before replying.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets as _secrets
import shutil
import subprocess
import sys
from pathlib import Path

from .client_config import default_client_config_path, load_client_config, write_new_client_config
from .config import default_config_path, load_config
from .errors import ValetError, ValidationError
from .host_config import (
    client_config_snippet,
    find_client_identity,
    list_client_identities,
    normalize_client_id,
    remove_client_identity,
    upsert_client_identity,
)
from .rpc import RpcError, ValetClient, resolve_target
from .repl import Session, interact
from .server_host import serve as serve_host
from .server_ws import serve as serve_lan


def _cmd_init(args: argparse.Namespace) -> int:
    config_path = _resolve_config_path(args)
    valet_dir = config_path.parent
    is_mac = sys.platform == "darwin"
    workspace_sb = (valet_dir / "workspace.sb") if is_mac else None

    # Never clobber: if a target already exists, stop and let the user decide.
    existing = [p for p in (config_path, workspace_sb) if p is not None and p.exists()]
    if existing:
        print("valet: these files already exist:", file=sys.stderr)
        for item in existing:
            print(f"  {item}", file=sys.stderr)
        print("Remove or rename them, then run `valet init` again.", file=sys.stderr)
        return 2

    example = _example_config_path()
    if not example.exists():
        print(f"valet: cannot find config.example.toml (looked at {example}).",
              file=sys.stderr)
        return 2

    if not valet_dir.exists():
        if not _confirm(f"Create directory {valet_dir}?", default=True):
            print("valet: nothing created.")
            return 1
        valet_dir.mkdir(parents=True, exist_ok=True)

    if not _confirm(f"Create {config_path} from config.example.toml?", default=True):
        print("valet: nothing created.")
        return 1

    text = example.read_text()
    # Give the new config a stable, unique fingerprint salt up front.
    salt = _secrets.token_urlsafe(32)
    text, _n = re.subn(
        r'(?m)^(\s*fingerprint_salt\s*=\s*).*$',
        lambda m: f'{m.group(1)}"{salt}"',
        text,
    )

    if is_mac:
        text = _init_macos_sandbox(text, workspace_sb)

    config_path.write_text(text)
    print(f"valet: wrote {config_path}")

    # Health check at the end, mirroring `valet doctor`.
    print()
    try:
        _doctor_report(config_path, load_config(config_path))
    except ValetError as exc:
        print(f"valet: could not run the health check: {exc}", file=sys.stderr)
    print()
    print("valet: setup complete. Edit the config as needed, then run "
          "`valet doctor` to check config health again.")
    return 0


def _init_macos_sandbox(text: str, workspace_sb: Path) -> str:
    """Offer to install and activate the OS sandbox; return the (maybe edited) config."""
    if _confirm(f"Copy the OS sandbox profile to {workspace_sb}?", default=True):
        src = _workspace_sb_source()
        if src.exists():
            shutil.copyfile(src, workspace_sb)
            print(f"valet: wrote {workspace_sb}")
        else:
            print(f"valet: warning: {src} not found; skipping sandbox profile.",
                  file=sys.stderr)

    if not workspace_sb.exists():
        return text

    print()
    print("The OS sandbox (macOS sandbox-exec) confines every command to your")
    print("workspace: it blocks reads of your home, keychain, and other users,")
    print("jails writes to the workspace, and denies network access — a real")
    print("kernel boundary beyond command-line policy.")
    if not _confirm("Activate it now (recommended for maximum safety)?", default=True):
        return text

    activated, n = re.subn(
        r"(?m)^#\s*sandbox_profile\s*=.*$",
        f'sandbox_profile = "{_home_relative(workspace_sb)}"',
        text,
    )
    if n == 0:
        print("valet: warning: could not find the sandbox_profile line to activate; "
              "set it by hand.", file=sys.stderr)
        return text
    print("valet: activated sandbox_profile in the config.")
    return activated


def _confirm(prompt: str, *, default: bool) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    try:
        answer = input(prompt + suffix).strip().lower()
    except EOFError:
        return default
    if not answer:
        return default
    return answer in ("y", "yes")


def _example_config_path() -> Path:
    return Path(__file__).resolve().parent.parent / "config.example.toml"


def _workspace_sb_source() -> Path:
    return Path(__file__).resolve().parent.parent / "contrib" / "sandbox-exec" / "workspace.sb"


def _home_relative(path: Path) -> str:
    try:
        return "~/" + str(path.relative_to(Path.home()))
    except ValueError:
        return str(path)


def _cmd_doctor(args: argparse.Namespace) -> int:
    path = _resolve_config_path(args)
    try:
        cfg = load_config(path)
    except ValetError as exc:
        print(f"valet: could not load config: {exc}", file=sys.stderr)
        return 2
    return 1 if _doctor_report(path, cfg) else 0


def _doctor_report(path: Path, cfg) -> bool:
    """Print the config summary and sandbox checks; return True if a check failed."""
    print("valet doctor\n")
    workspace = _resolve_workspace(cfg.exec.workspace)
    ws_note = "(unset)"
    if workspace:
        ws_note = f"{workspace}  [{'exists' if os.path.isdir(workspace) else 'MISSING'}]"
    print(f"  config file:  {path}")
    print(f"  workspace:    {ws_note}")
    print(f"  shell:        {'on' if cfg.exec.shell else 'off'}")
    print(
        f"  policy:       reads={_onoff(cfg.policy.enforce_workspace_reads)} "
        f"writes={_onoff(cfg.policy.enforce_workspace_writes)}  "
        f"deny=+{len(cfg.policy.deny)}  "
        f"allow={'(none)' if not cfg.policy.allow else ','.join(cfg.policy.allow)}"
    )
    print(f"  sandbox:      {cfg.exec.sandbox_profile or '(not configured)'}")
    print()

    failed = _doctor_sandbox_checks(cfg, workspace)
    print()
    print("result: " + ("FAILED — see above" if failed else "all checks passed"))
    return failed


def _onoff(value: bool) -> str:
    return "on" if value else "off"


def _resolve_workspace(workspace) -> str:
    if not workspace:
        return ""
    return os.path.realpath(os.path.expanduser(os.path.expandvars(str(workspace))))


def _doctor_line(status: str, text: str) -> None:
    print(f"  [{status:^4}] {text}")


def _doctor_sandbox_checks(cfg, workspace: str) -> bool:
    """Run sandbox checks. Returns True if any hard check failed."""
    profile = cfg.exec.sandbox_profile
    if not profile:
        print("sandbox checks: skipped ([exec].sandbox_profile is unset)")
        return False

    print("sandbox checks:")
    failed = False

    if sys.platform != "darwin":
        _doctor_line("WARN", "sandbox_profile is set but sandbox-exec is macOS-only")
        return False

    exe = shutil.which("sandbox-exec")
    if not exe:
        _doctor_line("FAIL", "sandbox-exec not found on PATH")
        return True
    _doctor_line(" OK ", f"sandbox-exec present: {exe}")

    profile_path = os.path.expanduser(os.path.expandvars(profile))
    if not os.path.isfile(profile_path):
        _doctor_line("FAIL", f"profile not found: {profile_path}")
        return True
    _doctor_line(" OK ", f"profile readable: {profile_path}")

    if not workspace or not os.path.isdir(workspace):
        _doctor_line("FAIL", "[exec].workspace must be set and exist for the sandbox")
        return True

    def run(*cmd):
        full = ["sandbox-exec", "-D", f"WORKSPACE={workspace}", "-f", profile_path, *cmd]
        try:
            return subprocess.run(full, capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return exc

    # 1. A trivial command must launch without aborting (the exit -6 you hit).
    res = run("/usr/bin/true")
    if not hasattr(res, "returncode"):
        _doctor_line("FAIL", f"could not run a sandboxed command: {res}")
        return True
    if res.returncode == -6:
        _doctor_line("FAIL", "profile aborts programs at launch (SIGABRT / exit -6)")
        print("         → the profile is too strict for process startup; use the")
        print("           shipped contrib/sandbox-exec/workspace.sb, or see its README.")
        failed = True
    elif res.returncode != 0:
        _doctor_line("FAIL", f"trivial command failed (exit {res.returncode}): "
                             f"{res.stderr.strip()[:200]}")
        failed = True
    else:
        _doctor_line(" OK ", "launches a trivial command")

    # 2. The workspace must be readable inside the sandbox.
    res = run("/bin/ls", workspace)
    if hasattr(res, "returncode") and res.returncode == 0:
        _doctor_line(" OK ", "workspace is readable inside the sandbox")
    else:
        _doctor_line("FAIL", "workspace is NOT readable inside the sandbox")
        failed = True

    # 3. The home directory must NOT be readable inside the sandbox.
    home = os.path.expanduser("~")
    res = run("/bin/ls", home)
    if hasattr(res, "returncode") and res.returncode == 0:
        _doctor_line("WARN", "home directory IS readable inside the sandbox "
                             "(reads are not confined)")
        print("         → [exec].workspace is your home (or an ancestor of it). Set it")
        print("           to a dedicated subdirectory (e.g. ~/valet-workspace) so only")
        print("           that subtree is readable, not the whole home.")
    else:
        _doctor_line(" OK ", "home directory is blocked inside the sandbox")

    # 4. The profile should deny the network (static check).
    try:
        profile_text = Path(profile_path).read_text()
    except OSError:
        profile_text = ""
    if "deny network" in profile_text:
        _doctor_line(" OK ", "profile denies network access")
    else:
        _doctor_line("WARN", "profile has no `(deny network*)` rule")

    return failed


def _resolve_config_path(args: argparse.Namespace) -> Path:
    """The config file to use: an explicit ``-c`` path, else the default search."""
    return Path(args.config) if args.config else default_config_path()


def _cmd_serve(args: argparse.Namespace) -> int:
    path = _resolve_config_path(args)
    cfg = load_config(path)  # raises ConfigError (exit 2) if -c names a missing file
    print(f"valet: config path: {path.resolve()}")
    serve_host(cfg, config_path=path)
    return 0


def _cmd_serve_lan(args: argparse.Namespace) -> int:
    path = _resolve_config_path(args)
    cfg = load_config(path)
    print(f"valet: config path: {path.resolve()}")
    serve_lan(cfg)
    return 0


def _connect(args: argparse.Namespace) -> tuple[ValetClient, object, object | None]:
    target, _client_cfg = resolve_target(
        host_name=args.host,
        force_local=args.local,
        client_config_path=args.config,
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
        # A local target reads the host's [exec].shell from its own config; a
        # remote target has no access to it, so ask the host for its default.
        # Without this the REPL would default remote sessions to shell=off and
        # send shell=False, running argv mode even when the host allows a shell.
        shell_default = cfg.exec.shell if cfg else _remote_shell_default(conn)
        session = Session(
            shell=shell_default,
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


def _remote_shell_default(conn: ValetClient) -> bool:
    """Ask a remote host whether it defaults exec to shell mode.

    Falls back to False if the host is old enough not to report it or the
    ping fails; the host still rejects shell requests it does not allow.
    """
    try:
        resp = conn.request({"op": "ping"})
    except (ConnectionError, RpcError, OSError):
        return False
    return bool(resp.get("shell_default", False))


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


def _parse_env_args(values: list[str] | None) -> dict[str, str] | None:
    if not values:
        return None
    env: dict[str, str] = {}
    for item in values:
        if "=" not in item:
            raise ValidationError("--env must be NAME=VALUE")
        name, value = item.split("=", 1)
        if not name:
            raise ValidationError("--env name cannot be empty")
        env[name] = value
    return env


def _attach_env(args: argparse.Namespace, req: dict) -> None:
    env = _parse_env_args(getattr(args, "env", None))
    if env:
        req["env"] = env


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
    _attach_env(args, req)
    return _streaming_one_shot(args, req)


def _cmd_sh(args: argparse.Namespace) -> int:
    req = {"op": "exec", "cmd": args.command, "shell": True,
           "timeout": args.timeout}
    if args.cwd:
        req["cwd"] = args.cwd
    _attach_env(args, req)
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
    cfg = load_client_config(args.config)
    if not cfg.hosts:
        print(f"valet: no remote hosts configured in {cfg.path}")
        return 0
    for name, host in sorted(cfg.hosts.items()):
        marker = "*" if name == cfg.default_host else " "
        print(f"{marker} {name}\t{host.url}\tclient_id={host.client_id or cfg.id}")
    return 0


def _cmd_processes_list(args: argparse.Namespace) -> int:
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
        resp = conn.request({"op": "processes.list"})
    finally:
        conn.close()
    if not resp.get("ok"):
        return _print_response(resp)
    processes = resp.get("processes") or []
    if not processes:
        print("valet: no running subprocesses")
        return 0
    print("PID\tSECONDS\tSHELL\tCOMMAND")
    for item in processes:
        print(
            f"{item.get('pid')}\t"
            f"{item.get('runtime_seconds')}\t"
            f"{str(bool(item.get('shell'))).lower()}\t"
            f"{item.get('cmd') or ''}"
        )
    return 0


def _cmd_processes_kill(args: argparse.Namespace) -> int:
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
        resp = conn.request({"op": "processes.kill", "pid": args.pid})
    finally:
        conn.close()
    if not resp.get("ok"):
        return _print_response(resp)
    print(f"valet: killed subprocess {resp.get('pid')}")
    return 0


def _cmd_client_init(args: argparse.Namespace) -> int:
    path = Path(args.config) if args.config else default_client_config_path()
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

    raw_id = args.client_id.strip()
    if not raw_id:
        print("valet clients add: client id cannot be empty", file=sys.stderr)
        return 2
    try:
        client_id = normalize_client_id(raw_id)
    except ValueError as exc:
        print(f"valet clients add: {exc}", file=sys.stderr)
        return 2

    if find_client_identity(path, client_id) and not args.yes:
        answer = input(
            f"valet: client {client_id!r} already exists. "
            "Replace its key? [y/N] "
        )
        if answer.strip().lower() not in ("y", "yes"):
            print("valet: client key unchanged.")
            return 1

    update = upsert_client_identity(path, client_id=client_id)
    cfg = load_config(path)
    host_name = args.host_name or cfg.host.id
    url = args.url or _default_lan_url(cfg.host.listen)

    action = "rotated" if update.existed else "added"
    print(f"valet: {action} client {update.client_id!r} in {path}")
    print("\nClient config:")
    print(client_config_snippet(update, host_name=host_name, url=url, host_id=cfg.host.id))
    return 0


def _cmd_clients_list(args: argparse.Namespace) -> int:
    path = Path(args.config) if args.config else default_config_path()
    if not path.exists():
        print(f"valet: {path} not found. Copy config.example.toml first:",
              file=sys.stderr)
        return 2

    entries = list_client_identities(path)
    if not entries:
        print(f"valet: no approved clients in {path}")
        return 0
    for entry in sorted(entries, key=lambda item: item.client_id):
        key_state = "key=set" if entry.has_key else "key=missing"
        print(f"{entry.client_id}\t{key_state}")
    return 0


def _cmd_clients_remove(args: argparse.Namespace) -> int:
    path = Path(args.config) if args.config else default_config_path()
    if not path.exists():
        print(f"valet: {path} not found. Copy config.example.toml first:",
              file=sys.stderr)
        return 2

    raw_id = args.client_id.strip()
    if not raw_id:
        print("valet clients remove: client id cannot be empty", file=sys.stderr)
        return 2
    try:
        client_id = normalize_client_id(raw_id)
    except ValueError as exc:
        print(f"valet clients remove: {exc}", file=sys.stderr)
        return 2

    removed = remove_client_identity(path, client_id)
    if removed is None:
        print(f"valet: client {client_id!r} was not found in {path}", file=sys.stderr)
        return 1
    print(f"valet: removed client {removed.client_id!r} from {path}")
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
                   help="path to config.toml — holds both server and "
                        "[client]/[hosts] sections (default: $VALET_CONFIG, "
                        "else ~/.valet/config.toml, else the repo config.toml)")
    p.add_argument("--host", default=None,
                   help="configured remote host to use for client commands")
    p.add_argument("--local", action="store_true",
                   help="force the local Unix-domain socket transport")
    p.add_argument("-e", "--env", "-env", action="append", default=[],
                   metavar="NAME=VALUE",
                   help="set an environment variable for run/sh without shell syntax")
    p.add_argument("--cwd", default=None,
                   help="working directory for run/sh without shell syntax")
    p.set_defaults(func=_cmd_repl)  # no subcommand => REPL
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("init", help="create config.toml (and, on macOS, the sandbox profile)"
                   ).set_defaults(func=_cmd_init)
    sub.add_parser("doctor", help="check config and the OS sandbox setup"
                   ).set_defaults(func=_cmd_doctor)
    sub.add_parser("serve", help="run the configured host daemon").set_defaults(func=_cmd_serve)
    sub.add_parser("serve-lan", help="run the Level 1 trusted-LAN WebSocket RPC host"
                   ).set_defaults(func=_cmd_serve_lan)
    sub.add_parser("repl", help="interactive redacting shell (default)"
                   ).set_defaults(func=_cmd_repl)
    sub.add_parser("ping", help="check the selected host").set_defaults(func=_cmd_ping)
    sub.add_parser("hosts", help="list configured remote hosts").set_defaults(func=_cmd_hosts)

    processes = sub.add_parser("processes", help="inspect or kill valet subprocesses")
    processes_sub = processes.add_subparsers(dest="processes_cmd", required=True)
    processes_sub.add_parser("list", help="list running valet subprocesses"
                             ).set_defaults(func=_cmd_processes_list)
    processes_kill = processes_sub.add_parser(
        "kill",
        help="terminate a running valet subprocess",
    )
    processes_kill.add_argument("pid", type=int)
    processes_kill.set_defaults(func=_cmd_processes_kill)

    client = sub.add_parser("client", help="manage client-only configuration")
    client_sub = client.add_subparsers(dest="client_cmd", required=True)
    client_init = client_sub.add_parser("init", help="create a client-only config")
    client_init.add_argument("--host-name", default="lan-host")
    client_init.add_argument("--url", required=True, help="ws://HOST:PORT/rpc")
    client_init.add_argument("--force", action="store_true")
    client_init.set_defaults(func=_cmd_client_init)

    clients = sub.add_parser("clients", help="manage host-approved client identities")
    clients_sub = clients.add_subparsers(dest="clients_cmd", required=True)
    clients_sub.add_parser("list", help="list approved client identities"
                           ).set_defaults(func=_cmd_clients_list)
    clients_add = clients_sub.add_parser("add", help="generate and approve a client key")
    clients_add.add_argument("client_id", metavar="id",
                             help="client id (the identity's section name; "
                                  "spaces become hyphens)")
    clients_add.add_argument("--yes", "-y", action="store_true",
                             help="replace an existing client key without prompting")
    clients_add.add_argument("--host-name", default=None,
                             help="host profile name to print in the client snippet")
    clients_add.add_argument("--url", default=None,
                             help="WebSocket URL to print in the client snippet")
    clients_add.set_defaults(func=_cmd_clients_add)
    clients_remove = clients_sub.add_parser("remove", help="remove an approved client key")
    clients_remove.add_argument("client_id", metavar="id", help="client id to remove")
    clients_remove.set_defaults(func=_cmd_clients_remove)

    run = sub.add_parser("run", help="run an argv (no shell), print redacted output")
    run.add_argument("--cwd", default=argparse.SUPPRESS)
    run.add_argument("--timeout", type=int, default=60)
    run.add_argument("command", nargs=argparse.REMAINDER,
                     help="the command and its arguments")
    run.set_defaults(func=_cmd_run)

    sh = sub.add_parser("sh", help="run a shell command line, print redacted output")
    sh.add_argument("--cwd", default=argparse.SUPPRESS)
    sh.add_argument("--timeout", type=int, default=60)
    sh.add_argument("command", help="the command line to run via the shell")
    sh.set_defaults(func=_cmd_sh)

    call = sub.add_parser("call", help="send a raw JSON request to the daemon")
    call.add_argument("--json", required=True, help='e.g. \'{"op":"ping"}\'')
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
