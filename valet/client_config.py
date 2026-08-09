"""Client-only configuration for selecting local or remote Valet hosts."""
from __future__ import annotations

import os
import re
import secrets
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .config import default_config_path
from .errors import ConfigError

DEFAULT_CLIENT_CONFIG_ENV = "VALET_CLIENT_CONFIG"
DEFAULT_CLIENT_CONFIG_NAME = "client.toml"


def _expand(path: str) -> str:
    return os.path.expanduser(os.path.expandvars(path))


@dataclass(frozen=True)
class ClientHost:
    name: str
    url: str
    client_id: str
    key: str
    host_id: str = ""
    reconnect_max_retries: int = 5
    reconnect_backoff_seconds: float = 0.25
    reconnect_backoff_max_seconds: float = 3.0


@dataclass(frozen=True)
class ClientConfig:
    path: Path
    id: str
    key: str
    default_host: str
    hosts: dict[str, ClientHost]
    # Workspace this client runs commands in when none is given on the command
    # line. Takes priority over the host's own default workspace; an explicit
    # ``-w/--workspace`` still overrides it. Empty means "use the host default".
    default_workspace: str = ""


def default_client_config_path() -> Path:
    """Where non-``serve`` commands look for client config.

    Defaults to the same ``config.toml`` the server uses — a single file holds
    both the ``[client]`` / ``[hosts]`` sections and the server sections, which
    each loader reads independently. ``VALET_CLIENT_CONFIG`` overrides it when a
    separate client-only file is wanted.
    """
    env = os.environ.get(DEFAULT_CLIENT_CONFIG_ENV)
    if env:
        return Path(_expand(env))
    return default_config_path()


def load_client_config(
    path: Optional[str | os.PathLike] = None,
    *,
    required: bool = False,
) -> ClientConfig:
    cfg_path = Path(path) if path is not None else default_client_config_path()
    if not cfg_path.exists():
        if required:
            raise ConfigError(f"client config not found at {cfg_path}")
        return ClientConfig(path=cfg_path, id="", key="", default_host="",
                            hosts={}, default_workspace="")
    try:
        with open(cfg_path, "rb") as fh:
            raw = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"client config is not valid TOML: {exc}") from exc

    client = raw.get("client", {})
    client_id = str(client.get("id", ""))
    client_key = str(client.get("key", ""))
    default_host = str(client.get("default_host", ""))
    default_workspace = str(client.get("default_workspace", ""))
    reconnect_max_retries = int(client.get("reconnect_max_retries", 5))
    reconnect_backoff_seconds = float(client.get("reconnect_backoff_seconds", 0.25))
    reconnect_backoff_max_seconds = float(client.get("reconnect_backoff_max_seconds", 3.0))
    hosts: dict[str, ClientHost] = {}
    for name, value in raw.get("hosts", {}).items():
        if not isinstance(value, dict):
            continue
        url = str(value.get("url", ""))
        if not url:
            continue
        host_client_id = str(value.get("client_id", client_id))
        host_key = str(value.get("key", client_key))
        hosts[str(name)] = ClientHost(
            name=str(name),
            url=url,
            client_id=host_client_id,
            key=host_key,
            # host_id defaults to the [hosts.<name>] section key, so a config
            # whose section is already named after the host needs no separate
            # host_id line. Set it explicitly only to label the section
            # differently from the host's own [host].id.
            host_id=str(value.get("host_id") or name),
            reconnect_max_retries=int(
                value.get("reconnect_max_retries", reconnect_max_retries)
            ),
            reconnect_backoff_seconds=float(
                value.get("reconnect_backoff_seconds", reconnect_backoff_seconds)
            ),
            reconnect_backoff_max_seconds=float(
                value.get("reconnect_backoff_max_seconds", reconnect_backoff_max_seconds)
            ),
        )
    return ClientConfig(
        path=cfg_path,
        id=client_id,
        key=client_key,
        default_host=default_host,
        hosts=hosts,
        default_workspace=default_workspace,
    )


def write_new_client_config(path: Path, *, host_name: str, url: str) -> ClientConfig:
    client_id = "client_" + secrets.token_hex(8)
    key = secrets.token_urlsafe(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = (
        "[client]\n"
        f'id = "{client_id}"\n'
        f'key = "{key}"\n'
        f'default_host = "{host_name}"\n'
        "reconnect_max_retries = 5\n"
        "reconnect_backoff_seconds = 0.25\n"
        "reconnect_backoff_max_seconds = 3.0\n"
        "\n"
        f"[hosts.{host_name}]\n"
        f'url = "{url}"\n'
        # host_id is implied by the section name here, so it is omitted.
    )
    path.write_text(text)
    return load_client_config(path)


def set_client_default_workspace(path: Path, workspace_id: str) -> None:
    """Set ``default_workspace`` inside the ``[client]`` section of the config.

    The edit is scoped to the ``[client]`` section so a combined config (one file
    holding both ``[client]`` and the host's ``[exec]``) never has its host-side
    ``[exec].default_workspace`` touched. Replaces an existing value or inserts
    the key, creating a ``[client]`` section if there is none.
    """
    text = path.read_text()
    line = f'default_workspace = "{_toml_escape(workspace_id)}"'
    header = re.search(r"(?m)^\[client\]\s*$", text)
    if header is None:
        separator = "" if text == "" or text.endswith("\n") else "\n"
        path.write_text(f"{text}{separator}\n[client]\n{line}\n")
        return
    body_start = header.end()
    nxt = re.search(r"(?m)^\[[^\]]+\]\s*$", text[body_start:])
    body_end = body_start + nxt.start() if nxt else len(text)
    body = text[body_start:body_end]
    new_body, replaced = re.subn(
        r"(?m)^\s*default_workspace\s*=.*$", lambda _m: line, body, count=1
    )
    if replaced:
        text = text[:body_start] + new_body + text[body_end:]
    else:
        insert_at = body_start
        if insert_at < len(text) and text[insert_at] == "\n":
            insert_at += 1
        text = text[:insert_at] + line + "\n" + text[insert_at:]
    path.write_text(text)


def unset_client_default_workspace(path: Path) -> bool:
    """Remove ``default_workspace`` from the ``[client]`` section.

    Returns True if a value was removed, False if none was set. Scoped to the
    ``[client]`` section so a combined config's host-side ``[exec]`` is untouched.
    """
    text = path.read_text()
    header = re.search(r"(?m)^\[client\]\s*$", text)
    if header is None:
        return False
    body_start = header.end()
    nxt = re.search(r"(?m)^\[[^\]]+\]\s*$", text[body_start:])
    body_end = body_start + nxt.start() if nxt else len(text)
    body = text[body_start:body_end]
    new_body, removed = re.subn(
        r"(?m)^[ \t]*default_workspace[ \t]*=.*\n?", "", body, count=1
    )
    if not removed:
        return False
    path.write_text(text[:body_start] + new_body + text[body_end:])
    return True


def _toml_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')
