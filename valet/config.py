"""Load valet's local config.

The config file is not committed (see .gitignore). It says where the socket
lives, which files hold secret values to redact, and the (currently permissive)
execution policy. Everything is optional with sensible defaults so valet is
usable out of the box.
"""
from __future__ import annotations

import os
import secrets as _secrets
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .errors import ConfigError

DEFAULT_CONFIG_ENV = "VALET_CONFIG"
DEFAULT_CONFIG_NAME = "config.toml"


def _expand(path: str) -> str:
    return os.path.expanduser(os.path.expandvars(path))


@dataclass(frozen=True)
class ExecConfig:
    # Default working directory for commands, and the future write-jail root.
    workspace: Optional[str] = None
    # Run through a shell by default (permissive shell-wrapper behavior).
    shell: bool = True


@dataclass(frozen=True)
class RedactionConfig:
    # Files whose *values* are loaded and blocked from all output.
    secret_sources: tuple[str, ...] = ()
    # Filenames auto-loaded from each command's cwd (e.g. project .env/.secrets).
    cwd_secret_files: tuple[str, ...] = (".env", ".secrets")
    # Extra literal strings to always redact.
    extra_values: tuple[str, ...] = ()
    # Heuristically mask values that *look* secret (sensitive key names, known
    # token shapes) even when valet does not know the exact value.
    redact_suspected: bool = True
    # Opt-in, noisy: mask long high-entropy tokens anywhere in output (catches
    # bare unknown secrets, but also some hashes/base64/IDs). Off by default.
    redact_high_entropy: bool = False


@dataclass(frozen=True)
class PolicyConfig:
    # Empty allow == allow everything (permissive v1). Reserved for future use.
    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()
    # Glob patterns of files a command may not reference (supports ** / * / ?).
    deny_read_paths: tuple[str, ...] = ()
    # When true, existing command-line paths must remain inside the workspace.
    enforce_workspace_reads: bool = False
    # When true (future), commands may not write outside the workspace.
    enforce_workspace_writes: bool = False


@dataclass(frozen=True)
class HttpConfig:
    # Loopback by default; set deliberately if you want another interface.
    host: str = "127.0.0.1"
    port: int = 8765
    # Required to serve HTTP. Keep it in config.toml, which is git-ignored.
    bearer_token: str = ""


@dataclass(frozen=True)
class AuditConfig:
    # Optional newline-delimited JSON audit log path. Empty means no file log.
    log_path: str = ""
    # Server adapters print human-readable audit events to stdout by default.
    console: bool = True


@dataclass(frozen=True)
class HostConfig:
    # Level 1 LAN host identity and WebSocket bind address.
    id: str = "local"
    listen: str = "127.0.0.1:8766"


@dataclass(frozen=True)
class ClientIdentity:
    name: str
    key: str


@dataclass(frozen=True)
class IdentityConfig:
    # Mapping of client_id -> shared client key for Level 1 challenge-response.
    clients: dict[str, ClientIdentity] = field(default_factory=dict)


@dataclass(frozen=True)
class BrokerConfig:
    socket_path: str
    timeout_seconds: int
    fingerprint_salt: str
    exec: ExecConfig = field(default_factory=ExecConfig)
    redaction: RedactionConfig = field(default_factory=RedactionConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    http: HttpConfig = field(default_factory=HttpConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    host: HostConfig = field(default_factory=HostConfig)
    identity: IdentityConfig = field(default_factory=IdentityConfig)


def default_config_path() -> Path:
    env = os.environ.get(DEFAULT_CONFIG_ENV)
    if env:
        return Path(_expand(env))
    return Path(__file__).resolve().parent.parent / DEFAULT_CONFIG_NAME


def load_config(path: Optional[str | os.PathLike] = None) -> BrokerConfig:
    cfg_path = Path(path) if path is not None else default_config_path()
    if not cfg_path.exists():
        raise ConfigError(
            f"config not found at {cfg_path}. Copy config.example.toml to "
            f"config.toml (or set {DEFAULT_CONFIG_ENV})."
        )
    try:
        with open(cfg_path, "rb") as fh:
            raw = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"config is not valid TOML: {exc}") from exc

    broker = raw.get("broker", {})
    exec_ = raw.get("exec", {})
    red = raw.get("redaction", {})
    pol = raw.get("policy", {})
    http = raw.get("http", {})
    audit = raw.get("audit", {})
    host = raw.get("host", {})
    identity = raw.get("identity", {})

    # A stable salt keeps redaction tags comparable across runs; if unset we
    # generate an ephemeral one so the tool works with zero setup.
    salt = broker.get("fingerprint_salt", "")
    if not salt or salt.startswith("CHANGE_ME"):
        salt = _secrets.token_urlsafe(24)

    workspace = exec_.get("workspace")
    return BrokerConfig(
        socket_path=_expand(broker.get("socket_path", "~/.valet/broker.sock")),
        timeout_seconds=int(broker.get("timeout_seconds", 60)),
        fingerprint_salt=salt,
        exec=ExecConfig(
            workspace=_expand(workspace) if workspace else None,
            shell=bool(exec_.get("shell", True)),
        ),
        redaction=RedactionConfig(
            secret_sources=tuple(_expand(s) for s in red.get("secret_sources", ())),
            cwd_secret_files=tuple(red.get("cwd_secret_files", (".env", ".secrets"))),
            extra_values=tuple(red.get("extra_values", ())),
            redact_suspected=bool(red.get("redact_suspected", True)),
            redact_high_entropy=bool(red.get("redact_high_entropy", False)),
        ),
        policy=PolicyConfig(
            allow=tuple(pol.get("allow", ())),
            deny=tuple(pol.get("deny", ())),
            deny_read_paths=tuple(pol.get("deny_read_paths", ())),
            enforce_workspace_reads=bool(pol.get("enforce_workspace_reads", False)),
            enforce_workspace_writes=bool(pol.get("enforce_workspace_writes", False)),
        ),
        http=HttpConfig(
            host=str(http.get("host", "127.0.0.1")),
            port=int(http.get("port", 8765)),
            bearer_token=str(http.get("bearer_token", "")),
        ),
        audit=AuditConfig(
            log_path=_expand(str(audit.get("log_path", ""))),
            console=bool(audit.get("console", True)),
        ),
        host=HostConfig(
            id=str(host.get("id", "local")),
            listen=str(host.get("listen", "127.0.0.1:8766")),
        ),
        identity=IdentityConfig(
            clients=_load_client_identities(identity.get("clients", {})),
        ),
    )


def _load_client_identities(raw: object) -> dict[str, ClientIdentity]:
    if not isinstance(raw, dict):
        return {}
    clients: dict[str, ClientIdentity] = {}
    for client_id, value in raw.items():
        if not isinstance(value, dict):
            continue
        key = str(value.get("key", ""))
        if not key:
            continue
        clients[str(client_id)] = ClientIdentity(
            name=str(value.get("name", client_id)),
            key=key,
        )
    return clients
