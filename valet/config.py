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
    # Shell execution is disabled by default. Set shell=true explicitly only for
    # trusted hosts that need shell syntax.
    shell: bool = False
    # Optional OS sandbox: path to a macOS sandbox-exec (.sb) profile. When set,
    # every command is wrapped with `sandbox-exec -D WORKSPACE=<workspace> -f
    # <profile>`, giving a real kernel boundary. Requires [exec].workspace.
    sandbox_profile: Optional[str] = None


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
    # Empty allow == allow everything not otherwise denied. Set a non-empty list
    # to switch to default-deny: only these command names may run.
    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()
    # Glob patterns of files a command may not reference (supports ** / * / ?).
    deny_read_paths: tuple[str, ...] = ()
    # Confine command-line paths to the workspace. Both default on: reads reject
    # existing paths outside it, writes reject path-like targets outside it.
    enforce_workspace_reads: bool = True
    enforce_workspace_writes: bool = True


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
    lan: bool = False
    listen: str = "127.0.0.1:8766"


@dataclass(frozen=True)
class ClientIdentity:
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
    audit: AuditConfig = field(default_factory=AuditConfig)
    host: HostConfig = field(default_factory=HostConfig)
    identity: IdentityConfig = field(default_factory=IdentityConfig)


def default_config_path() -> Path:
    """Resolve the config path when ``-c`` is not given.

    ``$VALET_CONFIG`` wins if set. Otherwise the first existing of
    ``~/.valet/config.toml`` (the canonical install location) then
    ``<repo>/config.toml`` (a dev checkout) is used; if neither exists,
    ``~/.valet/config.toml`` is returned so the not-found message names it.
    """
    env = os.environ.get(DEFAULT_CONFIG_ENV)
    if env:
        return Path(_expand(env))
    user = Path(_expand(f"~/.valet/{DEFAULT_CONFIG_NAME}"))
    repo = Path(__file__).resolve().parent.parent / DEFAULT_CONFIG_NAME
    for candidate in (user, repo):
        if candidate.exists():
            return candidate
    return user


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
            shell=bool(exec_.get("shell", False)),
            sandbox_profile=(
                _expand(exec_["sandbox_profile"])
                if exec_.get("sandbox_profile") else None
            ),
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
            enforce_workspace_reads=bool(pol.get("enforce_workspace_reads", True)),
            enforce_workspace_writes=bool(pol.get("enforce_workspace_writes", True)),
        ),
        audit=AuditConfig(
            log_path=_expand(str(audit.get("log_path", ""))),
            console=bool(audit.get("console", True)),
        ),
        host=HostConfig(
            id=str(host.get("id", "local")),
            lan=bool(host.get("lan", False)),
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
        # The section name is the client id used for auth lookup. A legacy
        # ``name`` field is tolerated for backward compatibility but ignored.
        clients[str(client_id)] = ClientIdentity(key=key)
    return clients
