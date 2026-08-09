"""Load valet's local config.

The config file is not committed (see .gitignore). It says where the socket
lives, which files hold secret values to redact, and the (currently permissive)
execution policy. Everything is optional with sensible defaults so valet is
usable out of the box.
"""
from __future__ import annotations

import os
import re
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
    # Default environment variables applied to every command (per-command env
    # overrides these). `$VALET_WORKSPACE` in a value expands to the workspace
    # root, so e.g. AWS_SHARED_CREDENTIALS_FILE can point inside the workspace.
    env: dict[str, str] = field(default_factory=dict)


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
class WorkspaceConfig:
    """One workspace: its resolved exec/redaction/policy settings.

    A workspace is a named directory the agent's commands are confined to.
    ``exec.workspace`` holds its resolved ``path``. The exec/redaction/policy
    here are the top-level defaults with any ``[workspaces.<id>.*]`` overrides
    already merged in, so the broker can use them directly.
    """
    id: str
    exec: ExecConfig = field(default_factory=ExecConfig)
    redaction: RedactionConfig = field(default_factory=RedactionConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)


DEFAULT_WORKSPACE_ID = "default"


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
    # Which workspace requests use when they name none. The exec/redaction/policy
    # above are the shared defaults; ``workspaces`` holds the per-id resolved
    # configs. When ``workspaces`` is empty, ``resolve_workspaces`` synthesises a
    # single default workspace from the defaults above.
    default_workspace: str = DEFAULT_WORKSPACE_ID
    workspaces: dict[str, WorkspaceConfig] = field(default_factory=dict)


def resolve_workspaces(cfg: BrokerConfig) -> dict[str, WorkspaceConfig]:
    """The effective workspace map for a config.

    Uses ``cfg.workspaces`` when populated; otherwise synthesises one default
    workspace from the top-level exec/redaction/policy defaults so a config (or
    a directly-built ``BrokerConfig``) with no ``[workspaces.*]`` sections still
    works as a single-workspace host.
    """
    if cfg.workspaces:
        return dict(cfg.workspaces)
    wid = cfg.default_workspace or DEFAULT_WORKSPACE_ID
    return {wid: WorkspaceConfig(id=wid, exec=cfg.exec,
                                 redaction=cfg.redaction, policy=cfg.policy)}


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

    # `[exec].workspace` was replaced by per-workspace `[workspaces.<id>].path`.
    # Reject the old key rather than silently synthesising a workspace from it,
    # so a legacy config fails loudly (in `valet doctor` and every other command)
    # instead of appearing healthy.
    if "workspace" in exec_:
        raise ConfigError(
            "[exec].workspace is no longer supported. Define a workspace instead:\n"
            "  [workspaces.default]\n"
            '  path = "<your workspace dir>"\n'
            'and set [exec].default_workspace = "default". '
            "Run `valet workspaces add <id> <dir>` or see config.example.toml."
        )
    # The workspace table is plural (`[workspaces.<id>]`, like `[identity.clients]`).
    # A singular `[workspace.*]` would be silently ignored, so flag it.
    if "workspace" in raw:
        raise ConfigError(
            "use [workspaces.<id>] (plural), not [workspace.<id>]"
        )

    # A stable salt keeps redaction tags comparable across runs; if unset we
    # generate an ephemeral one so the tool works with zero setup.
    salt = broker.get("fingerprint_salt", "")
    if not salt or salt.startswith("CHANGE_ME"):
        salt = _secrets.token_urlsafe(24)

    # Top-level [exec]/[redaction]/[policy] are the shared defaults for every
    # workspace; each [workspaces.<id>.*] section overrides them per key.
    default_exec = _parse_exec_table(exec_, ExecConfig(), path=None)
    default_redaction = _parse_redaction_table(red, RedactionConfig())
    default_policy = _parse_policy_table(pol, PolicyConfig())

    default_workspace = str(exec_.get("default_workspace", DEFAULT_WORKSPACE_ID))
    workspaces = _load_workspaces(
        raw.get("workspaces", {}),
        default_exec, default_redaction, default_policy,
    )
    if not workspaces:
        # No [workspaces.*] sections at all: a single, path-less default workspace
        # (no directory jail) built from the shared defaults. This is the valid
        # "run anywhere" config; a legacy [exec].workspace was already rejected.
        workspaces = {
            default_workspace: WorkspaceConfig(
                id=default_workspace, exec=default_exec,
                redaction=default_redaction, policy=default_policy,
            )
        }
    if default_workspace not in workspaces:
        raise ConfigError(
            f"[exec].default_workspace = {default_workspace!r} but no "
            f"[workspaces.{default_workspace}] section is defined"
        )

    return BrokerConfig(
        socket_path=_expand(broker.get("socket_path", "~/.valet/broker.sock")),
        timeout_seconds=int(broker.get("timeout_seconds", 60)),
        fingerprint_salt=salt,
        exec=default_exec,
        redaction=default_redaction,
        policy=default_policy,
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
        default_workspace=default_workspace,
        workspaces=workspaces,
    )


def _parse_exec_table(table: dict, base: ExecConfig, *, path: object) -> ExecConfig:
    """Parse an [exec] (or [workspaces.<id>.exec]) table over ``base`` defaults.

    ``path`` (a workspace's ``path``) wins for the workspace directory; env
    tables merge over the base env per-key.
    """
    if path is not None:
        workspace = path
    else:
        workspace = table.get("workspace", base.workspace)
    if "sandbox_profile" in table:
        sandbox = table["sandbox_profile"]
        sandbox_profile = _expand(sandbox) if sandbox else None
    else:
        sandbox_profile = base.sandbox_profile
    env = dict(base.env)
    env.update(_load_exec_env(table.get("env", {})))
    return ExecConfig(
        workspace=_expand(str(workspace)) if workspace else None,
        shell=bool(table.get("shell", base.shell)),
        sandbox_profile=sandbox_profile,
        env=env,
    )


def _parse_redaction_table(table: dict, base: RedactionConfig) -> RedactionConfig:
    return RedactionConfig(
        secret_sources=(
            tuple(_expand(s) for s in table["secret_sources"])
            if "secret_sources" in table else base.secret_sources
        ),
        cwd_secret_files=(
            tuple(table["cwd_secret_files"])
            if "cwd_secret_files" in table else base.cwd_secret_files
        ),
        extra_values=(
            tuple(table["extra_values"])
            if "extra_values" in table else base.extra_values
        ),
        redact_suspected=bool(table.get("redact_suspected", base.redact_suspected)),
        redact_high_entropy=bool(table.get("redact_high_entropy", base.redact_high_entropy)),
    )


def _parse_policy_table(table: dict, base: PolicyConfig) -> PolicyConfig:
    return PolicyConfig(
        allow=tuple(table["allow"]) if "allow" in table else base.allow,
        deny=tuple(table["deny"]) if "deny" in table else base.deny,
        deny_read_paths=(
            tuple(table["deny_read_paths"])
            if "deny_read_paths" in table else base.deny_read_paths
        ),
        enforce_workspace_reads=bool(
            table.get("enforce_workspace_reads", base.enforce_workspace_reads)
        ),
        enforce_workspace_writes=bool(
            table.get("enforce_workspace_writes", base.enforce_workspace_writes)
        ),
    )


def _load_workspaces(
    raw: object,
    default_exec: ExecConfig,
    default_redaction: RedactionConfig,
    default_policy: PolicyConfig,
) -> dict[str, WorkspaceConfig]:
    """Build the workspace map from [workspaces.<id>] sections.

    Each section's ``path`` sets the workspace directory; its optional
    ``[workspaces.<id>.exec]`` / ``.policy`` / ``.redaction`` sub-tables override
    the shared defaults per key.
    """
    if not isinstance(raw, dict):
        return {}
    workspaces: dict[str, WorkspaceConfig] = {}
    for wid, table in raw.items():
        if not isinstance(table, dict):
            continue
        path = table.get("path")
        if not path:
            raise ConfigError(f"[workspaces.{wid}] must set a 'path'")
        workspaces[str(wid)] = WorkspaceConfig(
            id=str(wid),
            exec=_parse_exec_table(table.get("exec", {}), default_exec, path=path),
            redaction=_parse_redaction_table(table.get("redaction", {}), default_redaction),
            policy=_parse_policy_table(table.get("policy", {}), default_policy),
        )
    return workspaces


def _load_exec_env(raw: object) -> dict[str, str]:
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError("[exec].env must be a table of NAME = \"value\" pairs")
    env: dict[str, str] = {}
    for key, value in raw.items():
        name = str(key)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ConfigError(f"[exec].env: {name!r} is not a valid variable name")
        env[name] = str(value)
    return env


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
