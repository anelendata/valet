"""Load and validate valet's local config, and enforce the allowlists.

The config file is never committed (see .gitignore); it maps public aliases to
real project directories and AWS profiles. All allowlist checks live here so
there is a single, auditable choke point.
"""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import SCHEDULE_SCOPES
from .errors import ConfigError, ValidationError

DEFAULT_CONFIG_ENV = "VALET_CONFIG"
DEFAULT_CONFIG_NAME = "config.toml"


def _expand(path: str) -> str:
    return os.path.expanduser(os.path.expandvars(path))


@dataclass(frozen=True)
class Project:
    alias: str
    project_dir: str
    workspace_dir: str
    aws_profile: Optional[str]
    stages: tuple[str, ...]
    secret_sources: tuple[str, ...]

    def check_stage(self, stage: str) -> str:
        if stage not in self.stages:
            # Do not echo the caller's value verbatim into a message that might
            # be logged widely; keep it terse. The allowed set is not secret.
            raise ValidationError(
                f"stage not allowed for project; allowed: {list(self.stages)}"
            )
        return stage


@dataclass(frozen=True)
class BrokerConfig:
    socket_path: str
    handoff_bin: str
    timeout_seconds: int
    fingerprint_salt: str
    projects: dict[str, Project] = field(default_factory=dict)

    # ---- allowlist accessors -------------------------------------------------

    def project(self, alias: str) -> Project:
        """Return the project for ``alias`` or reject it. Alias allowlist."""
        if not isinstance(alias, str) or alias not in self.projects:
            raise ValidationError("unknown project_alias")
        return self.projects[alias]

    @staticmethod
    def check_scope(scope: str) -> str:
        if scope not in SCHEDULE_SCOPES:
            raise ValidationError(
                f"invalid scope; allowed: {list(SCHEDULE_SCOPES)}"
            )
        return scope


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
    salt = broker.get("fingerprint_salt", "")
    if not salt or salt.startswith("CHANGE_ME"):
        raise ConfigError(
            "broker.fingerprint_salt is unset. Run `valet init` to generate one."
        )

    projects: dict[str, Project] = {}
    for alias, pj in raw.get("projects", {}).items():
        missing = [k for k in ("project_dir", "workspace_dir") if k not in pj]
        if missing:
            raise ConfigError(
                f"project '{alias}' is missing keys: {missing}"
            )
        projects[alias] = Project(
            alias=alias,
            project_dir=_expand(pj["project_dir"]),
            workspace_dir=_expand(pj["workspace_dir"]),
            aws_profile=pj.get("aws_profile"),
            stages=tuple(pj.get("stages", ("prod", "dev"))),
            secret_sources=tuple(
                _expand(s) for s in pj.get("secret_sources", ())
            ),
        )

    if not projects:
        raise ConfigError("config defines no [projects.<alias>] blocks")

    return BrokerConfig(
        socket_path=_expand(broker.get("socket_path", "~/.valet/broker.sock")),
        handoff_bin=broker.get("handoff_bin", "handoff"),
        timeout_seconds=int(broker.get("timeout_seconds", 60)),
        fingerprint_salt=salt,
        projects=projects,
    )
