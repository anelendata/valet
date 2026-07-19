"""Execution policy — command allow/deny and path bans.

Two kinds of constraint, both off unless configured (v0.2 stays permissive by
default):

  - ``deny`` — program-name deny list (e.g. ``curl``, ``rm``).
  - ``deny_read_paths`` — glob patterns of files a command may not reference,
    so it cannot reveal their content. Supports ``**`` (any depth), ``*``, and
    ``?``. Example: ``**/.env`` bans reading any ``.env`` no matter where it
    sits; ``~/.aws/**`` bans anything under ``~/.aws``.

The path ban is coarse by nature: it looks at the *tokens of the command* and
refuses if one resolves to an existing file matching a banned glob. It catches
the explicit reveal cases (``cat``/``less``/``grep`` a path) — not a program
that opens the file internally without naming it. Content redaction
(valet/sanitize.py) remains the backstop for that.

Redaction is separate and always on; policy is about *whether a command may run
at all*.
"""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional, Union

from .config import PolicyConfig
from .errors import PolicyError

Command = Union[str, list[str]]


@dataclass(frozen=True)
class Policy:
    workspace: Optional[str] = None
    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()
    deny_read_paths: tuple[str, ...] = ()
    enforce_workspace_writes: bool = False

    @classmethod
    def from_config(cls, cfg: PolicyConfig, workspace: Optional[str]) -> "Policy":
        return cls(
            workspace=workspace,
            allow=tuple(cfg.allow),
            deny=tuple(cfg.deny),
            # Expand ~ / $VARS in patterns up front so absolute patterns like
            # ~/.aws/** compare against real absolute paths.
            deny_read_paths=tuple(
                os.path.expanduser(os.path.expandvars(p)) for p in cfg.deny_read_paths
            ),
            enforce_workspace_writes=cfg.enforce_workspace_writes,
        )

    def check(self, cmd: Command, cwd: Optional[str]) -> None:
        """Raise :class:`PolicyError` if ``cmd`` may not run."""
        tokens = _tokens(cmd)

        if self.deny and tokens:
            if os.path.basename(tokens[0]) in self.deny:
                raise PolicyError("command is on the deny list")

        if self.deny_read_paths:
            for tok in tokens:
                if self._is_denied_path(tok, cwd):
                    raise PolicyError("command references a denied path")

        # allow-list and workspace write-jail intentionally not enforced yet.
        return

    def _is_denied_path(self, token: str, cwd: Optional[str]) -> bool:
        # Resolve the token to a concrete path (as the shell would see it).
        path = os.path.expanduser(os.path.expandvars(token))
        if cwd and not os.path.isabs(path):
            path = os.path.join(cwd, path)
        path = os.path.normpath(path)

        # Only ban a real file — if nothing exists at the path, there is no
        # content to reveal, and this avoids false positives on tokens that
        # merely look like a path (e.g. a grep pattern).
        if not os.path.exists(path):
            return False

        abspath = os.path.abspath(path)
        return any(
            _compile(pattern).match(abspath) is not None
            for pattern in self.deny_read_paths
        )


def _tokens(cmd: Command) -> list[str]:
    if isinstance(cmd, (list, tuple)):
        return [str(t) for t in cmd]
    try:
        return shlex.split(cmd)
    except ValueError:
        return cmd.split()


@lru_cache(maxsize=256)
def _compile(pattern: str) -> re.Pattern[str]:
    """Compile a glob (with ``**``/``*``/``?``) into an anchored regex."""
    i, n = 0, len(pattern)
    out = ["(?s:"]
    while i < n:
        if pattern[i:i + 3] == "**/":
            out.append("(?:.*/)?")  # any number of leading directories
            i += 3
        elif pattern[i:i + 2] == "**":
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    out.append(r")\Z")
    return re.compile("".join(out))
