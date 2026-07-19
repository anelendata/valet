"""Execution policy — command allow/deny and path bans.

Two kinds of constraint, both off unless configured (valet stays permissive by
default):

  - ``deny`` — program-name deny list (e.g. ``curl``, ``rm``).
  - ``deny_read_paths`` — glob patterns of files a command may not reference,
    so it cannot reveal their content. Supports ``**`` (any depth), ``*``, and
    ``?``. Example: ``**/.env`` bans reading any ``.env`` no matter where it
    sits; ``~/.aws/**`` bans anything under ``~/.aws``.

The path ban is **best-effort static analysis** of the command line: it splits
on shell operators (``;`` ``&&`` ``||`` ``|`` ``&`` ``(`` ``)`` and newlines),
tracks ``cd``/``pushd`` so a token is resolved against the directory in effect
where it appears, and refuses if any token resolves to an existing file matching
a banned glob. This catches the realistic reveals — ``cat``/``less``/``grep`` a
path, including after a ``cd``. It cannot catch a program that opens the file
via a computed path (variable expansion, ``eval``, ``$(...)``, base64) or that
reads it internally without naming it. For a hard guarantee, content redaction
(valet/sanitize.py) is the backstop, and OS-level sandboxing would be required
to stop a determined reader.

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

# Tokens made up entirely of these characters are shell control operators and
# act as sub-command separators (";", "&&", "||", "|", "&", "(", ")", "<", ">").
_OPERATOR_CHARS = set(";&|()<>")


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
        effective_cwd = cwd
        for sub in _split_subcommands(cmd):
            if not sub:
                continue

            if self.deny and os.path.basename(sub[0]) in self.deny:
                raise PolicyError("command is on the deny list")

            if self.deny_read_paths:
                for tok in sub:
                    if self._is_denied_path(tok, effective_cwd):
                        raise PolicyError("command references a denied path")

            # Track directory changes so later sub-commands resolve correctly.
            if sub[0] in ("cd", "pushd") and len(sub) >= 2:
                effective_cwd = self._resolve(sub[1], effective_cwd)

        # allow-list and workspace write-jail intentionally not enforced yet.
        return

    def _resolve(self, token: str, cwd: Optional[str]) -> str:
        path = os.path.expanduser(os.path.expandvars(token))
        if cwd and not os.path.isabs(path):
            path = os.path.join(cwd, path)
        return os.path.normpath(path)

    def _is_denied_path(self, token: str, cwd: Optional[str]) -> bool:
        path = self._resolve(token, cwd)
        # Only ban a real file — if nothing exists at the path there is no
        # content to reveal, and this avoids false positives on tokens that
        # merely look like a path (e.g. a grep pattern).
        if not os.path.exists(path):
            return False
        abspath = os.path.abspath(path)
        return any(
            _compile(pattern).match(abspath) is not None
            for pattern in self.deny_read_paths
        )


def _split_subcommands(cmd: Command) -> list[list[str]]:
    """Split a command into sub-commands (token lists) on shell operators.

    An argv list is a single sub-command. A shell string is lexed with operator
    awareness; newlines also separate sub-commands.
    """
    if isinstance(cmd, (list, tuple)):
        return [[str(t) for t in cmd]]

    subs: list[list[str]] = []
    for line in cmd.splitlines():
        for tokens in _split_line(line):
            subs.append(tokens)
    return subs


def _split_line(line: str) -> list[list[str]]:
    try:
        lex = shlex.shlex(line, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:
        tokens = line.split()

    subs: list[list[str]] = []
    cur: list[str] = []
    for tok in tokens:
        if tok and set(tok) <= _OPERATOR_CHARS:  # a pure-operator token
            if cur:
                subs.append(cur)
                cur = []
        else:
            cur.append(tok)
    if cur:
        subs.append(cur)
    return subs


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
