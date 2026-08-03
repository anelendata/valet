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
  - ``enforce_workspace_reads`` — refuse existing command-line paths and an
    explicit working directory when they resolve outside the workspace.

Redaction is separate and always on; policy is about *whether a command may run
at all*.

``config.toml`` is an exception: it is always protected. The broker refuses a
command that names a file with that basename, whether it exists (read) or not
(write target). This is deliberately not configurable.
"""
from __future__ import annotations

import os
import re
import shlex
from glob import glob, has_magic
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional, Union

from .config import DEFAULT_CONFIG_NAME, PolicyConfig
from .errors import PolicyError

Command = Union[str, list[str]]

# Tokens made up entirely of these characters are shell control operators and
# act as sub-command separators (";", "&&", "||", "|", "&", "(", ")", "<", ">").
_OPERATOR_CHARS = set(";&|()<>")


def _is_config_name(path: str) -> bool:
    """Match config.toml consistently on case-insensitive filesystems."""
    return os.path.basename(path).casefold() == DEFAULT_CONFIG_NAME.casefold()


@dataclass(frozen=True)
class Policy:
    workspace: Optional[str] = None
    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()
    deny_read_paths: tuple[str, ...] = ()
    enforce_workspace_reads: bool = False
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
            enforce_workspace_reads=cfg.enforce_workspace_reads,
            enforce_workspace_writes=cfg.enforce_workspace_writes,
        )

    def check(self, cmd: Command, cwd: Optional[str]) -> None:
        """Raise :class:`PolicyError` if ``cmd`` may not run."""
        effective_cwd = cwd
        if self.enforce_workspace_reads and self._is_outside_workspace(effective_cwd, None):
            raise PolicyError("working directory is outside the workspace")
        for sub in _split_subcommands(cmd):
            if not sub:
                continue

            # This guard is deliberately independent of PolicyConfig. Shell
            # redirects can become a token list of their own, so examine every
            # token rather than only command arguments.
            if any(self._is_protected_config_path(tok, effective_cwd) for tok in sub):
                raise PolicyError("config.toml is protected")

            if self.deny and os.path.basename(sub[0]) in self.deny:
                raise PolicyError("command is on the deny list")

            for tok in sub[1:]:
                if self.enforce_workspace_reads and self._is_outside_workspace(tok, effective_cwd):
                    raise PolicyError("command references a path outside the workspace")
                if self.deny_read_paths:
                    if self._is_denied_path(tok, effective_cwd):
                        raise PolicyError("command references a denied path")

            # Track directory changes so later sub-commands resolve correctly.
            if sub[0] in ("cd", "pushd") and len(sub) >= 2:
                effective_cwd = self._resolve(sub[1], effective_cwd)

        # Allow-list and workspace write-jail intentionally not enforced yet.
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

    def _is_protected_config_path(self, token: str, cwd: Optional[str]) -> bool:
        """Whether a token names valet's always-protected config filename.

        The file need not exist: shell redirections and ``touch`` can create a
        target, so a write attempt must be refused too.
        """
        path = self._resolve(token, cwd)
        if _is_config_name(path):
            return True
        # Shell globs are expanded after policy evaluation. Inspect existing
        # matches so `cat config.*` cannot expand to the protected file.
        return has_magic(path) and any(_is_config_name(match) for match in glob(path))

    def _is_outside_workspace(self, token: Optional[str], cwd: Optional[str]) -> bool:
        """Whether an existing path escapes the configured workspace."""
        if not self.workspace or not token:
            return False
        path = self._resolve(token, cwd)
        if not os.path.exists(path):
            return False
        workspace = os.path.realpath(os.path.expanduser(os.path.expandvars(self.workspace)))
        target = os.path.realpath(path)
        return target != workspace and not target.startswith(workspace + os.sep)


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
