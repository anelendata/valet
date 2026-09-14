"""Host-side guards for the ``files.*`` ops (agent <-> workspace file transfer).

Pushing a file lets the agent place bytes on the host, so the destination check
goes further than "inside the workspace". A push may not:

  - land on a secret source (``redaction.secret_file_paths``) — overwriting a
    ``.env`` swaps the credentials trusted tools use, and a new file there feeds
    arbitrary values into the redaction index;
  - land on a ``policy.deny_read`` path — a file the agent is not meant to touch;
  - land in VCS internals (``.git/`` …) — hooks and ``core.*`` config run code
    the next time a trusted ``git`` command runs;
  - land in valet's own state (``config.toml``, ``~/.valet``, the socket, the
    audit log, the sandbox profile);
  - shadow a program: a file in the workspace ``bin/`` (searched before PATH)
    named like a program already on PATH, or a file anywhere named like an
    ``allow_exec`` entry (``valet run -- tools/aws`` passes an ``aws`` allowlist).

Path checks are case-insensitive and Unicode-normalised (macOS filesystems are
both) and are applied to the lexical *and* the symlink-resolved destination, so
neither ``.ENV`` nor a symlinked alias reaches a protected file.

The write itself walks the resolved path one directory at a time with
``O_NOFOLLOW``, so a directory swapped for a symlink after the check cannot
redirect the write outside the workspace.
"""
from __future__ import annotations

import os
import secrets
import shutil
import stat
import unicodedata
from dataclasses import dataclass
from typing import Any, Iterable

from .config import DEFAULT_CONFIG_NAME
from .errors import CommandError, PolicyError, ValidationError
from .globmatch import compile_glob

VCS_DIRS = frozenset({".git", ".hg", ".svn"})


def _fold(path: str) -> str:
    return unicodedata.normalize("NFC", path).casefold()


def _lineage(path: str) -> Iterable[str]:
    """``path`` and each of its ancestors, up to the filesystem root."""
    cur = path
    while True:
        yield cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return
        cur = parent


def _is_within(path: str, base: str) -> bool:
    p, b = _fold(path), _fold(base)
    return p == b or p.startswith(b.rstrip(os.sep) + os.sep)


@dataclass(frozen=True)
class TransferGuard:
    """Destination rules for one workspace. Build with :meth:`for_workspace`."""

    root: str
    secret_patterns: tuple[str, ...]
    deny_read_patterns: tuple[str, ...]
    protected_paths: tuple[str, ...]
    allow_exec: tuple[str, ...]
    search_path: str

    @classmethod
    def for_workspace(cls, ws: Any, cfg: Any) -> "TransferGuard":
        root = ws.root()
        if root is None:
            raise ValidationError("workspace path is not configured")
        secret = tuple(_anchor(p, root) for p in ws.redaction.secret_file_paths)
        # Policy matches deny_read against absolute paths as written; a relative
        # entry is also tried against the root so it cannot be sidestepped here.
        deny = []
        for p in ws.policy.deny_read:
            deny.append(p)
            if not os.path.isabs(p):
                deny.append(os.path.join(root, p))
        protected = [os.path.expanduser(cfg.socket_path),
                     os.path.expanduser("~/.valet")]
        if cfg.audit.log_path:
            protected.append(os.path.expanduser(cfg.audit.log_path))
        if ws.exec.sandbox_profile:
            protected.append(os.path.expanduser(ws.exec.sandbox_profile))
        search_path = ws.exec.env.get("PATH") or os.environ.get("PATH", "")
        return cls(
            root=root,
            secret_patterns=secret,
            deny_read_patterns=tuple(deny),
            protected_paths=tuple(p for p in protected if p),
            allow_exec=tuple(ws.policy.allow_exec),
            search_path=search_path,
        )

    # -- path resolution ---------------------------------------------------------

    def resolve(self, raw_path: Any) -> tuple[str, str]:
        """``(lexical, real)`` absolute paths for a workspace-virtual path.

        A leading ``~``/``/`` means the workspace root. No ``$VAR`` expansion: the
        path is the agent's, and expanding host variables would disclose them
        (``$HOME`` in the returned path) or reach outside the virtual layout.
        """
        target = str(raw_path or "").strip()
        if "\x00" in target:
            raise ValidationError("path contains a NUL byte")
        if target.startswith("~"):
            target = target[1:]
        target = target.lstrip("/")
        if not target:
            raise ValidationError("missing 'path'")
        lexical = os.path.normpath(os.path.join(self.root, target))
        real = os.path.realpath(lexical)
        for p in (lexical, real):
            if p != self.root and not p.startswith(self.root + os.sep):
                raise PolicyError("path is outside the workspace")
        return lexical, real

    # -- rules -------------------------------------------------------------------

    def check_common(self, lexical: str, real: str) -> None:
        """Rules shared by every transfer direction."""
        for p in (lexical, real):
            if os.path.basename(p).casefold() == DEFAULT_CONFIG_NAME.casefold():
                raise PolicyError("config.toml is protected")
        for p in (lexical, real):
            rel = os.path.relpath(p, self.root)
            if any(_fold(part) in VCS_DIRS for part in rel.split(os.sep)):
                raise PolicyError("version-control internals are protected")
        for p in (lexical, real):
            if any(_is_within(p, base) for base in self.protected_paths):
                raise PolicyError("valet state files are protected")
        if self._matches(lexical, real, self.secret_patterns):
            raise PolicyError(
                "path is a secret source (redaction.secret_file_paths)")
        if self._matches(lexical, real, self.deny_read_patterns):
            raise PolicyError("path is denied (policy.deny_read)")

    def check_push(self, lexical: str, real: str) -> None:
        self.check_common(lexical, real)
        name = os.path.basename(real)
        if self.allow_exec and _fold(name) in {_fold(n) for n in self.allow_exec}:
            raise PolicyError(
                "destination name shadows an allow_exec program")
        bin_dir = os.path.join(self.root, "bin")
        if any(_fold(os.path.dirname(p)) == _fold(bin_dir) for p in (lexical, real)):
            if shutil.which(name, path=self._path_without(bin_dir)):
                raise PolicyError(
                    "destination would shadow a program on PATH (workspace bin/)")

    def _path_without(self, bin_dir: str) -> str:
        keep = [d for d in self.search_path.split(os.pathsep)
                if d and _fold(os.path.realpath(d)) != _fold(bin_dir)]
        return os.pathsep.join(keep)

    @staticmethod
    def _matches(lexical: str, real: str, patterns: tuple[str, ...]) -> bool:
        """A pattern names a file, a directory (everything under it), or a glob —
        so the path *or any ancestor* matching is a hit."""
        if not patterns:
            return False
        compiled = [compile_glob(_fold(p)) for p in patterns]
        for p in (lexical, real):
            for anc in _lineage(_fold(p)):
                if any(c.match(anc) for c in compiled):
                    return True
        return False


def _anchor(pattern: str, root: str) -> str:
    expanded = os.path.expanduser(os.path.expandvars(pattern))
    return expanded if os.path.isabs(expanded) else os.path.join(root, expanded)


# -- race-safe filesystem access ---------------------------------------------------

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _open_parent(root: str, real: str, *, create: bool) -> tuple[int, str]:
    """Open ``real``'s parent by walking down from ``root`` without following
    symlinks. Returns ``(dir_fd, basename)``; the caller closes ``dir_fd``.

    ``real`` is already symlink-resolved, so every component is a plain directory
    at check time; one that has since become a symlink fails ``O_NOFOLLOW``.
    """
    rel = os.path.relpath(real, root)
    parts = [] if rel == "." else rel.split(os.sep)
    if not parts or ".." in parts:
        raise ValidationError("path is not a file inside the workspace")
    fd = os.open(root, _DIR_FLAGS)
    try:
        for part in parts[:-1]:
            try:
                nxt = os.open(part, _DIR_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise ValidationError("no such file") from None
                os.mkdir(part, 0o755, dir_fd=fd)
                nxt = os.open(part, _DIR_FLAGS, dir_fd=fd)
            except OSError as exc:
                # A symlink under O_NOFOLLOW fails with ELOOP (Linux) or ENOTDIR
                # (macOS): the path changed after it was checked.
                try:
                    is_link = stat.S_ISLNK(
                        os.stat(part, dir_fd=fd, follow_symlinks=False).st_mode)
                except OSError:
                    is_link = False
                if is_link or not isinstance(exc, NotADirectoryError):
                    raise PolicyError(
                        "path changed while it was being resolved") from exc
                raise ValidationError(
                    "a parent of the path is not a directory") from exc
            os.close(fd)
            fd = nxt
    except BaseException:
        os.close(fd)
        raise
    return fd, parts[-1]


def write_file(root: str, real: str, content: bytes, mode: int,
               *, overwrite: bool) -> bool:
    """Atomically write ``content`` to ``real`` (inside ``root``).

    Returns whether the file was newly created. Writes a temp file beside the
    destination, then renames it over; a hard link at the destination is replaced
    rather than written through.
    """
    dir_fd, name = _open_parent(root, real, create=True)
    tmp = None
    try:
        try:
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            existed = True
        except FileNotFoundError:
            existed = False
            st = None
        if st is not None and stat.S_ISDIR(st.st_mode):
            raise ValidationError("destination is a directory")
        if existed and not overwrite:
            raise ValidationError("destination exists (overwrite is disabled)")
        tmp = f".valet-push-{secrets.token_hex(8)}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(tmp, flags, 0o600, dir_fd=dir_fd)
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)
            os.fchmod(fh.fileno(), mode)
        os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        tmp = None
        return not existed
    except OSError as exc:
        raise CommandError("could not write the destination file") from exc
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp, dir_fd=dir_fd)
            except OSError:
                pass
        os.close(dir_fd)


def clamp_mode(raw: Any) -> int:
    """Permission bits for a pushed file: default 0644, at most 0755.

    setuid/setgid/sticky and group/other write are dropped — a pushed file never
    becomes privileged or writable by other local users.
    """
    if raw is None:
        return 0o644
    try:
        mode = raw if isinstance(raw, int) else int(str(raw), 8)
    except (TypeError, ValueError) as exc:
        raise ValidationError("mode must be octal permission bits") from exc
    return stat.S_IMODE(mode) & 0o755
