"""Host-side guards for the ``files.*`` ops (agent <-> workspace file transfer).

Both directions share the path rules below (:meth:`TransferGuard.check_common`);
push adds the program-shadowing rules, pull adds file-identity and content
checks (:func:`read_file`, :func:`check_not_secret_file`, :func:`check_content`).

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
import re
import secrets
import shutil
import stat
import unicodedata
from collections import Counter
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


# -- pull: race-safe read and content inspection ------------------------------------

# Same sniff as the redaction index: a NUL in the head means binary.
_BINARY_SNIFF_BYTES = 8192
# Secret shapes that are unambiguous even inside binary data.
_BINARY_SECRET_RES = (
    re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(rb"(?:AKIA|ASIA)[0-9A-Z]{16}"),
)
_REDACTION_TAG_RE = re.compile(r"\[REDACTED:([a-z_-]+)")


def read_file(root: str, real: str, max_bytes: int) -> tuple[bytes, os.stat_result]:
    """Read ``real`` (inside ``root``) without following symlinks.

    Refuses anything but a regular file with a single link: a FIFO would block,
    a device or socket is not a file, and a hard link is another name for a file
    whose other name might be protected (``ln .secrets/key notes.txt``).
    """
    dir_fd, name = _open_parent(root, real, create=False)
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(name, flags, dir_fd=dir_fd)
        except FileNotFoundError as exc:
            raise ValidationError("no such file") from exc
        except OSError as exc:
            raise PolicyError("path is not a regular file") from exc
    finally:
        os.close(dir_fd)
    try:
        st = os.fstat(fd)
        if stat.S_ISDIR(st.st_mode):
            raise ValidationError("path is a directory")
        if not stat.S_ISREG(st.st_mode):
            raise PolicyError("path is not a regular file")
        if st.st_nlink != 1:
            raise PolicyError("path is a hard link to another file")
        if st.st_size > max_bytes:
            raise ValidationError(
                f"file exceeds the {max_bytes // (1024 * 1024)} MiB transfer limit")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValidationError(
                    f"file exceeds the {max_bytes // (1024 * 1024)} MiB transfer limit")
            chunks.append(chunk)
        return b"".join(chunks), st
    finally:
        os.close(fd)


def check_not_secret_file(st: os.stat_result, content: bytes,
                          secret_files: Iterable[str]) -> None:
    """Refuse a file that *is*, or is a byte-for-byte copy of, a secret source.

    Identity (device + inode) catches an alias the path rules missed; an exact
    copy (``cp .secrets/key out.bin``) is caught by comparing against secret
    files of the same size — which also covers binary and >1 MB secret files
    that contribute no redaction values.
    """
    size = len(content)
    for path in secret_files:
        try:
            sst = os.stat(path)
        except OSError:
            continue
        if (sst.st_dev, sst.st_ino) == (st.st_dev, st.st_ino):
            raise PolicyError("file is a secret source")
        if sst.st_size == size and size > 0:
            try:
                with open(path, "rb") as fh:
                    same = fh.read(size + 1) == content
            except OSError:
                continue
            if same:
                raise PolicyError("file is a copy of a secret source")


def is_binary(content: bytes) -> bool:
    if b"\x00" in content[:_BINARY_SNIFF_BYTES]:
        return True
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def check_content(content: bytes, redactor: Any, *, allow_binary: bool) -> None:
    """Refuse content valet would redact, rather than return a doctored file.

    Text is run through the workspace's full redactor; any change — a known
    secret value, a suspected secret, a key/token shape, an identifier valet
    de-identifies (ARN, account id, email), or the real host path — refuses the
    pull, so a pull never reveals what ``valet run -- cat`` would mask. The
    refusal names only the categories found, never the values.

    Binary content cannot be scanned meaningfully (compressed or encoded data
    hides anything), so it is refused unless ``allow_binary``; when allowed it
    is still searched for every known secret value and unambiguous key shapes.
    """
    if is_binary(content):
        if not allow_binary:
            raise PolicyError(
                "binary file pull is disabled ([policy].allow_pull_binary)")
        for value in redactor.secret_values:
            if value and value.encode("utf-8") in content:
                raise PolicyError("file contains a known secret value")
        if any(r.search(content) for r in _BINARY_SECRET_RES):
            raise PolicyError("file contains a private key or access key id")
        return
    text = content.decode("utf-8")
    redacted = redactor.redact(text)
    if redacted == text:
        return
    found = sorted(Counter(_REDACTION_TAG_RE.findall(redacted))
                   - Counter(_REDACTION_TAG_RE.findall(text)))
    what = ", ".join(found) if found else "host path"
    raise PolicyError(f"file contains content valet redacts ({what})")
