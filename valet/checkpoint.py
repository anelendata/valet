"""Host-side storage for the ``checkpoint.*`` ops: a hand-off note between agent
sessions, kept in the workspace.

An agent's context window is finite and its process can die without warning, so
it writes down where a task stands (``checkpoint.create``) and the next session
picks it up (``checkpoint.resume``). The layout, relative to the workspace root::

    checkpoint/<YYYY-MM-DD-HH-MM-SS>-<brief-title>.md          the current one
    checkpoint/archive/<YYYY-MM-DD-HH-MM-SS>-<brief-title>.md  superseded / read

Writing a new checkpoint archives the current one; resuming reads the latest and
archives it, so a checkpoint is handed to exactly one successor; archiving moves
the current one away without reading it. Nothing is ever deleted.

The directory is an ordinary part of the workspace, so the destination clears
the same rules as ``files.push`` (:class:`valet.files.TransferGuard`), and every
file is opened and moved through directory descriptors walked down from the root
without following symlinks — a ``checkpoint`` symlinked elsewhere cannot carry a
write or a rename out of the workspace.
"""
from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from .errors import CommandError, PolicyError, ValidationError
from .files import TransferGuard, _open_parent, read_file, write_file

CHECKPOINT_DIR = "checkpoint"
ARCHIVE_DIR = "archive"
# A checkpoint is a page of notes, not a file transfer: it travels as JSON text
# and is printed whole into the next agent's context.
CHECKPOINT_MAX_BYTES = 1024 * 1024
_SLUG_MAX_WORDS = 6
_SLUG_MAX_CHARS = 48
_STAMP_FORMAT = "%Y-%m-%d-%H-%M-%S"


@dataclass(frozen=True)
class Entry:
    name: str
    mtime_ns: int
    size: int


def slugify(text: str) -> str:
    """A very brief, filename-safe title: ``Fix the login bug!`` -> ``fix-the-login-bug``."""
    words = re.findall(r"[a-z0-9]+", text.casefold())[:_SLUG_MAX_WORDS]
    slug = "-".join(words)[:_SLUG_MAX_CHARS].strip("-")
    return slug or "checkpoint"


def title_from_content(content: str) -> str:
    """The first non-empty line, without its Markdown heading marks."""
    for line in content.splitlines():
        line = line.strip().lstrip("#").strip()
        if line:
            return line
    return ""


def _virtual(rel: str) -> str:
    return "./" + rel


class CheckpointStore:
    """Checkpoints for one workspace, guarded by its transfer rules."""

    def __init__(self, guard: TransferGuard) -> None:
        self.guard = guard
        self.root = guard.root

    # -- listing -----------------------------------------------------------------

    def current(self) -> list[Entry]:
        """Current checkpoints, oldest first (normally zero or one)."""
        return self._list(CHECKPOINT_DIR)

    def archived_count(self) -> int:
        return len(self._list(os.path.join(CHECKPOINT_DIR, ARCHIVE_DIR)))

    def latest(self) -> Optional[Entry]:
        entries = self.current()
        return entries[-1] if entries else None

    def _list(self, rel_dir: str) -> list[Entry]:
        try:
            dir_fd = self._open_dir(rel_dir, create=False)
        except (ValidationError, PolicyError):
            return []
        try:
            entries = []
            for name in os.listdir(dir_fd):
                if name.startswith(".") or not name.endswith(".md"):
                    continue
                try:
                    st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode):
                    entries.append(Entry(name, st.st_mtime_ns, st.st_size))
        finally:
            os.close(dir_fd)
        # The timestamp prefix sorts by creation; mtime orders a hand-dropped file.
        return sorted(entries, key=lambda e: (_stamp_key(e), e.name))

    # -- operations --------------------------------------------------------------

    def create(self, content: str, title: str | None = None,
               now: datetime | None = None) -> tuple[str, list[str]]:
        """Write a new current checkpoint, archiving any existing one first.

        Returns ``(virtual path written, virtual paths archived)``.
        """
        data = content.encode("utf-8")
        if not content.strip():
            raise ValidationError("checkpoint is empty")
        if len(data) > CHECKPOINT_MAX_BYTES:
            raise ValidationError(
                f"checkpoint is {len(data)} bytes, over the "
                f"{CHECKPOINT_MAX_BYTES // 1024} KiB limit")
        stamp = (now or datetime.now()).strftime(_STAMP_FORMAT)
        slug = slugify(title or title_from_content(content))
        # Check the destination before archiving, so a refusal moves nothing.
        self.guard.check_push(*self.guard.resolve(
            os.path.join(CHECKPOINT_DIR, f"{stamp}-{slug}.md")))
        archived = self.archive()
        name = self._free_name(CHECKPOINT_DIR, f"{stamp}-{slug}")
        rel = os.path.join(CHECKPOINT_DIR, name)
        lexical, real = self.guard.resolve(rel)
        self.guard.check_push(lexical, real)
        write_file(self.root, real, data, 0o644, overwrite=False)
        return _virtual(rel), archived

    def resume(self, redact) -> dict:
        """Read the latest checkpoint and archive it.

        ``redact`` maps the text to what the client may see. When it withholds the
        whole text the checkpoint stays current — it has not been handed over.
        """
        entry = self.latest()
        if entry is None:
            raise ValidationError("no checkpoint to resume")
        rel = os.path.join(CHECKPOINT_DIR, entry.name)
        lexical, real = self.guard.resolve(rel)
        self.guard.check_common(lexical, real)
        content, _st = read_file(self.root, real, CHECKPOINT_MAX_BYTES)
        text = redact(content.decode("utf-8", errors="replace"))
        withheld = text is None
        archived = None if withheld else self._move_to_archive(entry.name)
        return {
            "path": _virtual(rel),
            "name": entry.name,
            "content": text,
            "bytes_read": len(content),
            "withheld": withheld,
            "archived_to": archived,
            "remaining": len(self.current()),
        }

    def archive(self) -> list[str]:
        """Move every current checkpoint into the archive."""
        return [self._move_to_archive(e.name) for e in self.current()]

    # -- helpers -----------------------------------------------------------------

    def _move_to_archive(self, name: str) -> str:
        src_rel = os.path.join(CHECKPOINT_DIR, name)
        lexical, real = self.guard.resolve(src_rel)
        self.guard.check_common(lexical, real)
        archive_rel = os.path.join(CHECKPOINT_DIR, ARCHIVE_DIR)
        dest_name = self._free_name(archive_rel, name[:-len(".md")])
        dest_rel = os.path.join(archive_rel, dest_name)
        d_lexical, d_real = self.guard.resolve(dest_rel)
        self.guard.check_push(d_lexical, d_real)

        src_fd, src_name = _open_parent(self.root, real, create=False)
        try:
            dst_fd = self._open_dir(archive_rel, create=True)
            try:
                st = os.stat(src_name, dir_fd=src_fd, follow_symlinks=False)
                if not stat.S_ISREG(st.st_mode):
                    raise PolicyError("checkpoint is not a regular file")
                os.rename(src_name, dest_name, src_dir_fd=src_fd, dst_dir_fd=dst_fd)
            except OSError as exc:
                raise CommandError("could not archive the checkpoint") from exc
            finally:
                os.close(dst_fd)
        finally:
            os.close(src_fd)
        return _virtual(dest_rel)

    def _free_name(self, rel_dir: str, stem: str) -> str:
        """``stem.md``, or ``stem-2.md``... when that name is taken."""
        taken = set()
        try:
            dir_fd = self._open_dir(rel_dir, create=False)
        except (ValidationError, PolicyError):
            dir_fd = None
        if dir_fd is not None:
            try:
                taken = set(os.listdir(dir_fd))
            finally:
                os.close(dir_fd)
        name, n = f"{stem}.md", 2
        while name in taken:
            name, n = f"{stem}-{n}.md", n + 1
        return name

    def _open_dir(self, rel_dir: str, *, create: bool) -> int:
        """An fd for ``root/rel_dir``, walked down without following symlinks."""
        lexical, real = self.guard.resolve(rel_dir)
        if create:
            self.guard.check_push(lexical, real)
        # _open_parent opens everything but the last component; add a dummy leaf.
        parent_fd, leaf = _open_parent(self.root, os.path.join(real, "x"), create=create)
        del leaf
        return parent_fd


_STAMP_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})")


def _stamp_key(entry: Entry) -> str:
    m = _STAMP_RE.match(entry.name)
    if m:
        return m.group(1)
    return datetime.fromtimestamp(entry.mtime_ns / 1e9).strftime(_STAMP_FORMAT)
