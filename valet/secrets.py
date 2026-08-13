"""Load the *values* of known secrets so valet can block them from output.

This is what makes valet stronger than a regex scrubber: valet can read the
credential files the agent cannot, so it knows the exact literal strings that
must never appear in returned output. It extracts VALUES only (never keys), and
ignores anything too short to be meaningfully secret.

Supported source formats, detected by extension/content:
  - AWS credentials/config ini  (``[profile]`` sections, ``key = value``)
  - dotenv / .secrets           (``KEY=VALUE``, optional ``export``, quotes)
  - JSON                        (all string/number leaf values)
  - YAML (``.yaml``/``.yml``    (all scalar leaf values)
    and ``.secrets``)

Parsing is deliberately lenient and never raises on a malformed source: a
source we cannot read simply contributes no redaction values, and the generic
regex backstop in sanitize.py still applies.
"""
from __future__ import annotations

import configparser
import json
import os
import re
import threading
import time
from glob import glob, has_magic
from pathlib import Path
from typing import Iterable, Iterator, Optional

import yaml

from . import MIN_REDACT_LEN
from .globmatch import path_matches_globs

# Values equal to these (case-insensitive) are never redacted even if long
# enough — they are structural, not secret, and blanking them destroys output.
_NON_SECRET_LITERALS = {
    "true", "false", "none", "null", "prod", "dev", "staging", "default",
}

_DOTENV_LINE = re.compile(r"""^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$""")


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _keep(value: object) -> bool:
    if not isinstance(value, str):
        value = str(value)
    v = value.strip()
    if len(v) < MIN_REDACT_LEN:
        return False
    if v.lower() in _NON_SECRET_LITERALS:
        return False
    return True


def _from_ini(text: str) -> Iterable[str]:
    parser = configparser.RawConfigParser()
    # AWS config uses "[profile name]" headers; RawConfigParser handles them.
    try:
        parser.read_string(text)
    except configparser.Error:
        return []
    values = []
    for section in parser.sections():
        for _key, value in parser.items(section):
            values.append(value)
    return values


def _from_dotenv(text: str) -> Iterable[str]:
    values = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _DOTENV_LINE.match(line)
        if m:
            values.append(_strip_quotes(m.group(2)))
    return values


def _from_json(text: str) -> Iterable[str]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    out: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
        elif isinstance(node, (str, int, float)):
            out.append(str(node))

    walk(data)
    return out


def _from_yaml(text: str) -> Iterable[str]:
    """Scalar leaf values from a YAML source.

    Uses ``safe_load`` only — never the object-constructing loader — and never
    raises on a malformed source.
    """
    try:
        docs = list(yaml.safe_load_all(text))
    except Exception:
        # PyYAML raises YAMLError, but be defensive: this must never propagate.
        return []
    out: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, (list, tuple)):
            for v in node:
                walk(v)
        elif isinstance(node, bool):
            return  # bool is an int subclass; a flag is not a secret value
        elif isinstance(node, (str, int, float)):
            out.append(str(node))

    for doc in docs:
        walk(doc)
    return out


# A secret file larger than this is not loaded as a single whole-content blob
# (it is still parsed for structured values). Secret files are small; this only
# guards against someone pointing a source at a huge file.
MAX_WHOLE_FILE_BYTES = 1_000_000

# A file whose first chunk contains a NUL byte is treated as binary and skipped:
# text secret files never contain NUL, binaries almost always do near the start
# (the same cheap heuristic git and grep use). This keeps images/archives/etc.
# under a broad source glob (e.g. `**/.config/**`) out of the index, so their
# bytes are not decoded into junk redaction values — and a big binary is never
# read past the sniff. Text (incl. non-ASCII UTF-8) is unaffected, so a secret
# with unicode content is still loaded; an ASCII-only test would wrongly skip it.
_BINARY_SNIFF_BYTES = 8192


def _parse_text(name: str, suffix: str, text: str) -> list[str]:
    """Extract structured values (KEY=VALUE / ini / json / yaml) from file text."""
    if suffix == ".json":
        return list(_from_json(text))
    if suffix in (".yaml", ".yml"):
        return list(_from_yaml(text))
    if suffix in (".env",) or name in (".secrets", ".env") or "credentials" in name or name == "config":
        # AWS credentials/config are ini; .env/.secrets are dotenv. Try both
        # and keep whatever each yields — they don't overlap destructively.
        values = list(_from_ini(text)) + list(_from_dotenv(text))
        # .secrets has no fixed format and is frequently YAML.
        if name == ".secrets":
            values += list(_from_yaml(text))
        return values
    # Unknown: best-effort dotenv, then ini, then yaml.
    return list(_from_dotenv(text)) + list(_from_ini(text)) + list(_from_yaml(text))


# Parsed values per file, keyed by (mtime_ns, size). Parsing a large secret file
# (e.g. a multi-MB .har, which falls to the slow pure-Python YAML loader) is the
# dominant rebuild cost; this makes it a one-time-per-version cost instead of a
# per-rebuild one. Process-wide (paths are absolute) and thread-safe.
_FILE_VALUE_CACHE: dict[str, tuple[tuple[int, int], list[str]]] = {}
_FILE_VALUE_LOCK = threading.Lock()
_FILE_VALUE_CACHE_MAX = 4096


def _read_file_values(path: Path) -> list[str]:
    """Redaction values for one secret file (uncached).

    Binary files (see :data:`_BINARY_SNIFF_BYTES`) are skipped. For a text file,
    this includes the ENTIRE file content as one blob (so any dump of the file —
    `cat`, `less`, a bare token file, a PEM key, whatever the format — is masked
    wholesale) PLUS the structured values (so a single secret leaking on its own,
    e.g. `echo $KEY`, is still caught). The whole-content blob is longest, so the
    Redactor (which sorts longest-first) masks the full file before anything
    else.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(_BINARY_SNIFF_BYTES)
            if b"\x00" in head:  # binary file: not a text secret source
                return []
            raw = head + fh.read()
    except OSError:
        return []

    text = raw.decode("utf-8", errors="replace")
    values: list[str] = list(_parse_text(path.name.lower(), path.suffix.lower(), text))

    whole = text.strip()
    if whole and len(raw) <= MAX_WHOLE_FILE_BYTES:
        values.append(whole)

    return values


def _load_one(path: Path) -> list[str]:
    """Cached wrapper over :func:`_read_file_values`.

    Reuses the parsed values while the file's ``(mtime_ns, size)`` is unchanged,
    so a big secret file is parsed once, not on every index rebuild. An edited
    file gets a new stamp and is re-parsed.
    """
    key = str(path)
    stamp = _stat_stamp(key)
    if stamp is None:
        return []
    with _FILE_VALUE_LOCK:
        cached = _FILE_VALUE_CACHE.get(key)
        if cached is not None and cached[0] == stamp:
            return cached[1]
    # Parse outside the lock: a slow YAML load must not serialize other files. A
    # concurrent re-parse of the same file just does duplicate work.
    values = _read_file_values(path)
    with _FILE_VALUE_LOCK:
        if len(_FILE_VALUE_CACHE) >= _FILE_VALUE_CACHE_MAX:
            _FILE_VALUE_CACHE.clear()
        _FILE_VALUE_CACHE[key] = (stamp, values)
    return values


# Directories that never legitimately hold a user's secret files but are large
# and dominate a recursive walk. Skipped when expanding a `**` pattern so
# `**/.secrets/**` doesn't crawl a giant node_modules/.git on every rebuild. A
# dir named explicitly in the pattern is never pruned (see `_prune_dirs_for`),
# so an intentional `**/node_modules/**` still works.
_PRUNE_DIRS = frozenset({
    ".git", ".hg", ".svn",
    "node_modules", ".venv", "venv", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".cache", ".gradle",
})


def _prune_dirs_for(pattern: str) -> frozenset[str]:
    """The prune set minus any directory the pattern names literally."""
    literals = {seg for seg in pattern.split(os.sep) if seg and not has_magic(seg)}
    return _PRUNE_DIRS - literals


def _split_recursive(pattern: str) -> tuple[str, str]:
    """Split at the first ``**`` segment into (base_dir_before, tail_after)."""
    parts = pattern.split(os.sep)
    for i, part in enumerate(parts):
        if part == "**":
            base = os.sep.join(parts[:i]) or ("." if not pattern.startswith(os.sep) else os.sep)
            return base, os.sep.join(parts[i + 1:])
    return pattern, ""


def _walk_dirs(base: str, prune: frozenset[str]) -> Iterator[str]:
    """Yield ``base`` and every descendant directory, skipping pruned names."""
    if not os.path.isdir(base):
        return
    for root, dirs, _files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in prune]
        yield root


def _classify_tail(tail: str) -> Optional[tuple[str, Optional[str]]]:
    """Reduce a post-``**`` tail to an anchor so many patterns share one walk.

    ``""``            -> ("all", None)      every file under the base
    ``<name>/**``     -> ("dir", name)      any dir named <name>, all files under it
    ``<name>``        -> ("file", name)     any file named <name>
    anything else (a glob tail like ``*.pem`` or ``a/**/b``) -> None, handled
    per-pattern by :func:`_expand_recursive_glob`.
    """
    if tail == "":
        return ("all", None)
    parts = tail.split(os.sep)
    if len(parts) == 2 and parts[1] == "**" and parts[0] and not has_magic(parts[0]):
        return ("dir", parts[0])
    if len(parts) == 1 and parts[0] and not has_magic(parts[0]):
        return ("file", parts[0])
    return None


class _AnchorGroup:
    """The anchors of every simple ``**`` pattern sharing one base directory."""

    __slots__ = ("dir_names", "file_names", "collect_all")

    def __init__(self) -> None:
        self.dir_names: set[str] = set()
        self.file_names: set[str] = set()
        self.collect_all = False

    def add(self, kind: str, name: Optional[str]) -> None:
        if kind == "all":
            self.collect_all = True
        elif kind == "dir" and name is not None:
            self.dir_names.add(name)
        elif kind == "file" and name is not None:
            self.file_names.add(name)


def _walk_anchored(base: str, group: "_AnchorGroup") -> Iterator[str]:
    """One pruned walk of ``base`` yielding files matched by any anchor.

    A file is a match when it sits inside a directory named by ``dir_names`` (at
    any depth), or its own name is in ``file_names``, or ``collect_all`` is set.
    Equivalent to running each ``**/<name>/**`` and ``**/<name>`` pattern
    separately, but the whole tree is traversed only once.
    """
    if not os.path.isdir(base):
        return
    # Never prune a directory we are explicitly anchoring on (e.g. someone lists
    # `**/node_modules/**`); prune the rest of the heavy dirs.
    prune = _PRUNE_DIRS - group.dir_names
    dir_names = group.dir_names
    file_names = group.file_names
    collect_all = group.collect_all
    base_len = len(base.rstrip(os.sep))
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in prune]
        rel = root[base_len:].strip(os.sep)
        inside = collect_all or (bool(dir_names) and not dir_names.isdisjoint(rel.split(os.sep)))
        if inside:
            for name in files:
                yield os.path.join(root, name)
        elif file_names:
            for name in files:
                if name in file_names:
                    yield os.path.join(root, name)


def _expand_recursive_glob(pattern: str) -> Iterator[str]:
    """Expand a ``**`` pattern with pruning, matching glob semantics.

    Only the leading ``**`` recursion is done here (a pruned ``os.walk``); the
    remainder of the pattern is handed to ``glob`` per directory, so tail matching
    (``*``, ``?``, dotfile rules, a trailing ``**``) is exactly what ``glob``
    would do. Versus plain ``glob(pattern, recursive=True)`` the result differs
    only by (a) excluding files under pruned dirs and (b) also descending hidden
    intermediate dirs, which ``glob``'s ``**`` skips — a superset that can only
    catch *more* secrets, never fewer.
    """
    base, tail = _split_recursive(pattern)
    prune = _prune_dirs_for(pattern)
    seen: set[str] = set()
    for directory in _walk_dirs(base, prune):
        inner = os.path.join(directory, tail) if tail else os.path.join(directory, "*")
        for match in glob(inner, recursive=True):
            if match not in seen and os.path.isfile(match):
                seen.add(match)
                yield match


def _expand_source(src: str) -> Iterator[str]:
    """Resolve one configured source to the concrete files it names.

    A plain file path is yielded as-is (``_load_one`` tolerates a missing one).
    A glob pattern (``**/.secrets/**``) expands recursively to its file matches,
    and a directory is walked for every file beneath it — so a *directory* of
    secrets (e.g. ``.secrets/``) has all its contents loaded into the redactor,
    not just a file that happens to be named ``.secrets``. Recursive (`**`)
    patterns and directory walks prune well-known huge non-secret dirs.
    """
    if has_magic(src):
        if "**" in src.split(os.sep):
            yield from _expand_recursive_glob(src)
        else:
            for match in glob(src, recursive=True):
                if os.path.isfile(match):
                    yield match
        return
    if os.path.isdir(src):
        prune = _prune_dirs_for(src)
        for root, dirs, files in os.walk(src):
            dirs[:] = [d for d in dirs if d not in prune]
            for name in files:
                yield os.path.join(root, name)
        return
    yield src


def _expand_all(sources: Iterable[str]) -> list[str]:
    """The concrete files named by ``sources`` (globs/dirs expanded), de-duped.

    This is the expensive step: a recursive glob such as ``**/.secrets/**`` walks
    the whole tree. Kept separate from value loading so a cache can decide when to
    repeat it (see :class:`SecretIndex`).

    Simple recursive patterns (``**/<dir>/**`` and ``**/<file>``) that share a
    base directory are collapsed into a SINGLE pruned walk of that base, instead
    of one walk per pattern — the default set is ~10 such patterns all rooted at
    the same cwd, so this is roughly a 10x reduction in traversal. Anything else
    (a plain file, a directory, a non-recursive glob, or a complex ``**`` tail)
    is expanded individually by :func:`_expand_source`.
    """
    files: list[str] = []
    seen: set[str] = set()

    def add(path: str) -> None:
        if path not in seen and os.path.isfile(path):
            seen.add(path)
            files.append(path)

    groups: dict[str, _AnchorGroup] = {}
    leftovers: list[str] = []
    for src in sources:
        spec = None
        if has_magic(src) and "**" in src.split(os.sep):
            base, tail = _split_recursive(src)
            spec = _classify_tail(tail)
            if spec is not None:
                groups.setdefault(base, _AnchorGroup()).add(spec[0], spec[1])
        if spec is None:
            leftovers.append(src)

    for base, group in groups.items():
        for path in _walk_anchored(base, group):
            add(path)
    for src in leftovers:
        for path in _expand_source(src):
            add(path)
    return files


def _values_from_files(files: Iterable[str]) -> list[str]:
    """Redaction values for a concrete file list, de-duped and longest-first."""
    found: set[str] = set()
    for path in files:
        for value in _load_one(Path(path)):
            if _keep(value):
                found.add(value.strip() if isinstance(value, str) else str(value))
    return sorted(found, key=len, reverse=True)


def load_secret_values(sources: Iterable[str]) -> list[str]:
    """Return the de-duplicated, redaction-worthy secret values from sources.

    Each source may be a file, a glob, or a directory (see ``_expand_source``).
    For every file, both the whole file content and its structured values are
    collected. Longest first, so that when one value contains another (e.g. the
    whole-file blob contains an individual value) the longer, more specific
    redaction is applied first.
    """
    return _values_from_files(_expand_all(sources))


# ---- cached index -----------------------------------------------------------
#
# Rebuilding the value set scans (globs/walks) the workspace tree. With a
# recursive pattern like ``**/.secrets/**`` over a large tree, paying that on
# EVERY command is what makes each command slow. ``valet serve`` is long-lived,
# so we memoize the loaded values per resolved source set and reuse them across
# commands, rebuilding only when the tree looks stale.

# A newly created secret file is picked up within this many seconds (a full
# rebuild is forced at least this often). Edits to already-indexed files are
# caught immediately by mtime, so this only bounds the window for BRAND-NEW
# files — kept short because that window is time in which a fresh secret could
# appear unredacted.
SECRET_INDEX_TTL_SECONDS = 5.0


def _stat_stamp(path: str) -> Optional[tuple[int, int]]:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size)


class _IndexEntry:
    __slots__ = ("values", "stamps", "built_at")

    def __init__(self, values: list[str], stamps: dict[str, Optional[tuple[int, int]]],
                 built_at: float) -> None:
        self.values = values
        self.stamps = stamps
        self.built_at = built_at

    def files_unchanged(self) -> bool:
        """True while every indexed file still has the mtime/size it was read at.

        Catches an edited or deleted secret immediately (its stamp changes), so a
        modified secret is never served stale. It cannot see a brand-new file in
        an as-yet-unscanned directory — the TTL rebuild covers that.
        """
        return all(_stat_stamp(path) == stamp for path, stamp in self.stamps.items())


class SecretIndex:
    """Per-workspace cache of loaded secret values, keyed by resolved source set.

    Correctness is preserved versus calling :func:`load_secret_values` directly:
    the returned values are identical; only the *frequency* of the scan changes.
    An entry is reused only while (a) it is younger than the TTL and (b) every
    file it indexed is byte-for-byte unchanged. Otherwise it is rebuilt.
    """

    def __init__(self, ttl_seconds: float = SECRET_INDEX_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._entries: dict[tuple[tuple[str, ...], tuple[str, ...]], _IndexEntry] = {}

    def values_for(self, sources: Iterable[str],
                   deny_globs: Iterable[str] = ()) -> list[str]:
        """Loaded secret values for ``sources``, minus files matching ``deny_globs``.

        A file a command may not read (``policy.deny_read``) can never reach the
        agent through valet, so there is nothing to redact from it — indexing it
        would only cost the parse and risk over-masking (its non-secret leaves
        would mask unrelated output). ``deny_globs`` is part of the cache key, so
        a config change re-scans.
        """
        sources_key = tuple(sources)
        deny_key = tuple(deny_globs)
        key = (sources_key, deny_key)
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(key)
            if (entry is not None
                    and (now - entry.built_at) < self._ttl
                    and entry.files_unchanged()):
                return entry.values
        # Rebuild outside the lock: the scan can be slow and must not block other
        # workspaces' requests. A concurrent rebuild of the same key just does
        # duplicate work, never wrong work.
        files = _expand_all(sources_key)
        if deny_key:
            files = [f for f in files if not path_matches_globs(f, deny_key)]
        stamps = {f: _stat_stamp(f) for f in files}
        values = _values_from_files(files)
        with self._lock:
            self._entries[key] = _IndexEntry(values, stamps, time.monotonic())
        return values
