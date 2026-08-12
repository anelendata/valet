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


def _load_one(path: Path) -> list[str]:
    """Redaction values for one secret file.

    Includes the ENTIRE file content as one blob (so any dump of the file —
    `cat`, `less`, a bare token file, a PEM key, whatever the format — is masked
    wholesale) PLUS the structured values (so a single secret leaking on its own,
    e.g. `echo $KEY`, is still caught). The whole-content blob is longest, so the
    Redactor (which sorts longest-first) masks the full file before anything
    else.
    """
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return []

    values: list[str] = list(_parse_text(path.name.lower(), path.suffix.lower(), text))

    whole = text.strip()
    if whole and len(text.encode("utf-8", "replace")) <= MAX_WHOLE_FILE_BYTES:
        values.append(whole)

    return values


def _expand_source(src: str) -> Iterator[str]:
    """Resolve one configured source to the concrete files it names.

    A plain file path is yielded as-is (``_load_one`` tolerates a missing one).
    A glob pattern (``.secrets/**``) expands recursively to its file matches, and
    a directory is walked for every file beneath it — so a *directory* of secrets
    (e.g. ``.secrets/``) has all its contents loaded into the redactor, not just
    a file that happens to be named ``.secrets``.
    """
    if has_magic(src):
        for match in glob(src, recursive=True):
            if os.path.isfile(match):
                yield match
        return
    if os.path.isdir(src):
        for root, _dirs, files in os.walk(src):
            for name in files:
                yield os.path.join(root, name)
        return
    yield src


def _expand_all(sources: Iterable[str]) -> list[str]:
    """The concrete files named by ``sources`` (globs/dirs expanded), de-duped.

    This is the expensive step: a recursive glob such as ``**/.secrets/**`` walks
    the whole tree. Kept separate from value loading so a cache can decide when to
    repeat it (see :class:`SecretIndex`).
    """
    files: list[str] = []
    seen: set[str] = set()
    for src in sources:
        for path in _expand_source(src):
            if path not in seen:
                seen.add(path)
                files.append(path)
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
        self._entries: dict[tuple[str, ...], _IndexEntry] = {}

    def values_for(self, sources: Iterable[str]) -> list[str]:
        key = tuple(sources)
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
        files = _expand_all(key)
        stamps = {f: _stat_stamp(f) for f in files}
        values = _values_from_files(files)
        with self._lock:
            self._entries[key] = _IndexEntry(values, stamps, time.monotonic())
        return values
