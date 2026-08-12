"""Glob (``**`` / ``*`` / ``?``) matching against absolute paths.

Shared so that policy's ``deny_read`` enforcement and secrets' exclusion of
``deny_read`` files from the redaction index use *identical* semantics: a file
excluded from indexing is exactly a file a command would be denied for reading.
"""
from __future__ import annotations

import os
import re
from functools import lru_cache
from typing import Iterable


@lru_cache(maxsize=256)
def compile_glob(pattern: str) -> re.Pattern[str]:
    """Compile a glob (with ``**``/``*``/``?``) into an anchored regex.

    ``**/`` matches any number of leading directories, ``**`` matches anything,
    ``*`` matches within a path segment, ``?`` a single non-slash character.
    """
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


def path_matches_globs(path: str, patterns: Iterable[str]) -> bool:
    """True if ``path`` (as an absolute path) matches any of ``patterns``.

    Patterns are expected to already have ``~``/``$VAR`` expanded.
    """
    abspath = os.path.abspath(path)
    return any(compile_glob(p).match(abspath) is not None for p in patterns)
