"""Aho-Corasick multi-pattern search, for fast redaction of many secret values.

The naive redactor scans the output once per secret value (O(values × output)),
which is slow when a big structured secret file (e.g. a multi-MB ``.har``)
explodes into tens of thousands of values. This builds one automaton over all
those values and masks them in a SINGLE pass over the output (O(output), plus the
matches), independent of the number of values, with the same coverage.

Selected from :mod:`valet.sanitize` via ``AHO_CORASICK``. It is used only for
*short* values; a handful of very long values (whole-file blobs, PEM keys) are
still handled by the plain ``in``/``replace`` loop there, so the trie never has
to hold megabyte-long patterns.

Coverage guarantee: every occurrence of every pattern ends at some position, and
at that position the automaton knows the *longest* pattern ending there — a span
that fully contains the occurrence. Masking the (merged) longest-ending spans
therefore removes every pattern occurrence from the text.
"""
from __future__ import annotations

from collections import deque
from typing import Callable, Iterable

try:  # optional C-accelerated backend; install the `speedups` extra to use it.
    import ahocorasick as _pyahocorasick
except ImportError:  # pragma: no cover - exercised only where it isn't installed
    _pyahocorasick = None

HAS_PYAHOCORASICK = _pyahocorasick is not None


def _apply_spans(text: str, spans: list[tuple[int, int]],
                 tag: Callable[[str], str]) -> str:
    """Replace the (possibly overlapping) match spans, longest coverage kept.

    Shared by every backend so they produce byte-identical output: overlapping
    spans merge into one replaced region, separated spans stay distinct, and each
    replaced region is passed to ``tag`` as its matched substring.
    """
    if not spans:
        return text
    spans.sort()
    merged: list[tuple[int, int]] = [spans[0]]
    for start, end in spans[1:]:
        m_start, m_end = merged[-1]
        if start <= m_end:  # overlap -> extend the current masked span
            merged[-1] = (m_start, max(m_end, end))
        else:
            merged.append((start, end))

    out: list[str] = []
    pos = 0
    for start, end in merged:
        if pos < start:
            out.append(text[pos:start])
        out.append(tag(text[start:end + 1]))
        pos = end + 1
    out.append(text[pos:])
    return "".join(out)


class _Node:
    __slots__ = ("children", "fail", "length")

    def __init__(self) -> None:
        self.children: dict[str, _Node] = {}
        self.fail: "_Node | None" = None
        # Length of the longest pattern that ends at this node (0 if none). After
        # fail links are wired this includes patterns that are proper suffixes,
        # so it is the longest pattern ending at the current text position.
        self.length: int = 0


class AhoCorasick:
    """Immutable multi-pattern matcher. Build once (it is cacheable), match many."""

    def __init__(self, patterns: Iterable[str]) -> None:
        self._root = _Node()
        self._empty = True
        for pattern in patterns:
            if pattern:
                self._add(pattern)
                self._empty = False
        self._wire_fail_links()

    def _add(self, pattern: str) -> None:
        node = self._root
        for ch in pattern:
            child = node.children.get(ch)
            if child is None:
                child = _Node()
                node.children[ch] = child
            node = child
        if len(pattern) > node.length:
            node.length = len(pattern)

    def _wire_fail_links(self) -> None:
        root = self._root
        queue: deque[_Node] = deque()
        for child in root.children.values():
            child.fail = root
            queue.append(child)
        while queue:
            node = queue.popleft()
            for ch, child in node.children.items():
                fail = node.fail
                while fail is not None and ch not in fail.children:
                    fail = fail.fail
                child.fail = fail.children[ch] if (fail and ch in fail.children) else root
                # Inherit the longest pattern reachable via suffix (fail) links.
                if child.fail.length > child.length:
                    child.length = child.fail.length
                queue.append(child)

    def replace(self, text: str, tag: Callable[[str], str]) -> str:
        """Replace every matched pattern occurrence, preferring the longest.

        ``tag`` maps a matched substring to its replacement. Overlapping matches
        are merged into one replaced span; separated matches stay distinct.
        """
        if self._empty or not text:
            return text
        root = self._root
        node = root
        n = len(text)
        # longest pattern length ending at each index (0 = none)
        best = [0] * n
        for i, ch in enumerate(text):
            while node is not root and ch not in node.children:
                node = node.fail  # type: ignore[assignment]
            nxt = node.children.get(ch)
            node = nxt if nxt is not None else root
            if node.length:
                best[i] = node.length

        spans = [(i - best[i] + 1, i) for i in range(n) if best[i]]
        return _apply_spans(text, spans, tag)


class PyAhoCorasick:
    """Same interface as :class:`AhoCorasick`, backed by the ``pyahocorasick`` C
    extension. Selected by setting ``sanitize.AHO_CORASICK = PyAhoCorasick``;
    construction raises if the extension isn't installed. Produces byte-identical
    output to the in-house backend (same :func:`_apply_spans`).
    """

    def __init__(self, patterns: Iterable[str]) -> None:
        if _pyahocorasick is None:
            raise RuntimeError(
                "pyahocorasick is not installed; `pip install valet-ai[speedups]` "
                "or set sanitize.AHO_CORASICK back to the in-house AhoCorasick."
            )
        automaton = _pyahocorasick.Automaton()
        count = 0
        for pattern in patterns:
            if pattern:
                automaton.add_word(pattern, len(pattern))  # payload = length
                count += 1
        self._empty = count == 0
        if not self._empty:
            automaton.make_automaton()
        self._automaton = automaton

    def replace(self, text: str, tag: Callable[[str], str]) -> str:
        if self._empty or not text:
            return text
        spans = [(end - length + 1, end) for end, length in self._automaton.iter(text)]
        return _apply_spans(text, spans, tag)
