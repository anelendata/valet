"""Introspection for the secret-redaction index — backs ``valet doctor redact``.

Two host-side views over what the exact-value firewall (:mod:`valet.secrets` +
:mod:`valet.sanitize`) would mask for a workspace:

* :func:`summarize` — which source files contribute which values, the fingerprint
  tag each maps to, and whether it takes the automaton or the naive long-value
  path. Answers "why is this value redacted?". Plaintext values are hidden unless
  ``show_values`` is set (they are the secrets themselves).
* :func:`benchmark` — times the cold index build, splitting the tree walk from the
  per-file parse and breaking both down by directory, so a slow workspace can be
  diagnosed (a broad ``**`` glob over a large tree, or one heavy file).

Both reuse the broker's own loaders, so the result matches what ``valet serve``
indexes for that workspace (same source resolution, deny_read exclusion, and
binary-file skipping).
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from .config import BrokerConfig, resolve_workspaces
from .globmatch import path_matches_globs
from .sanitize import _AC_MAX_PATTERN_LEN, AHO_CORASICK, fingerprint
from .secrets import _expand_all, _expand_source, _keep, _read_file_values


def _resolve_sources(patterns, root: str | None) -> list[str]:
    """Mirror Broker.redactor_for: absolute/~ patterns as-is, relatives under root."""
    out: list[str] = []
    for pat in patterns:
        p = os.path.expanduser(os.path.expandvars(pat))
        if os.path.isabs(p):
            out.append(p)
        elif root:
            out.append(os.path.join(root, p))
        # a relative pattern with no workspace root can't be located; skip it
    return out


def _matched_files(wcfg, root: str | None):
    """(sources, files, deny) for a workspace, deny_read excluded like the broker."""
    sources = _resolve_sources(list(wcfg.redaction.secret_file_paths), root)
    files = _expand_all(sources)
    deny = tuple(wcfg.policy.deny_read)
    if deny:
        files = [f for f in files if not path_matches_globs(f, deny)]
    return sources, files, deny


def _human_bytes(n: float) -> str:
    for unit in ("B", "K", "M"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}G"


def _group_key(path: str, root: str | None, depth: int) -> str:
    """First ``depth`` path segments of the file's PARENT dir, relative to root.

    A file directly under root groups as ".". This is the "top-n level directory"
    the file's cost is attributed to.
    """
    rel = os.path.relpath(path, root) if root else path
    parent = os.path.dirname(rel)
    if not parent or parent.startswith(".."):
        return "."
    return os.sep.join(parent.split(os.sep)[:depth]) or "."


def _header(cfg: BrokerConfig, wid: str, wcfg, root, patterns, deny, files) -> None:
    print(f"workspace : {wid}")
    print(f"root      : {root or '(unset)'}")
    print(f"patterns  : {patterns}")
    print(f"deny_read : {list(deny)}")
    print(f"backend   : {AHO_CORASICK.__name__ if AHO_CORASICK else 'None (naive loop)'}")
    print(f"files     : {len(files)} matched")


def summarize(cfg: BrokerConfig, wid: str, *,
              show_values: bool = False, max_len: int = 80) -> None:
    """Print the redaction index for one workspace, grouped by source file."""
    wcfg = resolve_workspaces(cfg)[wid]
    root = wcfg.exec.workspace
    patterns = list(wcfg.redaction.secret_file_paths)
    _sources, files, deny = _matched_files(wcfg, root)

    if show_values:
        print("WARNING: --show-values prints secrets in plaintext to stdout",
              file=sys.stderr)

    all_values: set[str] = set()
    file_map: dict[str, list[str]] = {}
    for f in files:
        vals = sorted({v.strip() for v in _read_file_values(Path(f)) if _keep(v)},
                      key=len, reverse=True)
        if vals:
            file_map[f] = vals
            all_values.update(vals)

    _header(cfg, wid, wcfg, root, patterns, deny, files)
    print(f"values    : {len(all_values)} unique\n")

    for f, vals in file_map.items():
        rel = os.path.relpath(f, root) if root else f
        print(f"── {rel}  ({len(vals)} value(s))")
        for v in vals:
            route = "naive" if len(v) > _AC_MAX_PATTERN_LEN else "auto "
            tag = "[REDACTED:secret:" + fingerprint(v, cfg.fingerprint_salt) + "]"
            shown = ""
            if show_values:
                shown = v if max_len == 0 or len(v) <= max_len else v[:max_len] + "…"
            print(f"   [{route}] len={len(v):<6} {tag}  {shown}".rstrip())
        print()

    long_n = sum(len(v) > _AC_MAX_PATTERN_LEN for v in all_values)
    print("summary")
    print(f"   unique values : {len(all_values)}")
    print(f"   automaton     : {len(all_values) - long_n}  (len <= {_AC_MAX_PATTERN_LEN})")
    print(f"   naive long    : {long_n}  (len >  {_AC_MAX_PATTERN_LEN})")
    if not show_values:
        print("\n(values hidden; re-run with --show-values to print plaintext)")


def benchmark(cfg: BrokerConfig, wid: str, *, depth: int = 1) -> None:
    """Time the cold index build for one workspace, broken down by directory.

    Two costs are separated so a slowdown can be diagnosed:
      * scan   — one pruned walk/glob of the tree (_expand_all). Grows with the
                 NUMBER of files/dirs traversed, even non-matching ones.
      * parse  — reading + structured-parsing each matched file (uncached — the
                 real per-rebuild cost), dominated by big/complex files.
    """
    wcfg = resolve_workspaces(cfg)[wid]
    root = wcfg.exec.workspace
    patterns = list(wcfg.redaction.secret_file_paths)
    sources, files, deny = _matched_files(wcfg, root)

    _header(cfg, wid, wcfg, root, patterns, deny, files)
    print()

    t0 = time.perf_counter()
    _expand_all(sources)  # re-run purely to time the walk/glob (real, grouped)
    scan_ms = (time.perf_counter() - t0) * 1000

    # Per-pattern cost, each expanded INDEPENDENTLY. Caveat: at runtime the simple
    # `**/<name>` and `**/<name>/**` patterns are collapsed into ONE shared walk,
    # so their real combined cost is much less than the sum here; but a
    # complex-tail pattern (e.g. **/.config/gws/x.json) always runs its own full
    # tree walk, so its number here IS its real cost — that is what this is for.
    per_pattern = []
    for src in sources:
        t = time.perf_counter()
        n = sum(1 for _ in _expand_source(src))
        per_pattern.append(((time.perf_counter() - t) * 1000, n, src))

    groups: dict[str, dict] = {}
    slowest_file = ("", 0.0)
    for f in files:
        try:
            size = os.path.getsize(f)
        except OSError:
            size = 0
        t = time.perf_counter()
        vals = _read_file_values(Path(f))          # cold parse (uncached)
        ms = (time.perf_counter() - t) * 1000
        kept = sum(1 for v in vals if _keep(v))
        g = groups.setdefault(_group_key(f, root, depth),
                              {"files": 0, "bytes": 0, "ms": 0.0, "values": 0})
        g["files"] += 1
        g["bytes"] += size
        g["ms"] += ms
        g["values"] += kept
        if ms > slowest_file[1]:
            slowest_file = (f, ms)

    total_ms = sum(g["ms"] for g in groups.values())
    total_files = sum(g["files"] for g in groups.values())
    total_bytes = sum(g["bytes"] for g in groups.values())
    total_values = sum(g["values"] for g in groups.values())

    print(f"scan (walk+glob) : {scan_ms:8.1f} ms")
    print(f"parse (all files): {total_ms:8.1f} ms   ({total_files} files, "
          f"{_human_bytes(total_bytes)}, {total_values} values)")
    print(f"total build est. : {scan_ms + total_ms:8.1f} ms\n")

    print(f"{'scan_ms':>10}  {'matched':>7}  pattern (independent expansion)")
    print(f"{'-'*10}  {'-'*7}  {'-'*30}")
    for ms, n, src in sorted(per_pattern, reverse=True):
        print(f"{ms:10.1f}  {n:7d}  {src}")
    print()

    hdr = f"depth-{depth} directory"
    print(f"{'parse_ms':>10}  {'files':>7}  {'size':>8}  {'values':>7}  {hdr}")
    print(f"{'-'*10}  {'-'*7}  {'-'*8}  {'-'*7}  {'-'*len(hdr)}")
    for name, g in sorted(groups.items(), key=lambda kv: kv[1]["ms"], reverse=True):
        print(f"{g['ms']:10.1f}  {g['files']:7d}  {_human_bytes(g['bytes']):>8}  "
              f"{g['values']:7d}  {name}")

    if slowest_file[0]:
        rel = os.path.relpath(slowest_file[0], root) if root else slowest_file[0]
        print(f"\nslowest single file: {slowest_file[1]:.1f} ms  {rel}")
