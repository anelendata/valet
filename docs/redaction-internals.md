# Redaction internals

How valet finds secret values, scrubs them from command output, and does both
fast enough to leave on for large workspaces. This documents the implementation
in `valet/secrets.py`, `valet/sanitize.py`, and `valet/multimatch.py` as of
v0.0.9, and the known limitations that follow from the design.

- [The model: an exact-value firewall](#the-model-an-exact-value-firewall)
- [End-to-end: one command](#end-to-end-one-command)
- [Finding secret files: the pruned combined walk](#finding-secret-files-the-pruned-combined-walk)
- [Loading values: parse + per-file cache](#loading-values-parse--per-file-cache)
- [Caching layers](#caching-layers)
- [Masking output: the Redactor](#masking-output-the-redactor)
- [Aho-Corasick matcher](#aho-corasick-matcher)
- [Correctness and how it's tested](#correctness-and-how-its-tested)
- [Performance](#performance)
- [Known issues and limitations](#known-issues-and-limitations)

## The model: an exact-value firewall

valet's primary defense is not a regex scrubber. Because the daemon runs outside
the agent's sandbox, it can *read the credential files the agent cannot* and
learn the **exact literal strings** that must never appear in output. Redaction
then replaces those known values wherever and however they are formatted, tagging
each with a stable, non-reversible fingerprint (`[REDACTED:secret:h:xxxxxxxx]`)
so distinct secrets stay distinguishable without being revealed.

Two supporting layers back this up (see [the Redactor](#masking-output-the-redactor)):
a **heuristic** pass that masks things that only *look* secret (sensitively-named
keys, known token shapes) and a **pattern backstop** (ARNs, AWS key IDs, PEM
blocks, emails, account IDs). The exact-value layer is the one that scales with
workspace size, and it's the subject of most of this document.

## End-to-end: one command

For each exec/`sh`/REPL request the broker builds a `Redactor` and runs the
command's stdout/stderr (and the echoed command) through it:

```
Workspace.redactor_for(cwd)
  → resolve secret_file_paths patterns  (relative → workspace ROOT, not cwd)
  → SecretIndex.values_for(sources)      (cached scan)
        → _expand_all(sources)           (find files: pruned combined walk)
        → drop files matching deny_read   (a blocked file needs no redaction)
        → _values_from_files(files)      (parse each file → values; per-file cache)
  → Redactor.build(values, salt, …)
Redactor.redact(text)                    (per output chunk: 5 layers)
```

The scan and parse are memoized so repeated commands don't repeat the work; the
first command (or a config reload / server start) pays the cold cost, warmed
eagerly at startup (see [Caching](#caching-layers)).

### Why relative patterns resolve against the workspace root

A relative pattern like `**/.secrets/**` is joined to the **workspace root**, not
the command's cwd. Resolving against cwd was a real leak: `cd`-ing *into* a
`.secrets`/`.config` dir put the anchor *above* cwd, so `**/.config/**` matched
nothing and the file's value was never loaded. Root-relative loads the whole
workspace's secrets regardless of where the command runs, and it means one cache
key per workspace (every cwd shares it, and the warmup fills it). Absolute/`~`
patterns are used as-is; without a workspace, valet falls back to cwd.

## Finding secret files: the pruned combined walk

`secret_file_paths` entries are globs. Expanding them naively — one
`glob(pattern, recursive=True)` per pattern — walks the whole tree ~10 times for
the default set and is the dominant cost on a big workspace. `_expand_all` instead
recognizes that the default patterns are all one of two shapes and collapses them
into a **single** walk.

`_classify_tail` reduces the part after the leading `**/` to an *anchor*:

| Pattern tail | Meaning | Anchor |
|---|---|---|
| `""` (e.g. `~/.aws/**`) | every file under the base | "all" |
| `<name>/**` (e.g. `.secrets/**`) | any dir named `<name>`, all files under it | dir `<name>` |
| `<name>` (e.g. `.env`) | any file named `<name>` | file `<name>` |
| anything else (`*.pem`, `a/**/b`) | — | falls back to a per-pattern glob expander |

All simple patterns that share a base directory (the relative ones all share the
workspace root) are grouped into one `_AnchorGroup` and handled by a single
`_walk_anchored`: one `os.walk`, testing every entry against **all** dir/file
anchors at once. A directory is "inside a secret dir" when any path segment (below
the base) is in the dir-anchor set; then every file under it is a match.

**Pruning.** The walk skips directories that never hold intended secrets but
dominate traversal time — `_PRUNE_DIRS` = `.git`, `node_modules`, `.venv`/`venv`,
`__pycache__`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `.tox`, `.cache`,
`.gradle`, `.hg`, `.svn`. A directory named literally in a pattern (e.g. someone
writes `**/node_modules/**`) is never pruned.

Complex tails fall back to `_expand_recursive_glob`, which reimplements only the
outer `**` recursion (a pruned `os.walk`) and hands the tail to `glob` per
directory, so tail semantics match `glob` exactly. Versus plain
`glob(recursive=True)` the result differs only by (a) excluding pruned dirs and
(b) also descending hidden intermediate dirs — a **superset** that can catch more
secrets, never fewer.

## Loading values: parse + per-file cache

`_read_file_values` turns one file into redaction values:

1. **Whole-file blob** — the entire stripped content is added as one value (so any
   `cat`/`less`/dump of the file is masked wholesale), when it is ≤ 1 MB
   (`MAX_WHOLE_FILE_BYTES`). Because the Redactor sorts longest-first, the full
   blob masks before any inner value.
2. **Structured values** — `_parse_text` extracts leaf values by format:
   AWS ini, dotenv/`.secrets` (`KEY=VALUE`), JSON, YAML. Unknown extensions try
   dotenv + ini + YAML. This is what catches a single secret leaking on its own
   (`echo $KEY`).

Values shorter than `MIN_REDACT_LEN` (6) or equal to structural literals
(`true`, `false`, `none`, `prod`, `default`, …) are dropped so trivial strings
don't blank out output.

**Per-file parse cache.** Parsing is the real cost for large files (a multi-MB
`.har` falls to the slow pure-Python YAML loader — seconds each). `_load_one`
memoizes `_read_file_values` per file keyed by `(mtime_ns, size)`, process-wide
and thread-safe. An unchanged file is free on every later rebuild; an edited file
gets a new stamp and is re-parsed. Bounded at `_FILE_VALUE_CACHE_MAX` (4096)
entries (cleared wholesale when full — secret files are few).

## Caching layers

Three independent caches, each keyed so that "same inputs → reuse, changed inputs
→ rebuild":

- **`SecretIndex`** (per workspace) — memoizes the *scan result* (the value list)
  keyed by the resolved source tuple. An entry is reused only while it is younger
  than `SECRET_INDEX_TTL_SECONDS` (5s) **and** every file it indexed is
  byte-for-byte unchanged (`files_unchanged()` re-stats each). So an edited or
  deleted secret is caught immediately; a brand-new file in an as-yet-unscanned
  directory is caught within the TTL. Rebuilds happen outside the lock.
- **Per-file value cache** (above) — memoizes each file's parsed values across
  index rebuilds, so a TTL rebuild only re-reads *changed* files.
- **Matcher prep cache** (`sanitize._AC_PREP_CACHE`) — memoizes the long/short
  value split and the built automaton, keyed by `(backend, values)`, so the
  Aho-Corasick automaton is built once per value-set, not per command.

**Startup warmup.** `valet serve` calls `Broker.warm_redaction()` in a background
thread as soon as it is listening (and after a config reload): it builds each
workspace's index at its root and runs a tiny redact to build+cache the matcher.
The first *client* request then hits warm caches. Warmup is best-effort — a
workspace that fails is skipped.

## Masking output: the Redactor

`Redactor.redact(text)` runs five layers in order (`valet/sanitize.py`):

0. **Workspace-root virtualization** — the real workspace root path is rewritten
   to `./` so output never leaks the parent directory or username.
1. **Exact known values** — every loaded secret value → its fingerprint tag. This
   is the firewall; it uses the [Aho-Corasick matcher](#aho-corasick-matcher).
2. **Heuristic (`redact_suspected`, default on)** — the value of a
   sensitively-named key, the `value:` of a key/value pair, and known token shapes
   (AWS/GitHub/Slack/Stripe/Google, JWT, PEM). Keys stay visible.
2b. **High-entropy (`redact_high_entropy`, opt-in)** — long high-entropy tokens
   anywhere; skips git SHAs/hashes, UUIDs, decimal ids, and paths.
3. **Pattern backstop** — ARNs, PEM blocks, AWS key IDs, home-dir credential
   paths, emails, 12-digit account ids.
4. **Home-dir rewrite** — a remaining home prefix → `~`.

`is_clean(text)` asserts no known value survives; the broker checks it before
returning anything.

## Aho-Corasick matcher

Layer 1 must replace *every* known value. Doing it as one `str.replace` per value
is `O(values × output)` — with a big `.har` exploding into ~10k values that is
~90 ms per command and grows with output size. `valet/multimatch.py` replaces the
loop with a single pass.

**Algorithm.** Build an Aho-Corasick automaton (a trie of all patterns plus
failure links). Each node carries `length` = the longest pattern ending at it
(after failure links are wired, this includes patterns that are proper suffixes,
i.e. the longest pattern ending at the current text position). One left-to-right
scan yields, for each index, the longest pattern ending there. Those
`(start, end)` spans are merged (overlapping → one region, separated → distinct)
and each merged region is replaced by its tag. `_apply_spans` is shared by all
backends so their output is byte-identical.

**Coverage guarantee.** Every occurrence of every pattern ends at some position
whose *longest-ending* span contains it, so masking the merged longest-ending
spans removes every occurrence — the same coverage as the naive loop.

**Backends** (`sanitize.AHO_CORASICK`, a hard switch — no config knob yet):

- `AhoCorasick` — in-house pure-Python automaton, zero dependencies.
- `PyAhoCorasick` — the `pyahocorasick` C extension (`pip install valet-ai[speedups]`).
- `None` — the naive `in`/`replace` loop.

The default auto-selects `PyAhoCorasick` when the extension is installed, else the
in-house one. All three produce identical output.

**Long-value split.** Values longer than `_AC_MAX_PATTERN_LEN` (256) — whole-file
blobs, PEM keys — bypass the automaton and stay on the `in`/`replace` loop: there
are few of them, a long needle fails fast, and keeping megabyte-long entries out
of the trie avoids a memory blowup.

## Correctness and how it's tested

Redaction *coverage* is invariant across every optimization; only speed changes.
This is enforced by differential tests rather than asserted by hand:

- Grouped/pruned expander vs plain `glob(recursive=True)` — equality on fixed and
  25 randomized trees, plus prune / dedup / hidden-intermediate-dir cases.
- Aho-Corasick vs a brute-force coverage reference — 300-iteration fuzz.
- Aho-Corasick vs the naive `Redactor` — 60-trial byte-identical output.
- In-house vs `pyahocorasick` — 300-iteration differential (skipped when the extra
  isn't installed; CI runs the suite both with and without it).
- Regressions: nested-dir coverage, cwd-independent masking (cwd at root / inside
  the secret dir / a sibling / `None`), the per-file cache, and the startup warmup.

## Performance

Representative numbers from this work (synthetic trees and a real workspace with
multi-MB `.har` captures):

| Stage | Before | After |
|---|---|---|
| Walk (find files, ~3.8k dirs) | ~1190 ms (glob per pattern) | ~113 ms (combined pruned walk) |
| Parse (rebuild, big files) | ~6.2 s | ~19 ms (per-file cache) |
| Redact (~10k values, ~50 KB out) | ~170 ms/command | ~8–12 ms/command (AC) |

## Known issues and limitations

- **Over-redaction of big structured files.** For a known secret file valet
  extracts *every* leaf value. For a HAR (an HTTP capture) that is tens of
  thousands of leaves — cookies and tokens, but also URLs, hostnames, timestamps,
  mime types. All become redaction values, so unrelated output gets masked too:
  e.g. the literal word `substack` appearing anywhere is replaced because it is a
  value somewhere in a capture. **Partial mitigation shipped:** a file matched by
  `policy.deny_read` is excluded from the index (it can't be read, so it needs no
  redaction), so `deny_read = ["**/*.har"]` both blocks and un-indexes such files.
  That only helps files you're willing to make unreadable, though — a capture a
  trusted tool must *read* still over-masks. The general fix is about *what* we
  extract from big files (size-tiered blob-only, or shape/sensitive-key
  filtering), still open.
- **TTL staleness window.** A brand-new secret file created in an as-yet-unscanned
  directory can be unmasked for up to `SECRET_INDEX_TTL_SECONDS` (5s) until the
  next rebuild. Edited/deleted files are caught immediately. Not yet configurable;
  filesystem-watch invalidation was considered and deferred.
- **Cold cost on first use.** The first command per workspace (or after a config
  reload / restart) still parses every secret file once — seconds if there are big
  HARs. Warmup moves this off the client's critical path but does not remove it.
- **Whole-file blob cap.** Files larger than 1 MB get no whole-blob value; they
  rely on structured-leaf extraction (and thus on parsing succeeding). A >1 MB
  binary or opaque secret file may not be fully covered.
- **Overlap tag semantics.** When two distinct secret values overlap in the
  output, their spans merge into one tag whose fingerprint is of the concatenation
  rather than either value. Rare in practice; coverage is unaffected.
- **`MIN_REDACT_LEN` floor.** Values shorter than 6 chars are never masked as
  exact secrets, to avoid blanking trivial strings. A genuinely short secret would
  rely on the heuristic/backstop layers.
- **No config knobs yet** for the AC backend, the TTL, the prune set, or the
  per-file/whole-blob size thresholds — all are module constants today.
