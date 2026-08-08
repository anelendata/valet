"""Load the *values* of known secrets so valet can block them from output.

This is what makes valet stronger than a regex scrubber: valet can read the
credential files the agent cannot, so it knows the exact literal strings that
must never appear in returned output. It extracts VALUES only (never keys), and
ignores anything too short to be meaningfully secret.

Supported source formats, detected by extension/content:
  - AWS credentials/config ini  (``[profile]`` sections, ``key = value``)
  - dotenv / .secrets           (``KEY=VALUE``, optional ``export``, quotes)
  - JSON                        (all string/number leaf values)
  - YAML (``.yaml``/``.yml``,   (all scalar leaf values; requires PyYAML —
    and ``.secrets``)            ``pip install 'valet[yaml]'``. Without it, YAML
                                 files are still redacted whole-file.)

Parsing is deliberately lenient and never raises on a malformed source: a
source we cannot read simply contributes no redaction values, and the generic
regex backstop in sanitize.py still applies.
"""
from __future__ import annotations

import configparser
import json
import re
from pathlib import Path
from typing import Iterable

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

    YAML support is optional: without PyYAML installed this returns nothing (the
    whole-file blob still masks the file). Uses ``safe_load`` only — never the
    object-constructing loader — and never raises.
    """
    try:
        import yaml
    except ImportError:
        return []
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


def load_secret_values(sources: Iterable[str]) -> list[str]:
    """Return the de-duplicated, redaction-worthy secret values from sources.

    For each source, both the whole file content and its structured values are
    collected. Longest first, so that when one value contains another (e.g. the
    whole-file blob contains an individual value) the longer, more specific
    redaction is applied first.
    """
    found: set[str] = set()
    for src in sources:
        for value in _load_one(Path(src)):
            if _keep(value):
                found.add(value.strip() if isinstance(value, str) else str(value))
    return sorted(found, key=len, reverse=True)
