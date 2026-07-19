"""Load the *values* of known secrets so valet can block them from output.

This is what makes valet stronger than a regex scrubber: valet can read the
credential files the agent cannot, so it knows the exact literal strings that
must never appear in returned output. It extracts VALUES only (never keys), and
ignores anything too short to be meaningfully secret.

Supported source formats, detected by extension/content:
  - AWS credentials/config ini  (``[profile]`` sections, ``key = value``)
  - dotenv / .secrets           (``KEY=VALUE``, optional ``export``, quotes)
  - JSON                        (all string/number leaf values)

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


def _parse_source(path: Path) -> Iterable[str]:
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return []
    suffix = path.suffix.lower()
    name = path.name.lower()
    if suffix == ".json":
        return _from_json(text)
    if suffix in (".env",) or name in (".secrets", ".env") or "credentials" in name or name == "config":
        # AWS credentials/config are ini; .env/.secrets are dotenv. Try both
        # and keep whatever each yields — they don't overlap destructively.
        return list(_from_ini(text)) + list(_from_dotenv(text))
    # Unknown: best-effort dotenv, then ini.
    return list(_from_dotenv(text)) + list(_from_ini(text))


def load_secret_values(sources: Iterable[str]) -> list[str]:
    """Return the de-duplicated, redaction-worthy secret values from sources.

    Longest values first, so that when one secret value contains another the
    longer (more specific) redaction is applied first.
    """
    found: set[str] = set()
    for src in sources:
        path = Path(src)
        for value in _parse_source(path):
            if _keep(value):
                found.add(value.strip() if isinstance(value, str) else str(value))
    return sorted(found, key=len, reverse=True)
