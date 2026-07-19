"""Heuristic redaction — mask values that *look* secret, even when valet does
not know the exact value (e.g. secrets a command fetched at runtime).

This complements the exact value-firewall (valet/secrets.py): that masks values
valet has loaded from files; this catches secrets that only appear at runtime.

Precision-first (see README): it masks
  1. the VALUE of an assignment whose KEY name looks sensitive
     (`AWS_SECRET_ACCESS_KEY=...`, `password: ...`, `"api_key": "..."`),
  2. the `value:` field of a `key:`/`value:` object pair (as dumped by tools
     like `handoff secrets print`), and
  3. known token shapes (AWS keys, GitHub/GitLab/Slack/Stripe/Google tokens,
     JWTs, PEM blocks) wherever they appear.

It keeps the key visible and masks only the value, so output stays useful for
debugging ("which setting exists") without revealing the secret.
"""
from __future__ import annotations

import re

SUSPECTED = "[REDACTED:suspected]"
TOKEN = "[REDACTED:token]"

# Words that, when they appear in a key name, mark its value as sensitive.
_SENSITIVE_WORDS = {
    "password", "passwd", "pwd", "passphrase", "secret", "token", "apikey",
    "credential", "credentials", "authorization", "privatekey", "seckey",
}
# Sensitive two-word combinations (e.g. API_KEY -> api + key).
_SENSITIVE_BIGRAMS = {
    "api_key", "access_key", "secret_key", "private_key", "client_secret",
    "refresh_token", "session_token", "security_token", "sas_token",
    "connection_string", "auth_token", "secret_access_key", "service_account",
    "account_key", "encryption_key", "signing_key", "app_secret",
}


def key_is_sensitive(key: str) -> bool:
    norm = re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")
    if not norm:
        return False
    words = norm.split("_")
    if set(words) & _SENSITIVE_WORDS:
        return True
    bigrams = {f"{a}_{b}" for a, b in zip(words, words[1:])}
    return bool(bigrams & _SENSITIVE_BIGRAMS)


def _already_redacted(val: str) -> bool:
    return val.lstrip("\"'").startswith("[REDACTED")


# "key": value  — a JSON pair anywhere in the text (compact, pretty, or nested),
# with a SCALAR value only (string / number / bool / null). Object and array
# values are left alone so the scan recurses into them and catches inner keys.
_JSON_PAIR_RE = re.compile(
    r'"(?P<key>(?:[^"\\]|\\.)*)"\s*:\s*'
    r'(?P<val>"(?:[^"\\]|\\.)*"|-?\d[\d.eE+\-]*|true|false|null)'
)

# KEY=VALUE (env / export), value is quoted or a run without space/semicolon.
_ASSIGN_RE = re.compile(
    r"(?<![A-Za-z0-9_.\-])(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)(?P<eq>=)"
    r"(?P<val>\"[^\"]*\"|'[^']*'|[^\s;|&]+)"
)

# key: value with an UNQUOTED key (YAML / env colon form), one line.
_COLON_RE = re.compile(
    r"(?mi)^(?P<pre>\s*(?:-\s*)?)(?P<key>[A-Za-z_][A-Za-z0-9_.\- ]*?)"
    r"(?P<sep>\s*:\s*)(?P<val>.+?)(?P<trail>\s*,?\s*)$"
)

_KV_KEY_RE = re.compile(r"^(?P<pre>\s*(?:-\s*)?)key\s*:\s*(?P<name>.+?)\s*$", re.I)
_KV_VALUE_RE = re.compile(r"^(?P<pre>\s*(?:-\s*)?)value\s*:\s*(?P<val>.+?)\s*$", re.I)

# Known token shapes, masked wherever they occur.
_TOKEN_PATTERNS = [
    re.compile(p) for p in (
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",                       # AWS access key id
        r"\bghp_[A-Za-z0-9]{36}\b",                             # GitHub PAT
        r"\bgho_[A-Za-z0-9]{36}\b",
        r"\bgithub_pat_[A-Za-z0-9_]{60,}\b",
        r"\bglpat-[A-Za-z0-9_\-]{20}\b",                        # GitLab PAT
        r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",                    # Slack
        r"\b[sr]k_live_[A-Za-z0-9]{16,}\b",                     # Stripe
        r"\bAIza[0-9A-Za-z_\-]{35}\b",                          # Google API key
        r"\bya29\.[0-9A-Za-z_\-]+",                             # Google OAuth
        r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b",  # JWT
        r"-----BEGIN [^-]+-----",                               # PEM header
    )
]


def _sub_json(m: re.Match) -> str:
    if key_is_sensitive(m.group("key")) and not _already_redacted(m.group("val")):
        # Keep the result valid JSON: replace the scalar with a quoted tag.
        return f'"{m.group("key")}": "{SUSPECTED}"'
    return m.group(0)


def _sub_assign(m: re.Match) -> str:
    if key_is_sensitive(m.group("key")) and not _already_redacted(m.group("val")):
        return f"{m.group('key')}{m.group('eq')}{SUSPECTED}"
    return m.group(0)


def _sub_colon(m: re.Match) -> str:
    if key_is_sensitive(m.group("key")) and not _already_redacted(m.group("val")):
        return f"{m.group('pre')}{m.group('key')}{m.group('sep')}{SUSPECTED}{m.group('trail')}"
    return m.group(0)


def _redact_kv_pairs(text: str) -> str:
    """Mask the `value:` of a `key:`/`value:` object pair (e.g. secrets dumps)."""
    lines = text.split("\n")
    in_pair = False
    for i, line in enumerate(lines):
        if _KV_KEY_RE.match(line):
            in_pair = True
            continue
        vm = _KV_VALUE_RE.match(line)
        if vm and in_pair and not _already_redacted(vm.group("val")):
            lines[i] = f"{vm.group('pre')}value: {SUSPECTED}"
            in_pair = False
    return "\n".join(lines)


def redact_suspected(text: str) -> str:
    if not text:
        return text
    text = _redact_kv_pairs(text)
    text = _JSON_PAIR_RE.sub(_sub_json, text)
    text = _ASSIGN_RE.sub(_sub_assign, text)
    text = _COLON_RE.sub(_sub_colon, text)
    for pattern in _TOKEN_PATTERNS:
        text = pattern.sub(TOKEN, text)
    return text
