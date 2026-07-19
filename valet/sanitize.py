"""Redaction: block known secret values, plus a generic backstop, from output.

Two layers:

1. Value redaction (primary): every literal secret value loaded from the
   project's secret sources is replaced with ``[REDACTED:<fp>]``. Because valet
   knows the actual values, this catches secrets regardless of how the command
   happened to format them.

2. Pattern backstop (defense in depth): AWS account IDs, ARNs, access-key IDs,
   PEM blocks, and home-dir credential paths are masked even if they were not
   in a known secret source. This protects the free-text error channel.

Fingerprints (stable salted hashes) let a caller compare identity across runs
without ever seeing the real identifier.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Iterable

# --- generic backstop patterns ------------------------------------------------
# Order matters: ARNs are matched before bare 12-digit account IDs so the whole
# ARN is masked as one unit.
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"arn:aws[a-z-]*:[^\s\"']+"), "[REDACTED:arn]"),
    (re.compile(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", re.DOTALL),
     "[REDACTED:pem]"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED:aws_key_id]"),
    # secret paths under a home dir
    (re.compile(r"/(?:home|Users)/[^/\s\"']+/\.aws/[^\s\"':]+"),
     "[REDACTED:aws_path]"),
    (re.compile(r"/[^\s\"':]*/\.secrets\b"), "[REDACTED:secret_path]"),
    (re.compile(r"/[^\s\"':]*/\.env\b"), "[REDACTED:env_path]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
     "[REDACTED:email]"),
    # bare 12-digit AWS account id (after ARNs already consumed)
    (re.compile(r"\b\d{12}\b"), "[REDACTED:acct_id]"),
]


def fingerprint(value: str, salt: str, length: int = 8) -> str:
    """Stable, non-reversible tag for an identifier. ``h:xxxxxxxx``."""
    digest = hmac.new(
        salt.encode("utf-8"), value.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return "h:" + digest[:length]


@dataclass
class Redactor:
    """Replaces known secret values and backstop patterns in text."""

    secret_values: tuple[str, ...]
    salt: str

    @classmethod
    def build(cls, secret_values: Iterable[str], salt: str) -> "Redactor":
        # Longest first so a value that is a substring of another is not
        # partially masked by the shorter one.
        vals = tuple(sorted({v for v in secret_values if v}, key=len, reverse=True))
        return cls(secret_values=vals, salt=salt)

    def redact(self, text: str) -> str:
        if not text:
            return text
        # Layer 1: exact known secret values → tagged with a stable fingerprint
        # so distinct secrets stay distinguishable without being revealed.
        for value in self.secret_values:
            if value and value in text:
                tag = "[REDACTED:secret:" + fingerprint(value, self.salt) + "]"
                text = text.replace(value, tag)
        # Layer 2: generic backstop
        for pattern, replacement in _PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    def is_clean(self, text: str) -> bool:
        """True if no known secret value remains. Used as an assertion in the
        broker before anything is returned."""
        return not any(v and v in text for v in self.secret_values)
