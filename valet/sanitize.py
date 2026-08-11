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

from .heuristics import redact_high_entropy, redact_suspected

# --- generic backstop patterns ------------------------------------------------
# Order matters: ARNs are matched before bare 12-digit account IDs so the whole
# ARN is masked as one unit.
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"arn:aws[a-z-]*:[^\s\"']+"), "[REDACTED:arn]"),
    (re.compile(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", re.DOTALL),
     "[REDACTED:pem]"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED:aws_key_id]"),
    # A home-dir credential path de-identifies the username (and works even in
    # non-workspace mode, where the home->~ rewrite is off). NOT a general
    # secret-file-path mask: the *paths* of secret files (.secrets/, .env, ...)
    # are not themselves secret — the agent can list them — and masking them just
    # turns useful output like "updated .secrets/token.txt" into noise. The
    # file *contents* are what matter, and those are handled by value redaction
    # (secret_file_paths), not here.
    (re.compile(r"/(?:home|Users)/[^/\s\"']+/\.aws/[^\s\"':]+"),
     "[REDACTED:aws_path]"),
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
    suspected: bool = True
    high_entropy: bool = False
    workspace_root: str = ""
    home_dir: str = ""

    @classmethod
    def build(cls, secret_values: Iterable[str], salt: str,
              suspected: bool = True, high_entropy: bool = False,
              workspace_root: str = "", home_dir: str = "") -> "Redactor":
        # Longest first so a value that is a substring of another is not
        # partially masked by the shorter one.
        vals = tuple(sorted({v for v in secret_values if v}, key=len, reverse=True))
        return cls(secret_values=vals, salt=salt, suspected=suspected,
                   high_entropy=high_entropy, workspace_root=workspace_root,
                   home_dir=home_dir)

    def __post_init__(self) -> None:
        # Precompile the workspace-root rewrite. The lookbehind/lookahead keep it
        # to real path boundaries so ``/ws`` in ``/other/ws`` or ``/wsX`` is left
        # alone; only the workspace root (and paths beneath it) collapse to "./".
        root = self.workspace_root
        if root and root != "/":
            self._root_re = re.compile(
                r"(?<![\w./-])" + re.escape(root) + r"(?:/|(?![\w./-]))"
            )
        else:
            self._root_re = None
        # A home-directory prefix outside the workspace (a sibling of it, say) is
        # rewritten to "~" so output does not leak the real absolute path or the
        # username. The workspace itself is already handled above, so skip when
        # home == workspace.
        home = self.home_dir
        if home and home not in ("/", self.workspace_root):
            self._home_re = re.compile(
                r"(?<![\w./-])" + re.escape(home) + r"(?:/|(?![\w./-]))"
            )
        else:
            self._home_re = None

    def redact(self, text: str) -> str:
        if not text:
            return text
        # Layer 0: virtualize the workspace root so no output — command stdout,
        # error text, echoed paths — leaks the real parent directory above it.
        # The "./" prefix marks a workspace-relative path (not the real root).
        if self._root_re is not None:
            text = self._root_re.sub("./", text)
        # Layer 1: exact known secret values → tagged with a stable fingerprint
        # so distinct secrets stay distinguishable without being revealed.
        for value in self.secret_values:
            if value and value in text:
                tag = "[REDACTED:secret:" + fingerprint(value, self.salt) + "]"
                text = text.replace(value, tag)
        # Layer 2: heuristic redaction of things that *look* secret (values of
        # sensitively-named keys, key/value dumps, known token shapes).
        if self.suspected:
            text = redact_suspected(text)
        # Layer 2b: opt-in high-entropy scan for bare unknown secrets.
        if self.high_entropy:
            text = redact_high_entropy(text)
        # Layer 3: generic backstop
        for pattern, replacement in _PATTERNS:
            text = pattern.sub(replacement, text)
        # Layer 4: rewrite a remaining home-directory prefix to "~". Runs last so
        # the more specific backstop paths (~/.aws/**, etc.) match the real path
        # first; whatever real home path is left (e.g. a sibling of the
        # workspace) then loses its absolute form and username.
        if self._home_re is not None:
            text = self._home_re.sub(
                lambda m: "~/" if m.group(0).endswith("/") else "~", text
            )
        return text

    def is_clean(self, text: str) -> bool:
        """True if no known secret value remains. Used as an assertion in the
        broker before anything is returned."""
        return not any(v and v in text for v in self.secret_values)
