"""valet — a narrow local credential broker for AI agents.

valet runs outside the agent's filesystem-deny sandbox. It can read
credentials at runtime, but exposes only allowlisted read-only operations and
returns output with every known secret *value* redacted. See README.md for the
threat model.
"""

__version__ = "0.1.0"

# Values shorter than this are never treated as secret material to redact,
# so that trivial values ("1", "true", "us-east-1") don't blank out output.
MIN_REDACT_LEN = 6

# The scope allowlist for handoff `cloud schedule list`.
SCHEDULE_SCOPES = ("declared", "prefix", "all")
