"""valet — a secret-redacting command runner for AI agents.

valet runs outside the agent's filesystem-deny sandbox. It can read the secret
files the agent cannot, so it runs a command on the agent's behalf and returns
the output with every known secret *value* scrubbed out. See README.md.

v0.2: general shell wrapper. It runs (almost) any command — constraints such as
command allow/deny lists and a workspace write-jail are layered on later via
``valet/policy.py``. Redaction is always on.
"""

__version__ = "0.2.0"

# Values shorter than this are never treated as secret material to redact,
# so that trivial values ("1", "true", "us-east-1") don't blank out output.
MIN_REDACT_LEN = 6
