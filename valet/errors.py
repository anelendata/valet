"""Error types and the high-level error classes valet reports to callers.

Only the *class name* (a short stable string) ever crosses the trust boundary
to the caller — never an underlying exception message, which could embed a
secret path, an AWS ARN, or a credential.
"""


class ValetError(Exception):
    """Base class for all valet errors. Carries a stable ``error_class``."""

    error_class = "ValetError"


class ValidationError(ValetError):
    """Caller sent something not on an allowlist (op, alias, stage, scope)."""

    error_class = "ValidationError"


class ConfigError(ValetError):
    """The local config is missing, malformed, or incomplete."""

    error_class = "ConfigError"


class TimeoutError_(ValetError):
    """The underlying command exceeded the configured timeout."""

    error_class = "Timeout"


class CredentialsError(ValetError):
    """The underlying command failed in a way that looks credential-related."""

    error_class = "CredentialsError"


class CommandError(ValetError):
    """The underlying command failed for some other reason."""

    error_class = "HandoffError"
