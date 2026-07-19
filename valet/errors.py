"""Error types and the high-level error classes valet reports to callers.

Only the *class name* (a short stable string) ever crosses the trust boundary
to the caller — never an underlying exception message, which could embed a
secret path, an AWS ARN, or a credential.
"""


class ValetError(Exception):
    """Base class for all valet errors. Carries a stable ``error_class``."""

    error_class = "ValetError"


class ValidationError(ValetError):
    """Caller sent a malformed or unacceptable request."""

    error_class = "ValidationError"


class ConfigError(ValetError):
    """The local config is missing, malformed, or incomplete."""

    error_class = "ConfigError"


class PolicyError(ValetError):
    """A command was refused by policy (allow/deny list, workspace jail)."""

    error_class = "PolicyDenied"


class TimeoutError_(ValetError):
    """The command exceeded the configured timeout."""

    error_class = "Timeout"


class CommandError(ValetError):
    """The command could not be launched (e.g. executable not found)."""

    error_class = "CommandError"
