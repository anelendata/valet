"""Run the underlying command safely: fixed argv, no shell, timeout, capture.

The executor never sees caller-supplied strings as a command. It takes an argv
LIST built by an operation (valet/operations.py) and runs it with
``shell=False``, so there is no shell to interpret metacharacters and no code
path that turns caller input into a command.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Optional, Sequence

from .errors import TimeoutError_


@dataclass
class RunResult:
    argv: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str


def run(
    argv: Sequence[str],
    *,
    cwd: Optional[str] = None,
    timeout: int = 60,
    aws_profile: Optional[str] = None,
    extra_env: Optional[dict[str, str]] = None,
) -> RunResult:
    """Execute ``argv`` and capture output. Raises Timeout on overrun.

    stdout/stderr are captured here and stay internal to the broker; callers
    receive only redacted / derived data, never this raw text.
    """
    if not argv or not isinstance(argv, (list, tuple)):
        raise ValueError("argv must be a non-empty list")

    env = dict(os.environ)
    if aws_profile:
        env["AWS_PROFILE"] = aws_profile
    if extra_env:
        env.update(extra_env)

    try:
        proc = subprocess.run(
            list(argv),
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,  # explicit: never a shell
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError_("command timed out") from exc

    return RunResult(
        argv=tuple(argv),
        exit_code=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
    )


def classify_failure(result: RunResult) -> str:
    """Map a nonzero run to a high-level error class, from stderr patterns.

    Only the returned label leaves the boundary — never the stderr text.
    """
    blob = (result.stderr + "\n" + result.stdout).lower()
    cred_markers = (
        "expiredtoken", "credential", "accessdenied", "access denied",
        "unable to locate credentials", "invalidclienttokenid",
        "not authorized", "unauthorized", "signature",
    )
    if any(m in blob for m in cred_markers):
        return "CredentialsError"
    if "unrecognized command" in blob or "no such" in blob:
        return "ConfigError"
    return "HandoffError"
