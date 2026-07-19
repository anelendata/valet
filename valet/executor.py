"""Run a command and capture its output.

Supports two modes:
  - shell=False: ``cmd`` is an argv list, run directly (no shell).
  - shell=True:  ``cmd`` is a string, run via the system shell (/bin/sh -c),
    giving pipes/globs/redirection — the "shell wrapper" behavior.

stdout/stderr are captured here and stay internal to the broker; callers get
them back only after redaction.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Optional, Sequence, Union

from .errors import CommandError, TimeoutError_

Command = Union[str, Sequence[str]]


@dataclass
class RunResult:
    exit_code: int
    stdout: str
    stderr: str


def run(
    cmd: Command,
    *,
    shell: bool = False,
    cwd: Optional[str] = None,
    timeout: int = 60,
    extra_env: Optional[dict[str, str]] = None,
) -> RunResult:
    if shell:
        if not isinstance(cmd, str):
            raise CommandError("shell mode requires a command string")
        popen_arg: Command = cmd
    else:
        if isinstance(cmd, str) or not cmd:
            raise CommandError("non-shell mode requires a non-empty argv list")
        popen_arg = list(cmd)

    env = None
    if extra_env:
        env = dict(os.environ)
        env.update(extra_env)

    try:
        proc = subprocess.run(
            popen_arg,
            shell=shell,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError_("command timed out") from exc
    except FileNotFoundError:
        # argv mode with a missing executable — normalize to a 127 result so
        # callers get a uniform shape (matches how a shell reports not-found).
        return RunResult(exit_code=127, stdout="", stderr="command not found")

    return RunResult(
        exit_code=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
    )
