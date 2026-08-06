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
import queue
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Iterator, Optional, Sequence, Union

from .errors import CommandError, TimeoutError_

Command = Union[str, Sequence[str]]


@dataclass
class RunResult:
    exit_code: int
    stdout: str
    stderr: str


@dataclass
class OutputChunk:
    stream: str
    text: str


StreamItem = Union[OutputChunk, RunResult]


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


def iter_run(
    cmd: Command,
    *,
    shell: bool = False,
    cwd: Optional[str] = None,
    timeout: int = 60,
    extra_env: Optional[dict[str, str]] = None,
    cancel_event: Optional[threading.Event] = None,
) -> Iterator[StreamItem]:
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
        proc = subprocess.Popen(
            popen_arg,
            shell=shell,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        yield RunResult(exit_code=127, stdout="", stderr="command not found")
        return

    out: dict[str, list[str]] = {"stdout": [], "stderr": []}
    q: queue.Queue[OutputChunk] = queue.Queue()

    def read_pipe(name: str, pipe) -> None:
        try:
            for text in iter(pipe.readline, ""):
                out[name].append(text)
                q.put(OutputChunk(name, text))
        finally:
            try:
                pipe.close()
            except OSError:
                pass

    threads = [
        threading.Thread(target=read_pipe, args=("stdout", proc.stdout), daemon=True),
        threading.Thread(target=read_pipe, args=("stderr", proc.stderr), daemon=True),
    ]
    for thread in threads:
        thread.start()

    deadline = time.monotonic() + timeout
    while True:
        try:
            yield q.get(timeout=0.05)
            continue
        except queue.Empty:
            pass

        if proc.poll() is None and time.monotonic() >= deadline:
            proc.kill()
            proc.wait()
            for thread in threads:
                thread.join(timeout=1)
            while True:
                try:
                    yield q.get_nowait()
                except queue.Empty:
                    break
            raise TimeoutError_("command timed out")

        if cancel_event is not None and cancel_event.is_set() and proc.poll() is None:
            proc.kill()
            proc.wait()
            for thread in threads:
                thread.join(timeout=1)
            while True:
                try:
                    yield q.get_nowait()
                except queue.Empty:
                    break
            yield RunResult(
                exit_code=130,
                stdout="".join(out["stdout"]),
                stderr="".join(out["stderr"]),
            )
            return

        if proc.poll() is not None and all(not thread.is_alive() for thread in threads):
            break

    for thread in threads:
        thread.join(timeout=1)
    while True:
        try:
            yield q.get_nowait()
        except queue.Empty:
            break

    yield RunResult(
        exit_code=proc.returncode,
        stdout="".join(out["stdout"]),
        stderr="".join(out["stderr"]),
    )
