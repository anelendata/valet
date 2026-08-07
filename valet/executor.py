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
import shlex
import signal
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


@dataclass
class ProcessInfo:
    pid: int
    cmd: str
    shell: bool
    cwd: Optional[str]
    started_at: float
    runtime_seconds: float


@dataclass
class _TrackedProcess:
    proc: subprocess.Popen
    cmd: str
    shell: bool
    cwd: Optional[str]
    started_at: float


StreamItem = Union[OutputChunk, RunResult]
_PROCESSES: dict[int, _TrackedProcess] = {}
_PROCESSES_LOCK = threading.RLock()


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
        proc = subprocess.Popen(
            popen_arg,
            shell=shell,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        _register_process(proc, popen_arg, shell=shell, cwd=cwd)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            _kill_process(proc)
            stdout, stderr = proc.communicate()
            raise TimeoutError_("command timed out") from exc
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError_("command timed out") from exc
    except FileNotFoundError:
        # argv mode with a missing executable — normalize to a 127 result so
        # callers get a uniform shape (matches how a shell reports not-found).
        return RunResult(exit_code=127, stdout="", stderr="command not found")
    finally:
        if "proc" in locals():
            _unregister_process(proc)

    return RunResult(
        exit_code=proc.returncode,
        stdout=stdout or "",
        stderr=stderr or "",
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
            start_new_session=True,
        )
    except FileNotFoundError:
        yield RunResult(exit_code=127, stdout="", stderr="command not found")
        return
    _register_process(proc, popen_arg, shell=shell, cwd=cwd)

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
            _kill_process(proc, force=True)
            proc.wait()
            _unregister_process(proc)
            for thread in threads:
                thread.join(timeout=1)
            while True:
                try:
                    yield q.get_nowait()
                except queue.Empty:
                    break
            raise TimeoutError_("command timed out")

        if cancel_event is not None and cancel_event.is_set() and proc.poll() is None:
            _kill_process(proc)
            proc.wait()
            _unregister_process(proc)
            for thread in threads:
                thread.join(timeout=1)
            while True:
                try:
                    yield q.get_nowait()
                except queue.Empty:
                    break
            try:
                yield RunResult(
                    exit_code=130,
                    stdout="".join(out["stdout"]),
                    stderr="".join(out["stderr"]),
                )
            finally:
                _unregister_process(proc)
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

    try:
        yield RunResult(
            exit_code=proc.returncode,
            stdout="".join(out["stdout"]),
            stderr="".join(out["stderr"]),
        )
    finally:
        _unregister_process(proc)


def list_processes() -> list[ProcessInfo]:
    now = time.time()
    with _PROCESSES_LOCK:
        _prune_finished_locked()
        return [
            ProcessInfo(
                pid=pid,
                cmd=tracked.cmd,
                shell=tracked.shell,
                cwd=tracked.cwd,
                started_at=tracked.started_at,
                runtime_seconds=max(0.0, now - tracked.started_at),
            )
            for pid, tracked in sorted(_PROCESSES.items())
        ]


def kill_process(pid: int) -> bool:
    with _PROCESSES_LOCK:
        _prune_finished_locked()
        tracked = _PROCESSES.get(pid)
    if tracked is None:
        return False
    _kill_process(tracked.proc)
    return True


def _register_process(
    proc: subprocess.Popen,
    cmd: Command,
    *,
    shell: bool,
    cwd: Optional[str],
) -> None:
    with _PROCESSES_LOCK:
        _PROCESSES[proc.pid] = _TrackedProcess(
            proc=proc,
            cmd=_display_cmd(cmd),
            shell=shell,
            cwd=cwd,
            started_at=time.time(),
        )


def _unregister_process(proc: subprocess.Popen) -> None:
    with _PROCESSES_LOCK:
        _PROCESSES.pop(proc.pid, None)


def _prune_finished_locked() -> None:
    finished = [pid for pid, tracked in _PROCESSES.items() if tracked.proc.poll() is not None]
    for pid in finished:
        _PROCESSES.pop(pid, None)


def _kill_process(proc: subprocess.Popen, *, force: bool = False) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL if force else signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        if force:
            proc.kill()
        else:
            proc.terminate()


def _display_cmd(cmd: Command) -> str:
    if isinstance(cmd, str):
        return cmd
    return shlex.join([str(part) for part in cmd])
