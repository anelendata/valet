"""Transport-agnostic core: one request dict -> one response dict.

The single operation is ``exec``: run a command and return its output with
known secret values redacted. Every string returned is passed through the
Redactor and asserted clean before it leaves. UDS and REPL are thin shells over
``Broker.handle``.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from . import __version__
from .audit import AuditContext, AuditLogger
from .config import BrokerConfig
from .errors import (
    CommandError,
    PolicyError,
    TimeoutError_,
    ValetError,
    ValidationError,
)
from .executor import OutputChunk, RunResult, iter_run, kill_process, list_processes, run
from .policy import Policy
from .sanitize import Redactor
from .secrets import load_secret_values

_WITHHELD = "[REDACTED: output withheld — residual secret detected]"
_STRUCTURED_LINE_RE = re.compile(
    r"^\s*(?:---\s*)?$|"
    r"^\s*[\{\[]|"
    r"^\s*(?:-\s*)?[A-Za-z_][A-Za-z0-9_.\- ]*\s*:\s*|"
    r"^\s*\"(?:[^\"\\]|\\.)*\"\s*:\s*"
)
_PEM_LINE_RE = re.compile(r"-----BEGIN [^-]+-----")


@dataclass
class _ExecPlan:
    cmd: Any
    shell: bool
    cwd: Optional[str]
    timeout: int
    extra_env: dict[str, str]
    redactor: Redactor
    echoed: str


class _StreamRedactor:
    """Line-stream output unless the shape needs whole-context redaction."""

    def __init__(self, redactor: Redactor):
        self.redactor = redactor
        self.pending = ""
        self.buffering = False

    def feed(self, text: str) -> list[str]:
        if not text:
            return []
        self.pending += text
        if self.buffering:
            return []

        out = []
        while "\n" in self.pending:
            line, sep, rest = self.pending.partition("\n")
            candidate = line + sep
            if self._needs_whole_context(candidate):
                self.buffering = True
                self.pending = candidate + rest
                return out
            out.append(self._safe(candidate))
            self.pending = rest
        return out

    def finish(self) -> list[str]:
        if not self.pending:
            return []
        text = self._safe(self.pending)
        self.pending = ""
        return [text] if text else []

    def _needs_whole_context(self, text: str) -> bool:
        stripped = text.strip()
        if not stripped:
            return False
        if stripped[:1] in ("{", "[") and self._is_complete_json_record(stripped):
            return False
        return bool(_PEM_LINE_RE.search(text) or _STRUCTURED_LINE_RE.match(text))

    @staticmethod
    def _is_complete_json_record(text: str) -> bool:
        try:
            json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return False
        return True

    def _safe(self, text: str) -> str:
        return Broker._safe(self.redactor, text)


class Broker:
    def __init__(self, cfg: BrokerConfig, *, audit_to_console: bool = False):
        self._lock = threading.RLock()
        self.cfg = cfg
        self._audit_to_console = audit_to_console
        self.policy = Policy.from_config(
            cfg.policy,
            cfg.exec.workspace,
            allow_shell=cfg.exec.shell,
        )
        self.audit = AuditLogger(
            log_path=cfg.audit.log_path,
            console=audit_to_console,
        )

    def reload(self, cfg: BrokerConfig) -> None:
        """Replace mutable config-backed state for future requests."""
        with self._lock:
            self.cfg = cfg
            self.policy = Policy.from_config(
                cfg.policy,
                cfg.exec.workspace,
                allow_shell=cfg.exec.shell,
            )
            self.audit = AuditLogger(
                log_path=cfg.audit.log_path,
                console=self._audit_to_console and cfg.audit.console,
            )

    # -- public entrypoint -----------------------------------------------------

    def handle(
        self,
        request: Any,
        *,
        audit_context: Optional[dict[str, Any]] = None,
    ) -> dict:
        started = time.monotonic()
        context = AuditContext.from_mapping(audit_context)
        base = {"broker_version": __version__}
        response: Optional[dict] = None
        try:
            if not isinstance(request, dict):
                raise ValidationError("request must be a JSON object")
            op = request.get("op", "exec")
            if op == "exec":
                response = {**base, **self._exec(request)}
                return response
            if op == "chdir":
                response = {**base, **self._chdir(request)}
                return response
            if op == "ping":
                response = {**base, "ok": True, "pong": True}
                return response
            if op == "redaction_info":
                response = {**base, **self._redaction_info(request)}
                return response
            if op == "complete":
                response = {**base, **self._complete(request)}
                return response
            if op == "processes.list":
                response = {**base, **self._processes_list(request)}
                return response
            if op == "processes.kill":
                response = {**base, **self._processes_kill(request)}
                return response
            raise ValidationError(f"unknown op: {op!r}")
        except ValetError as exc:
            response = {
                **base,
                "op": request.get("op") if isinstance(request, dict) else None,
                "ok": False,
                "error_class": exc.error_class,
                "detail": str(exc),
            }
            return response
        except Exception:
            # Never leak an unexpected exception's message.
            response = {**base, "ok": False, "error_class": "InternalError",
                        "detail": "internal error"}
            return response
        finally:
            if response is not None:
                self._audit(request, response, context, time.monotonic() - started)

    # -- operations ------------------------------------------------------------

    def _exec(self, request: dict) -> dict:
        plan = self._exec_plan(request)

        try:
            result = run(
                plan.cmd,
                shell=plan.shell,
                cwd=plan.cwd,
                timeout=plan.timeout,
                extra_env=plan.extra_env,
            )
        except (TimeoutError_, CommandError) as exc:
            return {
                "op": "exec", "ok": False, "error_class": exc.error_class,
                "detail": str(exc), "cwd": plan.cwd, "shell": plan.shell,
            }

        return {
            "op": "exec",
            "ok": result.exit_code == 0,
            "exit_code": result.exit_code,
            "cwd": plan.cwd,
            "shell": plan.shell,
            "cmd": self._safe(plan.redactor, plan.echoed),
            "stdout": self._safe(plan.redactor, result.stdout),
            "stderr": self._safe(plan.redactor, result.stderr),
            "redacted_value_count": len(plan.redactor.secret_values),
        }

    def handle_stream(
        self,
        request: Any,
        *,
        audit_context: Optional[dict[str, Any]] = None,
        cancel_event: Optional[threading.Event] = None,
    ):
        """Yield redacted stream events followed by the final exec response."""
        started = time.monotonic()
        context = AuditContext.from_mapping(audit_context)
        base = {"broker_version": __version__}
        response: Optional[dict] = None
        try:
            if not isinstance(request, dict):
                raise ValidationError("request must be a JSON object")
            if request.get("op", "exec") != "exec":
                response = self.handle(request, audit_context=audit_context)
                yield response
                return

            plan = self._exec_plan(request)
            self._audit_exec_started(request, plan, context)
            buffers = {
                "stdout": _StreamRedactor(plan.redactor),
                "stderr": _StreamRedactor(plan.redactor),
            }

            result: Optional[RunResult] = None
            for item in iter_run(
                plan.cmd,
                shell=plan.shell,
                cwd=plan.cwd,
                timeout=plan.timeout,
                extra_env=plan.extra_env,
                cancel_event=cancel_event,
            ):
                if isinstance(item, OutputChunk):
                    for text in buffers[item.stream].feed(item.text):
                        yield {**base, "op": "exec_chunk", "stream": item.stream,
                               "data": text}
                else:
                    result = item

            if result is None:
                result = RunResult(exit_code=1, stdout="", stderr="")

            for stream, buffer in buffers.items():
                for text in buffer.finish():
                    yield {**base, "op": "exec_chunk", "stream": stream, "data": text}

            response = {
                **base,
                "op": "exec",
                "ok": result.exit_code == 0,
                "exit_code": result.exit_code,
                "cwd": plan.cwd,
                "shell": plan.shell,
                "cmd": self._safe(plan.redactor, plan.echoed),
                "stdout": "",
                "stderr": "",
                "streamed": True,
                "redacted_value_count": len(plan.redactor.secret_values),
            }
            yield response
        except (TimeoutError_, CommandError) as exc:
            response = {
                **base, "op": "exec", "ok": False, "error_class": exc.error_class,
                "detail": str(exc),
            }
            yield response
        except ValetError as exc:
            response = {
                **base,
                "op": request.get("op") if isinstance(request, dict) else None,
                "ok": False,
                "error_class": exc.error_class,
                "detail": str(exc),
            }
            yield response
        except Exception:
            response = {**base, "ok": False, "error_class": "InternalError",
                        "detail": "internal error"}
            yield response
        finally:
            if response is not None and not (
                isinstance(request, dict) and request.get("op", "exec") != "exec"
            ):
                self._audit(request, response, context, time.monotonic() - started)

    def _chdir(self, request: dict) -> dict:
        """Resolve a `cd` for a stateful client, jailed to the workspace.

        The daemon is stateless; the REPL holds the cwd and calls this to move
        it. ``realpath`` resolves ``..`` and symlinks first, so neither can be
        used to climb above the workspace root.
        """
        workspace = self.cfg.exec.workspace
        target = str(request.get("target", "") or "")
        cur = request.get("cwd") or workspace

        # A bare `cd` (or `cd ~`) returns to the workspace root when jailed.
        if target in ("", "~") and workspace:
            newpath = os.path.realpath(os.path.expanduser(workspace))
        else:
            t = os.path.expanduser(os.path.expandvars(target)) if target else "."
            base = os.path.expanduser(cur) if cur else os.getcwd()
            newpath = os.path.realpath(t if os.path.isabs(t) else os.path.join(base, t))

        if not os.path.isdir(newpath):
            raise ValidationError("no such directory")

        if workspace:
            wroot = os.path.realpath(os.path.expanduser(workspace))
            if newpath != wroot and not newpath.startswith(wroot + os.sep):
                raise PolicyError("cannot cd above the workspace")

        return {"op": "chdir", "ok": True, "cwd": newpath}

    def _redaction_info(self, request: dict) -> dict:
        cwd = self._resolve_cwd(request.get("cwd"))
        redactor = self._redactor_for(cwd)
        return {"ok": True, "cwd": cwd,
                "redacted_value_count": len(redactor.secret_values)}

    def _complete(self, request: dict) -> dict:
        from .repl import completion_candidates

        line = str(request.get("line", ""))
        cwd = self._resolve_cwd(request.get("cwd"))
        workspace = self.cfg.exec.workspace if self.cfg.policy.enforce_workspace_reads else None
        candidates = completion_candidates(line, cwd, workspace=workspace)
        return {"op": "complete", "ok": True, "cwd": cwd, "candidates": candidates}

    def _processes_list(self, request: dict) -> dict:
        processes = [
            {
                "pid": item.pid,
                "cmd": item.cmd,
                "shell": item.shell,
                "cwd": item.cwd,
                "started_at": item.started_at,
                "runtime_seconds": round(item.runtime_seconds, 3),
            }
            for item in list_processes()
        ]
        return {"op": "processes.list", "ok": True, "processes": processes}

    def _processes_kill(self, request: dict) -> dict:
        try:
            pid = int(request.get("pid"))
        except (TypeError, ValueError):
            raise ValidationError("pid must be an integer")
        if pid <= 0:
            raise ValidationError("pid must be positive")
        if not kill_process(pid):
            raise PolicyError("process is not a valet subprocess")
        return {"op": "processes.kill", "ok": True, "pid": pid, "killed": True}

    # -- helpers ---------------------------------------------------------------

    def _exec_plan(self, request: dict) -> _ExecPlan:
        raw_cmd = request.get("cmd")
        if not raw_cmd:
            raise ValidationError("missing 'cmd'")

        shell = bool(request.get("shell", self.cfg.exec.shell))
        if shell and not self.cfg.exec.shell:
            raise PolicyError("shell execution is disabled")
        cmd = self._normalize_cmd(raw_cmd, shell)
        extra_env = self._normalize_env(request.get("env"))

        cwd = self._resolve_cwd(request.get("cwd"))
        if cwd is not None and not os.path.isdir(cwd):
            raise ValidationError("cwd does not exist")

        timeout = int(request.get("timeout", self.cfg.timeout_seconds))

        # Policy gate (permissive in v0.2; see valet/policy.py).
        self.policy.check(cmd, cwd)

        redactor = self._redactor_for(cwd, extra_values=extra_env.values())
        echoed = cmd if isinstance(cmd, str) else shlex.join(cmd)
        return _ExecPlan(cmd=cmd, shell=shell, cwd=cwd, timeout=timeout,
                         extra_env=extra_env, redactor=redactor, echoed=echoed)

    @staticmethod
    def _normalize_cmd(raw_cmd, shell: bool):
        """Coerce the request's cmd into the shape the chosen mode needs."""
        if shell:
            if isinstance(raw_cmd, (list, tuple)):
                return shlex.join([str(t) for t in raw_cmd])
            return str(raw_cmd)
        # non-shell: need an argv list
        if isinstance(raw_cmd, str):
            try:
                return shlex.split(raw_cmd)
            except ValueError as exc:
                raise ValidationError(f"could not parse command: {exc}") from exc
        if not isinstance(raw_cmd, (list, tuple)):
            raise ValidationError("cmd must be a string or argv list")
        return [str(t) for t in raw_cmd]

    def _resolve_cwd(self, raw_cwd: Any) -> Optional[str]:
        cwd = raw_cwd or self.cfg.exec.workspace
        if cwd is None:
            return None
        cwd = os.path.expanduser(os.path.expandvars(str(cwd)))
        if not os.path.isabs(cwd):
            workspace = self.cfg.exec.workspace
            if workspace:
                cwd = os.path.join(os.path.expanduser(os.path.expandvars(workspace)), cwd)
            else:
                cwd = os.path.abspath(cwd)
        return os.path.realpath(cwd)

    @staticmethod
    def _normalize_env(raw_env: Any) -> dict[str, str]:
        if raw_env in (None, {}):
            return {}
        if not isinstance(raw_env, dict):
            raise ValidationError("env must be an object")
        env: dict[str, str] = {}
        for key, value in raw_env.items():
            name = str(key)
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                raise ValidationError("env names must be valid shell identifiers")
            env[name] = str(value)
        return env

    def _redactor_for(
        self,
        cwd: Optional[str],
        *,
        extra_values=(),
    ) -> Redactor:
        sources = list(self.cfg.redaction.secret_sources)
        if cwd:
            for name in self.cfg.redaction.cwd_secret_files:
                sources.append(os.path.join(cwd, name))
        values = load_secret_values(sources)
        values.extend(v for v in self.cfg.redaction.extra_values if v)
        values.extend(v for v in extra_values if v)
        return Redactor.build(
            values, self.cfg.fingerprint_salt,
            suspected=self.cfg.redaction.redact_suspected,
            high_entropy=self.cfg.redaction.redact_high_entropy,
        )

    @staticmethod
    def _safe(redactor: Redactor, text: str) -> str:
        out = redactor.redact(text or "")
        # Fail closed: if any known secret value somehow survived, withhold.
        return out if redactor.is_clean(out) else _WITHHELD

    # -- audit ----------------------------------------------------------------

    def _audit(
        self,
        request: Any,
        response: dict,
        context: AuditContext,
        duration_seconds: float,
    ) -> None:
        try:
            event = self._audit_event(request, response, context, duration_seconds)
            self.audit.record(event)
        except Exception as exc:
            print(f"valet: audit logging failed: {exc}", file=sys.stderr)

    def _audit_exec_started(
        self,
        request: Any,
        plan: _ExecPlan,
        context: AuditContext,
    ) -> None:
        response = {
            "broker_version": __version__,
            "op": "exec",
            "ok": True,
            "cwd": plan.cwd,
            "shell": plan.shell,
            "cmd": self._safe(plan.redactor, plan.echoed),
            "redacted_value_count": len(plan.redactor.secret_values),
            "phase": "started",
        }
        self._audit(request, response, context, 0)

    def _audit_event(
        self,
        request: Any,
        response: dict,
        context: AuditContext,
        duration_seconds: float,
    ) -> dict[str, Any]:
        request_dict = request if isinstance(request, dict) else {}
        redactor = self._audit_redactor(request_dict)
        command = response.get("cmd") or self._audit_command(request_dict, redactor)
        cwd = response.get("cwd") or self._audit_cwd(request_dict)
        detail = response.get("detail")
        redacted_value_count = response.get("redacted_value_count")
        if redacted_value_count is None:
            redacted_value_count = len(redactor.secret_values)

        event = {
            "timestamp": _utc_timestamp(),
            "request_id": uuid.uuid4().hex,
            "level": "INFO",
            "caller": context.caller,
            "transport": context.transport,
            "broker_version": response.get("broker_version", __version__),
            "op": request_dict.get("op", "exec") if request_dict else response.get("op"),
            "phase": response.get("phase"),
            "decision": self._audit_decision(response),
            "approval": "not_required",
            "command": command,
            "cwd": self._safe(redactor, str(cwd)) if cwd else None,
            "shell": response.get("shell", request_dict.get("shell")),
            "timeout_seconds": request_dict.get("timeout", self.cfg.timeout_seconds),
            "duration_ms": round(duration_seconds * 1000, 3),
            "ok": bool(response.get("ok")),
            "exit_code": response.get("exit_code"),
            "error_class": response.get("error_class"),
            "detail": self._safe(redactor, str(detail)) if detail else None,
            "redacted_value_count": redacted_value_count,
            "returned_stdout_bytes": _byte_count(response.get("stdout", "")),
            "returned_stderr_bytes": _byte_count(response.get("stderr", "")),
            "withheld_output": (
                response.get("stdout") == _WITHHELD
                or response.get("stderr") == _WITHHELD
            ),
        }
        event["request"] = {
            "op": event["op"],
            "cmd": command,
            "cwd": event["cwd"],
            "shell": event["shell"],
            "timeout_seconds": event["timeout_seconds"],
        }
        event["response"] = {
            "ok": event["ok"],
            "exit_code": event["exit_code"],
            "error_class": event["error_class"],
            "detail": event["detail"],
            "phase": event["phase"],
            "redacted_value_count": event["redacted_value_count"],
            "returned_stdout_bytes": event["returned_stdout_bytes"],
            "returned_stderr_bytes": event["returned_stderr_bytes"],
            "withheld_output": event["withheld_output"],
        }
        return event

    def _audit_redactor(self, request: dict) -> Redactor:
        try:
            extra_env = self._normalize_env(request.get("env"))
        except ValetError:
            extra_env = {}
        return self._redactor_for(self._audit_cwd(request), extra_values=extra_env.values())

    def _audit_cwd(self, request: dict) -> Optional[str]:
        return self._resolve_cwd(request.get("cwd"))

    def _audit_command(self, request: dict, redactor: Redactor) -> Optional[str]:
        raw_cmd = request.get("cmd")
        if raw_cmd is None:
            return None
        shell = bool(request.get("shell", self.cfg.exec.shell))
        try:
            cmd = self._normalize_cmd(raw_cmd, shell)
        except ValetError:
            cmd = raw_cmd
        if isinstance(cmd, str):
            echoed = cmd
        else:
            echoed = shlex.join([str(t) for t in cmd])
        return self._safe(redactor, echoed)

    @staticmethod
    def _audit_decision(response: dict) -> str:
        error_class = response.get("error_class")
        if error_class == "PolicyDenied":
            return "denied"
        if error_class == "InternalError":
            return "error"
        if error_class:
            return "rejected"
        return "allowed"


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _byte_count(value: Any) -> int:
    return len(str(value or "").encode("utf-8"))
