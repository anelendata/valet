"""Transport-agnostic core: one request dict -> one response dict.

The single operation is ``exec``: run a command and return its output with
known secret values redacted. Every string returned is passed through the
Redactor and asserted clean before it leaves. UDS and REPL are thin shells over
``Broker.handle``.
"""
from __future__ import annotations

import os
import shlex
import sys
import time
import uuid
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
from .executor import run
from .policy import Policy
from .sanitize import Redactor
from .secrets import load_secret_values

_WITHHELD = "[REDACTED: output withheld — residual secret detected]"


class Broker:
    def __init__(self, cfg: BrokerConfig, *, audit_to_console: bool = False):
        self.cfg = cfg
        self.policy = Policy.from_config(cfg.policy, cfg.exec.workspace)
        self.audit = AuditLogger(
            log_path=cfg.audit.log_path,
            console=audit_to_console,
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
        raw_cmd = request.get("cmd")
        if not raw_cmd:
            raise ValidationError("missing 'cmd'")

        shell = bool(request.get("shell", self.cfg.exec.shell))
        cmd = self._normalize_cmd(raw_cmd, shell)

        cwd = request.get("cwd") or self.cfg.exec.workspace
        cwd = os.path.expanduser(cwd) if cwd else None
        if cwd is not None and not os.path.isdir(cwd):
            raise ValidationError("cwd does not exist")

        timeout = int(request.get("timeout", self.cfg.timeout_seconds))

        # Policy gate (permissive in v0.2; see valet/policy.py).
        self.policy.check(cmd, cwd)

        redactor = self._redactor_for(cwd)

        try:
            result = run(cmd, shell=shell, cwd=cwd, timeout=timeout)
        except (TimeoutError_, CommandError) as exc:
            return {
                "op": "exec", "ok": False, "error_class": exc.error_class,
                "detail": str(exc), "cwd": cwd, "shell": shell,
            }

        echoed = cmd if isinstance(cmd, str) else shlex.join(cmd)
        return {
            "op": "exec",
            "ok": result.exit_code == 0,
            "exit_code": result.exit_code,
            "cwd": cwd,
            "shell": shell,
            "cmd": self._safe(redactor, echoed),
            "stdout": self._safe(redactor, result.stdout),
            "stderr": self._safe(redactor, result.stderr),
            "redacted_value_count": len(redactor.secret_values),
        }

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
        cwd = request.get("cwd") or self.cfg.exec.workspace
        cwd = os.path.expanduser(cwd) if cwd else None
        redactor = self._redactor_for(cwd)
        return {"ok": True, "cwd": cwd,
                "redacted_value_count": len(redactor.secret_values)}

    # -- helpers ---------------------------------------------------------------

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
        return [str(t) for t in raw_cmd]

    def _redactor_for(self, cwd: Optional[str]) -> Redactor:
        sources = list(self.cfg.redaction.secret_sources)
        if cwd:
            for name in self.cfg.redaction.cwd_secret_files:
                sources.append(os.path.join(cwd, name))
        values = load_secret_values(sources)
        values.extend(v for v in self.cfg.redaction.extra_values if v)
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
            "redacted_value_count": event["redacted_value_count"],
            "returned_stdout_bytes": event["returned_stdout_bytes"],
            "returned_stderr_bytes": event["returned_stderr_bytes"],
            "withheld_output": event["withheld_output"],
        }
        return event

    def _audit_redactor(self, request: dict) -> Redactor:
        return self._redactor_for(self._audit_cwd(request))

    def _audit_cwd(self, request: dict) -> Optional[str]:
        cwd = request.get("cwd") or self.cfg.exec.workspace
        return os.path.expanduser(str(cwd)) if cwd else None

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
