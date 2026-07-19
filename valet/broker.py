"""Transport-agnostic core: one request dict -> one response dict.

The single operation is ``exec``: run a command and return its output with
known secret values redacted. Every string returned is passed through the
Redactor and asserted clean before it leaves. UDS and REPL are thin shells over
``Broker.handle``.
"""
from __future__ import annotations

import os
import shlex
from typing import Any, Optional

from . import __version__
from .config import BrokerConfig
from .errors import CommandError, TimeoutError_, ValetError, ValidationError
from .executor import run
from .policy import Policy
from .sanitize import Redactor
from .secrets import load_secret_values

_WITHHELD = "[REDACTED: output withheld — residual secret detected]"


class Broker:
    def __init__(self, cfg: BrokerConfig):
        self.cfg = cfg
        self.policy = Policy.from_config(cfg.policy, cfg.exec.workspace)

    # -- public entrypoint -----------------------------------------------------

    def handle(self, request: Any) -> dict:
        base = {"broker_version": __version__}
        try:
            if not isinstance(request, dict):
                raise ValidationError("request must be a JSON object")
            op = request.get("op", "exec")
            if op == "exec":
                return {**base, **self._exec(request)}
            if op == "ping":
                return {**base, "ok": True, "pong": True}
            if op == "redaction_info":
                return {**base, **self._redaction_info(request)}
            raise ValidationError(f"unknown op: {op!r}")
        except ValetError as exc:
            return {
                **base,
                "op": request.get("op") if isinstance(request, dict) else None,
                "ok": False,
                "error_class": exc.error_class,
                "detail": str(exc),
            }
        except Exception:
            # Never leak an unexpected exception's message.
            return {**base, "ok": False, "error_class": "InternalError",
                    "detail": "internal error"}

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
        return Redactor.build(values, self.cfg.fingerprint_salt)

    @staticmethod
    def _safe(redactor: Redactor, text: str) -> str:
        out = redactor.redact(text or "")
        # Fail closed: if any known secret value somehow survived, withhold.
        return out if redactor.is_clean(out) else _WITHHELD
