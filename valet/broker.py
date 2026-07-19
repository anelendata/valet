"""Transport-agnostic core: one request dict -> one response dict.

Every path that returns to the caller funnels through here, and every string
field is passed through the Redactor and asserted clean before it leaves. UDS
and HTTP adapters are thin shells over ``Broker.handle``.
"""
from __future__ import annotations

from typing import Any

from . import __version__
from .config import BrokerConfig
from .errors import ValetError, ValidationError
from .executor import RunResult, classify_failure, run
from .operations import (
    READ_ONLY_OPS,
    _parse_handoff_output,
    build_schedule_list_argv,
    run_schedule_list,
    summarize_schedule_list,
)
from .sanitize import Redactor
from .secrets import load_secret_values


class Broker:
    def __init__(self, cfg: BrokerConfig):
        self.cfg = cfg

    # -- public entrypoint -----------------------------------------------------

    def handle(self, request: Any) -> dict:
        """Validate, dispatch, and return a sanitized response dict."""
        base = {"broker_version": __version__}
        try:
            if not isinstance(request, dict):
                raise ValidationError("request must be a JSON object")
            op = request.get("op")
            if op not in READ_ONLY_OPS:
                # Unknown or mutating op: rejected. There is no generic-exec path.
                raise ValidationError("unknown or non-allowlisted op")

            if op == "schedule_list":
                return {**base, **self._schedule_list(request)}

            raise ValidationError("unhandled op")  # pragma: no cover
        except ValetError as exc:
            return {
                **base,
                "op": request.get("op") if isinstance(request, dict) else None,
                "ok": False,
                "error_class": exc.error_class,
                "detail": str(exc),
            }
        except Exception:
            # Never leak an unexpected exception's message — it could embed a
            # path or credential from deep in a dependency.
            return {
                **base,
                "ok": False,
                "error_class": "InternalError",
                "detail": "internal error",
            }

    # -- operations ------------------------------------------------------------

    def _schedule_list(self, request: dict) -> dict:
        alias = request.get("project_alias")
        stage = request.get("stage", "prod")
        scope = request.get("scope", "declared")
        compare = bool(request.get("compare", False))

        project = self.cfg.project(alias)                 # alias allowlist
        stage = project.check_stage(stage)                # stage allowlist
        scope = BrokerConfig.check_scope(scope)           # scope allowlist

        redactor = Redactor.build(
            load_secret_values(project.secret_sources), self.cfg.fingerprint_salt
        )

        summary = run_schedule_list(self.cfg, project, stage, scope, redactor)

        response: dict = {
            "op": "schedule_list",
            "project_alias": alias,
            "stage": stage,
            **summary,
        }

        # Over-match answer for issue #134: only when explicitly requested, run
        # the declared + prefix baselines and compare. Off by default so the
        # common call stays a single handoff run.
        if compare:
            self._add_over_match(project, stage, redactor, response)

        # If we could not parse structured output (e.g. PyYAML not installed or
        # handoff changed its format), fall back to value-redacted raw output so
        # the caller still gets something safe. This is the only place output
        # text is ever returned, and it is guaranteed clean below.
        if not summary.get("parsed"):
            argv = build_schedule_list_argv(self.cfg, project, stage, scope)
            raw = run(argv, cwd=project.project_dir,
                      timeout=self.cfg.timeout_seconds,
                      aws_profile=project.aws_profile)
            response["redacted_output"] = self._redact_output(raw, redactor)
            response.setdefault("error_class",
                                None if raw.exit_code == 0 else classify_failure(raw))

        return self._scrub_response(response, redactor)

    def _add_over_match(self, project, stage, redactor, response: dict) -> None:
        by_scope = dict(response.get("by_scope", {}))
        for sc in ("declared", "prefix"):
            if sc not in by_scope:
                s = run_schedule_list(self.cfg, project, stage, sc, redactor)
                if s.get("count") is not None:
                    by_scope[sc] = s["count"]
        declared = by_scope.get("declared")
        prefix = by_scope.get("prefix")
        response["by_scope"] = by_scope
        if declared is not None and prefix is not None:
            response["prefix_over_match"] = {
                "over_matches": prefix > declared,
                "extra_beyond_declared": max(prefix - declared, 0),
            }

    # -- redaction gate --------------------------------------------------------

    def _redact_output(self, raw: RunResult, redactor: Redactor) -> str:
        text = redactor.redact(raw.stdout + ("\n---stderr---\n" + raw.stderr
                                             if raw.stderr else ""))
        # Belt-and-suspenders: if any known secret value somehow survived,
        # refuse to return the text at all.
        if not redactor.is_clean(text):
            return "[REDACTED:output withheld — residual secret detected]"
        return text

    def _scrub_response(self, response: dict, redactor: Redactor) -> dict:
        """Final pass: redact every string value and assert cleanliness."""
        def scrub(node):
            if isinstance(node, str):
                out = redactor.redact(node)
                return out if redactor.is_clean(out) else "[REDACTED]"
            if isinstance(node, dict):
                return {k: scrub(v) for k, v in node.items()}
            if isinstance(node, list):
                return [scrub(v) for v in node]
            return node

        return scrub(response)
