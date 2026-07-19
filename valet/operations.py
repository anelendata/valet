"""The allowlisted operation registry.

There is exactly ONE operation: ``schedule_list``. It is read-only. No mutating
handoff command (create/delete/deploy) is registered, so there is no code path
that can invoke one — rejection of mutations is structural, not a blocklist.

Each operation:
  1. builds a fixed argv (valet supplies every token; the caller supplies only
     allowlisted alias/stage/scope values),
  2. runs it via the executor,
  3. summarizes the result into derived, redacted facts.
"""
from __future__ import annotations

from typing import Optional

from .config import BrokerConfig, Project
from .executor import RunResult, classify_failure, run
from .sanitize import Redactor, fingerprint

try:  # PyYAML is optional; handoff prints YAML.
    import yaml  # type: ignore
except Exception:  # pragma: no cover - exercised only when yaml missing
    yaml = None


# Operations valet is willing to run, and the fact that they are read-only.
# Anything not here is rejected by the broker.
READ_ONLY_OPS = ("schedule_list",)


def build_schedule_list_argv(
    cfg: BrokerConfig, project: Project, stage: str, scope: str
) -> list[str]:
    """Construct the exact, read-only handoff invocation.

    Equivalent to:
      handoff cloud schedule list -p <dir> -w <ws> -s <stage> -v scope=<scope>
    """
    return [
        cfg.handoff_bin,
        "cloud", "schedule", "list",
        "-p", project.project_dir,
        "-w", project.workspace_dir,
        "-s", stage,
        "-v", f"scope={scope}",
    ]


def _parse_handoff_output(stdout: str) -> Optional[dict]:
    """Parse handoff's YAML stdout into a dict, or None if unparseable."""
    if yaml is None:
        return None
    try:
        data = yaml.safe_load(stdout)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _rule_identity(item: dict) -> str:
    """Best-effort canonical identity for a schedule record."""
    rule = item.get("rule")
    if isinstance(rule, dict) and rule.get("Name"):
        return str(rule["Name"])
    if item.get("name"):
        return str(item["name"])
    if item.get("target_id") is not None:
        return str(item["target_id"])
    return repr(sorted(item.items())) if item else "<empty>"


def summarize_schedule_list(
    result: RunResult,
    parsed: Optional[dict],
    scope: str,
    redactor: Redactor,
    salt: str,
) -> dict:
    """Turn one run into derived facts. Never includes raw output."""
    # handoff reports its own failures as {"status": "error", "message": ...}
    handoff_errored = bool(parsed and parsed.get("status") == "error")
    ok = result.exit_code == 0 and not handoff_errored

    schedules = []
    if parsed and isinstance(parsed.get("schedules"), list):
        schedules = parsed["schedules"]

    count = len(schedules)
    fingerprints = sorted(
        fingerprint(_rule_identity(s), salt)
        for s in schedules
        if isinstance(s, dict)
    )

    summary: dict = {
        "ok": ok,
        "exit_code": result.exit_code,
        "scope": scope,
        "count": count if parsed is not None else None,
        "by_scope": {scope: count} if parsed is not None else {},
        "rule_fingerprints": fingerprints,
        "parsed": parsed is not None,
    }
    if not ok:
        summary["error_class"] = classify_failure(result)
    return summary


def run_schedule_list(
    cfg: BrokerConfig,
    project: Project,
    stage: str,
    scope: str,
    redactor: Redactor,
) -> dict:
    """Run schedule_list once at ``scope`` and summarize."""
    argv = build_schedule_list_argv(cfg, project, stage, scope)
    result = run(
        argv,
        cwd=project.project_dir,
        timeout=cfg.timeout_seconds,
        aws_profile=project.aws_profile,
    )
    parsed = _parse_handoff_output(result.stdout)
    summary = summarize_schedule_list(
        result, parsed, scope, redactor, cfg.fingerprint_salt
    )
    return summary
