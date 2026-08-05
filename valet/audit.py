"""Safe audit logging for broker requests.

The audit stream is intentionally metadata-only. It records what valet decided
and the shape of the request, but never raw stdout, raw stderr, credential
values, or unredacted command material.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


@dataclass(frozen=True)
class AuditContext:
    transport: str = "direct"
    caller: str = "unknown"

    @classmethod
    def from_mapping(cls, value: Optional[dict[str, Any]]) -> "AuditContext":
        if not value:
            return cls()
        return cls(
            transport=_safe_label(value.get("transport") or "direct"),
            caller=_safe_label(value.get("caller") or "unknown"),
        )


class AuditLogger:
    def __init__(self, *, log_path: str = "", console: bool = False):
        self.log_path = log_path
        self.console = console
        if self.log_path:
            Path(self.log_path).expanduser().parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: dict[str, Any]) -> None:
        if self.log_path:
            self._append_json(event)
        if self.console:
            self._print_console(event)

    def _append_json(self, event: dict[str, Any]) -> None:
        path = Path(self.log_path).expanduser()
        try:
            with path.open("a", encoding="utf-8") as fh:
                json.dump(event, fh, sort_keys=True)
                fh.write("\n")
        except OSError as exc:
            print(f"valet: audit log write failed: {exc}", file=sys.stderr)

    def _print_console(self, event: dict[str, Any]) -> None:
        timestamp = str(event.get("timestamp", _utc_timestamp()))
        caller = _safe_label(event.get("caller", "unknown"))
        transport = _safe_label(event.get("transport", "direct"))
        decision = _safe_label(event.get("decision", "unknown"))
        phase_value = event.get("phase")
        phase = _single_line(str(phase_value)) if phase_value else ""
        command = _single_line(str(event.get("command") or event.get("op") or "-"))
        phase_part = f" {phase}" if phase else ""
        print(f"{timestamp} INFO: {caller} {transport} {decision}{phase_part} {command}")
        body = json.dumps(event, indent=2, sort_keys=True)
        for line in body.splitlines():
            print(f"   {line}")


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _safe_label(value: Any) -> str:
    label = str(value)
    return _single_line(label) or "unknown"


def _single_line(value: str, *, limit: int = 500) -> str:
    collapsed = " ".join(value.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1] + "..."
