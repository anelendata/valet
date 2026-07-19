"""Execution policy — the extension point for future constraints.

v0.2 is deliberately PERMISSIVE: :meth:`Policy.check` allows every command. The
structure is here so that the constraints described on the roadmap slot in
without touching the broker:

  - command allow/deny lists (``allow`` / ``deny``)
  - a workspace write-jail (``enforce_workspace_writes``): a write operation may
    not touch anything outside ``workspace``.

Redaction is separate and always on (see valet/sanitize.py); policy is about
*whether a command may run at all*, not about output.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence, Union

from .config import PolicyConfig
from .errors import PolicyError

Command = Union[str, list[str]]


@dataclass(frozen=True)
class Policy:
    workspace: Optional[str] = None
    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()
    enforce_workspace_writes: bool = False

    @classmethod
    def from_config(cls, cfg: PolicyConfig, workspace: Optional[str]) -> "Policy":
        return cls(
            workspace=workspace,
            allow=tuple(cfg.allow),
            deny=tuple(cfg.deny),
            enforce_workspace_writes=cfg.enforce_workspace_writes,
        )

    def check(self, cmd: Command, cwd: Optional[str]) -> None:
        """Raise :class:`PolicyError` if ``cmd`` may not run. Permissive now.

        Future logic goes here; keep it fail-closed when constraints are added:
        an unparseable command under an enabled policy should be *denied*, not
        allowed. For v0.2 there are no enabled constraints, so this returns.
        """
        # Even in permissive mode, honor an explicit deny list if one is set,
        # so operators can start locking things down incrementally.
        if self.deny:
            name = _program_name(cmd)
            if name is not None and name in self.deny:
                raise PolicyError("command is on the deny list")
        # allow-list and workspace write-jail intentionally not enforced yet.
        return


def _program_name(cmd: Command) -> Optional[str]:
    """Best-effort program name for deny matching. None if undeterminable."""
    import os
    import shlex

    if isinstance(cmd, (list, tuple)):
        tokens: Sequence[str] = cmd
    else:
        try:
            tokens = shlex.split(cmd)
        except ValueError:
            return None
    if not tokens:
        return None
    return os.path.basename(tokens[0])
