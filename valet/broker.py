"""Transport-agnostic core: one request dict -> one response dict.

The single operation is ``exec``: run a command and return its output with
known secret values redacted. Every string returned is passed through the
Redactor and asserted clean before it leaves. UDS and REPL are thin shells over
``Broker.handle``.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import shlex
import stat
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from . import __version__
from .audit import AuditContext, AuditLogger
from .config import BrokerConfig, resolve_workspaces
from .errors import (
    CommandError,
    ConfigError,
    PolicyError,
    TimeoutError_,
    ValetError,
    ValidationError,
)
from .executor import OutputChunk, RunResult, iter_run, kill_process, list_processes, run
from .files import (
    TransferGuard,
    apply_edits,
    check_content,
    check_not_secret_file,
    clamp_mode,
    diff_context_lines,
    is_binary,
    parse_edits,
    read_file,
    render_diff,
    write_file,
)
from .policy import Policy
from .sanitize import Redactor
from .secrets import _keep as _worth_redacting
from .secrets import SecretIndex

_WITHHELD = "[REDACTED: output withheld — residual secret detected]"
# Cap README bytes returned by the ``workspace_info`` op so a pathological file
# can't flood a client orienting itself.
_README_MAX_BYTES = 64 * 1024
# Cap the decoded size of a ``files.push`` upload. The whole request travels as
# one JSON text frame, and the WebSocket transport rejects any frame over 16 MiB
# (see wsproto.read_frame). base64 inflates ~33%, so 8 MiB of file becomes
# ~10.9 MiB on the wire — comfortably inside the frame cap with the JSON envelope.
# The client (cli) enforces the same limit up front so oversize files fail fast.
FILE_PUSH_MAX_BYTES = 8 * 1024 * 1024
# A pulled file travels back the same way (base64 in one response frame).
FILE_PULL_MAX_BYTES = FILE_PUSH_MAX_BYTES
# A patched file is read and rewritten host-side; only the diff crosses the wire.
FILE_PATCH_MAX_BYTES = FILE_PUSH_MAX_BYTES
# Diff context beyond this is a file dump wearing a diff's clothes; `files pull`
# is the op for reading a file.
MAX_DIFF_CONTEXT = 10
# Transports whose client is on this machine as the socket owner. Anything else
# (the WebSocket LAN host) sends pulled bytes off-machine and needs its own opt-in.
_LOCAL_TRANSPORTS = frozenset({"uds", "direct"})
_STRUCTURED_LINE_RE = re.compile(
    r"^\s*(?:---\s*)?$|"
    r"^\s*[\{\[]|"
    r"^\s*(?:-\s*)?[A-Za-z_][A-Za-z0-9_.\- ]*\s*:\s*|"
    r"^\s*\"(?:[^\"\\]|\\.)*\"\s*:\s*"
)
_PEM_LINE_RE = re.compile(r"-----BEGIN [^-]+-----")
_ENV_ASSIGN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_WORKSPACE_VAR_RE = re.compile(r"\$\{VALET_WORKSPACE\}|\$VALET_WORKSPACE(?![A-Za-z0-9_])")


def _expand_workspace(value: str, root: Optional[str]) -> str:
    """Substitute ``$VALET_WORKSPACE`` / ``${VALET_WORKSPACE}`` with the root."""
    if not root:
        return value
    return _WORKSPACE_VAR_RE.sub(lambda _m: root, value)


def _split_leading_env(argv: list[str]) -> tuple[dict[str, str], list[str]]:
    """Split leading ``NAME=value`` tokens from an argv into (env, remainder).

    Mirrors the shell: only assignments *before* the first real word count; a
    ``NAME=value`` after the command stays an ordinary argument.
    """
    env: dict[str, str] = {}
    index = 0
    for token in argv:
        if not _ENV_ASSIGN_RE.match(token):
            break
        name, _, value = token.partition("=")
        env[name] = value
        index += 1
    return env, argv[index:]


@dataclass
class _ExecPlan:
    cmd: Any
    shell: bool          # the caller's intent, reported back and audited
    cwd: Optional[str]
    timeout: int
    extra_env: dict[str, str]
    redactor: Redactor
    echoed: str
    run_shell: bool = False  # how the executor actually runs it (a sandbox
                             # wrapper makes this an argv even for shell mode)
    path_prepend: Optional[str] = None  # a workspace-local bin to search first
    workspace_root: Optional[str] = None  # exported to the child as VALET_WORKSPACE


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


class Workspace:
    """Runtime for one workspace: its path jail, redaction, and policy.

    All workspace-scoped logic (root resolution, virtual<->real path mapping,
    redactor construction, sandbox wrapping, the policy gate) lives here so the
    broker can serve many workspaces from one daemon by selecting the right one
    per request. Instances are immutable after construction and safe to share
    across the daemon's request threads.
    """

    def __init__(
        self,
        workspace_id: str,
        exec_cfg,
        redaction_cfg,
        policy: Policy,
        fingerprint_salt: str,
    ) -> None:
        self.id = workspace_id
        self.exec = exec_cfg
        self.redaction = redaction_cfg
        self.policy = policy
        self.fingerprint_salt = fingerprint_salt
        # Memoizes the (expensive) secret-file scan across commands. Config is
        # immutable per Workspace — a config reload builds a fresh Workspace, so
        # this cache is naturally discarded when redaction settings change.
        self._secret_index = SecretIndex()

    def root(self) -> Optional[str]:
        """The real, canonical workspace root, or None when unconfigured."""
        workspace = self.exec.workspace
        if not workspace:
            return None
        return os.path.realpath(os.path.expanduser(os.path.expandvars(workspace)))

    def workspace_bin(self) -> Optional[str]:
        """A ``bin`` directory at the workspace root, to search before PATH."""
        root = self.root()
        if not root:
            return None
        bin_dir = os.path.join(root, "bin")
        return bin_dir if os.path.isdir(bin_dir) else None

    def maybe_sandbox(self, cmd: Any, shell: bool) -> tuple[Any, bool]:
        """Wrap a command in this workspace's OS sandbox, if any.

        Returns ``(command, run_shell)``. Without a sandbox the command runs as
        given. With one, it becomes an argv prefixed by ``sandbox-exec`` (a real
        binary), so a shell command is executed as ``sandbox-exec ... /bin/sh -c
        <line>`` and ``run_shell`` is False even though the caller asked for a
        shell.
        """
        profile = self.exec.sandbox_profile
        if not profile:
            return cmd, shell
        root = self.root()
        if root is None:
            raise PolicyError("sandbox requires the workspace path to be set")
        prefix = [
            "sandbox-exec",
            "-D", f"WORKSPACE={root}",
            "-f", os.path.expanduser(os.path.expandvars(profile)),
        ]
        if shell:
            return prefix + ["/bin/sh", "-c", cmd], False
        return prefix + list(cmd), False

    def to_virtual(self, real: Optional[str]) -> Optional[str]:
        """Present a real path as a workspace-relative virtual path.

        The workspace root becomes "./", a child becomes "./child", and anything
        outside the workspace (which should not normally occur) is returned as
        is so we never invent a misleading mapping. The "./" prefix (rather than
        a bare "/") signals a workspace-relative path so it is not mistaken for
        the real filesystem root.
        """
        if real is None:
            return None
        root = self.root()
        if not root or root == os.sep:
            return real
        real = os.path.realpath(real)
        if real == root:
            return "./"
        if real.startswith(root + os.sep):
            return "./" + real[len(root) + 1:]
        return real

    def real_from_virtual(self, path: Any, base_real: Optional[str]) -> str:
        """Resolve a client path (virtual absolute or relative) to a real path.

        With a workspace set, an absolute path is virtual (rooted at the
        workspace), a bare/`~` path is the workspace root, and a relative path is
        joined onto ``base_real``. Callers jail the result where needed.
        """
        root = self.root()
        assert root is not None
        target = os.path.expandvars(str(path or ""))
        if target in ("", "~"):
            return root
        if target.startswith("~/"):
            target = "/" + target[2:]
        if target.startswith("/"):
            # Disambiguate a real absolute path from a virtual one:
            #   1. already inside the workspace  -> real, as-is
            #   2. names an existing workspace child ("/sub") -> virtual
            #   3. otherwise -> real, as-is (legacy callers, outside paths)
            real = os.path.realpath(target)
            if real == root or real.startswith(root + os.sep):
                return real
            virtual = os.path.realpath(os.path.join(root, target.lstrip("/")))
            if os.path.isdir(virtual):
                return virtual
            return real
        base = base_real or root
        return os.path.realpath(os.path.join(base, target))

    def resolve_cwd(self, raw_cwd: Any) -> Optional[str]:
        root = self.root()
        if root is None:
            cwd = raw_cwd
            if cwd is None:
                return None
            cwd = os.path.expanduser(os.path.expandvars(str(cwd)))
            if not os.path.isabs(cwd):
                cwd = os.path.abspath(cwd)
            return os.path.realpath(cwd)
        if not raw_cwd:
            return root
        return self.real_from_virtual(raw_cwd, root)

    def secret_sources(self, cwd: Optional[str] = None) -> list[str]:
        """``secret_file_paths`` resolved to absolute sources (see redactor_for)."""
        base = self.root() or cwd
        sources = []
        for pattern in self.redaction.secret_file_paths:
            resolved = os.path.expanduser(os.path.expandvars(pattern))
            if os.path.isabs(resolved):
                sources.append(resolved)
            elif base:
                sources.append(os.path.join(base, resolved))
            # A relative pattern with no base can't be located; skip it.
        return sources

    def secret_files(self) -> list[str]:
        """The concrete files behind this workspace's secret sources."""
        return self._secret_index.files_for(self.secret_sources(), self.policy.deny_read)

    def redactor_for(self, cwd: Optional[str], *, extra_values=(),
                     load_secrets: bool = True) -> Redactor:
        # Each secret_file_paths entry is a glob (like deny_read). An
        # absolute / ~-rooted pattern applies to every command; a relative one is
        # resolved against the WORKSPACE ROOT (not the command's cwd), so the
        # whole workspace's secrets are masked no matter where the command runs.
        # Resolving against cwd used to leak: `cd` into a `.config`/`.secrets`
        # dir put the anchor ABOVE cwd, so `**/.config/**` matched nothing and
        # the file's value was never loaded. Root-relative also means one cache
        # key per workspace (every cwd shares it, and the startup warmup fills
        # it). Without a workspace, fall back to cwd.
        #
        # load_secrets=False returns a PATH-ONLY redactor: it keeps the
        # workspace-root/home virtualization but loads no secret values, so it
        # skips the whole-workspace scan entirely. Used to audit read-only ops
        # (complete/ping/chdir/...) that have no command output to scrub — a
        # keystroke Tab-completion must not trigger a full secret index build.
        values: list[str] = []
        if load_secrets:
            # Copy: the index returns its cached list, which must not collect
            # every command's extra values.
            values = list(self._secret_index.values_for(
                self.secret_sources(cwd), self.policy.deny_read))
            # Config-listed literals are always masked; env values (e.g. an
            # inline `NAME=value` prefix or --env) are masked only if long enough
            # to look secret, so trivial ones like `1` or `tiny` don't over-redact.
            values.extend(v for v in self.redaction.extra_values if v)
            values.extend(v for v in extra_values if _worth_redacting(v))
        workspace_root = self.root() or ""
        # Only rewrite the home prefix when confined to a workspace: that is the
        # mode where leaking the real host layout (a sibling of the workspace,
        # the username) matters. Without a workspace, output is left verbatim.
        home_dir = os.path.expanduser("~") if workspace_root else ""
        return Redactor.build(
            values, self.fingerprint_salt,
            suspected=self.redaction.redact_suspected if load_secrets else False,
            high_entropy=self.redaction.redact_high_entropy if load_secrets else False,
            workspace_root=workspace_root,
            home_dir=home_dir,
        )


class Broker:
    def __init__(self, cfg: BrokerConfig, *, audit_to_console: bool = False):
        self._lock = threading.RLock()
        self._audit_to_console = audit_to_console
        self._install_config(cfg, console=audit_to_console)

    def reload(self, cfg: BrokerConfig) -> None:
        """Replace mutable config-backed state for future requests."""
        with self._lock:
            self._install_config(
                cfg, console=self._audit_to_console and cfg.audit.console
            )

    def warm_redaction(self) -> int:
        """Pre-build each workspace's secret index + matcher at its root.

        The first command in a workspace otherwise pays the whole cost of
        scanning, parsing (a big .har can be seconds), and building the matcher.
        Doing it up front at server start moves that off the client's critical
        path. Best-effort: a workspace that fails is skipped. Returns the count
        warmed.
        """
        with self._lock:
            workspaces = list(self.workspaces.values())
        warmed = 0
        for ws in workspaces:
            root = ws.root()
            if not root:
                continue
            try:
                # redactor_for triggers the scan+parse cache; redact() on a
                # non-empty string forces the exact-value matcher to be built
                # and cached, so nothing is left for the first real request.
                ws.redactor_for(root).redact(" ")
                warmed += 1
            except Exception:
                continue
        return warmed

    def _install_config(self, cfg: BrokerConfig, *, console: bool) -> None:
        self.cfg = cfg
        self.workspaces = self._build_workspaces(cfg)
        if not self.workspaces:
            raise ConfigError(
                "no workspace configured. Add one with "
                "`valet workspaces add <id> <dir>` before starting the server."
            )
        self.default_workspace = (
            cfg.default_workspace if cfg.default_workspace in self.workspaces
            else next(iter(self.workspaces))
        )
        # Kept for callers/tests that reach for a single policy: the default
        # workspace's gate.
        self.policy = self.workspaces[self.default_workspace].policy
        self.audit = AuditLogger(log_path=cfg.audit.log_path, console=console)

    @staticmethod
    def _build_workspaces(cfg: BrokerConfig) -> dict[str, "Workspace"]:
        result: dict[str, Workspace] = {}
        for wid, wcfg in resolve_workspaces(cfg).items():
            result[wid] = Workspace(
                wid,
                wcfg.exec,
                wcfg.redaction,
                Policy.from_config(
                    wcfg.policy, wcfg.exec.workspace, allow_shell=wcfg.exec.shell
                ),
                cfg.fingerprint_salt,
            )
        return result

    def _workspace(self, request: Any) -> "Workspace":
        """The workspace a request targets, raising if it names an unknown one."""
        wid = None
        if isinstance(request, dict):
            wid = request.get("workspace")
        wid = wid or self.default_workspace
        ws = self.workspaces.get(wid)
        if ws is None:
            raise ValidationError(f"unknown workspace: {wid!r}")
        return ws

    def _workspace_or_default(self, request: Any) -> "Workspace":
        """Like ``_workspace`` but never raises — for audit, where an unknown
        workspace must still produce a (default) redactor rather than blow up."""
        wid = None
        if isinstance(request, dict):
            wid = request.get("workspace")
        return self.workspaces.get(wid or self.default_workspace) or \
            self.workspaces[self.default_workspace]

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
            if op == "files.push":
                response = {**base, **self._files_push(request)}
                return response
            if op == "files.pull":
                response = {**base, **self._files_pull(request, context)}
                return response
            if op == "files.patch":
                response = {**base, **self._files_patch(request, context)}
                return response
            if op == "ping":
                default_ws = self.workspaces[self.default_workspace]
                response = {
                    **base,
                    "ok": True,
                    "pong": True,
                    "shell_default": default_ws.exec.shell,
                    "default_workspace": self.default_workspace,
                    "workspaces": sorted(self.workspaces),
                }
                return response
            if op == "workspaces":
                response = {**base, **self._workspaces_list()}
                return response
            if op == "workspace_info":
                response = {**base, **self._workspace_info(request)}
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
        ws = self._workspace(request)
        plan = self._exec_plan(request, ws)

        try:
            result = run(
                plan.cmd,
                shell=plan.run_shell,
                cwd=plan.cwd,
                timeout=plan.timeout,
                extra_env=plan.extra_env,
                allow_script_fallback=ws.exec.shell,
                path_prepend=plan.path_prepend,
                workspace_root=plan.workspace_root,
            )
        except (TimeoutError_, CommandError) as exc:
            return {
                "op": "exec", "ok": False, "error_class": exc.error_class,
                "detail": str(exc), "cwd": ws.to_virtual(plan.cwd),
                "shell": plan.shell,
            }

        return {
            "op": "exec",
            "ok": result.exit_code == 0,
            "exit_code": result.exit_code,
            "cwd": ws.to_virtual(plan.cwd),
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

            ws = self._workspace(request)
            plan = self._exec_plan(request, ws)
            self._audit_exec_started(request, plan, context)
            buffers = {
                "stdout": _StreamRedactor(plan.redactor),
                "stderr": _StreamRedactor(plan.redactor),
            }
            emitted = {"stdout": False, "stderr": False}

            result: Optional[RunResult] = None
            for item in iter_run(
                plan.cmd,
                shell=plan.run_shell,
                cwd=plan.cwd,
                timeout=plan.timeout,
                extra_env=plan.extra_env,
                cancel_event=cancel_event,
                allow_script_fallback=ws.exec.shell,
                path_prepend=plan.path_prepend,
                workspace_root=plan.workspace_root,
            ):
                if isinstance(item, OutputChunk):
                    for text in buffers[item.stream].feed(item.text):
                        emitted[item.stream] = True
                        yield {**base, "op": "exec_chunk", "stream": item.stream,
                               "data": text}
                else:
                    result = item

            if result is None:
                result = RunResult(exit_code=1, stdout="", stderr="")

            for stream, buffer in buffers.items():
                for text in buffer.finish():
                    emitted[stream] = True
                    yield {**base, "op": "exec_chunk", "stream": stream, "data": text}

            response = {
                **base,
                "op": "exec",
                "ok": result.exit_code == 0,
                "exit_code": result.exit_code,
                "cwd": ws.to_virtual(plan.cwd),
                "shell": plan.shell,
                "cmd": self._safe(plan.redactor, plan.echoed),
                "stdout": (
                    "" if emitted["stdout"] else self._safe(plan.redactor, result.stdout)
                ),
                "stderr": (
                    "" if emitted["stderr"] else self._safe(plan.redactor, result.stderr)
                ),
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
        it. With a workspace set the client speaks in virtual paths ("/" is the
        workspace root); ``realpath`` resolves ``..`` and symlinks first, so
        neither can be used to climb above the root, and the reply is virtual so
        the real parent path is never disclosed.
        """
        ws = self._workspace(request)
        root = ws.root()
        target = str(request.get("target", "") or "")

        if root is None:
            cur = request.get("cwd")
            t = os.path.expanduser(os.path.expandvars(target)) if target else "."
            base = os.path.expanduser(cur) if cur else os.getcwd()
            newpath = os.path.realpath(t if os.path.isabs(t) else os.path.join(base, t))
            if not os.path.isdir(newpath):
                raise ValidationError("no such directory")
            return {"op": "chdir", "ok": True, "cwd": newpath}

        base_real = ws.real_from_virtual(request.get("cwd") or "/", None)
        newpath = ws.real_from_virtual(target, base_real)
        if not os.path.isdir(newpath):
            raise ValidationError("no such directory")
        if newpath != root and not newpath.startswith(root + os.sep):
            raise PolicyError("cannot cd above the workspace")
        return {"op": "chdir", "ok": True, "cwd": ws.to_virtual(newpath)}

    def _files_push(self, request: dict) -> dict:
        """Write a client-supplied file into the workspace (agent -> host).

        Bytes arrive base64-encoded in ``content_b64`` (the JSON transport carries
        only UTF-8 text, so any file type must be encoded) and are decoded and
        written to ``path`` *inside the workspace*. The destination is always a
        workspace-virtual path jailed to the root, and it may not be a secret
        source, a ``deny_read`` path, VCS internals, valet's own state, or a name
        that shadows a program — see :mod:`valet.files` for the full rule set.
        """
        ws = self._workspace(request)
        guard = TransferGuard.for_workspace(ws, self.cfg)

        content = self._decode_push_content(request.get("content_b64"))
        lexical, dest = guard.resolve(request.get("path"))
        if dest == guard.root:
            raise ValidationError("destination is a directory")
        guard.check_push(lexical, dest)

        mode = clamp_mode(request.get("mode"))
        created = write_file(guard.root, dest, content, mode,
                             overwrite=bool(request.get("overwrite", True)))

        return {
            "op": "files.push",
            "ok": True,
            "path": ws.to_virtual(dest),
            "bytes_written": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "created": created,
        }

    def _files_pull(self, request: dict, context: AuditContext) -> dict:
        """Return a workspace file's bytes to the client (host -> agent).

        Unlike every other op, the result is not passed through redaction — a
        redacted file is a corrupted file — so a pull is refused instead whenever
        redaction would have mattered. In order:

          1. enabled per workspace (``allow_pull``), and for WebSocket clients on
             other machines separately (``allow_pull_lan``);
          2. the path rules shared with push: no secret source, ``deny_read``
             path, VCS internals, or valet state (case-insensitive, lexical and
             symlink-resolved);
          3. opened without following symlinks; must be a regular, single-link
             file within the size cap;
          4. not a secret file by identity, nor a byte-for-byte copy of one;
          5. content: text that the workspace redactor would change is refused;
             binary is refused unless ``allow_pull_binary``, and even then is
             searched for known secret values and key shapes.

        What this cannot stop is a secret *transformed* into a workspace file by
        a command (base64, compression, encryption) — the same limit exec has;
        policy and the audit trail contain that.
        """
        ws = self._workspace(request)
        if not ws.policy.allow_pull:
            raise PolicyError(
                "files pull is disabled for this workspace ([policy].allow_pull)")
        if context.transport not in _LOCAL_TRANSPORTS and not ws.policy.allow_pull_lan:
            raise PolicyError(
                "files pull over the network is disabled ([policy].allow_pull_lan)")
        guard = TransferGuard.for_workspace(ws, self.cfg)
        lexical, real = guard.resolve(request.get("path"))
        if real == guard.root:
            raise ValidationError("path is a directory")
        guard.check_common(lexical, real)

        content, st = read_file(guard.root, real, FILE_PULL_MAX_BYTES)
        check_not_secret_file(st, content, ws.secret_files())
        check_content(content, ws.redactor_for(guard.root),
                      allow_binary=ws.policy.allow_pull_binary)

        return {
            "op": "files.pull",
            "ok": True,
            "path": ws.to_virtual(real),
            "bytes_read": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "mode": stat.S_IMODE(st.st_mode) & 0o755,
            "content_b64": base64.b64encode(content).decode("ascii"),
        }

    def _files_patch(self, request: dict, context: AuditContext) -> dict:
        """Edit a workspace file in place from literal anchors (agent -> host).

        The round-trip this collapses is: pull the file, edit it locally, push it
        back, then run something to confirm the edit landed. Instead the client
        sends ``edits`` — ``old``/``new`` literals, each with the number of
        occurrences it expects (default 1) — and the host applies them in order,
        refusing the whole request unless every count matches exactly. An anchor
        that has drifted or turns out to be ambiguous therefore fails loudly and
        changes nothing, which is the property that makes a blind edit safe.

        A patch is a host-side write, so the destination must clear the same rules
        as ``files.push`` (secret sources, ``deny_read``, VCS internals, valet
        state, program shadowing) — patching ``bin/aws`` is no safer than pushing
        it. It also reads the file, so the pull-side identity checks apply: a file
        that *is* a secret source by inode, or a copy of one, is refused even when
        its path looked ordinary.

        ``append`` adds a line at the end of the file after the edits — the one
        change that has no anchor to aim at, and the reason a run log or a table
        can be added to without first reading its last row. It is newline-
        terminated, and so is the text it follows.

        What comes back is a unified diff. At the default ``context = 0`` its every
        line is one the client supplied (removed lines are its anchors, added lines
        its replacements), so it discloses nothing the client did not already have.
        Asking for context lines means asking to read the file around the edit,
        which is ``files.pull``'s question: it needs ``allow_pull`` (and
        ``allow_pull_lan`` off-machine), and the disclosed lines go through the
        same content gate, so a patch next to a credential is refused before
        anything is written rather than returning a doctored diff.
        """
        ws = self._workspace(request)
        guard = TransferGuard.for_workspace(ws, self.cfg)
        lexical, real = guard.resolve(request.get("path"))
        if real == guard.root:
            raise ValidationError("path is a directory")
        guard.check_push(lexical, real)

        edits = parse_edits(request.get("edits"))
        ctx = self._patch_context(request, ws, context)
        append = request.get("append")
        if append is not None and not isinstance(append, str):
            raise ValidationError("append must be a string")
        dry_run = bool(request.get("dry_run"))

        content, st = read_file(guard.root, real, FILE_PATCH_MAX_BYTES)
        check_not_secret_file(st, content, ws.secret_files())
        if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise PolicyError("cannot patch a setuid/setgid file")
        if is_binary(content):
            raise ValidationError("cannot patch a binary file — its bytes have no "
                                  "lines to anchor to; push a replacement instead")
        before = content.decode("utf-8")

        after, applied = apply_edits(before, edits)
        if append:
            if not after.endswith("\n") and after:
                after += "\n"
            after += append if append.endswith("\n") else append + "\n"
        new_content = after.encode("utf-8")
        if len(new_content) > FILE_PATCH_MAX_BYTES:
            raise ValidationError(
                f"the patched file would exceed the "
                f"{FILE_PATCH_MAX_BYTES // (1024 * 1024)} MiB limit")

        virtual = ws.to_virtual(real)
        diff = render_diff(before, after, virtual, ctx)
        if ctx:
            check_content(diff_context_lines(diff).encode("utf-8"),
                          ws.redactor_for(guard.root), allow_binary=False)

        changed = new_content != content
        if changed and not dry_run:
            write_file(guard.root, real, new_content,
                       stat.S_IMODE(st.st_mode) & 0o777,
                       overwrite=True, expect=st)

        return {
            "op": "files.patch",
            "ok": True,
            "path": virtual,
            "edits": applied,
            "appended_bytes": len(append.encode("utf-8")) if append else 0,
            "changed": changed,
            "dry_run": dry_run,
            "context": ctx,
            "bytes_before": len(content),
            "bytes_after": len(new_content),
            "bytes_written": len(new_content) if (changed and not dry_run) else 0,
            "sha256_before": hashlib.sha256(content).hexdigest(),
            "sha256": hashlib.sha256(new_content).hexdigest(),
            "diff": diff,
        }

    def _patch_context(self, request: dict, ws: "Workspace",
                       context: AuditContext) -> int:
        """Validate the requested diff context, and gate it like a pull."""
        raw = request.get("context", 0)
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise ValidationError("context must be an integer")
        if not 0 <= raw <= MAX_DIFF_CONTEXT:
            raise ValidationError(
                f"context must be between 0 and {MAX_DIFF_CONTEXT}")
        if raw:
            if not ws.policy.allow_pull:
                raise PolicyError(
                    "diff context lines are file content this workspace does not "
                    "hand back ([policy].allow_pull); patch without --context")
            if context.transport not in _LOCAL_TRANSPORTS and not ws.policy.allow_pull_lan:
                raise PolicyError(
                    "diff context lines over the network are disabled "
                    "([policy].allow_pull_lan)")
        return raw

    @staticmethod
    def _decode_push_content(raw: Any) -> bytes:
        if raw is None:
            raise ValidationError("missing 'content_b64'")
        if not isinstance(raw, str):
            raise ValidationError("content_b64 must be a base64 string")
        try:
            content = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValidationError("content_b64 is not valid base64") from exc
        if len(content) > FILE_PUSH_MAX_BYTES:
            raise ValidationError(
                f"file exceeds the {FILE_PUSH_MAX_BYTES // (1024 * 1024)} MiB "
                "push limit"
            )
        return content

    def _redaction_info(self, request: dict) -> dict:
        ws = self._workspace(request)
        cwd = ws.resolve_cwd(request.get("cwd"))
        redactor = ws.redactor_for(cwd)
        return {"ok": True, "cwd": ws.to_virtual(cwd),
                "redacted_value_count": len(redactor.secret_values)}

    def _complete(self, request: dict) -> dict:
        from .repl import completion_candidates

        ws = self._workspace(request)
        line = str(request.get("line", ""))
        cwd = ws.resolve_cwd(request.get("cwd"))
        workspace = ws.exec.workspace if ws.policy.enforce_workspace_reads else None
        candidates = completion_candidates(line, cwd, workspace=workspace)
        return {"op": "complete", "ok": True, "cwd": ws.to_virtual(cwd),
                "candidates": candidates}

    def _workspaces_list(self) -> dict:
        """List the host's workspaces (id, default flag, shell mode).

        Path is intentionally omitted so a remote client never learns the real
        directory layout — only names it can select with ``--workspace``.
        """
        workspaces = [
            {
                "id": wid,
                "default": wid == self.default_workspace,
                "shell": ws.exec.shell,
            }
            for wid, ws in sorted(self.workspaces.items())
        ]
        return {"op": "workspaces", "ok": True,
                "default_workspace": self.default_workspace,
                "workspaces": workspaces}

    def _workspace_info(self, request: dict) -> dict:
        """Return a workspace's ``README.md`` so an agent can orient itself.

        Like ``_workspaces_list``, the real path is never disclosed — only the
        id and the README's text, defensively redacted and size-capped so a
        pathological file can't be used to flood a client.
        """
        ws = self._workspace(request)
        result: dict = {
            "op": "workspace_info", "ok": True, "workspace": ws.id,
            "default": ws.id == self.default_workspace, "shell": ws.exec.shell,
            "has_readme": False, "readme": None, "truncated": False,
        }
        root = ws.root()
        if root is None:
            return result
        try:
            with open(os.path.join(root, "README.md"),
                      "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(_README_MAX_BYTES + 1)
        except (FileNotFoundError, IsADirectoryError, OSError):
            return result
        truncated = len(text) > _README_MAX_BYTES
        redactor = ws.redactor_for(root)
        result["has_readme"] = True
        result["readme"] = self._safe(redactor, text[:_README_MAX_BYTES])
        result["truncated"] = truncated
        return result

    def _processes_list(self, request: dict) -> dict:
        ws = self.workspaces[self.default_workspace]
        redactor = ws.redactor_for(None)
        processes = [
            {
                "pid": item.pid,
                "cmd": self._safe(redactor, item.cmd),
                "shell": item.shell,
                "cwd": ws.to_virtual(item.cwd),
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

    def _exec_plan(self, request: dict, ws: "Optional[Workspace]" = None) -> _ExecPlan:
        if ws is None:
            ws = self._workspace(request)
        raw_cmd = request.get("cmd")
        if not raw_cmd:
            raise ValidationError("missing 'cmd'")

        shell = bool(request.get("shell", ws.exec.shell))
        if shell and not ws.exec.shell:
            raise PolicyError("shell execution is disabled")
        cmd = self._normalize_cmd(raw_cmd, shell)
        extra_env = self._normalize_env(request.get("env"))

        # Support `NAME=value cmd ...` env-assignment prefixes in argv mode, the
        # way `env NAME=value cmd` does, so this common shell-ism works without
        # enabling a full shell. (Note: `$VAR` expansion still needs a shell.)
        if not shell and isinstance(cmd, list):
            prefix_env, rest = _split_leading_env(cmd)
            if prefix_env:
                if not rest:
                    raise ValidationError(
                        "no command to run (only environment assignments, which "
                        "do not persist across commands)"
                    )
                cmd = rest
                extra_env = {**prefix_env, **extra_env}  # explicit env wins

        # Config default env (with $VALET_WORKSPACE expanded) is the base layer;
        # per-command env (above) overrides it.
        root = ws.root()
        config_env = {
            name: _expand_workspace(value, root)
            for name, value in ws.exec.env.items()
        }
        if config_env:
            extra_env = {**config_env, **extra_env}

        # In argv mode there is no shell to expand $VALET_WORKSPACE, so valet
        # substitutes that one variable itself — in the command's arguments and
        # its env values — so `ls $VALET_WORKSPACE` works. (Shell mode leaves all
        # expansion to the shell.)
        if not shell and root:
            if isinstance(cmd, list):
                cmd = [_expand_workspace(token, root) for token in cmd]
            extra_env = {k: _expand_workspace(v, root) for k, v in extra_env.items()}

        cwd = ws.resolve_cwd(request.get("cwd"))
        if cwd is not None and not os.path.isdir(cwd):
            raise ValidationError("cwd does not exist")

        timeout = int(request.get("timeout", self.cfg.timeout_seconds))

        # Policy gate (permissive in v0.2; see valet/policy.py).
        ws.policy.check(cmd, cwd)

        redactor = ws.redactor_for(cwd, extra_values=extra_env.values())
        echoed = cmd if isinstance(cmd, str) else shlex.join(cmd)
        run_cmd, run_shell = ws.maybe_sandbox(cmd, shell)
        return _ExecPlan(cmd=run_cmd, shell=shell, cwd=cwd, timeout=timeout,
                         extra_env=extra_env, redactor=redactor, echoed=echoed,
                         run_shell=run_shell, path_prepend=ws.workspace_bin(),
                         workspace_root=root)

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

    @staticmethod
    def _safe(redactor: Redactor, text: str) -> str:
        out = redactor.redact(text or "")
        # Fail closed: if any known secret value somehow survived, withhold.
        return out if redactor.is_clean(out) else _WITHHELD

    # -- audit ----------------------------------------------------------------

    def audit_security_rejection(
        self,
        *,
        op: str,
        caller: str,
        transport: str,
        detail: str,
        error_class: str = "authentication_failed",
        peer: Optional[str] = None,
        phase: str = "handshake",
    ) -> None:
        """Record a rejected handshake or a revoked session.

        Transports call this when a client fails to authenticate (phase
        ``handshake``) or when an established session is torn down because its
        identity was removed (phase ``session``), so refused and revoked
        connections leave a trail in the same audit sink as executed commands.
        The event carries no secret material — only who was refused and why.
        """
        event = {
            "timestamp": _utc_timestamp(),
            "request_id": uuid.uuid4().hex,
            "level": "WARNING",
            "caller": caller or "unknown",
            "transport": transport,
            "broker_version": __version__,
            "op": op,
            "phase": phase,
            "decision": "denied",
            "approval": "not_required",
            "ok": False,
            "error_class": error_class,
            "detail": detail,
            "peer": peer,
        }
        try:
            self.audit.record(event)
        except Exception as exc:
            print(f"valet: audit logging failed: {exc}", file=sys.stderr)

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
        ws = self._workspace_or_default(request_dict)
        # Only exec has an echoed command and command output to scrub. Read-only
        # ops (complete/ping/chdir/workspaces/...) don't, so they use a path-only
        # redactor and never trigger the whole-workspace secret scan — otherwise
        # every REPL Tab-completion would rebuild the index.
        op = request_dict.get("op", "exec") if request_dict else response.get("op")
        redactor = self._audit_redactor(request_dict, ws, load_secrets=(op == "exec"))
        command = response.get("cmd") or self._audit_command(request_dict, redactor, ws)
        cwd = response.get("cwd") or self._audit_cwd(request_dict, ws)
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
            # Which workspace the command targeted: the requested id, or the
            # host default when none was named. The virtual cwd ("./…") hides
            # this otherwise, so it is recorded explicitly for the audit trail.
            "workspace": request_dict.get("workspace") or self.default_workspace,
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
            # Visible even when the command was allowed, so probing outside the
            # workspace is auditable rather than hidden behind a virtual cwd.
            "referenced_outside_workspace": self._references_outside_workspace(request_dict, ws),
        }
        # files ops have no command; record the destination (already a virtual,
        # host-layout-free path) and size so the transfer is auditable. A refused
        # transfer has no resolved path, so record what was asked for — probing
        # protected paths must be visible too.
        push_path = response.get("path")
        if not push_path and str(request_dict.get("op", "")).startswith("files."):
            push_path = request_dict.get("path")
        event["path"] = self._safe(redactor, str(push_path)) if push_path else None
        event["bytes_written"] = response.get("bytes_written")
        event["bytes_read"] = response.get("bytes_read")
        event["sha256"] = response.get("sha256")
        event["request"] = {
            "op": event["op"],
            "cmd": command,
            "workspace": event["workspace"],
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

    def _audit_redactor(self, request: dict, ws: "Workspace",
                        *, load_secrets: bool = True) -> Redactor:
        extra_env: dict = {}
        if load_secrets:
            try:
                extra_env = self._normalize_env(request.get("env"))
            except ValetError:
                extra_env = {}
        return ws.redactor_for(
            self._audit_cwd(request, ws),
            extra_values=extra_env.values(),
            load_secrets=load_secrets,
        )

    @staticmethod
    def _audit_cwd(request: dict, ws: "Workspace") -> Optional[str]:
        return ws.resolve_cwd(request.get("cwd"))

    def _references_outside_workspace(self, request: dict, ws: "Workspace") -> bool:
        raw_cmd = request.get("cmd")
        if raw_cmd is None:
            return False
        shell = bool(request.get("shell", ws.exec.shell))
        try:
            cmd = self._normalize_cmd(raw_cmd, shell)
        except ValetError:
            cmd = raw_cmd
        try:
            return ws.policy.references_outside_workspace(cmd, self._audit_cwd(request, ws))
        except Exception:
            return False

    def _audit_command(self, request: dict, redactor: Redactor, ws: "Workspace") -> Optional[str]:
        raw_cmd = request.get("cmd")
        if raw_cmd is None:
            return None
        shell = bool(request.get("shell", ws.exec.shell))
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
