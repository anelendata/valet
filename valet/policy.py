"""Execution policy — command allow/deny and path bans.

Valet starts with a small built-in deny list for commands that control the host,
processes, shells, or valet itself. Additional policy constraints are configured
with:

  - built-in dangerous command bans — process/system control and valet itself.
  - ``deny_exec`` — additional program-name deny list (e.g. ``curl``, ``rm``).
  - ``deny_read`` — glob patterns of files a command may not reference,
    so it cannot reveal their content. Supports ``**`` (any depth), ``*``, and
    ``?``. Example: ``**/.env`` bans reading any ``.env`` no matter where it
    sits; ``~/.aws/**`` bans anything under ``~/.aws``.

The path ban is **best-effort static analysis** of the command line: it splits
on shell operators (``;`` ``&&`` ``||`` ``|`` ``&`` ``(`` ``)`` and newlines),
tracks ``cd``/``pushd`` so a token is resolved against the directory in effect
where it appears, and refuses if any token resolves to an existing file matching
a banned glob. This catches the realistic reveals — ``cat``/``less``/``grep`` a
    path, including after a ``cd``. It cannot catch a program that opens the file
    via a computed path (variable expansion, ``eval``, ``$(...)``, base64) or that
    reads it internally without naming it. For a hard guarantee, content redaction
    (valet/sanitize.py) is the backstop, and OS-level sandboxing would be required
    to stop a determined reader.
  - ``enforce_workspace_reads`` — refuse existing command-line paths and an
    explicit working directory when they resolve outside the workspace.
  - ``allow_exec`` — a non-empty list is default-deny: only these program names
    run. A path-qualified program (``tools/aws``, ``/usr/bin/git``) must also
    be the very file its bare name finds on the host ``PATH`` and lie outside
    the workspace; otherwise an agent that can write a file anywhere (the
    workspace, ``/tmp``) could name it after an allowed program. The workspace
    ``bin/`` does not count here: it is admin-trusted and already first on
    ``PATH``, so its programs run by bare name.

Per-request environment variables that redirect program lookup or load code
into the program (``PATH``, ``LD_PRELOAD``, ``PYTHONPATH``, ``GIT_CONFIG_*`` …,
see :data:`RESTRICTED_ENV`) are refused in every mode, whether they come from
``--env``, a ``NAME=value`` prefix, ``env NAME=value``, or ``export``. The host
admin can still set them in ``[exec].env``, which is not checked here.

Redaction is separate and always on; policy is about *whether a command may run
at all*.

``config.toml`` is an exception: it is always protected. The broker refuses a
command that names a file with that basename, whether it exists (read) or not
(write target). This is deliberately not configurable.
"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import unicodedata
from glob import glob, has_magic
from dataclasses import dataclass
from typing import Mapping, Optional, Union

from .config import DEFAULT_CONFIG_NAME, PolicyConfig
from .errors import PolicyError
from .globmatch import compile_glob as _compile

Command = Union[str, list[str]]

BUILTIN_DENY: tuple[str, ...] = (
    # Valet control-plane recursion.
    "valet",
    # Environment/process discovery/control.
    "env", "printenv",
    "kill", "killall", "pkill", "ps", "pgrep", "top", "htop", "lsof",
    # Privilege/session/system control.
    "sudo", "su", "doas", "login", "passwd",
    "shutdown", "reboot", "halt", "poweroff",
    "launchctl", "osascript",
    # Host/identity/environment reconnaissance.
    "whoami", "uname", "hostname", "id", "groups", "w", "who", "last",
    "finger", "arch", "uptime",
    "sw_vers", "system_profiler", "hostinfo", "dscl", "defaults", "scutil",
    "networksetup", "ioreg", "profiles",
    # Network reconnaissance.
    "ifconfig", "ipconfig", "netstat", "ss", "arp", "route", "traceroute",
    "dig", "nslookup", "host", "nmap", "tcpdump",
    # Network access / data exfiltration.
    "curl", "wget", "nc", "ncat", "netcat", "telnet",
    "ssh", "scp", "sftp", "ftp", "rsync",
    # Credential and keychain access.
    "security", "ssh-add", "ssh-agent",
    # Persistence / scheduling.
    "crontab", "at", "systemctl", "service",
    # Disk, mount, firmware, and destructive/system-state control.
    "mount", "umount", "diskutil", "dd", "mkfs", "fdisk",
    "nvram", "pmset", "kextload", "kextunload", "csrutil", "spctl",
    # Clipboard / app launching (exfil and out-of-band execution).
    "open", "pbcopy", "pbpaste",
)

SHELL_COMMANDS: tuple[str, ...] = (
    "sh", "bash", "zsh", "fish", "csh", "tcsh", "ksh",
)

# Environment variables a request may not set: each one makes an allowed program
# run code it did not ship with — a different program found first on PATH, a
# preloaded library, an interpreter startup/module path, or a config/helper that
# a tool executes. Compared case-insensitively (zsh ties `path` to PATH).
# Tool-specific config-file variables (AWS_CONFIG_FILE, KUBECONFIG, …) are not
# listed; see docs/THREAT_MODEL.md.
RESTRICTED_ENV: frozenset[str] = frozenset({
    # Program lookup and the files most tools read their config from.
    "PATH", "HOME", "XDG_CONFIG_HOME", "SHELL",
    # Shell startup and hooks.
    "ENV", "BASH_ENV", "ZDOTDIR", "SHELLOPTS", "BASHOPTS", "PROMPT_COMMAND", "PS4",
    # Interpreters.
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE",
    "PYTHONBREAKPOINT", "PYTHONWARNINGS", "PYTHONPLATLIBDIR",
    "NODE_OPTIONS", "NODE_PATH", "NODE_REPL_EXTERNAL_MODULE",
    "PERL5OPT", "PERL5LIB", "PERLLIB", "PERL5DB",
    "RUBYOPT", "RUBYLIB",
    "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH",
    "PHPRC", "PHP_INI_SCAN_DIR", "LUA_INIT", "LUA_PATH", "LUA_CPATH",
    # git (GIT_CONFIG* is a prefix below).
    "GIT_EXEC_PATH", "GIT_DIR", "GIT_COMMON_DIR", "GIT_TEMPLATE_DIR",
    "GIT_SSH", "GIT_SSH_COMMAND", "GIT_ASKPASS", "GIT_EDITOR",
    "GIT_SEQUENCE_EDITOR", "GIT_PAGER", "GIT_EXTERNAL_DIFF", "GIT_PROXY_COMMAND",
    # Helpers other tools exec.
    "EDITOR", "VISUAL", "PAGER", "MANPAGER", "LESSOPEN", "LESSCLOSE", "BROWSER",
    "SSH_ASKPASS", "SUDO_ASKPASS",
})
RESTRICTED_ENV_PREFIXES: tuple[str, ...] = (
    "LD_", "DYLD_", "GIT_CONFIG", "NPM_CONFIG_", "BASH_FUNC_",
)

# Shell builtins whose arguments set variables (`export PATH=./tools`).
_ENV_SETTING_BUILTINS = frozenset({"export", "declare", "typeset", "local", "readonly"})

# Tokens made up entirely of these characters are shell control operators and
# act as sub-command separators (";", "&&", "||", "|", "&", "(", ")", "<", ">").
_OPERATOR_CHARS = set(";&|()<>")


def _is_config_name(path: str) -> bool:
    """Match config.toml consistently on case-insensitive filesystems."""
    return os.path.basename(path).casefold() == DEFAULT_CONFIG_NAME.casefold()


@dataclass(frozen=True)
class Policy:
    workspace: Optional[str] = None
    allow_shell: bool = False
    allow_exec: tuple[str, ...] = ()
    deny_exec: tuple[str, ...] = ()
    deny_read: tuple[str, ...] = ()
    enforce_workspace_reads: bool = False
    enforce_workspace_writes: bool = False
    allow_pull: bool = False
    allow_pull_lan: bool = False
    allow_pull_binary: bool = False
    # PATH that bare program names resolve against (the admin's [exec].env PATH,
    # else the daemon's own); None means the daemon's PATH at check time.
    search_path: Optional[str] = None

    @classmethod
    def from_config(
        cls,
        cfg: PolicyConfig,
        workspace: Optional[str],
        *,
        allow_shell: bool = False,
        search_path: Optional[str] = None,
    ) -> "Policy":
        return cls(
            workspace=workspace,
            allow_shell=allow_shell,
            allow_exec=tuple(cfg.allow_exec),
            deny_exec=tuple(cfg.deny_exec),
            # Expand ~ / $VARS in patterns up front so absolute patterns like
            # ~/.aws/** compare against real absolute paths.
            deny_read=tuple(
                os.path.expanduser(os.path.expandvars(p)) for p in cfg.deny_read
            ),
            enforce_workspace_reads=cfg.enforce_workspace_reads,
            enforce_workspace_writes=cfg.enforce_workspace_writes,
            allow_pull=cfg.allow_pull,
            allow_pull_lan=cfg.allow_pull_lan,
            allow_pull_binary=cfg.allow_pull_binary,
            search_path=search_path,
        )

    def check(
        self,
        cmd: Command,
        cwd: Optional[str],
        env: Optional[Mapping[str, str]] = None,
    ) -> None:
        """Raise :class:`PolicyError` if ``cmd`` may not run.

        ``env`` is the per-request environment (``--env`` and argv ``NAME=value``
        prefixes). The admin's ``[exec].env`` must not be passed here.
        """
        for name in env or ():
            _check_env_name(name)
        effective_cwd = cwd
        if self.enforce_workspace_reads and self._is_outside_workspace(effective_cwd, None):
            raise PolicyError("working directory is outside the workspace")
        for sub in _split_subcommands(cmd):
            if not sub:
                continue

            # This guard is deliberately independent of PolicyConfig. Shell
            # redirects can become a token list of their own, so examine every
            # token rather than only command arguments.
            if any(self._is_protected_config_path(tok, effective_cwd) for tok in sub):
                raise PolicyError("config.toml is protected")

            assignments, programs = _parse_invocation(sub)
            command = os.path.basename(programs[-1]).casefold() if programs else ""
            if command in _ENV_SETTING_BUILTINS:
                assignments += [tok for tok in sub[1:] if _is_env_assignment(tok)]
            for tok in assignments:
                _check_env_name(re.split(r"\+?=", tok, maxsplit=1)[0])

            is_navigation = command in ("cd", "pushd", "popd")
            if not self.allow_shell and command in SHELL_COMMANDS:
                raise PolicyError("shell execution is disabled")

            # A non-empty allow_exec list flips to default-deny. Navigation
            # builtins are exempt so `cd`/`pushd` still work in an allowed session.
            if self.allow_exec and command and not is_navigation:
                if command not in _casefold_names(self.allow_exec):
                    raise PolicyError("command is not on the allow list")
                # The allowlist matched a basename; a path-qualified program
                # (including an `env` wrapper's own path) must also be the
                # host's, not a workspace file carrying an allowed name.
                for program in programs:
                    if "/" in program and not self._is_host_program(program, effective_cwd):
                        raise PolicyError(
                            "a program given as a path must be the host program "
                            "its name finds on PATH; run it by name"
                        )

            if command in _casefold_names(BUILTIN_DENY + self.deny_exec):
                raise PolicyError("command is on the deny list")

            for tok in sub[1:]:
                if self.enforce_workspace_reads and self._is_outside_workspace(tok, effective_cwd):
                    raise PolicyError("command references a path outside the workspace")
                if self.enforce_workspace_writes and self._is_write_outside_workspace(tok, effective_cwd):
                    raise PolicyError("command targets a path outside the workspace")
                if self.deny_read:
                    if self._is_denied_path(tok, effective_cwd):
                        raise PolicyError("command references a denied path")

            # Track directory changes so later sub-commands resolve correctly.
            if sub[0] in ("cd", "pushd") and len(sub) >= 2:
                effective_cwd = self._resolve(sub[1], effective_cwd)

    def _resolve(self, token: str, cwd: Optional[str]) -> str:
        path = os.path.expanduser(os.path.expandvars(token))
        if cwd and not os.path.isabs(path):
            path = os.path.join(cwd, path)
        return os.path.normpath(path)

    def _is_denied_path(self, token: str, cwd: Optional[str]) -> bool:
        path = self._resolve(token, cwd)
        # Only ban a real file — if nothing exists at the path there is no
        # content to reveal, and this avoids false positives on tokens that
        # merely look like a path (e.g. a grep pattern).
        if not os.path.exists(path):
            return False
        abspath = os.path.abspath(path)
        return any(
            _compile(pattern).match(abspath) is not None
            for pattern in self.deny_read
        )

    def _is_protected_config_path(self, token: str, cwd: Optional[str]) -> bool:
        """Whether a token names valet's always-protected config filename.

        The file need not exist: shell redirections and ``touch`` can create a
        target, so a write attempt must be refused too.
        """
        path = self._resolve(token, cwd)
        if _is_config_name(path):
            return True
        # Shell globs are expanded after policy evaluation. Inspect existing
        # matches so `cat config.*` cannot expand to the protected file.
        return has_magic(path) and any(_is_config_name(match) for match in glob(path))

    def _is_outside_workspace(self, token: Optional[str], cwd: Optional[str]) -> bool:
        """Whether an existing path escapes the configured workspace."""
        if not self.workspace or not token:
            return False
        path = self._resolve(token, cwd)
        if not os.path.exists(path):
            return False
        return self._escapes_workspace(path)

    def _is_write_outside_workspace(self, token: Optional[str], cwd: Optional[str]) -> bool:
        """Whether a path-like token would write outside the workspace.

        Unlike the read check this does not require the path to exist — a new
        file created outside the workspace is exactly what the write jail must
        stop. To avoid flagging ordinary arguments, only tokens that look like a
        path (absolute, ``~``-rooted, or containing a separator) are considered.
        """
        if not self.workspace or not token or not _looks_like_path(token):
            return False
        return self._escapes_workspace(self._resolve(token, cwd))

    def _is_host_program(self, token: str, cwd: Optional[str]) -> bool:
        """Whether a path-qualified program is the one its bare name would run.

        It must be the same file that ``PATH`` lookup finds for its basename
        (without the workspace ``bin/``), so a file the agent wrote anywhere —
        the workspace or a host directory it can write, like ``/tmp`` — does not
        qualify. The path as executed (directories resolved, final component
        kept) and its resolved target must also lie outside the workspace, which
        catches a workspace directory the admin put on ``PATH``. The token is not
        normalised or ``$``/``~``-expanded: the shell and argv mode would
        disagree on what it names, so any expansion character fails closed.
        Without a workspace nothing qualifies.
        """
        if not self.workspace or any(ch in token for ch in "$`~*?[{\\"):
            return False
        path = os.path.join(cwd, token) if cwd else token
        if not os.path.isfile(path) or not os.access(path, os.X_OK):
            return False
        workspace = os.path.realpath(os.path.expanduser(os.path.expandvars(self.workspace)))
        as_run = os.path.join(os.path.realpath(os.path.dirname(path)), os.path.basename(path))
        if any(_is_within(p, workspace) for p in (as_run, os.path.realpath(path))):
            return False
        search_path = self.search_path
        if search_path is None:
            search_path = os.environ.get("PATH", "")
        found = shutil.which(os.path.basename(path), path=search_path)
        try:
            return found is not None and os.path.samefile(found, path)
        except OSError:
            return False

    def _escapes_workspace(self, path: str) -> bool:
        workspace = os.path.realpath(os.path.expanduser(os.path.expandvars(self.workspace)))
        target = os.path.realpath(path)
        return target != workspace and not target.startswith(workspace + os.sep)

    def references_outside_workspace(self, cmd: Command, cwd: Optional[str]) -> bool:
        """Detection only (never raises): does the command touch an existing
        path outside the workspace? Used to flag probing in the audit log even
        when enforcement is disabled."""
        if not self.workspace:
            return False
        if self._is_outside_workspace(cwd, None):
            return True
        effective_cwd = cwd
        for sub in _split_subcommands(cmd):
            for tok in sub[1:] if sub else ():
                if self._is_outside_workspace(tok, effective_cwd):
                    return True
            if sub and sub[0] in ("cd", "pushd") and len(sub) >= 2:
                effective_cwd = self._resolve(sub[1], effective_cwd)
        return False


def _looks_like_path(token: str) -> bool:
    """A token that plausibly names a filesystem path (not a bare flag/word)."""
    return token.startswith(("/", "~", "./", "../")) or "/" in token


def _split_subcommands(cmd: Command) -> list[list[str]]:
    """Split a command into sub-commands (token lists) on shell operators.

    An argv list is a single sub-command. A shell string is lexed with operator
    awareness; newlines also separate sub-commands.
    """
    if isinstance(cmd, (list, tuple)):
        return [[str(t) for t in cmd]]

    subs: list[list[str]] = []
    for line in cmd.splitlines():
        for tokens in _split_line(line):
            subs.append(tokens)
    return subs


def _casefold_names(names: tuple[str, ...]) -> set[str]:
    return {name.casefold() for name in names}


def _parse_invocation(tokens: list[str]) -> tuple[list[str], list[str]]:
    """Split a sub-command into its env assignments and the programs it runs.

    ``A=1 env B=2 aws s3 ls`` gives ``(["A=1", "B=2"], ["env", "aws"])``. The
    last program is the effective command; an ``env`` wrapper is listed too
    because its own path is executed.
    """
    assignments: list[str] = []
    i = 0
    while i < len(tokens) and _is_env_assignment(tokens[i]):
        assignments.append(tokens[i])
        i += 1
    if i >= len(tokens):
        return assignments, []

    programs = [tokens[i]]
    if os.path.basename(tokens[i]).casefold() != "env":
        return assignments, programs

    i += 1
    while i < len(tokens):
        tok = tokens[i]
        if _is_env_assignment(tok):
            assignments.append(tok)
            i += 1
            continue
        if tok == "--":
            i += 1
            break
        if tok.startswith("-"):
            # Keep env option handling intentionally conservative. Options with
            # their own arguments are treated as the env command itself rather
            # than guessing where the child command begins.
            return assignments, programs
        break
    if i < len(tokens):
        programs.append(tokens[i])
    return assignments, programs


def _is_env_assignment(token: str) -> bool:
    # `NAME+=value` appends in bash/zsh, so it sets NAME just the same.
    return re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\+?=.*", token, re.DOTALL) is not None


def _check_env_name(name: str) -> None:
    upper = name.upper()
    if upper in RESTRICTED_ENV or upper.startswith(RESTRICTED_ENV_PREFIXES):
        raise PolicyError(
            f"{name} may not be set per command (it can change which code runs); "
            "a host admin can set it in [exec].env"
        )


def _is_within(path: str, base: str) -> bool:
    """Case- and normalisation-insensitive containment (macOS filesystems are
    both), so a differently-cased path cannot pass as outside."""
    p = unicodedata.normalize("NFC", path).casefold()
    b = unicodedata.normalize("NFC", base).casefold().rstrip(os.sep)
    return p == b or p.startswith(b + os.sep)


def _split_line(line: str) -> list[list[str]]:
    try:
        lex = shlex.shlex(line, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:
        tokens = line.split()

    subs: list[list[str]] = []
    cur: list[str] = []
    for tok in tokens:
        if tok and set(tok) <= _OPERATOR_CHARS:  # a pure-operator token
            if cur:
                subs.append(cur)
                cur = []
        else:
            cur.append(tok)
    if cur:
        subs.append(cur)
    return subs
