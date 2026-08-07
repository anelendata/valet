"""Interactive client — a redacting shell.

Running ``valet`` with no subcommand (or ``valet repl``) drops into a prompt.
Any line you type is run as a command by the daemon, and its output comes back
with secret values scrubbed. Meta-commands start with ``:``.

The line handler is factored into ``run_command`` (pure: line + session + send
-> (keep_going, output)) so it is testable without stdin or a live socket.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Callable, Optional

from . import __version__
from .config import DEFAULT_CONFIG_NAME

Send = Callable[[dict], dict]

# Shell control characters; a line containing any of these is not a "pure cd".
_OPERATOR_CHARS = set(";&|()<>\n")
_COMMAND_SEPARATORS = set(";&|")
_SHELL_BUILTINS = (
    "cd", "echo", "exit", "export", "false", "pwd", "read", "set", "test",
    "true", "type", "umask", "unset",
)

HELP = """\
Type any command to run it; output has secrets redacted.
`cd <dir>` sticks for the session (jailed to the workspace). Meta-commands:
  :help, :?            this help
  :cwd [dir]           show or change the working directory (same as `cd`)
  :shell [on|off]      show or toggle shell mode (default off)
  :secrets             how many secret values are being redacted for the cwd
  :processes [list]    list subprocesses started by valet (:jobs also works)
  :processes kill PID  terminate a valet subprocess (:kill PID also works)
  :call <json>         send a raw request object to the daemon
  :quit, :exit         leave (Ctrl-D also works)
"""

BANNER = (
    f"valet {__version__} — redacting shell. "
    "Type a command to run it; ':help' for meta-commands, ':quit' to exit."
)


@dataclass
class Session:
    cwd: Optional[str] = None      # None => daemon's configured workspace
    shell: bool = False
    host_label: Optional[str] = None
    completion_send: Optional[Send] = None
    # Set by the CLI when policy.enforce_workspace_reads is enabled.
    completion_workspace: Optional[str] = None


def _pure_cd_target(line: str) -> Optional[str]:
    """If ``line`` is a standalone `cd [dir]`, return its target ("" for bare
    `cd`); otherwise None. A compound line (`cd x && y`, pipes) is not a pure cd
    — it runs as an exec, where the cd applies only to that subprocess."""
    if any(ch in line for ch in _OPERATOR_CHARS):
        return None
    try:
        tokens = shlex.split(line)
    except ValueError:
        return None
    if tokens and tokens[0] == "cd":
        return tokens[1] if len(tokens) > 1 else ""
    return None


def _change_dir(target: str, session: Session, send: Send) -> tuple[bool, Optional[str]]:
    req = {"op": "chdir", "target": target}
    if session.cwd:
        req["cwd"] = session.cwd
    try:
        resp = send(req)
    except ConnectionError as exc:
        return False, _connection_lost_message(exc)
    if resp.get("ok"):
        session.cwd = resp.get("cwd")
        return True, None  # shell-like: silent on success, prompt shows the dir
    return True, f"cd: {resp.get('detail') or resp.get('error_class') or 'failed'}"


def _connection_lost_message(exc: Exception) -> str:
    """Message shown when the daemon connection drops and the REPL exits.

    A refused/revoked identity arrives here as a ConnectionError carrying the
    host's reason, so the user learns they were rejected rather than seeing a
    bare "connection lost".
    """
    detail = str(exc).strip()
    if detail:
        return f"valet: {detail}. Exiting."
    return "connection to daemon lost. Exiting."


def run_command(line: str, session: Session, send: Send) -> tuple[bool, Optional[str]]:
    """Handle one REPL line. Returns ``(keep_going, output_text)``."""
    stripped = line.strip()
    if not stripped:
        return True, None

    if stripped.startswith(":"):
        return _meta(stripped[1:].strip(), session, send)

    # A standalone `cd` sticks for the session (handled by the daemon, jailed).
    cd_target = _pure_cd_target(stripped)
    if cd_target is not None:
        return _change_dir(cd_target, session, send)

    # Anything else is a command to run.
    req = {"op": "exec", "cmd": line, "shell": session.shell}
    if session.cwd:
        req["cwd"] = session.cwd
    try:
        resp = send(req)
    except ConnectionError as exc:
        return False, _connection_lost_message(exc)
    return True, format_exec(resp)


def _meta(body: str, session: Session, send: Send) -> tuple[bool, Optional[str]]:
    parts = body.split(None, 1)
    name = parts[0] if parts else ""
    arg = parts[1].strip() if len(parts) > 1 else ""

    if name in ("quit", "exit"):
        return False, None
    if name in ("help", "?", ""):
        return True, HELP
    if name == "cwd":
        if arg:
            return _change_dir(arg, session, send)
        return True, f"cwd: {session.cwd or '(daemon default)'}"
    if name == "shell":
        if arg in ("on", "true", "1"):
            session.shell = True
        elif arg in ("off", "false", "0"):
            session.shell = False
        elif arg:
            return True, "usage: :shell [on|off]"
        return True, f"shell: {'on' if session.shell else 'off'}"
    if name == "secrets":
        req = {"op": "redaction_info"}
        if session.cwd:
            req["cwd"] = session.cwd
        try:
            resp = send(req)
        except ConnectionError:
            return False, "connection to daemon lost. Exiting."
        n = resp.get("redacted_value_count", "?")
        return True, f"redacting {n} secret value(s) for {resp.get('cwd') or '(default)'}"
    if name in ("processes", "procs", "jobs"):
        return _meta_processes(arg, send)
    if name == "kill":
        return _meta_processes_kill(arg, send, "usage: :kill <pid>")
    if name == "call":
        if not arg:
            return True, ':usage: :call {"op":"exec","cmd":"echo hi"}'
        try:
            req = json.loads(arg)
        except json.JSONDecodeError as exc:
            return True, f"invalid JSON: {exc}"
        try:
            resp = send(req)
        except ConnectionError:
            return False, "connection to daemon lost. Exiting."
        return True, json.dumps(resp, indent=2)

    return True, f"unknown meta-command: :{name} (try :help)"


def _meta_processes(body: str, send: Send) -> tuple[bool, Optional[str]]:
    parts = body.split()
    if not parts or parts[0] in ("list", "ls"):
        if len(parts) > 1:
            return True, "usage: :processes [list] | :processes kill <pid>"
        try:
            resp = send({"op": "processes.list"})
        except ConnectionError:
            return False, "connection to daemon lost. Exiting."
        return True, _format_processes(resp)
    if parts[0] == "kill" and len(parts) == 2:
        return _meta_processes_kill(
            parts[1],
            send,
            "usage: :processes [list] | :processes kill <pid>",
        )
    return True, "usage: :processes [list] | :processes kill <pid>"


def _meta_processes_kill(
    pid_text: str,
    send: Send,
    usage: str,
) -> tuple[bool, Optional[str]]:
    try:
        pid = int(pid_text, 10)
    except ValueError:
        return True, usage
    if pid <= 0:
        return True, usage
    try:
        resp = send({"op": "processes.kill", "pid": pid})
    except ConnectionError:
        return False, "connection to daemon lost. Exiting."
    if not resp.get("ok"):
        return True, format_exec(resp)
    return True, f"killed subprocess {resp.get('pid')}"


def _format_processes(resp: dict) -> Optional[str]:
    if not resp.get("ok"):
        return format_exec(resp)
    processes = resp.get("processes") or []
    if not processes:
        return "no running subprocesses"
    rows = ["PID\tSECONDS\tSHELL\tCOMMAND"]
    for item in processes:
        rows.append(
            f"{item.get('pid')}\t"
            f"{item.get('runtime_seconds')}\t"
            f"{str(bool(item.get('shell'))).lower()}\t"
            f"{item.get('cmd') or ''}"
        )
    return "\n".join(rows)


def format_exec(resp: dict) -> Optional[str]:
    """Render an exec response the way a shell would: stdout, stderr, exit note."""
    if not isinstance(resp, dict):
        return str(resp)
    if resp.get("ok") is False and resp.get("error_class") == "PolicyDenied":
        detail = resp.get("detail") or "command is blocked by policy"
        return f"denied: {detail}"
    if resp.get("op") != "exec" and "stdout" not in resp:
        # An error response or a non-exec op: show it as JSON.
        if resp.get("ok") is False:
            return f"[{resp.get('error_class', 'error')}] {resp.get('detail', '')}".strip()
        return json.dumps(resp, indent=2)
    parts = []
    out = (resp.get("stdout") or "").rstrip("\n")
    err = (resp.get("stderr") or "").rstrip("\n")
    if out:
        parts.append(out)
    if err:
        parts.append(err)
    if resp.get("ok") is False and "exit_code" not in resp:
        error_class = resp.get("error_class") or "error"
        detail = resp.get("detail") or ""
        parts.append(f"valet: {error_class}: {detail}".rstrip())
    code = resp.get("exit_code", 0)
    if code not in (0, None):
        parts.append(f"[exit {code}]")
    return "\n".join(parts) if parts else None


def prompt_for(session: Session) -> str:
    """`<cwd> valet> `, or plain `valet> ` if the cwd is unknown.

    A virtual workspace path ("./...") is shown in full so it reads as
    workspace-relative, never as the real filesystem root. A real absolute path
    (no workspace jail) falls back to its basename to keep the prompt short.
    """
    prefix = f"{session.host_label}:" if session.host_label else ""
    cwd = session.cwd
    if cwd:
        shown = cwd if cwd.startswith("./") else (os.path.basename(cwd.rstrip("/")) or cwd)
        return f"{prefix}{shown} valet> "
    return f"{prefix}valet> "


def _word_start(line: str) -> int:
    """Return the start offset of the word being completed in ``line``."""
    start = 0
    quote: Optional[str] = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote != "'":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
        elif char.isspace() or char in _OPERATOR_CHARS:
            start = index + 1
    return start


def _is_command_position(line: str) -> bool:
    """Whether the next word after ``line`` starts a shell command."""
    has_word = False
    in_word = False
    quote: Optional[str] = None
    escaped = False
    for char in line:
        if escaped:
            escaped = False
            has_word = True
            in_word = True
            continue
        if char == "\\" and quote != "'":
            escaped = True
            continue
        if quote:
            has_word = True
            in_word = True
            if char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
            has_word = True
            in_word = True
        elif char.isspace():
            in_word = False
        elif char in _COMMAND_SEPARATORS:
            has_word = False
            in_word = False
        elif not in_word:
            has_word = True
            in_word = True
    return not has_word


def _unescape_word(word: str) -> tuple[str, Optional[str]]:
    """Turn a partially typed shell word into a pathname and quote context."""
    quote = word[0] if word[:1] in ("'", '"') else None
    if quote:
        word = word[1:]

    out: list[str] = []
    escaped = False
    for char in word:
        if escaped:
            out.append(char)
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        else:
            out.append(char)
    if escaped:
        out.append("\\")
    return "".join(out), quote


def _escape_unquoted(word: str) -> str:
    """Escape a completion so the shell treats it as one word."""
    special = " \t\\'\"$`!&;|<>()[]{}*?"
    return "".join("\\" + char if char in special else char for char in word)


def _render_completion(value: str, quote: Optional[str]) -> str:
    if quote == "'":
        return "'" + value
    if quote == '"':
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"')
    return _escape_unquoted(value)


def _completion_path(candidate: str, cwd: Optional[str]) -> str:
    """Resolve a rendered completion to its on-disk path."""
    value, _ = _unescape_word(candidate)
    value = os.path.expanduser(value)
    return value if os.path.isabs(value) else os.path.join(cwd or os.getcwd(), value)


def _inside_workspace(path: str, workspace: Optional[str]) -> bool:
    """Whether ``path`` remains in the configured completion workspace."""
    if not workspace:
        return True
    root = os.path.realpath(os.path.expanduser(os.path.expandvars(workspace)))
    target = os.path.realpath(path)
    return target == root or target.startswith(root + os.sep)


def path_candidates(prefix: str, cwd: Optional[str], workspace: Optional[str] = None) -> list[str]:
    """Complete a filename relative to ``cwd`` (or an absolute/tilde path)."""
    typed, quote = _unescape_word(prefix)
    if "/" in typed:
        dirname, leaf = typed.rsplit("/", 1)
        search_dir = dirname or os.sep
        display_dir = typed[:len(typed) - len(leaf)]
    else:
        search_dir = "."
        leaf = typed
        display_dir = ""

    search_dir = os.path.expanduser(search_dir)
    if not os.path.isabs(search_dir):
        search_dir = os.path.join(cwd or os.getcwd(), search_dir)
    if not _inside_workspace(search_dir, workspace):
        return []

    try:
        entries = list(os.scandir(search_dir))
    except OSError:
        return []

    matches = []
    for entry in entries:
        if not entry.name.startswith(leaf) or (not leaf.startswith(".") and entry.name.startswith(".")):
            continue
        # Match the broker's fixed guard: do not disclose the config file or
        # make it easy to reference from the interactive client.
        if entry.name.casefold() == DEFAULT_CONFIG_NAME.casefold():
            continue
        try:
            suffix = "/" if entry.is_dir() else ""
        except OSError:
            continue
        if not _inside_workspace(entry.path, workspace):
            continue
        matches.append(_render_completion(display_dir + entry.name + suffix, quote))
    return sorted(matches, key=str.casefold)


def command_candidates(prefix: str, cwd: Optional[str], path: Optional[str] = None,
                       workspace: Optional[str] = None) -> list[str]:
    """Complete shell builtins and executable files found on ``PATH``."""
    typed, quote = _unescape_word(prefix)
    if "/" in typed or typed.startswith("~"):
        return [candidate for candidate in path_candidates(prefix, cwd, workspace)
                if candidate.endswith("/") or os.access(_completion_path(candidate, cwd), os.X_OK)]

    candidates = {name for name in _SHELL_BUILTINS if name.startswith(typed)}
    search_path = path if path is not None else os.environ.get("PATH", "")
    for directory in search_path.split(os.pathsep):
        directory = os.path.expanduser(directory or (cwd or os.getcwd()))
        try:
            entries = os.scandir(directory)
        except OSError:
            continue
        with entries:
            for entry in entries:
                if not entry.name.startswith(typed):
                    continue
                try:
                    executable = entry.is_file() and os.access(entry.path, os.X_OK)
                except OSError:
                    continue
                if executable:
                    candidates.add(entry.name)
    return sorted((_render_completion(name, quote) for name in candidates), key=str.casefold)


def completion_candidates(line: str, cwd: Optional[str], path: Optional[str] = None,
                          workspace: Optional[str] = None) -> list[str]:
    """Return candidates for the word at the end of a partially typed line."""
    start = _word_start(line)
    prefix = line[start:]
    if _is_command_position(line[:start]):
        return command_candidates(prefix, cwd, path, workspace)
    return path_candidates(prefix, cwd, workspace)


def session_completion_candidates(line: str, session: Session) -> list[str]:
    """Return completion candidates, using the daemon when configured."""
    if session.completion_send is not None:
        req = {"op": "complete", "line": line}
        if session.cwd:
            req["cwd"] = session.cwd
        try:
            resp = session.completion_send(req)
        except (ConnectionError, OSError):
            return []
        if resp.get("ok") and isinstance(resp.get("candidates"), list):
            return [str(candidate) for candidate in resp["candidates"]]
        if session.host_label:
            return []
    return completion_candidates(
        line,
        session.cwd,
        workspace=session.completion_workspace,
    )


def format_candidate_columns(candidates: list[str]) -> str:
    """Render candidates in two readable columns for readline's display hook."""
    if not candidates:
        return ""
    left_width = max(len(item) for item in candidates[::2]) + 2
    rows = []
    for index in range(0, len(candidates), 2):
        left = candidates[index]
        right = candidates[index + 1] if index + 1 < len(candidates) else ""
        rows.append(f"{left:<{left_width}}{right}".rstrip())
    return "\n".join(rows)


def _display_matches(matches: list[str]) -> None:
    """Display a completion list, letting ``more`` page a long list on a TTY."""
    candidates = list(dict.fromkeys(matches))
    rendered = format_candidate_columns(candidates)
    if not rendered:
        return

    rows = (len(candidates) + 1) // 2
    terminal = shutil.get_terminal_size(fallback=(80, 24))
    if rows <= max(1, terminal.lines - 2) or not shutil.which("more"):
        print("\n" + rendered)
        return

    # ``more FILE`` keeps stdin attached to the terminal, so q cancels paging.
    with tempfile.NamedTemporaryFile("w", prefix="valet-completions-", delete=False) as fh:
        fh.write(rendered)
        fh.write("\n")
        filename = fh.name
    try:
        print()
        subprocess.run(["more", filename], check=False)
    finally:
        try:
            os.unlink(filename)
        except OSError:
            pass


def tab_completion_binding(readline_doc: Optional[str]) -> str:
    """Return the Tab binding appropriate for GNU readline or macOS libedit."""
    if "libedit" in (readline_doc or "").lower():
        return "bind ^I rl_complete"
    return "tab: complete"


def _uses_libedit(readline_doc: Optional[str]) -> bool:
    return "libedit" in (readline_doc or "").lower()


def _configure_completion(readline, session: Session) -> None:
    """Install a readline completer that follows the REPL's current directory."""
    matches: list[str] = []

    def complete(_text: str, state: int) -> Optional[str]:
        nonlocal matches
        if state == 0:
            line = readline.get_line_buffer()[:readline.get_endidx()]
            matches = session_completion_candidates(line, session)
        return matches[state] if state < len(matches) else None

    def display(_substitution: str, display_matches: list[str], _longest: int) -> None:
        _display_matches(display_matches)

    readline.set_completer_delims(" \t\n|&;()<>")
    readline.set_completer(complete)
    readline.set_completion_display_matches_hook(display)
    readline.parse_and_bind(tab_completion_binding(readline.__doc__))


def _redraw_line(prompt: str, buffer: list[str], cursor: int) -> None:
    """Redraw a raw-mode input line and put the cursor back in place."""
    line = "".join(buffer)
    sys.stdout.write("\r\033[2K" + prompt + line)
    if cursor < len(buffer):
        sys.stdout.write(f"\033[{len(buffer) - cursor}D")
    sys.stdout.flush()


def _replace_current_word(buffer: list[str], cursor: int, completion: str) -> tuple[list[str], int]:
    before = "".join(buffer[:cursor])
    start = _word_start(before)
    updated = buffer[:start] + list(completion) + buffer[cursor:]
    return updated, start + len(completion)


def _libedit_input(prompt: str, session: Session, readline) -> str:
    """A tiny line editor for libedit, whose Python display hook is ignored.

    It deliberately covers the familiar editing keys needed at the prompt while
    owning Tab so completion lists are consistently two columns.
    """
    import termios
    import tty

    fd = sys.stdin.fileno()
    original = termios.tcgetattr(fd)
    history = [readline.get_history_item(index)
               for index in range(1, readline.get_current_history_length() + 1)]
    history = [item for item in history if item is not None]
    history_index = len(history)
    buffer: list[str] = []
    cursor = 0

    sys.stdout.write(prompt)
    sys.stdout.flush()
    tty.setraw(fd)
    try:
        while True:
            char = sys.stdin.read(1)
            if char in ("\r", "\n"):
                line = "".join(buffer)
                sys.stdout.write("\r\n")
                sys.stdout.flush()
                if line:
                    readline.add_history(line)
                return line
            if char == "\x03":  # Ctrl-C
                sys.stdout.write("\r\n")
                sys.stdout.flush()
                raise KeyboardInterrupt
            if char == "\x04":  # Ctrl-D
                if not buffer:
                    sys.stdout.write("\r\n")
                    sys.stdout.flush()
                    raise EOFError
                if cursor < len(buffer):
                    del buffer[cursor]
                    _redraw_line(prompt, buffer, cursor)
                continue
            if char in ("\x7f", "\b"):
                if cursor:
                    del buffer[cursor - 1]
                    cursor -= 1
                    _redraw_line(prompt, buffer, cursor)
                continue
            if char == "\x01":  # Ctrl-A
                cursor = 0
                _redraw_line(prompt, buffer, cursor)
                continue
            if char == "\x05":  # Ctrl-E
                cursor = len(buffer)
                _redraw_line(prompt, buffer, cursor)
                continue
            if char == "\x15":  # Ctrl-U
                del buffer[:cursor]
                cursor = 0
                _redraw_line(prompt, buffer, cursor)
                continue
            if char == "\x10" and history_index:  # Ctrl-P
                history_index -= 1
                buffer = list(history[history_index])
                cursor = len(buffer)
                _redraw_line(prompt, buffer, cursor)
                continue
            if char == "\x0e":  # Ctrl-N
                if history_index < len(history) - 1:
                    history_index += 1
                    buffer = list(history[history_index])
                else:
                    history_index = len(history)
                    buffer = []
                cursor = len(buffer)
                _redraw_line(prompt, buffer, cursor)
                continue
            if char == "\t":
                before = "".join(buffer[:cursor])
                candidates = session_completion_candidates(before, session)
                if len(candidates) == 1:
                    buffer, cursor = _replace_current_word(buffer, cursor, candidates[0])
                elif candidates:
                    common = os.path.commonprefix(candidates)
                    start = _word_start(before)
                    if len(common) > len(before[start:]):
                        buffer, cursor = _replace_current_word(buffer, cursor, common)

                    # Restore cooked mode while `more` owns terminal input.
                    termios.tcsetattr(fd, termios.TCSADRAIN, original)
                    _display_matches(candidates)
                    tty.setraw(fd)
                else:
                    sys.stdout.write("\a")
                    sys.stdout.flush()
                _redraw_line(prompt, buffer, cursor)
                continue
            if char == "\x1b":  # Arrow-key sequences.
                sequence = sys.stdin.read(2)
                if sequence == "[D" and cursor:
                    cursor -= 1
                elif sequence == "[C" and cursor < len(buffer):
                    cursor += 1
                elif sequence == "[A" and history_index:
                    history_index -= 1
                    buffer = list(history[history_index])
                    cursor = len(buffer)
                elif sequence == "[B":
                    if history_index < len(history) - 1:
                        history_index += 1
                        buffer = list(history[history_index])
                    else:
                        history_index = len(history)
                        buffer = []
                    cursor = len(buffer)
                _redraw_line(prompt, buffer, cursor)
                continue
            if char.isprintable():
                buffer.insert(cursor, char)
                cursor += 1
                _redraw_line(prompt, buffer, cursor)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, original)


def interact(send: Send, *, session: Optional[Session] = None,
             input_fn: Callable[[str], str] = input) -> int:
    """Run the prompt loop. ``send`` performs one request/response."""
    session = session or Session()
    # Resolve the starting cwd (the workspace root) so the prompt and relative
    # `cd`s have a concrete base.
    if session.cwd is None:
        try:
            resp = send({"op": "chdir", "target": "."})
            if resp.get("ok"):
                session.cwd = resp.get("cwd")
        except (ConnectionError, OSError):
            pass

    line_input = input_fn
    try:  # arrow-key history/editing and tab completion if available
        import readline
        if input_fn is input:
            if _uses_libedit(readline.__doc__) and sys.stdin.isatty() and sys.stdout.isatty():
                line_input = lambda prompt: _libedit_input(prompt, session, readline)
            else:
                _configure_completion(readline, session)
    except Exception:
        pass

    print(BANNER)
    while True:
        try:
            line = line_input(prompt_for(session))
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print()
            continue
        keep_going, output = run_command(line, session, send)
        if output is not None:
            print(output)
        if not keep_going:
            break
    return 0
