"""Feeding a command its input: the `stdin` field on exec, and the CLI flags.

The point of the channel is that what a command reads is not what a shell
parses: a script, patch or JSON document reaches the program byte for byte
instead of running the gauntlet of the client's shell and the host's.
"""
import dataclasses
import io
import json
import os

import pytest

from valet.broker import EXEC_STDIN_MAX_BYTES, Broker
from valet.config import AuditConfig
from valet.executor import run as exec_run

SCRIPT = (
    "import sys\n"
    "data = sys.stdin.read()\n"
    "print('len', len(data))\n"
)


def _exec(broker, cmd, *, shell=False, **extra):
    return broker.handle({"op": "exec", "cmd": cmd, "shell": shell, **extra},
                         audit_context={"transport": "uds", "caller": "t"})


# -- executor ----------------------------------------------------------------------

def test_stdin_text_reaches_the_command():
    result = exec_run(["cat"], stdin="hello from the client\n")
    assert result.stdout == "hello from the client\n"
    assert result.exit_code == 0


def test_without_stdin_the_command_reads_nothing():
    # Not "blocks until the timeout": a command that reads stdin must see EOF.
    result = exec_run(["cat"], timeout=5)
    assert result.stdout == ""
    assert result.exit_code == 0


def test_the_command_does_not_inherit_the_daemons_stdin(tmp_path):
    # Regression: Popen used to pass no `stdin`, so the child inherited the
    # daemon's — on a daemon started in a terminal, a command reading stdin
    # consumed the operator's keystrokes and returned them to the agent.
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"TYPED-INTO-THE-DAEMONS-TERMINAL\n")
    os.close(write_fd)
    saved = os.dup(0)
    try:
        os.dup2(read_fd, 0)
        result = exec_run(["cat"], timeout=5)
    finally:
        os.dup2(saved, 0)
        os.close(saved)
        os.close(read_fd)
    assert result.stdout == ""


def test_large_stdin_does_not_deadlock_against_a_chatty_command():
    # A pipe would wedge here: the child fills the stdout buffer before reading
    # its input. stdin comes from a temp file, so there is nothing to wedge.
    payload = "x" * (256 * 1024)
    result = exec_run(["sh", "-c", "yes hello | head -c 200000; cat >/dev/null"],
                      stdin=payload, timeout=30)
    assert result.exit_code == 0
    assert len(result.stdout) == 200000


def test_stdin_is_seekable():
    # Some programs seek their input; a pipe would make this fail.
    result = exec_run(["python3", "-c",
                       "import sys; sys.stdin.read(); sys.stdin.seek(0); "
                       "print(sys.stdin.read().strip())"],
                      stdin="rewound\n")
    assert result.stdout.strip() == "rewound"


# -- broker ------------------------------------------------------------------------

def test_stdin_travels_through_the_exec_op(cfg):
    resp = _exec(Broker(cfg), ["cat"], stdin="through the broker\n")
    assert resp["ok"] is True
    assert resp["stdout"] == "through the broker\n"
    assert resp["stdin_bytes"] == len("through the broker\n")


def test_quotes_and_angle_brackets_survive_untouched(cfg):
    payload = """it's "quoted" <b>&amp;</b> $(not expanded) `nor this`\n"""
    resp = _exec(Broker(cfg), ["cat"], stdin=payload)
    assert resp["stdout"] == payload


def test_a_local_script_runs_without_touching_the_host_filesystem(cfg, workspace):
    resp = _exec(Broker(cfg), ["python3", "-"], stdin=SCRIPT + "print('ok')\n")
    assert resp["ok"] is True
    assert "ok" in resp["stdout"]
    assert os.listdir(workspace) == []  # nothing was written to run it


def test_shell_mode_takes_stdin_too(cfg):
    resp = _exec(Broker(cfg), "wc -l", shell=True, stdin="a\nb\nc\n")
    assert resp["ok"] is True
    assert resp["stdout"].strip() == "3"


def test_streaming_path_feeds_stdin_as_well(cfg):
    events = list(Broker(cfg).handle_stream(
        {"op": "exec", "cmd": ["cat"], "shell": False, "stdin": "streamed\n"},
        audit_context={"transport": "uds", "caller": "t"}))
    final = events[-1]
    assert final["ok"] is True
    assert final["stdin_bytes"] == len("streamed\n")
    assert "streamed" in "".join(
        e.get("data", "") for e in events if e.get("op") == "exec_chunk") + final["stdout"]


def test_no_stdin_field_when_none_was_sent(cfg):
    assert "stdin_bytes" not in _exec(Broker(cfg), ["echo", "hi"])


@pytest.mark.parametrize("value", [123, ["a"], {"a": 1}, True])
def test_non_string_stdin_is_refused(cfg, value):
    resp = _exec(Broker(cfg), ["cat"], stdin=value)
    assert resp["ok"] is False
    assert resp["error_class"] == "ValidationError"


def test_oversize_stdin_is_refused(cfg):
    resp = _exec(Broker(cfg), ["cat"], stdin="x" * (EXEC_STDIN_MAX_BYTES + 1))
    assert resp["ok"] is False
    assert "limit" in resp["detail"]


def test_audit_records_the_size_but_never_the_content(cfg, tmp_path):
    log = tmp_path / "audit.jsonl"
    broker = Broker(dataclasses.replace(cfg, audit=AuditConfig(log_path=str(log))))
    _exec(broker, ["cat"], stdin="SECRET-MARKER-ON-STDIN\n")
    text = log.read_text()
    event = json.loads(text.splitlines()[0])
    assert "SECRET-MARKER-ON-STDIN" not in text
    assert event["stdin_bytes"] == len("SECRET-MARKER-ON-STDIN\n")


# -- client ------------------------------------------------------------------------

class _Conn:
    def __init__(self):
        self.requests = []

    def request_stream(self, request, _on_event):
        self.requests.append(request)
        return {"op": "exec", "ok": True, "exit_code": 0, "stdout": "", "stderr": ""}

    def request(self, request):
        self.requests.append(request)
        return {"ok": True}

    def close(self):
        pass


@pytest.fixture
def conn(monkeypatch):
    c = _Conn()
    monkeypatch.setattr("valet.cli._connect", lambda _a: (c, object(), None))
    return c


def test_cli_stdin_file_is_sent_as_text(conn, tmp_path):
    from valet.cli import main
    script = tmp_path / "plan.py"
    script.write_text("print('hi')\n")
    assert main(["run", "--stdin-file", str(script), "--", "python3", "-"]) == 0
    assert conn.requests[0]["stdin"] == "print('hi')\n"
    assert conn.requests[0]["cmd"] == ["python3", "-"]


def test_cli_stdin_dash_reads_this_clients_stdin(conn, monkeypatch):
    from valet.cli import main
    monkeypatch.setattr("sys.stdin", io.StringIO("piped input\n"))
    assert main(["run", "--stdin-file", "-", "--", "cat"]) == 0
    assert conn.requests[0]["stdin"] == "piped input\n"


def test_cli_sh_dash_takes_the_command_line_from_stdin(conn, monkeypatch):
    from valet.cli import main
    # What a quoted heredoc delivers: no shell parsed any of this.
    line = """echo "it's <b>fine</b>" | tr '<' '['\n"""
    monkeypatch.setattr("sys.stdin", io.StringIO(line))
    assert main(["sh", "-"]) == 0
    assert conn.requests[0]["cmd"] == line
    assert conn.requests[0]["shell"] is True


def test_cli_sh_dash_with_an_empty_stdin_is_an_error(conn, monkeypatch, capsys):
    from valet.cli import main
    monkeypatch.setattr("sys.stdin", io.StringIO("   \n"))
    assert main(["sh", "-"]) == 2
    assert "no command on stdin" in capsys.readouterr().err
    assert conn.requests == []


def test_cli_refuses_to_read_stdin_twice(conn, monkeypatch, capsys):
    from valet.cli import main
    monkeypatch.setattr("sys.stdin", io.StringIO("echo hi\n"))
    assert main(["sh", "--stdin-file", "-", "-"]) == 2
    assert "already being read" in capsys.readouterr().err
    assert conn.requests == []


def test_cli_rejects_a_non_utf8_stdin_file(conn, tmp_path, capsys):
    from valet.cli import main
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"\xff\xfe\x00binary")
    assert main(["run", "--stdin-file", str(blob), "--", "cat"]) == 2
    assert "not UTF-8" in capsys.readouterr().err
    assert conn.requests == []


def test_cli_rejects_an_oversize_stdin_file(conn, tmp_path, capsys):
    from valet.cli import main
    big = tmp_path / "big.txt"
    big.write_text("x" * (EXEC_STDIN_MAX_BYTES + 10))
    assert main(["run", "--stdin-file", str(big), "--", "cat"]) == 2
    assert "limit" in capsys.readouterr().err
    assert conn.requests == []


def test_cli_missing_stdin_file(conn, capsys):
    from valet.cli import main
    assert main(["run", "--stdin-file", "/no/such/file", "--", "cat"]) == 2
    assert "cannot read" in capsys.readouterr().err


# -- argv mode runs no shell, and says so ------------------------------------------

@pytest.mark.parametrize("token", [">", ">>", "<", "|", "&&", ";", "2>"])
def test_cli_warns_when_argv_mode_is_handed_a_shell_operator(conn, capsys, token):
    from valet.cli import main
    # It is not an error — the token really is an argument — but silence made a
    # command that redirected nothing look like a redirect that failed.
    assert main(["run", "--", "echo", "hi", token, "out.txt"]) == 0
    err = capsys.readouterr().err
    assert repr(token) in err
    assert "runs no shell" in err
    assert conn.requests[0]["cmd"] == ["echo", "hi", token, "out.txt"]


def test_cli_does_not_warn_about_ordinary_arguments(conn, capsys):
    from valet.cli import main
    assert main(["run", "--", "grep", "-E", "a>b|c", "--color=always", "f.txt"]) == 0
    assert capsys.readouterr().err == ""


def test_cli_does_not_warn_in_shell_mode(conn, capsys):
    from valet.cli import main
    assert main(["sh", "echo hi > out.txt"]) == 0
    assert capsys.readouterr().err == ""
