"""The redacting-shell REPL: runs typed lines, handles :meta-commands."""
import json

from valet.repl import Session, format_exec, interact, run_command


def _recorder(resp=None):
    sent = []

    def send(req):
        sent.append(req)
        return resp if resp is not None else {"op": "exec", "ok": True,
                                              "exit_code": 0, "stdout": "hi\n",
                                              "stderr": ""}

    return send, sent


def test_plain_line_runs_as_command():
    send, sent = _recorder()
    sess = Session()
    keep, out = run_command("echo hi", sess, send)
    assert keep is True
    assert sent[0]["op"] == "exec"
    assert sent[0]["cmd"] == "echo hi"
    assert sent[0]["shell"] is True
    assert out == "hi"


def test_cwd_is_included_when_set():
    send, sent = _recorder()
    sess = Session(cwd="/tmp")
    run_command("ls", sess, send)
    assert sent[0]["cwd"] == "/tmp"


def test_meta_quit_stops_loop():
    send, _ = _recorder()
    assert run_command(":quit", Session(), send) == (False, None)
    assert run_command(":exit", Session(), send) == (False, None)


def test_meta_cwd_get_and_set():
    send, sent = _recorder()
    sess = Session()
    _, out = run_command(":cwd /work", sess, send)
    assert sess.cwd == "/work"
    assert "/work" in out
    _, out2 = run_command(":cwd", sess, send)
    assert "/work" in out2
    assert sent == []  # meta-commands don't run commands


def test_meta_shell_toggle_changes_requests():
    send, sent = _recorder()
    sess = Session()
    run_command(":shell off", sess, send)
    assert sess.shell is False
    run_command("echo hi", sess, send)
    assert sent[0]["shell"] is False


def test_meta_help_does_not_send():
    send, sent = _recorder()
    _, out = run_command(":help", Session(), send)
    assert "meta-command" in out.lower()
    assert sent == []


def test_unknown_meta_reported():
    send, sent = _recorder()
    _, out = run_command(":bogus", Session(), send)
    assert "unknown meta-command" in out
    assert sent == []


def test_meta_call_passes_json_through():
    send, sent = _recorder(resp={"ok": True, "pong": True})
    run_command(':call {"op":"ping"}', Session(), send)
    assert sent[0] == {"op": "ping"}


def test_format_exec_shows_stderr_and_exit():
    out = format_exec({"op": "exec", "ok": False, "exit_code": 2,
                       "stdout": "", "stderr": "boom"})
    assert "boom" in out
    assert "[exit 2]" in out


def test_format_exec_error_response():
    out = format_exec({"ok": False, "error_class": "Timeout", "detail": "timed out"})
    assert "Timeout" in out


def test_interact_loop_with_scripted_input():
    send, sent = _recorder()
    lines = iter(["echo hi", ":quit"])
    rc = interact(send, input_fn=lambda p: next(lines))
    assert rc == 0
    assert len(sent) == 1
