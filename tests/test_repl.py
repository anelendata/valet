"""The redacting-shell REPL: runs typed lines, handles :meta-commands."""
import json
import posixpath

from valet.repl import (
    Session,
    command_candidates,
    completion_candidates,
    format_candidate_columns,
    format_exec,
    interact,
    path_candidates,
    prompt_for,
    run_command,
    tab_completion_binding,
)


def _recorder(resp=None):
    """Fake daemon. Emulates `chdir` (join, no jail) so cwd tests work; every
    other op returns a canned exec-style response (or `resp` if given)."""
    sent = []

    def send(req):
        sent.append(req)
        if resp is None and req.get("op") == "chdir":
            base = req.get("cwd") or "/ws"
            target = req.get("target", "")
            if target in ("", "~"):
                newp = "/ws"
            elif target.startswith("/"):
                newp = posixpath.normpath(target)
            else:
                newp = posixpath.normpath(posixpath.join(base, target))
            return {"op": "chdir", "ok": True, "cwd": newp}
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
    sess = Session(cwd="/ws")
    _, out = run_command(":cwd work", sess, send)   # routes through chdir
    assert sess.cwd == "/ws/work"
    _, out2 = run_command(":cwd", sess, send)
    assert "/ws/work" in out2


def test_cd_sticks_for_session():
    send, sent = _recorder()
    sess = Session(cwd="/ws")
    keep, out = run_command("cd x-com", sess, send)
    assert keep is True
    assert out is None                     # silent on success, like a shell
    assert sess.cwd == "/ws/x-com"         # sticks
    assert sent[0]["op"] == "chdir"        # not an exec
    # a subsequent command runs in the new dir
    run_command("ls", sess, send)
    assert sent[1] == {"op": "exec", "cmd": "ls", "shell": True, "cwd": "/ws/x-com"}


def test_bare_cd_returns_to_workspace_root():
    send, _ = _recorder()
    sess = Session(cwd="/ws/deep/nested")
    run_command("cd", sess, send)
    assert sess.cwd == "/ws"


def test_compound_cd_is_not_intercepted():
    # `cd x && y` must run as an exec (cd applies only to that subprocess).
    send, sent = _recorder()
    sess = Session(cwd="/ws")
    run_command("cd x-com && cat f", sess, send)
    assert sent[0]["op"] == "exec"
    assert sess.cwd == "/ws"               # unchanged


def test_prompt_shows_last_dir_name():
    assert prompt_for(Session(cwd="/ws/x-com")) == "x-com valet> "
    assert prompt_for(Session(cwd="/ws")) == "ws valet> "
    assert prompt_for(Session(cwd=None)) == "valet> "


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


def test_format_exec_shows_policy_denial_for_exec_requests():
    out = format_exec({"op": "exec", "ok": False, "error_class": "PolicyDenied",
                       "detail": "command is on the deny list"})
    assert out == "denied: command is on the deny list"


def test_interact_loop_with_scripted_input():
    send, sent = _recorder()
    lines = iter(["echo hi", ":quit"])
    rc = interact(send, input_fn=lambda p: next(lines))
    assert rc == 0
    execs = [r for r in sent if r.get("op") == "exec"]
    assert len(execs) == 1


def test_command_completion_uses_path_and_skips_non_executables(tmp_path):
    executable = tmp_path / "valet-tool"
    executable.write_text("#!/bin/sh\n")
    executable.chmod(0o755)
    (tmp_path / "valet-note").write_text("not executable\n")

    assert command_candidates("valet-", str(tmp_path), str(tmp_path)) == ["valet-tool"]


def test_command_completion_allows_explicit_executable_paths(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    executable = bin_dir / "tool"
    executable.write_text("#!/bin/sh\n")
    executable.chmod(0o755)
    (bin_dir / "note").write_text("not executable\n")

    assert command_candidates("./bin/t", str(tmp_path)) == ["./bin/tool"]


def test_path_completion_includes_files_and_directories(tmp_path):
    (tmp_path / "report.txt").write_text("ok\n")
    (tmp_path / "reports").mkdir()
    (tmp_path / ".hidden").write_text("hidden\n")

    assert path_candidates("rep", str(tmp_path)) == ["report.txt", "reports/"]
    assert path_candidates(".", str(tmp_path)) == [".hidden"]


def test_workspace_limited_completion_hides_parent_paths_and_escape_symlinks(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "message.txt"
    outside.write_text("outside\n")
    (workspace / "linked.txt").symlink_to(outside)

    assert path_candidates("../", str(workspace), str(workspace)) == []
    assert path_candidates("linked", str(workspace), str(workspace)) == []
    assert completion_candidates("ls ../", str(workspace), workspace=str(workspace)) == []


def test_completion_uses_commands_at_command_positions_and_files_elsewhere(tmp_path):
    executable = tmp_path / "deploy"
    executable.write_text("#!/bin/sh\n")
    executable.chmod(0o755)
    (tmp_path / "data.json").write_text("{}\n")

    assert completion_candidates("dep", str(tmp_path), str(tmp_path)) == ["deploy"]
    assert completion_candidates("echo dat", str(tmp_path), str(tmp_path)) == ["data.json"]
    assert completion_candidates("echo ok | dep", str(tmp_path), str(tmp_path)) == ["deploy"]


def test_candidate_list_is_two_columns():
    assert format_candidate_columns(["alpha", "beta", "gamma"]) == "alpha  beta\ngamma"


def test_tab_completion_binding_supports_libedit_and_gnu_readline():
    assert tab_completion_binding("Importing this module enables libedit") == "bind ^I rl_complete"
    assert tab_completion_binding("GNU readline") == "tab: complete"
