"""The exec op runs commands and redacts secret values from their output."""
from valet.broker import Broker


def test_runs_command_and_returns_output(cfg):
    resp = Broker(cfg).handle({"op": "exec", "cmd": "echo hello-world"})
    assert resp["ok"] is True
    assert resp["exit_code"] == 0
    assert "hello-world" in resp["stdout"]


def test_secret_value_is_redacted_from_stdout(cfg):
    # Echo a known secret value; it must not survive into the response.
    resp = Broker(cfg).handle(
        {"op": "exec", "cmd": "echo leaking sup3r-s3cret-value-do-not-leak now"}
    )
    assert resp["ok"] is True
    assert "sup3r-s3cret-value-do-not-leak" not in resp["stdout"]
    assert "REDACTED:secret:" in resp["stdout"]
    assert resp["redacted_value_count"] >= 1


def test_cwd_dotenv_is_loaded_and_redacted(cfg, workspace):
    # A .env in the working directory should be auto-loaded and its value hidden.
    (workspace / ".env").write_text("API_TOKEN=tok_live_abcdef123456\n")
    resp = Broker(cfg).handle(
        {"op": "exec", "cmd": "echo tok_live_abcdef123456", "cwd": str(workspace)}
    )
    assert "tok_live_abcdef123456" not in resp["stdout"]


def test_nonzero_exit_is_reported(cfg):
    resp = Broker(cfg).handle({"op": "exec", "cmd": "sh -c 'exit 3'"})
    assert resp["ok"] is False
    assert resp["exit_code"] == 3


def test_argv_mode_no_shell(cfg):
    resp = Broker(cfg).handle(
        {"op": "exec", "cmd": ["echo", "a b c"], "shell": False}
    )
    # Without a shell, "a b c" is a single argument, printed verbatim.
    assert resp["stdout"].strip() == "a b c"


def test_command_not_found_argv(cfg):
    resp = Broker(cfg).handle(
        {"op": "exec", "cmd": ["definitely-not-a-real-binary-xyz"], "shell": False}
    )
    assert resp["ok"] is False
    assert resp["exit_code"] == 127


def test_missing_cmd_rejected(cfg):
    resp = Broker(cfg).handle({"op": "exec"})
    assert resp["ok"] is False
    assert resp["error_class"] == "ValidationError"


def test_unknown_op_rejected(cfg):
    resp = Broker(cfg).handle({"op": "not_a_real_op"})
    assert resp["ok"] is False
    assert resp["error_class"] == "ValidationError"


def test_bad_cwd_rejected(cfg):
    resp = Broker(cfg).handle(
        {"op": "exec", "cmd": "echo hi", "cwd": "/no/such/dir/xyz"}
    )
    assert resp["ok"] is False
    assert resp["error_class"] == "ValidationError"


def test_stderr_is_also_redacted(cfg):
    resp = Broker(cfg).handle(
        {"op": "exec",
         "cmd": "sh -c 'echo sup3r-s3cret-value-do-not-leak 1>&2; exit 1'"}
    )
    assert "sup3r-s3cret-value-do-not-leak" not in resp["stderr"]


def test_redaction_info_op(cfg):
    resp = Broker(cfg).handle({"op": "redaction_info"})
    assert resp["ok"] is True
    assert resp["redacted_value_count"] >= 1
