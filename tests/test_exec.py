"""The exec op runs commands and redacts secret values from their output."""
import dataclasses
import os
import sys

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
    # A configured cwd secret file should be auto-loaded and its value hidden.
    (workspace / "env_values_test").write_text("API_TOKEN=tok_live_abcdef123456\n")
    resp = Broker(cfg).handle(
        {"op": "exec", "cmd": "echo tok_live_abcdef123456", "cwd": str(workspace)}
    )
    assert "tok_live_abcdef123456" not in resp["stdout"]


def test_relative_cwd_resolves_from_workspace(cfg, workspace):
    subdir = workspace / "zendesk-jira"
    subdir.mkdir()
    script = "import os; print(os.getcwd())"
    expected = os.path.realpath(str(subdir))

    resp = Broker(cfg).handle({
        "op": "exec",
        "cmd": [sys.executable, "-c", script],
        "shell": False,
        "cwd": "zendesk-jira",
    })

    assert resp["ok"] is True
    assert resp["cwd"] == expected
    assert resp["stdout"].strip() == expected


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


def test_launch_os_error_is_command_error(cfg, monkeypatch):
    def fail_launch(*_args, **_kwargs):
        raise PermissionError("sensitive path")

    monkeypatch.setattr("valet.executor.subprocess.Popen", fail_launch)

    resp = Broker(cfg).handle(
        {"op": "exec", "cmd": [sys.executable, "-c", "print('never')"], "shell": False}
    )

    assert resp["ok"] is False
    assert resp["error_class"] == "CommandError"
    assert resp["detail"] == "command launch failed: permission denied"
    assert "sensitive path" not in resp["detail"]


def test_stream_launch_os_error_is_command_error(cfg, monkeypatch):
    def fail_launch(*_args, **_kwargs):
        raise PermissionError("sensitive path")

    monkeypatch.setattr("valet.executor.subprocess.Popen", fail_launch)

    events = list(Broker(cfg).handle_stream(
        {"op": "exec", "cmd": [sys.executable, "-c", "print('never')"], "shell": False}
    ))
    resp = events[-1]

    assert resp["ok"] is False
    assert resp["error_class"] == "CommandError"
    assert resp["detail"] == "command launch failed: permission denied"
    assert "sensitive path" not in resp["detail"]


def test_stream_shebangless_path_script_runs_when_shell_enabled(cfg, workspace):
    bindir = workspace / "bin"
    bindir.mkdir()
    script = bindir / "handoff"
    script.write_text(
        'if [ "$AWS_PROFILE" = tiny ]; then printf "env-ok "; fi\n'
        'printf "args=%s cwd=%s\\n" "$*" "$PWD"\n'
    )
    script.chmod(0o755)
    cwd = workspace / "zendesk-jira"
    cwd.mkdir()

    events = list(Broker(cfg).handle_stream({
        "op": "exec",
        "cmd": ["handoff", "-p", ".", "-w", "workspace", "cloud", "schedule", "list"],
        "shell": False,
        "cwd": "zendesk-jira",
        "env": {
            "AWS_PROFILE": "tiny",
            "PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}",
        },
    }))
    resp = events[-1]
    output = "".join(event["data"] for event in events if event.get("op") == "exec_chunk")

    assert resp["ok"] is True
    assert "env-ok args=-p . -w workspace cloud schedule list" in output
    assert f"cwd={cwd}" in output


def test_shebangless_path_script_requires_shell_fallback_enabled(cfg, workspace):
    c = dataclasses.replace(cfg, exec=dataclasses.replace(cfg.exec, shell=False))
    bindir = workspace / "bin"
    bindir.mkdir()
    script = bindir / "handoff"
    script.write_text('printf "never\\n"\n')
    script.chmod(0o755)

    events = list(Broker(c).handle_stream({
        "op": "exec",
        "cmd": ["handoff"],
        "shell": False,
        "env": {"PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}"},
    }))
    resp = events[-1]

    assert resp["ok"] is False
    assert resp["error_class"] == "CommandError"
    assert resp["detail"] == "command launch failed: executable format error (missing shebang?)"


def test_extra_env_is_passed_without_shell_and_redacted(cfg):
    value = "tiny-profile-secret-value"
    script = "import os; print(os.environ['AWS_PROFILE'])"
    resp = Broker(cfg).handle({
        "op": "exec",
        "cmd": [sys.executable, "-c", script],
        "shell": False,
        "env": {"AWS_PROFILE": value},
    })

    assert resp["ok"] is True
    assert value not in resp["stdout"]
    assert "REDACTED:secret:" in resp["stdout"]


def test_bad_env_name_is_rejected(cfg):
    resp = Broker(cfg).handle({
        "op": "exec",
        "cmd": ["echo", "ok"],
        "shell": False,
        "env": {"BAD-NAME": "x"},
    })

    assert resp["ok"] is False
    assert resp["error_class"] == "ValidationError"


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


def test_complete_op_returns_host_path_candidates(cfg, workspace):
    (workspace / "data.json").write_text("{}\n")
    (workspace / "dataset").mkdir()

    resp = Broker(cfg).handle(
        {"op": "complete", "line": "echo dat", "cwd": str(workspace)}
    )

    assert resp["op"] == "complete"
    assert resp["ok"] is True
    assert resp["cwd"] == str(workspace)
    assert resp["candidates"] == ["data.json", "dataset/"]


def test_stream_exec_yields_chunks_and_final(cfg):
    events = list(Broker(cfg).handle_stream({"op": "exec", "cmd": "printf 'one\\ntwo\\n'"}))
    chunks = [event for event in events if event.get("op") == "exec_chunk"]
    final = events[-1]

    assert [chunk["data"] for chunk in chunks] == ["one\n", "two\n"]
    assert final["op"] == "exec"
    assert final["ok"] is True
    assert final["exit_code"] == 0
    assert final["stdout"] == ""
    assert final["streamed"] is True


def test_stream_command_not_found_returns_stderr_in_final(cfg):
    events = list(Broker(cfg).handle_stream(
        {"op": "exec", "cmd": ["definitely-not-a-real-binary-xyz"], "shell": False}
    ))
    chunks = [event for event in events if event.get("op") == "exec_chunk"]
    final = events[-1]

    assert chunks == []
    assert final["op"] == "exec"
    assert final["ok"] is False
    assert final["exit_code"] == 127
    assert final["stdout"] == ""
    assert final["stderr"] == "definitely-not-a-real-binary-xyz: command not found"


def test_stream_exec_buffers_structured_secret_dump(cfg):
    secret = "1afbedbd65fedc34591eac1a79a9de2aff1aefe64"
    text = (
        "- key: google_client_secret\n"
        "  level: resource group\n"
        f"  value: \"{{\\n  \\\"private_key_id\\\": \\\"{secret}\\\"\\\n"
        "    ,\\n  \\\"private_key\\\": \\\"-----BEGIN PRIVATE KEY-----abc\\\"\"\n"
        "  updated_at: 2026-08-03\n"
    )
    script = "import sys; sys.stdout.write(%r)" % text
    events = list(Broker(cfg).handle_stream(
        {"op": "exec", "cmd": [sys.executable, "-c", script], "shell": False}
    ))
    streamed = "".join(event["data"] for event in events if event.get("op") == "exec_chunk")

    assert secret not in streamed
    assert "PRIVATE KEY" not in streamed
    assert "value: [REDACTED:suspected]" in streamed
    assert "updated_at: 2026-08-03" in streamed


def test_stream_exec_streams_complete_jsonl_records(cfg):
    script = (
        "import sys, time\n"
        "print('{\"private_key\":\"alpha-secret-one\",\"name\":\"first\"}', flush=True)\n"
        "time.sleep(0.01)\n"
        "print('{\"private_key\":\"beta-secret-two\",\"name\":\"second\"}', flush=True)\n"
    )
    events = list(Broker(cfg).handle_stream(
        {"op": "exec", "cmd": [sys.executable, "-c", script], "shell": False}
    ))
    chunks = [event["data"] for event in events if event.get("op") == "exec_chunk"]

    assert len(chunks) == 2
    assert "alpha-secret-one" not in "".join(chunks)
    assert "beta-secret-two" not in "".join(chunks)
    assert '"private_key": "[REDACTED:suspected]"' in chunks[0]
    assert '"name":"first"' in chunks[0]
    assert '"name":"second"' in chunks[1]


def test_bare_single_string_secret_file_is_redacted(cfg, workspace, tmp_path):
    """A secret file that is just one raw token (no KEY=VALUE) is still masked."""
    import dataclasses

    token_file = tmp_path / "auth_token.txt"
    token_file.write_text("aabbccdd-fake-token-value-xyz-9999\n")
    c = dataclasses.replace(
        cfg,
        redaction=dataclasses.replace(
            cfg.redaction, secret_sources=(str(token_file),)),
    )
    resp = Broker(c).handle(
        {"op": "exec", "cmd": f"cat {token_file}", "cwd": str(workspace)}
    )
    assert "aabbccdd-fake-token-value-xyz-9999" not in resp["stdout"]
    assert "REDACTED" in resp["stdout"]


def test_whole_file_content_masked_as_one_blob(cfg, workspace, tmp_path):
    """cat of a declared secret file masks the entire content, not just values."""
    import dataclasses

    creds = tmp_path / "credentials"
    creds.write_text(
        "[default]\n"
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    )
    c = dataclasses.replace(
        cfg,
        redaction=dataclasses.replace(
            cfg.redaction, secret_sources=(str(creds),)),
    )
    resp = Broker(c).handle(
        {"op": "exec", "cmd": f"cat {creds}", "cwd": str(workspace)}
    )
    out = resp["stdout"]
    assert "EXAMPLE" not in out                 # no key material
    assert "aws_secret_access_key" not in out   # whole content masked, not just value
    assert out.strip().startswith("[REDACTED")


# --- chdir (stateful cd, jailed to workspace) --------------------------------

def test_chdir_within_workspace(cfg, workspace):
    (workspace / "sub").mkdir()
    resp = Broker(cfg).handle({"op": "chdir", "target": "sub"})
    assert resp["ok"] is True
    assert resp["cwd"].endswith("/sub")


def test_chdir_above_workspace_is_blocked(cfg, workspace):
    resp = Broker(cfg).handle({"op": "chdir", "cwd": str(workspace), "target": ".."})
    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"


def test_chdir_dotdot_climb_blocked(cfg, workspace):
    (workspace / "sub").mkdir()
    resp = Broker(cfg).handle(
        {"op": "chdir", "cwd": str(workspace / "sub"), "target": "../../../etc"}
    )
    assert resp["ok"] is False
    assert resp["error_class"] in ("PolicyDenied", "ValidationError")


def test_chdir_bare_returns_to_workspace_root(cfg, workspace):
    (workspace / "a" / "b").mkdir(parents=True)
    resp = Broker(cfg).handle(
        {"op": "chdir", "cwd": str(workspace / "a" / "b"), "target": ""}
    )
    assert resp["ok"] is True
    import os
    assert resp["cwd"] == os.path.realpath(str(workspace))


def test_chdir_nonexistent_rejected(cfg, workspace):
    resp = Broker(cfg).handle({"op": "chdir", "target": "no_such_dir_xyz"})
    assert resp["ok"] is False
    assert resp["error_class"] == "ValidationError"
