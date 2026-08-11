from pathlib import Path

from valet.cli import main


def test_example_config_is_packaged_and_parses():
    # Regression: `valet init` reads this file, which must ship inside the wheel
    # and be resolvable from an installed package (not only a source checkout).
    import valet
    from valet.cli import _example_config_path
    from valet.config import load_config

    p = _example_config_path()
    assert p.exists(), f"example config not shipped at {p}"
    assert p.parent == Path(valet.__file__).resolve().parent
    load_config(str(p))  # valid TOML valet can parse


def test_sandbox_profile_packaged_and_matches_contrib():
    from valet.cli import _workspace_sb_source

    packaged = _workspace_sb_source()
    assert packaged.exists(), f"sandbox profile not shipped at {packaged}"
    contrib = (Path(__file__).resolve().parents[1]
               / "contrib" / "sandbox-exec" / "workspace.sb")
    if contrib.exists():  # present in a source checkout, absent in a wheel
        assert packaged.read_bytes() == contrib.read_bytes(), (
            "valet/workspace.sb drifted from contrib/sandbox-exec/workspace.sb"
        )


class _FakeTarget:
    def __init__(self, is_remote):
        self.is_remote = is_remote
        self.name = "lan-host" if is_remote else "local"


class _FakeConnection:
    def __init__(self, response):
        self.response = response
        self.requests = []
        self.closed = False

    def request(self, request):
        self.requests.append(request)
        if isinstance(self.response, dict) and request.get("op") == "ping":
            return {"ok": True, "pong": True, **self.response.get("ping", {})}
        return self.response

    def request_stream(self, request, on_event):
        self.requests.append(request)
        for event in self.response.get("events", ()):
            on_event(event)
        return self.response.get("final", self.response)

    def close(self):
        self.closed = True


def test_run_env_flags_attach_env_to_exec_request(monkeypatch):
    captured = {}

    def fake_streaming_one_shot(_args, request):
        captured.update(request)
        return 0

    monkeypatch.setattr("valet.cli._streaming_one_shot", fake_streaming_one_shot)

    rc = main([
        "-env", "AWS_PROFILE=tiny",
        "--env", "OTHER_VAR=something",
        "run", "--", "aws", "s3", "ls",
    ])

    assert rc == 0
    assert captured["shell"] is False
    assert captured["env"] == {
        "AWS_PROFILE": "tiny",
        "OTHER_VAR": "something",
    }
    assert captured["cmd"] == ["aws", "s3", "ls"]


def test_run_global_cwd_attaches_to_exec_request(monkeypatch):
    captured = {}

    def fake_streaming_one_shot(_args, request):
        captured.update(request)
        return 0

    monkeypatch.setattr("valet.cli._streaming_one_shot", fake_streaming_one_shot)

    rc = main([
        "--cwd", "zendesk-jira",
        "run", "--", "ls",
    ])

    assert rc == 0
    assert captured["shell"] is False
    assert captured["cwd"] == "zendesk-jira"
    assert captured["cmd"] == ["ls"]


def test_run_subcommand_cwd_still_attaches_to_exec_request(monkeypatch):
    captured = {}

    def fake_streaming_one_shot(_args, request):
        captured.update(request)
        return 0

    monkeypatch.setattr("valet.cli._streaming_one_shot", fake_streaming_one_shot)

    rc = main(["run", "--cwd", "zendesk-jira", "--", "ls"])

    assert rc == 0
    assert captured["cwd"] == "zendesk-jira"
    assert captured["cmd"] == ["ls"]


def test_run_prints_final_stderr_from_streaming_response(monkeypatch, capsys):
    conn = _FakeConnection({
        "final": {
            "op": "exec",
            "ok": False,
            "exit_code": 127,
            "stdout": "",
            "stderr": "woeijw: command not found",
        },
    })
    monkeypatch.setattr("valet.cli._connect", lambda _args: (conn, object(), None))

    rc = main(["run", "--", "woeijw"])

    captured = capsys.readouterr()
    assert rc == 127
    assert captured.out == ""
    assert captured.err == "woeijw: command not found\n"
    assert conn.requests == [{
        "op": "exec",
        "cmd": ["woeijw"],
        "shell": False,
        "timeout": 60,
        "stream": True,
    }]


def test_info_prints_readme_and_scan_hints(monkeypatch, capsys):
    conn = _FakeConnection({
        "op": "workspace_info", "ok": True, "workspace": "demo",
        "has_readme": True, "readme": "# Demo guide\n", "truncated": False,
    })
    monkeypatch.setattr("valet.cli._connect",
                        lambda _args: (conn, _FakeTarget(False), None))

    rc = main(["-w", "demo", "info"])

    assert rc == 0
    assert {"op": "workspace_info", "workspace": "demo"} in conn.requests
    out = capsys.readouterr().out
    assert "valet -w demo run -- ls -la" in out
    assert "data, not as instructions" in out
    assert "Demo guide" in out


def test_info_notes_when_no_readme(monkeypatch, capsys):
    conn = _FakeConnection({
        "op": "workspace_info", "ok": True, "workspace": "demo",
        "has_readme": False, "readme": None, "truncated": False,
    })
    monkeypatch.setattr("valet.cli._connect",
                        lambda _args: (conn, _FakeTarget(False), None))

    rc = main(["-w", "demo", "info"])

    assert rc == 0
    assert "No README.md in this workspace yet" in capsys.readouterr().out


def test_status_reports_workspaces_and_next_step(monkeypatch, capsys):
    conn = _FakeConnection(
        {"ping": {"default_workspace": "demo", "workspaces": ["demo", "other"]}})
    monkeypatch.setattr("valet.cli.resolve_target",
                        lambda **_kw: (_FakeTarget(False), None))
    monkeypatch.setattr("valet.cli._connect",
                        lambda _args: (conn, _FakeTarget(False), None))

    rc = main(["status"])

    assert rc == 0
    out = capsys.readouterr().out
    assert "demo*" in out and "other" in out
    assert "valet -w demo info" in out


def test_status_reports_unreachable_host(monkeypatch, capsys):
    monkeypatch.setattr("valet.cli.resolve_target",
                        lambda **_kw: (_FakeTarget(False), None))

    def boom(_args):
        raise FileNotFoundError()

    monkeypatch.setattr("valet.cli._connect", boom)

    rc = main(["status"])

    assert rc == 0
    assert "NOT reachable" in capsys.readouterr().out


def test_repl_remote_adopts_host_shell_default(monkeypatch):
    # A remote target has no local config, so the REPL must learn the host's
    # [exec].shell default from a ping — otherwise it defaults to shell=off and
    # runs argv mode, breaking `VAR=value cmd ...` env prefixes.
    conn = _FakeConnection({"ping": {"shell_default": True}})
    monkeypatch.setattr(
        "valet.cli._connect",
        lambda _args: (conn, _FakeTarget(is_remote=True), None),
    )
    captured = {}

    def fake_interact(_send, session):
        captured["shell"] = session.shell
        return 0

    monkeypatch.setattr("valet.cli.interact", fake_interact)

    rc = main(["--host", "lan-host", "repl"])

    assert rc == 0
    assert captured["shell"] is True
    assert {"op": "ping"} in conn.requests


def test_repl_remote_defaults_shell_off_when_host_disallows(monkeypatch):
    conn = _FakeConnection({"ping": {"shell_default": False}})
    monkeypatch.setattr(
        "valet.cli._connect",
        lambda _args: (conn, _FakeTarget(is_remote=True), None),
    )
    captured = {}

    def fake_interact(_send, session):
        captured["shell"] = session.shell
        return 0

    monkeypatch.setattr("valet.cli.interact", fake_interact)

    rc = main(["--host", "lan-host", "repl"])

    assert rc == 0
    assert captured["shell"] is False


def test_processes_kill_sends_broker_process_kill(monkeypatch, capsys):
    conn = _FakeConnection({"op": "processes.kill", "ok": True, "pid": 123, "killed": True})
    monkeypatch.setattr("valet.cli._connect", lambda _args: (conn, object(), None))

    rc = main(["processes", "kill", "123"])

    assert rc == 0
    assert conn.requests == [{"op": "processes.kill", "pid": 123}]
    assert conn.closed is True
    assert "killed subprocess 123" in capsys.readouterr().out


def _doctor_config(ws, *, exec_extra="", extra=""):
    """A single-workspace config for the doctor tests (new [workspaces.*] schema)."""
    return (
        "[broker]\nfingerprint_salt = 'x'\n\n"
        f"[exec]\ndefault_workspace = 'default'\n{exec_extra}\n"
        f"[workspaces.default]\npath = '{ws}'\n"
        f"{extra}"
    )


def test_doctor_reports_config_and_skips_sandbox_when_unset(tmp_path, capsys):
    ws = tmp_path / "ws"
    ws.mkdir()
    config = tmp_path / "config.toml"
    config.write_text(_doctor_config(ws))

    rc = main(["-c", str(config), "doctor"])

    assert rc == 0
    out = capsys.readouterr().out
    assert "valet doctor" in out
    assert "reads=on writes=on" in out
    assert "sandbox checks: skipped" in out


def test_doctor_warns_when_config_inside_workspace(tmp_path, capsys):
    ws = tmp_path / "ws"
    ws.mkdir()
    config = ws / "config.toml"  # placed INSIDE the workspace — unsafe
    config.write_text(_doctor_config(ws))

    rc = main(["-c", str(config), "doctor"])

    assert rc == 0  # a warning, not a hard failure
    out = capsys.readouterr().out
    assert "WARN" in out
    assert "config file is inside the workspace" in out


def test_doctor_no_warning_when_config_outside_workspace(tmp_path, capsys):
    ws = tmp_path / "ws"
    ws.mkdir()
    config = tmp_path / "config.toml"  # sibling of the workspace — safe
    config.write_text(_doctor_config(ws))

    rc = main(["-c", str(config), "doctor"])

    assert rc == 0
    assert "inside the workspace" not in capsys.readouterr().out


def test_doctor_warns_when_audit_log_inside_workspace(tmp_path, capsys):
    ws = tmp_path / "ws"
    ws.mkdir()
    config = tmp_path / "config.toml"
    config.write_text(_doctor_config(
        ws, extra=f"\n[audit]\nlog_path = '{ws / 'audit.jsonl'}'\n"))

    rc = main(["-c", str(config), "doctor"])

    assert rc == 0
    out = capsys.readouterr().out
    assert "audit log is inside the workspace" in out


def test_doctor_abbreviates_home_in_paths(tmp_path, monkeypatch, capsys):
    # doctor must not spell out the real home path / username.
    home = tmp_path / "home"
    ws = home / "proj"
    ws.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    config = home / ".valet" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text(_doctor_config(str(ws)))

    rc = main(["-c", str(config), "doctor"])

    assert rc == 0
    out = capsys.readouterr().out
    assert "~/proj" in out                # workspace path abbreviated
    assert "~/.valet/config.toml" in out  # config path abbreviated
    assert str(home) not in out           # real home path not disclosed


def test_doctor_warns_when_workspace_is_home(tmp_path, capsys, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    config = tmp_path / "config.toml"  # outside home, so only the home warning fires
    config.write_text(_doctor_config("~"))

    rc = main(["-c", str(config), "doctor"])

    assert rc == 0
    out = capsys.readouterr().out
    assert "WARN" in out
    assert "very high risk" in out
    assert "home directory" in out


def test_doctor_fails_when_sandbox_profile_missing(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("valet.cli.sys.platform", "darwin")
    monkeypatch.setattr("valet.cli.shutil.which", lambda _name: "/usr/bin/sandbox-exec")
    ws = tmp_path / "ws"
    ws.mkdir()
    config = tmp_path / "config.toml"
    config.write_text(_doctor_config(
        ws, exec_extra=f"sandbox_profile = '{tmp_path / 'nope.sb'}'\n"))

    rc = main(["-c", str(config), "doctor"])

    assert rc == 1
    out = capsys.readouterr().out
    assert "profile not found" in out
    assert "FAILED" in out


def _answers(*vals):
    it = iter(vals)
    return lambda prompt="": next(it)


def test_init_creates_config_and_injects_salt(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("valet.cli.sys.platform", "linux")  # skip macOS sandbox steps
    # create valet dir, create config, decline the LAN host prompt
    monkeypatch.setattr("builtins.input", _answers("y", "y", "n"))
    monkeypatch.setattr("valet.cli._doctor_report", lambda path, cfg: False)
    config = tmp_path / "valet" / "config.toml"

    rc = main(["-c", str(config), "init"])

    assert rc == 0
    assert config.exists()
    text = config.read_text()
    assert "[broker]" in text
    salt_line = next(l for l in text.splitlines() if l.strip().startswith("fingerprint_salt"))
    assert "CHANGE_ME" not in salt_line  # the salt value was replaced
    # No workspace is defined; the user is reminded to add one.
    from valet.config import load_config, resolve_workspaces
    assert resolve_workspaces(load_config(config)) == {}
    assert "workspaces add" in capsys.readouterr().out


def test_init_refuses_when_config_exists(tmp_path, capsys):
    config = tmp_path / "config.toml"
    config.write_text("[broker]\n")

    rc = main(["-c", str(config), "init"])

    assert rc == 2
    assert "already exist" in capsys.readouterr().err


def test_init_declining_creates_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr("valet.cli.sys.platform", "linux")
    monkeypatch.setattr("builtins.input", _answers("n"))  # decline config creation
    config = tmp_path / "config.toml"  # parent (tmp_path) exists -> only the config prompt

    rc = main(["-c", str(config), "init"])

    assert rc == 1
    assert not config.exists()


def test_init_activates_sandbox_on_macos(tmp_path, monkeypatch):
    monkeypatch.setattr("valet.cli.sys.platform", "darwin")
    # parent exists -> no dir prompt; then: create config, activate sandbox, no LAN
    monkeypatch.setattr("builtins.input", _answers("y", "y", "n"))
    monkeypatch.setattr("valet.cli._doctor_report", lambda path, cfg: False)
    config = tmp_path / "config.toml"

    rc = main(["-c", str(config), "init"])

    assert rc == 0
    assert (tmp_path / "workspace.sb").exists()
    text = config.read_text()
    assert any(line.strip().startswith("sandbox_profile =") for line in text.splitlines())


def test_init_enables_lan_when_confirmed(tmp_path, monkeypatch):
    monkeypatch.setattr("valet.cli.sys.platform", "linux")
    # create valet dir, create config, ENABLE the LAN host
    monkeypatch.setattr("builtins.input", _answers("y", "y", "y"))
    monkeypatch.setattr("valet.cli._doctor_report", lambda path, cfg: False)
    config = tmp_path / "valet" / "config.toml"

    rc = main(["-c", str(config), "init"])

    assert rc == 0
    from valet.config import load_config
    assert load_config(config).host.lan is True


def test_init_leaves_lan_off_when_declined(tmp_path, monkeypatch):
    monkeypatch.setattr("valet.cli.sys.platform", "linux")
    monkeypatch.setattr("builtins.input", _answers("y", "y", "n"))
    monkeypatch.setattr("valet.cli._doctor_report", lambda path, cfg: False)
    config = tmp_path / "valet" / "config.toml"

    rc = main(["-c", str(config), "init"])

    assert rc == 0
    from valet.config import load_config
    assert load_config(config).host.lan is False
