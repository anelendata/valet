from valet.cli import main


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

    rc = main(["--host", "lan-host"])

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

    rc = main(["--host", "lan-host"])

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


def test_doctor_reports_config_and_skips_sandbox_when_unset(tmp_path, capsys):
    ws = tmp_path / "ws"
    ws.mkdir()
    config = tmp_path / "config.toml"
    config.write_text(
        "[broker]\nfingerprint_salt = 'x'\n\n"
        f"[exec]\nworkspace = '{ws}'\n"
    )

    rc = main(["-c", str(config), "doctor"])

    assert rc == 0
    out = capsys.readouterr().out
    assert "valet doctor" in out
    assert "reads=on writes=on" in out
    assert "sandbox checks: skipped" in out


def test_doctor_fails_when_sandbox_profile_missing(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("valet.cli.sys.platform", "darwin")
    monkeypatch.setattr("valet.cli.shutil.which", lambda _name: "/usr/bin/sandbox-exec")
    ws = tmp_path / "ws"
    ws.mkdir()
    config = tmp_path / "config.toml"
    config.write_text(
        "[broker]\nfingerprint_salt = 'x'\n\n"
        f"[exec]\nworkspace = '{ws}'\nsandbox_profile = '{tmp_path / 'nope.sb'}'\n"
    )

    rc = main(["-c", str(config), "doctor"])

    assert rc == 1
    out = capsys.readouterr().out
    assert "profile not found" in out
    assert "FAILED" in out


def _answers(*vals):
    it = iter(vals)
    return lambda prompt="": next(it)


def test_init_creates_config_and_injects_salt(tmp_path, monkeypatch):
    monkeypatch.setattr("valet.cli.sys.platform", "linux")  # skip macOS sandbox steps
    monkeypatch.setattr("builtins.input", _answers("y", "y"))  # create dir, create config
    monkeypatch.setattr("valet.cli._doctor_report", lambda path, cfg: False)
    config = tmp_path / "valet" / "config.toml"

    rc = main(["-c", str(config), "init"])

    assert rc == 0
    assert config.exists()
    text = config.read_text()
    assert "[broker]" in text
    salt_line = next(l for l in text.splitlines() if l.strip().startswith("fingerprint_salt"))
    assert "CHANGE_ME" not in salt_line  # the salt value was replaced


def test_init_refuses_when_config_exists(tmp_path, capsys):
    config = tmp_path / "config.toml"
    config.write_text("[broker]\n")

    rc = main(["-c", str(config), "init"])

    assert rc == 2
    assert "already exist" in capsys.readouterr().err


def test_init_declining_creates_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr("valet.cli.sys.platform", "linux")
    monkeypatch.setattr("builtins.input", _answers("n"))  # decline config creation
    config = tmp_path / "config.toml"

    rc = main(["-c", str(config), "init"])

    assert rc == 1
    assert not config.exists()


def test_init_activates_sandbox_on_macos(tmp_path, monkeypatch):
    monkeypatch.setattr("valet.cli.sys.platform", "darwin")
    # parent exists -> no dir prompt; then: create config, copy sb, activate
    monkeypatch.setattr("builtins.input", _answers("y", "y", "y"))
    monkeypatch.setattr("valet.cli._doctor_report", lambda path, cfg: False)
    config = tmp_path / "config.toml"

    rc = main(["-c", str(config), "init"])

    assert rc == 0
    assert (tmp_path / "workspace.sb").exists()
    text = config.read_text()
    assert any(line.strip().startswith("sandbox_profile =") for line in text.splitlines())
