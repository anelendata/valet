from valet.cli import main


class _FakeConnection:
    def __init__(self, response):
        self.response = response
        self.requests = []
        self.closed = False

    def request(self, request):
        self.requests.append(request)
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
        "--client-config", "client.toml",
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


def test_processes_kill_sends_broker_process_kill(monkeypatch, capsys):
    conn = _FakeConnection({"op": "processes.kill", "ok": True, "pid": 123, "killed": True})
    monkeypatch.setattr("valet.cli._connect", lambda _args: (conn, object(), None))

    rc = main(["processes", "kill", "123"])

    assert rc == 0
    assert conn.requests == [{"op": "processes.kill", "pid": 123}]
    assert conn.closed is True
    assert "killed subprocess 123" in capsys.readouterr().out
