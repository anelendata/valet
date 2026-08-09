"""Multiple workspaces under one host: config, broker routing, CLI, REPL."""
import pytest

from valet.broker import Broker
from valet.cli import main
from valet.config import load_config, resolve_workspaces
from valet.errors import ConfigError
from valet.repl import Session, prompt_for, run_command
from valet.workspace_config import add_workspace, find_workspace, list_workspaces


def _write_config(path, workspaces, *, default="default", extra=""):
    body = [
        "[broker]",
        'fingerprint_salt = "salt"',
        "",
        "[exec]",
        f'default_workspace = "{default}"',
        "shell = false",
        "",
        "[policy]",
        'deny = ["curl"]',
        "",
        extra,
    ]
    for wid, section in workspaces.items():
        body.append(f"[workspaces.{wid}]")
        body.append(f'path = "{section["path"]}"')
        body.extend(section.get("lines", []))
        body.append("")
    path.write_text("\n".join(body))
    return path


# --- config parsing ----------------------------------------------------------

def test_defaults_apply_and_overrides_win(tmp_path):
    a = tmp_path / "a"; a.mkdir()
    b = tmp_path / "b"; b.mkdir()
    cfg_path = _write_config(tmp_path / "config.toml", {
        "default": {"path": str(a)},
        "personal": {"path": str(b), "lines": [
            "[workspaces.personal.exec]", "shell = true",
            "[workspaces.personal.policy]", 'deny = ["rm"]',
        ]},
    })

    cfg = load_config(cfg_path)
    ws = resolve_workspaces(cfg)

    # Shared [policy].deny=curl reaches both; personal overrides deny with rm.
    assert ws["default"].exec.shell is False
    assert ws["default"].policy.deny == ("curl",)
    assert ws["personal"].exec.shell is True
    assert ws["personal"].policy.deny == ("rm",)
    assert ws["personal"].exec.workspace == str(b)


def test_exec_env_merges_over_default(tmp_path):
    a = tmp_path / "a"; a.mkdir()
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        "[broker]\n"
        'fingerprint_salt = "salt"\n\n'
        "[exec]\n"
        'default_workspace = "default"\n\n'
        "[exec.env]\n"
        'GLOBAL = "1"\n'
        'SHARED = "base"\n\n'
        f'[workspaces.default]\npath = "{a}"\n\n'
        "[workspaces.default.exec.env]\n"
        'SHARED = "override"\n'
        'LOCAL = "2"\n'
    )

    ws = resolve_workspaces(load_config(cfg_path))["default"]

    assert ws.exec.env == {"GLOBAL": "1", "SHARED": "override", "LOCAL": "2"}


def test_missing_default_workspace_section_is_rejected(tmp_path):
    a = tmp_path / "a"; a.mkdir()
    cfg_path = _write_config(tmp_path / "config.toml",
                             {"other": {"path": str(a)}}, default="default")
    with pytest.raises(ConfigError):
        load_config(cfg_path)


def test_workspace_without_path_is_rejected(tmp_path):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        "[broker]\n"
        'fingerprint_salt = "salt"\n\n'
        "[exec]\n"
        'default_workspace = "default"\n\n'
        "[workspaces.default]\n"
        'shell = true\n'  # no path
    )
    with pytest.raises(ConfigError):
        load_config(cfg_path)


def test_legacy_exec_workspace_key_is_rejected(tmp_path):
    # The old [exec].workspace key is gone; a legacy config must fail loudly
    # (in `valet doctor` and every command) rather than load as healthy.
    a = tmp_path / "a"; a.mkdir()
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        "[broker]\n"
        'fingerprint_salt = "salt"\n\n'
        f'[exec]\nworkspace = "{a}"\nshell = true\n'
    )
    with pytest.raises(ConfigError, match="no longer supported"):
        load_config(cfg_path)


def test_no_workspace_configured_is_valid(tmp_path):
    # A config with neither [exec].workspace nor [workspaces.*] is the valid
    # "run anywhere, no jail" case: one path-less default workspace.
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text('[broker]\nfingerprint_salt = "salt"\n')
    ws = resolve_workspaces(load_config(cfg_path))
    assert list(ws) == ["default"]
    assert ws["default"].exec.workspace is None


# --- broker routing ----------------------------------------------------------

@pytest.fixture
def two_ws_broker(tmp_path):
    a = tmp_path / "a"; a.mkdir()
    b = tmp_path / "b"; b.mkdir()
    (b / "sub").mkdir()
    cfg_path = _write_config(tmp_path / "config.toml", {
        "default": {"path": str(a)},
        "personal": {"path": str(b), "lines": [
            "[workspaces.personal.exec]", "shell = true",
            "[workspaces.personal.policy]", 'deny = ["rm"]',
        ]},
    })
    return Broker(load_config(cfg_path)), a, b


def test_ping_and_workspaces_op_report_map(two_ws_broker):
    broker, _a, _b = two_ws_broker
    ping = broker.handle({"op": "ping"})
    assert ping["default_workspace"] == "default"
    assert ping["workspaces"] == ["default", "personal"]
    assert ping["shell_default"] is False

    listing = broker.handle({"op": "workspaces"})
    ids = {w["id"]: w for w in listing["workspaces"]}
    assert ids["default"]["default"] is True
    assert ids["personal"]["shell"] is True
    # Path is never disclosed by the op.
    assert all("path" not in w for w in listing["workspaces"])


def test_exec_runs_in_selected_workspace(two_ws_broker):
    broker, _a, _b = two_ws_broker
    # Shell pipe only works in personal (shell enabled there).
    ok = broker.handle({"op": "exec", "cmd": "echo hi | cat", "workspace": "personal"})
    assert ok["ok"] is True and ok["stdout"].strip() == "hi"
    denied = broker.handle({"op": "exec", "cmd": "echo hi | cat", "shell": True})
    assert denied["error_class"] == "PolicyDenied"


def test_per_workspace_policy_override(two_ws_broker):
    broker, _a, _b = two_ws_broker
    # rm is denied only in personal; curl is denied in both (shared default).
    assert broker.handle({"op": "exec", "cmd": ["rm", "x"],
                          "workspace": "personal"})["error_class"] == "PolicyDenied"
    assert broker.handle({"op": "exec", "cmd": ["rm", "x"]}).get("error_class") != "PolicyDenied"
    assert broker.handle({"op": "exec", "cmd": ["curl", "x"]})["error_class"] == "PolicyDenied"
    assert broker.handle({"op": "exec", "cmd": ["curl", "x"],
                          "workspace": "personal"})["error_class"] == "PolicyDenied"


def test_chdir_is_jailed_per_workspace(two_ws_broker):
    broker, _a, _b = two_ws_broker
    resp = broker.handle({"op": "chdir", "target": "sub", "workspace": "personal"})
    assert resp["cwd"] == "./sub"


def test_unknown_workspace_is_rejected(two_ws_broker):
    broker, _a, _b = two_ws_broker
    resp = broker.handle({"op": "exec", "cmd": ["pwd"], "workspace": "nope"})
    assert resp["ok"] is False
    assert resp["error_class"] == "ValidationError"


# --- workspace_config (host-side config edits) -------------------------------

def test_add_and_list_workspaces(tmp_path):
    a = tmp_path / "a"; a.mkdir()
    cfg_path = _write_config(tmp_path / "config.toml", {"default": {"path": str(a)}})

    result = add_workspace(cfg_path, workspace_id="Personal Box", workspace_path="~/personal")
    assert result.workspace_id == "personal-box"
    assert result.made_default is False  # default_workspace already set

    entries = {e.workspace_id: e for e in list_workspaces(cfg_path)}
    assert entries["personal-box"].path == "~/personal"
    assert entries["default"].is_default is True
    assert find_workspace(cfg_path, "personal-box") is not None
    # Round-trips through the loader.
    assert "personal-box" in load_config(cfg_path).workspaces


def test_add_workspace_detects_single_quoted_default(tmp_path):
    # A hand-edited single-quoted default_workspace must be detected so `add`
    # does not write a duplicate key (which would break TOML parsing).
    a = tmp_path / "a"; a.mkdir()
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        "[broker]\nfingerprint_salt = 'x'\n\n"
        "[exec]\ndefault_workspace = 'default'\n\n"
        f"[workspaces.default]\npath = '{a}'\n"
    )
    result = add_workspace(cfg_path, workspace_id="extra", workspace_path=str(a))
    assert result.made_default is False
    text = cfg_path.read_text()
    assert text.count("default_workspace") == 1
    load_config(cfg_path)  # still valid TOML / config


def test_add_first_workspace_sets_default(tmp_path):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text('[broker]\nfingerprint_salt = "s"\n')
    result = add_workspace(cfg_path, workspace_id="main", workspace_path=str(tmp_path))
    assert result.made_default is True
    cfg = load_config(cfg_path)
    assert cfg.default_workspace == "main"


# --- CLI + REPL integration --------------------------------------------------

def test_cli_workspace_flag_attaches_to_exec(monkeypatch):
    captured = {}
    monkeypatch.setattr("valet.cli._streaming_one_shot",
                        lambda _args, request: captured.update(request) or 0)
    assert main(["-w", "personal", "run", "--", "echo", "hi"]) == 0
    assert captured["workspace"] == "personal"


def test_cli_workspace_list(tmp_path, capsys):
    a = tmp_path / "a"; a.mkdir()
    cfg_path = _write_config(tmp_path / "config.toml", {"default": {"path": str(a)}})
    assert main(["-c", str(cfg_path), "workspaces", "list"]) == 0
    out = capsys.readouterr().out
    assert "* default" in out and str(a) in out


def test_repl_prompt_shows_workspace():
    assert prompt_for(Session(cwd="./sub", workspace="personal")) == "(personal) ./sub valet> "
    # No workspace set: unchanged compact prompt.
    assert prompt_for(Session(cwd="./sub")) == "./sub valet> "


def test_repl_exec_attaches_active_workspace():
    sent = []
    def send(req):
        sent.append(req)
        return {"op": "exec", "ok": True, "exit_code": 0, "stdout": "", "stderr": ""}
    run_command("ls", Session(workspace="personal"), send)
    assert sent[0]["workspace"] == "personal"


def test_repl_workspace_set_switches_and_adopts_shell():
    responses = {
        "workspaces": {"ok": True, "default_workspace": "default", "workspaces": [
            {"id": "default", "default": True, "shell": False},
            {"id": "personal", "default": False, "shell": True},
        ]},
        "chdir": {"op": "chdir", "ok": True, "cwd": "./"},
    }
    sent = []
    def send(req):
        sent.append(req)
        return responses.get(req.get("op"), {"ok": True})

    session = Session()
    keep, out = run_command(":workspaces set personal", session, send)

    assert keep is True
    assert session.workspace == "personal"
    assert session.shell is True         # adopted the workspace's shell default
    assert session.cwd == "./"
    # The chdir that re-roots the session carries the new workspace.
    assert any(r.get("op") == "chdir" and r.get("workspace") == "personal" for r in sent)


def test_repl_workspace_list_marks_active():
    def send(_req):
        return {"ok": True, "default_workspace": "default", "workspaces": [
            {"id": "default", "default": True, "shell": False},
            {"id": "personal", "default": False, "shell": True},
        ]}
    keep, out = run_command(":workspaces list", Session(workspace="personal"), send)
    assert keep is True
    lines = out.splitlines()
    assert any(line.startswith("* personal") for line in lines)
    assert any(line.startswith("  default") for line in lines)
