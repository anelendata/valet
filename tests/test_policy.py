"""Policy is permissive in v0.2, but an explicit deny list is honored."""
import dataclasses

from valet.broker import Broker
from valet.config import PolicyConfig
from valet.policy import Policy


def test_permissive_by_default(cfg):
    # No allow/deny configured => anything runs.
    resp = Broker(cfg).handle({"op": "exec", "cmd": "echo ok"})
    assert resp["ok"] is True


def test_deny_list_blocks_command(cfg):
    denied = dataclasses.replace(cfg, policy=PolicyConfig(deny=("curl",)))
    resp = Broker(denied).handle({"op": "exec", "cmd": "curl http://example.com"})
    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"


def test_deny_matches_basename_of_argv(cfg):
    denied = dataclasses.replace(cfg, policy=PolicyConfig(deny=("rm",)))
    resp = Broker(denied).handle(
        {"op": "exec", "cmd": ["/bin/rm", "-rf", "x"], "shell": False}
    )
    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"


def test_non_denied_command_still_runs(cfg):
    denied = dataclasses.replace(cfg, policy=PolicyConfig(deny=("curl",)))
    resp = Broker(denied).handle({"op": "exec", "cmd": "echo fine"})
    assert resp["ok"] is True


def test_policy_check_is_noop_without_constraints():
    Policy().check("anything at all", cwd=None)  # must not raise


# --- deny_read_paths (wildcard file bans) ------------------------------------

def _deny_paths_cfg(cfg, patterns):
    return dataclasses.replace(cfg, policy=PolicyConfig(deny_read_paths=patterns))


def test_wildcard_bans_env_anywhere(cfg, tmp_path):
    # .env sits several dirs deep; **/.env should still ban reading it.
    deep = tmp_path / "a" / "b" / "c"
    deep.mkdir(parents=True)
    (deep / ".env").write_text("SECRET=1\n")
    c = _deny_paths_cfg(cfg, ("**/.env",))
    resp = Broker(c).handle(
        {"op": "exec", "cmd": "cat .env", "cwd": str(deep)}
    )
    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"


def test_wildcard_bans_env_by_relative_path(cfg, tmp_path):
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / ".env").write_text("SECRET=1\n")
    c = _deny_paths_cfg(cfg, ("**/.env",))
    resp = Broker(c).handle(
        {"op": "exec", "cmd": "cat proj/.env", "cwd": str(tmp_path)}
    )
    assert resp["error_class"] == "PolicyDenied"


def test_secrets_dir_wildcard(cfg, tmp_path):
    d = tmp_path / "root" / ".secrets" / "x-com"
    d.mkdir(parents=True)
    (d / "auth_token.txt").write_text("tok\n")
    c = _deny_paths_cfg(cfg, ("**/.secrets/**",))
    resp = Broker(c).handle(
        {"op": "exec", "cmd": f"cat {d / 'auth_token.txt'}", "cwd": str(tmp_path)}
    )
    assert resp["error_class"] == "PolicyDenied"


def test_non_matching_file_is_allowed(cfg, tmp_path):
    (tmp_path / "README.md").write_text("hello\n")
    c = _deny_paths_cfg(cfg, ("**/.env",))
    resp = Broker(c).handle(
        {"op": "exec", "cmd": "cat README.md", "cwd": str(tmp_path)}
    )
    assert resp["ok"] is True


def test_nonexistent_path_not_falsely_denied(cfg, tmp_path):
    # ".env" as a grep pattern, with no .env file present, must not be banned.
    (tmp_path / "notes.txt").write_text("nothing here\n")
    c = _deny_paths_cfg(cfg, ("**/.env",))
    resp = Broker(c).handle(
        {"op": "exec", "cmd": "grep .env notes.txt", "cwd": str(tmp_path)}
    )
    assert resp["ok"] in (True, False)          # grep may exit 1 on no match
    assert resp.get("error_class") != "PolicyDenied"


def test_home_prefix_pattern(cfg, tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    (fake_home / ".aws").mkdir(parents=True)
    (fake_home / ".aws" / "credentials").write_text("[default]\n")
    monkeypatch.setenv("HOME", str(fake_home))
    c = _deny_paths_cfg(cfg, ("~/.aws/**",))
    resp = Broker(c).handle(
        {"op": "exec", "cmd": "cat ~/.aws/credentials", "cwd": str(tmp_path)}
    )
    assert resp["error_class"] == "PolicyDenied"
