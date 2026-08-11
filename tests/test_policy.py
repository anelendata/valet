"""Policy is permissive in v0.2, but an explicit deny list is honored."""
import dataclasses
from pathlib import Path

from valet.broker import Broker
from valet.config import ExecConfig, PolicyConfig
from valet.policy import Policy


def test_permissive_by_default(cfg):
    # No allow/deny configured => anything runs.
    resp = Broker(cfg).handle({"op": "exec", "cmd": "echo ok"})
    assert resp["ok"] is True


def test_deny_list_blocks_command(cfg):
    denied = dataclasses.replace(cfg, policy=PolicyConfig(deny_exec=("curl",)))
    resp = Broker(denied).handle({"op": "exec", "cmd": "curl http://example.com"})
    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"


def test_deny_matches_basename_of_argv(cfg):
    denied = dataclasses.replace(cfg, policy=PolicyConfig(deny_exec=("rm",)))
    resp = Broker(denied).handle(
        {"op": "exec", "cmd": ["/bin/rm", "-rf", "x"], "shell": False}
    )
    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"


def test_non_denied_command_still_runs(cfg):
    denied = dataclasses.replace(cfg, policy=PolicyConfig(deny_exec=("curl",)))
    resp = Broker(denied).handle({"op": "exec", "cmd": "echo fine"})
    assert resp["ok"] is True


def test_policy_check_is_noop_without_constraints():
    Policy().check("anything at all", cwd=None)  # must not raise


def test_shell_execution_is_disabled_by_default(cfg):
    locked = dataclasses.replace(
        cfg,
        exec=ExecConfig(workspace=cfg.exec.workspace, shell=False),
    )

    resp = Broker(locked).handle(
        {"op": "exec", "cmd": "echo blocked", "shell": True}
    )

    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"
    assert resp["detail"] == "shell execution is disabled"


def test_shell_command_bypass_is_disabled_by_default(cfg):
    locked = dataclasses.replace(
        cfg,
        exec=ExecConfig(workspace=cfg.exec.workspace, shell=False),
    )

    resp = Broker(locked).handle(
        {"op": "exec", "cmd": ["sh", "-c", "echo blocked"], "shell": False}
    )

    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"
    assert resp["detail"] == "shell execution is disabled"


def test_explicit_shell_config_allows_shell_commands(cfg):
    enabled = dataclasses.replace(
        cfg,
        exec=ExecConfig(workspace=cfg.exec.workspace, shell=True),
    )

    resp = Broker(enabled).handle(
        {"op": "exec", "cmd": "printf 'ok\\n'", "shell": True}
    )

    assert resp["ok"] is True
    assert resp["stdout"] == "ok\n"


def test_recon_and_network_commands_are_denied_by_default(cfg):
    for command in ("whoami", "uname", "hostname", "curl", "ssh", "security",
                    "ifconfig", "crontab", "open", "pbpaste"):
        resp = Broker(cfg).handle({"op": "exec", "cmd": [command], "shell": False})
        assert resp["ok"] is False, command
        assert resp["error_class"] == "PolicyDenied", command
        assert resp["detail"] == "command is on the deny list", command


# --- allow-list (default-deny when non-empty) --------------------------------

def _allow_cfg(cfg, allow):
    return dataclasses.replace(cfg, policy=PolicyConfig(allow_exec=allow))


def test_empty_allow_list_permits_any_non_denied_command(cfg):
    resp = Broker(cfg).handle({"op": "exec", "cmd": "echo hi", "shell": True})
    assert resp["ok"] is True


def test_allow_list_permits_listed_command(cfg):
    c = _allow_cfg(cfg, ("echo",))
    resp = Broker(c).handle({"op": "exec", "cmd": "echo hi", "shell": True})
    assert resp["ok"] is True
    assert resp["stdout"] == "hi\n"


def test_allow_list_blocks_unlisted_command(cfg):
    c = _allow_cfg(cfg, ("echo",))
    resp = Broker(c).handle({"op": "exec", "cmd": ["ls"], "shell": False})
    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"
    assert resp["detail"] == "command is not on the allow list"


def test_allow_list_still_honors_builtin_deny(cfg):
    # Allow-listing a dangerous name must not override the built-in deny.
    c = _allow_cfg(cfg, ("kill",))
    resp = Broker(c).handle({"op": "exec", "cmd": ["kill", "1"], "shell": False})
    assert resp["ok"] is False
    assert resp["detail"] == "command is on the deny list"


def test_allow_list_exempts_navigation_builtins(cfg):
    (Path(cfg.exec.workspace) / "sub").mkdir()
    (Path(cfg.exec.workspace) / "sub" / "f.txt").write_text("hi\n")
    c = _allow_cfg(cfg, ("cat",))
    resp = Broker(c).handle(
        {"op": "exec", "cmd": "cd sub && cat f.txt", "shell": True}
    )
    assert resp["ok"] is True
    assert resp["stdout"] == "hi\n"


# --- workspace write jail ----------------------------------------------------

def test_write_jail_blocks_absolute_path_outside_workspace(cfg, tmp_path):
    # A brand-new file outside the workspace (does not exist yet) is refused.
    target = tmp_path / "escapee.txt"
    resp = Broker(cfg).handle(
        {"op": "exec", "cmd": ["touch", str(target)], "shell": False}
    )
    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"
    assert resp["detail"] == "command targets a path outside the workspace"
    assert not target.exists()


def test_write_jail_allows_new_file_inside_workspace(cfg):
    resp = Broker(cfg).handle(
        {"op": "exec", "cmd": ["touch", "created.txt"], "shell": False}
    )
    assert resp["ok"] is True
    assert (Path(cfg.exec.workspace) / "created.txt").exists()


def test_write_jail_ignores_non_path_arguments(cfg):
    # Bare words and flags must not be mistaken for escaping paths.
    resp = Broker(cfg).handle({"op": "exec", "cmd": ["echo", "hello", "world"]})
    assert resp["ok"] is True
    assert "hello world" in resp["stdout"]


def test_builtin_dangerous_commands_are_denied(cfg):
    resp = Broker(cfg).handle(
        {"op": "exec", "cmd": ["kill", "12345"], "shell": False}
    )

    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"
    assert resp["detail"] == "command is on the deny list"


def test_builtin_env_command_is_denied(cfg):
    resp = Broker(cfg).handle(
        {"op": "exec", "cmd": ["env"], "shell": False}
    )

    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"


def test_builtin_dangerous_commands_are_denied_inside_shell_lines(cfg):
    resp = Broker(cfg).handle(
        {"op": "exec", "cmd": "echo ok; pkill something", "shell": True}
    )

    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"


def test_builtin_dangerous_commands_are_denied_after_env_assignment(cfg):
    resp = Broker(cfg).handle(
        {"op": "exec", "cmd": "AWS_PROFILE=tiny kill 12345", "shell": True}
    )

    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"


def test_builtin_dangerous_commands_are_denied_after_env_wrapper(cfg):
    resp = Broker(cfg).handle(
        {"op": "exec", "cmd": ["env", "AWS_PROFILE=tiny", "kill", "12345"], "shell": False}
    )

    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"


# --- built-in config.toml protection ----------------------------------------

def test_config_toml_is_always_protected_from_reads_and_writes(cfg):
    protected = Path(cfg.exec.workspace) / "config.toml"
    protected.write_text("token = 'do-not-read'\n")
    broker = Broker(cfg)

    for command in (
        "cat config.toml",
        "cat config.*",
        "echo changed > config.toml",
        "touch config.toml",
    ):
        resp = broker.handle({"op": "exec", "cmd": command})
        assert resp["error_class"] == "PolicyDenied"
        assert resp["detail"] == "config.toml is protected"


def test_config_toml_protection_cannot_be_disabled_in_policy(cfg):
    protected = Path(cfg.exec.workspace) / "config.toml"
    protected.write_text("token = 'do-not-read'\n")
    permissive = dataclasses.replace(cfg, policy=PolicyConfig())

    resp = Broker(permissive).handle({"op": "exec", "cmd": "cat config.toml"})
    assert resp["error_class"] == "PolicyDenied"


# --- deny_read (wildcard file bans) ------------------------------------------

def _deny_paths_cfg(cfg, patterns):
    # These tests exercise deny_read in a scratch dir outside the fixture
    # workspace, so the (now default-on) workspace jail is disabled here to keep
    # the two features under independent test.
    return dataclasses.replace(cfg, policy=PolicyConfig(
        deny_read=patterns,
        enforce_workspace_reads=False,
        enforce_workspace_writes=False,
    ))


def _workspace_read_cfg(cfg):
    return dataclasses.replace(cfg, policy=PolicyConfig(enforce_workspace_reads=True))


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


def test_cd_then_cat_is_denied(cfg, tmp_path):
    # The reported bypass: cd into the dir, then cat by bare name.
    d = tmp_path / "root" / ".secrets"
    d.mkdir(parents=True)
    (d / "secrets_proj.yml").write_text("token: leak\n")
    c = _deny_paths_cfg(cfg, ("**/.secrets/**",))
    resp = Broker(c).handle({
        "op": "exec",
        "cmd": f"cd {d}; cat secrets_proj.yml",
        "cwd": str(tmp_path),
    })
    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"


def test_cd_then_cat_env_with_and_operator(cfg, tmp_path):
    d = tmp_path / "a" / "b"
    d.mkdir(parents=True)
    (d / ".env").write_text("SECRET=1\n")
    c = _deny_paths_cfg(cfg, ("**/.env",))
    resp = Broker(c).handle({
        "op": "exec", "cmd": f"cd {d} && cat .env", "cwd": str(tmp_path),
    })
    assert resp["error_class"] == "PolicyDenied"


def test_pipe_from_denied_file_is_denied(cfg, tmp_path):
    (tmp_path / ".env").write_text("SECRET=1\n")
    c = _deny_paths_cfg(cfg, ("**/.env",))
    resp = Broker(c).handle({
        "op": "exec", "cmd": "cat .env | base64", "cwd": str(tmp_path),
    })
    assert resp["error_class"] == "PolicyDenied"


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


# --- workspace read jail -----------------------------------------------------

def test_workspace_read_jail_blocks_parent_file(cfg):
    parent_file = Path(cfg.exec.workspace).parent / "message.txt"
    parent_file.write_text("outside\n")
    c = _workspace_read_cfg(cfg)
    resp = Broker(c).handle({"op": "exec", "cmd": "cat ../message.txt"})
    assert resp["error_class"] == "PolicyDenied"


def test_workspace_read_jail_allows_workspace_file(cfg):
    workspace_file = Path(cfg.exec.workspace) / "message.txt"
    workspace_file.write_text("inside\n")
    c = _workspace_read_cfg(cfg)
    resp = Broker(c).handle({"op": "exec", "cmd": "cat message.txt"})
    assert resp["ok"] is True


def test_workspace_read_jail_blocks_outside_cwd(cfg, tmp_path):
    c = _workspace_read_cfg(cfg)
    resp = Broker(c).handle({"op": "exec", "cmd": "pwd", "cwd": str(tmp_path)})
    assert resp["error_class"] == "PolicyDenied"


def test_workspace_read_jail_blocks_relative_cwd_escape(cfg):
    c = _workspace_read_cfg(cfg)
    resp = Broker(c).handle({"op": "exec", "cmd": "pwd", "cwd": ".."})
    assert resp["error_class"] == "PolicyDenied"


def test_workspace_read_jail_resolves_symlinks(cfg, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n")
    link = Path(cfg.exec.workspace) / "linked.txt"
    link.symlink_to(outside)
    c = _workspace_read_cfg(cfg)
    resp = Broker(c).handle({"op": "exec", "cmd": "cat linked.txt"})
    assert resp["error_class"] == "PolicyDenied"
