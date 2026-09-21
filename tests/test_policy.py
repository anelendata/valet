"""Policy is permissive in v0.2, but an explicit deny list is honored."""
import dataclasses
import os
from pathlib import Path

import pytest

from valet.broker import Broker
from valet.config import ExecConfig, PolicyConfig
from valet.errors import PolicyError
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
        assert resp["detail"] == f"command is on the deny list: {command!r}", command


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
    assert resp["detail"] == "command is not on the allow list: 'ls'"


def test_allow_list_still_honors_builtin_deny(cfg):
    # Allow-listing a dangerous name must not override the built-in deny.
    c = _allow_cfg(cfg, ("kill",))
    resp = Broker(c).handle({"op": "exec", "cmd": ["kill", "1"], "shell": False})
    assert resp["ok"] is False
    assert resp["detail"] == "command is on the deny list: 'kill'"


def test_allow_list_exempts_navigation_builtins(cfg):
    (Path(cfg.exec.workspace) / "sub").mkdir()
    (Path(cfg.exec.workspace) / "sub" / "f.txt").write_text("hi\n")
    c = _allow_cfg(cfg, ("cat",))
    resp = Broker(c).handle(
        {"op": "exec", "cmd": "cd sub && cat f.txt", "shell": True}
    )
    assert resp["ok"] is True
    assert resp["stdout"] == "hi\n"


# --- allow-list: path-qualified programs --------------------------------------

_PATH_DENIED = (
    "a program given as a path must be the host program its name finds on PATH; "
    "run it by name"
)


def _program(path, output="ran"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\necho {output}\n")
    path.chmod(0o755)
    return path


def _with_host_path(cfg, allow, bindir):
    """An allowlist config whose [exec].env PATH puts ``bindir`` first."""
    c = _allow_cfg(cfg, allow)
    env = {"PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}"}
    return dataclasses.replace(c, exec=dataclasses.replace(c.exec, env=env))


def _assert_path_denied(resp):
    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"
    assert resp["detail"] == _PATH_DENIED


@pytest.mark.parametrize("cmd", [["tools/aws"], ["./tools/aws"], ["tools/../tools/aws"]])
def test_allow_list_refuses_workspace_file_named_like_allowed_program(cfg, cmd):
    _program(Path(cfg.exec.workspace) / "tools" / "aws", "agent-code")
    resp = Broker(_allow_cfg(cfg, ("aws",))).handle(
        {"op": "exec", "cmd": cmd, "shell": False}
    )
    _assert_path_denied(resp)


def test_allow_list_refuses_workspace_file_renamed_to_allowed_name(cfg):
    # Push refuses a file named `aws`, but a later rename (e.g. `git mv`) must
    # not get it past the allowlist either.
    tools = Path(cfg.exec.workspace) / "tools"
    _program(tools / "innocuous", "agent-code").rename(tools / "aws")
    resp = Broker(_allow_cfg(cfg, ("aws",))).handle(
        {"op": "exec", "cmd": ["tools/aws"], "shell": False}
    )
    _assert_path_denied(resp)


def test_allow_list_refuses_path_qualified_program_in_shell_mode(cfg):
    _program(Path(cfg.exec.workspace) / "tools" / "aws", "agent-code")
    resp = Broker(_allow_cfg(cfg, ("aws",))).handle(
        {"op": "exec", "cmd": "cd tools && ./aws", "shell": True}
    )
    _assert_path_denied(resp)


def test_allow_list_permits_absolute_path_to_host_program(cfg, tmp_path):
    host_aws = _program(tmp_path / "hostbin" / "aws", "host-aws")
    c = _with_host_path(cfg, ("aws",), tmp_path / "hostbin")
    resp = Broker(c).handle(
        {"op": "exec", "cmd": [str(host_aws)], "shell": False}
    )
    assert resp["ok"] is True
    assert resp["stdout"] == "host-aws\n"


def test_allow_list_permits_workspace_dir_link_to_host_programs(cfg, tmp_path):
    # The program file itself lives outside the workspace; only the directory
    # on the way is a link, so it is still the host's program.
    _program(tmp_path / "hostbin" / "aws", "host-aws")
    (Path(cfg.exec.workspace) / "hostbin").symlink_to(tmp_path / "hostbin")
    c = _with_host_path(cfg, ("aws",), tmp_path / "hostbin")
    resp = Broker(c).handle(
        {"op": "exec", "cmd": ["hostbin/aws"], "shell": False}
    )
    assert resp["ok"] is True


def test_allow_list_refuses_program_outside_workspace_but_not_on_path(cfg, tmp_path):
    # A host directory the agent can also write (its own /tmp, say) is outside
    # the workspace, yet a file there is still the agent's.
    planted = _program(tmp_path / "agent-tmp" / "aws", "agent-code")
    c = _with_host_path(cfg, ("aws",), tmp_path / "hostbin")
    _program(tmp_path / "hostbin" / "aws", "host-aws")
    resp = Broker(c).handle({"op": "exec", "cmd": [str(planted)], "shell": False})
    _assert_path_denied(resp)


def test_allow_list_path_must_match_first_path_hit(tmp_path, workspace):
    first = _program(tmp_path / "first" / "aws")
    second = _program(tmp_path / "second" / "aws")
    policy = Policy(
        workspace=str(workspace), allow_exec=("aws",),
        search_path=f"{first.parent}{os.pathsep}{second.parent}",
    )
    policy.check([str(first)], cwd=str(workspace))
    with pytest.raises(PolicyError, match="its name finds on PATH"):
        policy.check([str(second)], cwd=str(workspace))


def test_allow_list_refuses_workspace_symlink_named_like_allowed_program(cfg, tmp_path):
    # tools/aws -> a host program that is not on the allowlist.
    other = _program(tmp_path / "hostbin" / "python-ish", "not-aws")
    link = Path(cfg.exec.workspace) / "tools" / "aws"
    link.parent.mkdir()
    link.symlink_to(other)
    resp = Broker(_allow_cfg(cfg, ("aws",))).handle(
        {"op": "exec", "cmd": ["tools/aws"], "shell": False}
    )
    _assert_path_denied(resp)


def test_allow_list_refuses_host_symlink_into_workspace(cfg, tmp_path):
    target = _program(Path(cfg.exec.workspace) / "tools" / "aws", "agent-code")
    link = tmp_path / "hostbin" / "aws"
    link.parent.mkdir()
    link.symlink_to(target)
    resp = Broker(_allow_cfg(cfg, ("aws",))).handle(
        {"op": "exec", "cmd": [str(link)], "shell": False}
    )
    _assert_path_denied(resp)


def test_allow_list_workspace_bin_runs_by_name_not_by_path(cfg):
    # bin/ is admin-trusted and first on PATH: the bare name runs it, but a path
    # to it is treated like any other workspace file.
    _program(Path(cfg.exec.workspace) / "bin" / "mytool", "from-bin")
    c = _allow_cfg(cfg, ("mytool",))
    resp = Broker(c).handle({"op": "exec", "cmd": ["mytool"], "shell": False})
    assert resp["ok"] is True
    assert resp["stdout"] == "from-bin\n"
    resp = Broker(c).handle({"op": "exec", "cmd": ["bin/mytool"], "shell": False})
    _assert_path_denied(resp)


def test_allow_list_checks_every_program_in_an_env_wrapper(cfg, tmp_path):
    ws = Path(cfg.exec.workspace)
    _program(ws / "tools" / "aws", "agent-code")
    _program(ws / "tools" / "env", "agent-code")
    c = _allow_cfg(cfg, ("aws",))
    for cmd in (["env", "tools/aws"], ["tools/env", "aws"]):
        resp = Broker(c).handle({"op": "exec", "cmd": cmd, "shell": False})
        assert resp["ok"] is False, cmd
        assert resp["error_class"] == "PolicyDenied", cmd


def test_allow_list_refuses_missing_path_qualified_program(cfg):
    resp = Broker(_allow_cfg(cfg, ("aws",))).handle(
        {"op": "exec", "cmd": ["tools/aws"], "shell": False}
    )
    _assert_path_denied(resp)


@pytest.mark.parametrize("token", ["$HOME/aws", "~/aws", "tools/a*/aws", "{tools}/aws"])
def test_allow_list_refuses_program_path_with_expansion_characters(workspace, token):
    # argv mode runs these literally (a workspace dir named `$HOME`) while the
    # shell expands them, so no single resolution is safe to trust.
    policy = Policy(workspace=str(workspace), allow_exec=("aws",))
    with pytest.raises(PolicyError, match="its name finds on PATH"):
        policy.check([token], cwd=str(workspace))


def test_allow_list_workspace_match_is_case_insensitive(workspace):
    target = _program(workspace / "tools" / "aws")
    policy = Policy(workspace=str(workspace).upper(), allow_exec=("aws",),
                    search_path=str(target.parent))  # only the jail can refuse
    with pytest.raises(PolicyError, match="its name finds on PATH"):
        policy.check([str(target)], cwd=str(workspace))


def test_allow_list_path_qualified_program_needs_a_workspace(tmp_path):
    host_aws = _program(tmp_path / "hostbin" / "aws")
    policy = Policy(allow_exec=("aws",), search_path=str(host_aws.parent))
    with pytest.raises(PolicyError, match="its name finds on PATH"):
        policy.check([str(host_aws)], cwd=None)
    policy.check(["aws"], cwd=None)  # the bare name is still fine


def test_empty_allow_list_still_runs_path_qualified_workspace_program(cfg):
    _program(Path(cfg.exec.workspace) / "tools" / "mytool", "ran")
    resp = Broker(cfg).handle({"op": "exec", "cmd": ["tools/mytool"], "shell": False})
    assert resp["ok"] is True
    assert resp["stdout"] == "ran\n"


# --- per-request environment ---------------------------------------------------

@pytest.mark.parametrize("name", [
    "PATH", "path", "HOME", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
    "PYTHONPATH", "PYTHONSTARTUP", "NODE_OPTIONS", "GIT_CONFIG", "GIT_CONFIG_COUNT",
    "GIT_CONFIG_KEY_0", "GIT_CONFIG_PARAMETERS", "GIT_EXEC_PATH", "GIT_SSH_COMMAND",
    "BASH_ENV", "ENV", "PERL5OPT", "RUBYOPT", "JAVA_TOOL_OPTIONS", "LESSOPEN",
    "npm_config_node_options",
])
@pytest.mark.parametrize("allow_exec", [(), ("aws",)])
def test_restricted_env_name_is_refused_in_every_mode(name, allow_exec):
    policy = Policy(allow_exec=allow_exec)
    with pytest.raises(PolicyError, match=f"^{name} may not be set per command"):
        policy.check(["aws"], cwd=None, env={name: "./tools"})


@pytest.mark.parametrize("name", [
    "AWS_PROFILE", "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE", "GIT_AUTHOR_NAME",
    "NODE_ENV", "PATHS", "MY_PATH",
])
def test_ordinary_env_names_are_allowed(name):
    Policy(allow_exec=("aws",)).check(["aws"], cwd=None, env={name: "x"})


@pytest.mark.parametrize("cmd", [
    ["PATH=./tools", "aws"],
    ["env", "PATH=./tools", "aws"],
    ["A=1", "env", "B=2", "LD_PRELOAD=./x.so", "aws"],
    "PATH=./tools aws",
    "PATH+=:./tools aws",
    "export PATH=./tools; aws",
    "declare -x PYTHONPATH=./lib; aws",
    "echo hi && GIT_CONFIG_COUNT=1 aws",
    "PATH=./tools; aws",
])
def test_restricted_env_assignment_in_command_is_refused(cmd):
    with pytest.raises(PolicyError, match="may not be set per command"):
        Policy(allow_shell=True).check(cmd, cwd=None)


def test_assignment_after_the_command_is_an_argument_not_env():
    Policy(allow_exec=("aws",)).check(["aws", "PATH=./tools"], cwd=None)


def test_restricted_env_is_refused_through_the_broker(cfg):
    for request in (
        {"cmd": ["echo", "hi"], "shell": False, "env": {"PATH": "./tools"}},
        {"cmd": ["PYTHONPATH=./lib", "echo", "hi"], "shell": False},
        {"cmd": "LD_PRELOAD=./x.so echo hi", "shell": True},
    ):
        resp = Broker(cfg).handle({"op": "exec", **request})
        assert resp["ok"] is False, request
        assert resp["error_class"] == "PolicyDenied", request
        assert "may not be set per command" in resp["detail"], request


# --- workspace write jail ----------------------------------------------------

def test_write_jail_blocks_absolute_path_outside_workspace(cfg, tmp_path):
    # A brand-new file outside the workspace (does not exist yet) is refused.
    target = tmp_path / "escapee.txt"
    resp = Broker(cfg).handle(
        {"op": "exec", "cmd": ["touch", str(target)], "shell": False}
    )
    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"
    # The message names the token as the request wrote it, never its resolution.
    assert resp["detail"].startswith("command targets a path outside the workspace: ")
    assert str(target)[:20] in resp["detail"]
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
    assert resp["detail"] == "command is on the deny list: 'kill'"


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


# --- redirect operands are files, not commands -------------------------------

def _redirect_cfg(cfg, allow=("echo", "wc", "cat", "sort"), **policy):
    return dataclasses.replace(
        cfg, policy=PolicyConfig(allow_exec=allow, **policy))


@pytest.mark.parametrize("line", [
    "echo hi > out.txt",
    "echo hi >> out.txt",
    "wc -l < in.txt",
    "cat in.txt 2> err.txt",
    "sort < in.txt > out.txt",
    "cat <<'EOF'\nbody\nEOF",
])
def test_redirects_are_not_checked_against_the_allow_list(cfg, workspace, line):
    # The target of a redirect used to be lexed as the next sub-command, so
    # every redirect under an allowlist was refused for "not on the allow list"
    # — naming a filename that was never going to be run.
    (workspace / "in.txt").write_text("a\nb\n")
    resp = Broker(_redirect_cfg(cfg)).handle(
        {"op": "exec", "cmd": line, "shell": True})
    assert resp["ok"] is True, resp


def test_a_command_after_a_redirect_is_still_checked(cfg, workspace):
    # `;` starts a real sub-command again — being downstream of a redirect does
    # not make it an operand.
    resp = Broker(_redirect_cfg(cfg)).handle(
        {"op": "exec", "cmd": "echo hi > out.txt; rm -rf x", "shell": True})
    assert resp["ok"] is False
    assert "rm" in resp["detail"]


def test_process_substitution_is_not_treated_as_an_operand(cfg, workspace):
    # `<(` is not a redirect: its first word really is a command to check.
    resp = Broker(_redirect_cfg(cfg)).handle(
        {"op": "exec", "cmd": "cat <(rm -rf x)", "shell": True})
    assert resp["ok"] is False
    assert "rm" in resp["detail"]


def test_redirect_targets_are_still_path_checked(cfg, workspace):
    # Not being a command does not make it unchecked: clobbering a denied file
    # through a redirect is still refused. (deny_read only bans paths that
    # exist — a pattern that matches nothing on disk has nothing to reveal.)
    (workspace / "prod.creds").write_text("REAL=1\n")
    c = _redirect_cfg(cfg, deny_read=("**/*.creds",))
    resp = Broker(c).handle(
        {"op": "exec", "cmd": "echo stolen > prod.creds", "shell": True})
    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"
    assert "prod.creds" in resp["detail"]
    assert (workspace / "prod.creds").read_text() == "REAL=1\n"


def test_reading_a_denied_file_through_a_redirect_is_still_denied(cfg, workspace):
    # The read-side twin of the test above: `< denied` is an operand, and an
    # operand's paths are exactly what still gets checked.
    (workspace / "prod.creds").write_text("REAL=1\n")
    c = _redirect_cfg(cfg, deny_read=("**/*.creds",))
    resp = Broker(c).handle(
        {"op": "exec", "cmd": "cat < prod.creds", "shell": True})
    assert resp["ok"] is False
    assert "prod.creds" in resp["detail"]
    assert "REAL=1" not in resp.get("stdout", "")


def test_a_heredoc_body_is_input_not_commands(cfg, workspace):
    # The body is what the command reads; it is not parsed as sub-commands, so
    # a denied name inside it is data. The command itself is still checked.
    resp = Broker(_redirect_cfg(cfg)).handle(
        {"op": "exec", "cmd": "cat <<'EOF'\nrm -rf /\nEOF", "shell": True})
    assert resp["ok"] is True, resp
    assert "rm -rf /" in resp["stdout"]


def test_commands_after_a_heredoc_terminator_are_checked_again(cfg, workspace):
    resp = Broker(_redirect_cfg(cfg)).handle(
        {"op": "exec", "cmd": "cat <<'EOF'\nbody\nEOF\nrm -rf x", "shell": True})
    assert resp["ok"] is False
    assert "rm" in resp["detail"]


def test_redirect_out_of_the_workspace_is_still_jailed(cfg, tmp_path, workspace):
    target = tmp_path / "escaped.txt"
    c = _redirect_cfg(cfg, enforce_workspace_writes=True)
    resp = Broker(c).handle(
        {"op": "exec", "cmd": f"echo out > {target}", "shell": True})
    assert resp["ok"] is False
    assert not target.exists()


def test_unbalanced_quotes_mark_nothing_as_an_operand(cfg):
    # The fallback tokenisation is a guess, not the shell's parse, so it is not
    # trusted to say which token is a redirect's target.
    from valet.policy import _split_line
    subs = _split_line('echo "a > b; rm -rf c')
    assert not any(sub.is_operand for sub in subs)


def test_argv_mode_has_no_operands(cfg):
    from valet.policy import _split_subcommands
    subs = _split_subcommands(["echo", "hi", ">", "out.txt"])
    assert len(subs) == 1 and subs[0].is_operand is False


# --- denials name the token that caused them ----------------------------------

def test_allow_list_denial_names_the_program(cfg):
    resp = Broker(_allow_cfg(cfg, ("echo",))).handle(
        {"op": "exec", "cmd": ["/usr/bin/curl", "x"], "shell": False})
    assert resp["detail"] == "command is not on the allow list: '/usr/bin/curl'"


def test_path_denial_names_the_token_not_its_resolution(cfg, tmp_path):
    secret = tmp_path / "outside.txt"
    secret.write_text("x")
    c = dataclasses.replace(
        cfg, policy=PolicyConfig(enforce_workspace_reads=True))
    resp = Broker(c).handle(
        {"op": "exec", "cmd": ["cat", "../outside.txt"], "shell": False})
    assert resp["ok"] is False
    # The token as written, so the reply never spells out the host's layout.
    assert resp["detail"].endswith("'../outside.txt'")
    assert str(tmp_path) not in resp["detail"]


def test_a_long_token_is_truncated_in_the_message(cfg):
    long_name = "z" * 200
    resp = Broker(_allow_cfg(cfg, ("echo",))).handle(
        {"op": "exec", "cmd": [long_name], "shell": False})
    assert len(resp["detail"]) < 130
    assert "…" in resp["detail"]
