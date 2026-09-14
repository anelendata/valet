"""The files.push op: agent -> host file upload, jailed to the workspace."""
import base64
import dataclasses
import hashlib
import json
import os

import pytest

from valet.broker import FILE_PUSH_MAX_BYTES, Broker
from valet.config import AuditConfig


def _push(broker, path, content: bytes, **extra):
    req = {
        "op": "files.push",
        "path": path,
        "content_b64": base64.b64encode(content).decode("ascii"),
        **extra,
    }
    return broker.handle(req)


def test_writes_file_into_workspace(cfg, workspace):
    resp = _push(Broker(cfg), "uploaded.bin", b"hello bytes")
    assert resp["ok"] is True
    assert resp["path"] == "./uploaded.bin"
    assert resp["bytes_written"] == len(b"hello bytes")
    assert resp["created"] is True
    assert (workspace / "uploaded.bin").read_bytes() == b"hello bytes"


def test_handles_arbitrary_binary_including_nul_and_high_bytes(cfg, workspace):
    payload = bytes(range(256)) * 8  # every byte value, incl. NUL and 0xFF
    resp = _push(Broker(cfg), "blob.dat", payload)
    assert resp["ok"] is True
    written = (workspace / "blob.dat").read_bytes()
    assert written == payload
    assert resp["sha256"] == hashlib.sha256(payload).hexdigest()


def test_creates_parent_directories(cfg, workspace):
    resp = _push(Broker(cfg), "projects/new/tool.py", b"print('hi')\n")
    assert resp["ok"] is True
    assert (workspace / "projects" / "new" / "tool.py").read_bytes() == b"print('hi')\n"


def test_virtual_absolute_path_is_workspace_relative(cfg, workspace):
    # A leading "/" means the workspace root, not the host filesystem root.
    resp = _push(Broker(cfg), "/toproot.txt", b"x")
    assert resp["ok"] is True
    assert resp["path"] == "./toproot.txt"
    assert (workspace / "toproot.txt").exists()


def test_overwrite_by_default_and_no_clobber_refuses(cfg, workspace):
    (workspace / "f").write_bytes(b"old")
    resp = _push(Broker(cfg), "f", b"new")
    assert resp["ok"] is True
    assert resp["created"] is False
    assert (workspace / "f").read_bytes() == b"new"

    refused = _push(Broker(cfg), "f", b"newer", overwrite=False)
    assert refused["ok"] is False
    assert refused["error_class"] == "ValidationError"
    assert (workspace / "f").read_bytes() == b"new"  # unchanged


def test_escape_via_dotdot_is_refused(cfg, tmp_path, workspace):
    resp = _push(Broker(cfg), "../escape.txt", b"nope")
    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"
    assert not (tmp_path / "escape.txt").exists()


def test_escape_via_symlink_is_refused(cfg, tmp_path, workspace):
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace / "link").symlink_to(outside)  # link -> a dir outside the jail
    resp = _push(Broker(cfg), "link/pwned.txt", b"nope")
    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"
    assert not (outside / "pwned.txt").exists()


def test_config_toml_destination_is_protected(cfg):
    resp = _push(Broker(cfg), "config.toml", b"[evil]\n")
    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"


def test_directory_destination_is_rejected(cfg, workspace):
    (workspace / "adir").mkdir()
    resp = _push(Broker(cfg), "adir", b"x")
    assert resp["ok"] is False
    assert resp["error_class"] == "ValidationError"


def test_invalid_base64_is_rejected(cfg):
    resp = Broker(cfg).handle(
        {"op": "files.push", "path": "x", "content_b64": "not valid base64!!"}
    )
    assert resp["ok"] is False
    assert resp["error_class"] == "ValidationError"


def test_missing_content_is_rejected(cfg):
    resp = Broker(cfg).handle({"op": "files.push", "path": "x"})
    assert resp["ok"] is False
    assert resp["error_class"] == "ValidationError"


def test_oversize_upload_is_rejected(cfg, workspace):
    payload = b"a" * (FILE_PUSH_MAX_BYTES + 1)
    resp = _push(Broker(cfg), "big.bin", payload)
    assert resp["ok"] is False
    assert resp["error_class"] == "ValidationError"
    assert not (workspace / "big.bin").exists()


def test_mode_bits_are_applied(cfg, workspace):
    resp = _push(Broker(cfg), "bin/tool", b"#!/bin/sh\necho hi\n", mode="755")
    assert resp["ok"] is True
    got = os.stat(workspace / "bin" / "tool").st_mode & 0o777
    assert got == 0o755


def test_default_mode_is_644(cfg, workspace):
    _push(Broker(cfg), "plain.txt", b"data")
    assert (os.stat(workspace / "plain.txt").st_mode & 0o777) == 0o644


def test_push_is_audited_with_path_and_size(cfg, tmp_path, workspace):
    audit_log = tmp_path / "audit.jsonl"
    c = dataclasses.replace(cfg, audit=AuditConfig(log_path=str(audit_log)))
    resp = _push(Broker(c), "notes/todo.txt", b"remember", )
    assert resp["ok"] is True
    event = json.loads(audit_log.read_text().strip())
    assert event["op"] == "files.push"
    assert event["decision"] == "allowed"
    assert event["path"] == "./notes/todo.txt"
    assert event["bytes_written"] == len(b"remember")


# -- protected destinations ----------------------------------------------------

def _refused(resp, error_class="PolicyDenied"):
    assert resp["ok"] is False, resp
    assert resp["error_class"] == error_class
    return resp


def _with(cfg, **sections):
    return dataclasses.replace(cfg, **sections)


@pytest.mark.parametrize("dest", [
    ".secrets/token",               # a secret dir (default pattern)
    "nested/.secrets/new.txt",      # at depth via **/
    ".env",
    ".ENV",                         # case-insensitive filesystems
    "sub/../.env",
    "/.secrets/x",
    "~/.env",
])
def test_secret_file_paths_destination_is_refused(cfg, workspace, dest):
    c = _with(cfg, redaction=dataclasses.replace(
        cfg.redaction, secret_file_paths=("**/.secrets/**", "**/.env")))
    _refused(_push(Broker(c), dest, b"AWS_SECRET_ACCESS_KEY=attacker"))
    assert not (workspace / ".env").exists()
    assert not (workspace / ".secrets").exists()


def test_secret_directory_pattern_covers_everything_beneath(cfg, workspace):
    c = _with(cfg, redaction=dataclasses.replace(
        cfg.redaction, secret_file_paths=("creds",)))
    _refused(_push(Broker(c), "creds/deep/key.pem", b"x"))


def test_symlink_alias_into_secret_dir_is_refused(cfg, workspace):
    (workspace / "vault").mkdir()
    (workspace / "alias").symlink_to(workspace / "vault")
    c = _with(cfg, redaction=dataclasses.replace(
        cfg.redaction, secret_file_paths=("**/vault/**",)))
    _refused(_push(Broker(c), "alias/token", b"x"))
    assert not (workspace / "vault" / "token").exists()


def test_overwriting_existing_secret_file_is_refused(cfg, workspace):
    (workspace / "prod.creds").write_text("REAL=1\n")
    c = _with(cfg, redaction=dataclasses.replace(
        cfg.redaction, secret_file_paths=("**/*.creds",)))
    _refused(_push(Broker(c), "prod.creds", b"REAL=attacker\n"))
    assert (workspace / "prod.creds").read_text() == "REAL=1\n"


def test_deny_read_destination_is_refused(cfg, workspace):
    c = _with(cfg, policy=dataclasses.replace(cfg.policy, deny_read=("**/*.har",)))
    _refused(_push(Broker(c), "captures/session.HAR", b"{}"))


@pytest.mark.parametrize("dest", [
    ".git/hooks/pre-commit", ".git/config", "vendor/lib/.GIT/hooks/post-checkout",
    ".hg/hgrc", ".svn/entries",
])
def test_vcs_internals_are_refused(cfg, workspace, dest):
    _refused(_push(Broker(cfg), dest, b"#!/bin/sh\ncurl evil\n", mode="755"))


def test_audit_log_and_sandbox_profile_are_protected(cfg, workspace):
    audit_log = workspace / "logs" / "audit.jsonl"
    profile = workspace / "sandbox.sb"
    profile.write_text("(version 1)")
    c = _with(cfg, audit=AuditConfig(log_path=str(audit_log)),
              exec=dataclasses.replace(cfg.exec, sandbox_profile=str(profile)))
    broker = Broker(c)
    _refused(_push(broker, "logs/audit.jsonl", b"{}\n"))
    _refused(_push(broker, "sandbox.sb", b"(allow default)"))
    assert profile.read_text() == "(version 1)"


def test_config_toml_any_case_is_protected(cfg):
    _refused(_push(Broker(cfg), "sub/Config.TOML", b"[evil]\n"))


def test_bin_push_that_shadows_a_path_program_is_refused(cfg, workspace):
    _refused(_push(Broker(cfg), "bin/ls", b"#!/bin/sh\n", mode="755"))
    assert not (workspace / "bin" / "ls").exists()


def test_bin_push_of_a_new_tool_is_allowed(cfg, workspace):
    resp = _push(Broker(cfg), "bin/my-unique-valet-tool", b"#!/bin/sh\n", mode="755")
    assert resp["ok"] is True


def test_allow_exec_name_is_refused_anywhere(cfg, workspace):
    c = _with(cfg, policy=dataclasses.replace(cfg.policy, allow_exec=("aws",)))
    _refused(_push(Broker(c), "tools/AWS", b"#!/bin/sh\n", mode="755"))


def test_dollar_vars_are_not_expanded(cfg, workspace, monkeypatch):
    monkeypatch.setenv("VALET_TEST_LEAK", "host-secret-value")
    resp = _push(Broker(cfg), "$VALET_TEST_LEAK.txt", b"x")
    assert resp["ok"] is True
    assert "host-secret-value" not in resp["path"]
    assert (workspace / "$VALET_TEST_LEAK.txt").exists()


def test_nul_byte_in_path_is_a_validation_error(cfg):
    _refused(_push(Broker(cfg), "a\x00b", b"x"), "ValidationError")


def test_setuid_and_group_write_bits_are_dropped(cfg, workspace):
    _push(Broker(cfg), "tool.sh", b"#!/bin/sh\n", mode="4777")
    assert (os.stat(workspace / "tool.sh").st_mode & 0o7777) == 0o755


def test_hard_link_at_destination_is_replaced_not_written_through(cfg, tmp_path, workspace):
    outside = tmp_path / "outside.txt"
    outside.write_text("original")
    os.link(outside, workspace / "linked.txt")
    resp = _push(Broker(cfg), "linked.txt", b"new")
    assert resp["ok"] is True
    assert outside.read_text() == "original"
    assert (workspace / "linked.txt").read_bytes() == b"new"


def test_parent_swapped_for_symlink_after_check_is_refused(cfg, tmp_path, workspace, monkeypatch):
    # Simulate the race: the check sees a real dir, then it becomes a symlink
    # pointing outside before the write walks it.
    import valet.files as files
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace / "d").mkdir()
    real_check = files.TransferGuard.check_push

    def swap_then_check(self, lexical, real):
        real_check(self, lexical, real)
        (workspace / "d").rmdir()
        (workspace / "d").symlink_to(outside)

    monkeypatch.setattr(files.TransferGuard, "check_push", swap_then_check)
    _refused(_push(Broker(cfg), "d/pwned.txt", b"nope"))
    assert not (outside / "pwned.txt").exists()


def test_refused_push_is_audited_with_requested_path(cfg, tmp_path, workspace):
    audit_log = tmp_path / "audit.jsonl"
    c = _with(cfg, audit=AuditConfig(log_path=str(audit_log)))
    _push(Broker(c), ".git/hooks/pre-commit", b"x")
    event = json.loads(audit_log.read_text().strip())
    assert event["decision"] != "allowed"
    assert event["path"] == ".git/hooks/pre-commit"
