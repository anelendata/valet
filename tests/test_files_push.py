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
