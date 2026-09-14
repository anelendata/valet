"""The files.pull op: host -> agent download, gated by path, identity and content."""
import base64
import dataclasses
import hashlib
import json
import os
import threading

import pytest

from valet.broker import FILE_PULL_MAX_BYTES, Broker
from valet.config import AuditConfig


def _enabled(cfg, **policy):
    return dataclasses.replace(
        cfg, policy=dataclasses.replace(cfg.policy, allow_pull=True, **policy))


def _with_secrets(cfg, *patterns):
    return dataclasses.replace(cfg, redaction=dataclasses.replace(
        cfg.redaction, secret_file_paths=tuple(cfg.redaction.secret_file_paths) + patterns))


def _pull(broker, path, transport="uds", **extra):
    return broker.handle({"op": "files.pull", "path": path, **extra},
                         audit_context={"transport": transport, "caller": "t"})


def _refused(resp, error_class="PolicyDenied"):
    assert resp["ok"] is False, resp
    assert resp["error_class"] == error_class, resp
    assert "content_b64" not in resp
    return resp


# -- happy path & gating ---------------------------------------------------------

def test_disabled_by_default(cfg, workspace):
    (workspace / "report.txt").write_text("hello\n")
    resp = _refused(_pull(Broker(cfg), "report.txt"))
    assert "allow_pull" in resp["detail"]


def test_pulls_a_plain_text_file(cfg, workspace):
    (workspace / "out").mkdir()
    (workspace / "out" / "report.txt").write_text("rows: 42\n")
    os.chmod(workspace / "out" / "report.txt", 0o755)
    resp = _pull(Broker(_enabled(cfg)), "/out/report.txt")
    assert resp["ok"] is True
    data = base64.b64decode(resp["content_b64"])
    assert data == b"rows: 42\n"
    assert resp["sha256"] == hashlib.sha256(data).hexdigest()
    assert resp["bytes_read"] == len(data)
    assert resp["path"] == "./out/report.txt"
    assert resp["mode"] == 0o755


def test_lan_transport_needs_its_own_opt_in(cfg, workspace):
    (workspace / "a.txt").write_text("x\n")
    _refused(_pull(Broker(_enabled(cfg)), "a.txt", transport="websocket"))
    ok = _pull(Broker(_enabled(cfg, allow_pull_lan=True)), "a.txt", transport="websocket")
    assert ok["ok"] is True


# -- path rules --------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "secret_values_test", "SECRET_VALUES_TEST", "sub/../secret_values_test",
    "~/secret_values_test",
])
def test_secret_source_path_is_refused(cfg, workspace, path):
    (workspace / "secret_values_test").write_text("TOKEN=abcdefghijklmnopqrstuvwxyz\n")
    _refused(_pull(Broker(_enabled(cfg)), path))


def test_file_inside_secret_directory_is_refused(cfg, workspace):
    (workspace / "vault").mkdir()
    (workspace / "vault" / "note.txt").write_text("harmless-looking\n")
    _refused(_pull(Broker(_enabled(_with_secrets(cfg, "**/vault/**"))), "vault/note.txt"))


def test_symlink_alias_to_secret_is_refused(cfg, workspace):
    (workspace / "secret_values_test").write_text("TOKEN=abcdefghijklmnopqrstuvwxyz\n")
    (workspace / "innocent.txt").symlink_to(workspace / "secret_values_test")
    _refused(_pull(Broker(_enabled(cfg)), "innocent.txt"))


def test_symlink_out_of_workspace_is_refused(cfg, tmp_path, workspace):
    (tmp_path / "host.txt").write_text("host data\n")
    (workspace / "link.txt").symlink_to(tmp_path / "host.txt")
    _refused(_pull(Broker(_enabled(cfg)), "link.txt"))


def test_deny_read_path_is_refused(cfg, workspace):
    (workspace / "cap.har").write_text("{}\n")
    _refused(_pull(Broker(_enabled(cfg, deny_read=("**/*.har",))), "CAP.har"))


@pytest.mark.parametrize("path", [".git/config", "lib/.git/HEAD"])
def test_vcs_internals_are_refused(cfg, workspace, path):
    target = workspace / path
    target.parent.mkdir(parents=True)
    target.write_text("[core]\n")
    _refused(_pull(Broker(_enabled(cfg)), path))


def test_audit_log_is_refused(cfg, workspace):
    log = workspace / "audit.jsonl"
    c = dataclasses.replace(_enabled(cfg), audit=AuditConfig(log_path=str(log)))
    log.write_text("{}\n")
    _refused(_pull(Broker(c), "audit.jsonl"))


# -- file identity ----------------------------------------------------------------

def test_hard_link_to_a_secret_outside_the_workspace_is_refused(cfg, secret_file, workspace):
    os.link(secret_file, workspace / "notes.txt")
    resp = _refused(_pull(Broker(_enabled(cfg)), "notes.txt"))
    assert "hard link" in resp["detail"]


def test_binary_copy_of_a_binary_secret_is_refused(cfg, workspace):
    # A binary secret contributes no redaction values, so only the copy check
    # can recognise it.
    (workspace / "vault").mkdir()
    blob = b"\x00\x01PKCS12" + os.urandom(64)
    (workspace / "vault" / "id.p12").write_bytes(blob)
    (workspace / "exported.bin").write_bytes(blob)
    c = _enabled(_with_secrets(cfg, "**/vault/**"), allow_pull_binary=True)
    resp = _refused(_pull(Broker(c), "exported.bin"))
    assert "copy of a secret" in resp["detail"]


def test_fifo_is_refused_without_blocking(cfg, workspace):
    os.mkfifo(workspace / "pipe")
    result = {}
    t = threading.Thread(target=lambda: result.setdefault(
        "resp", _pull(Broker(_enabled(cfg)), "pipe")))
    t.start()
    t.join(timeout=5)
    assert not t.is_alive(), "pull blocked on a FIFO"
    _refused(result["resp"])


def test_directory_and_missing_file_are_validation_errors(cfg, workspace):
    (workspace / "d").mkdir()
    _refused(_pull(Broker(_enabled(cfg)), "d"), "ValidationError")
    _refused(_pull(Broker(_enabled(cfg)), "nope.txt"), "ValidationError")
    _refused(_pull(Broker(_enabled(cfg)), "/"), "ValidationError")


def test_oversize_file_is_refused(cfg, workspace):
    (workspace / "big.txt").write_bytes(b"a" * (FILE_PULL_MAX_BYTES + 1))
    _refused(_pull(Broker(_enabled(cfg)), "big.txt"), "ValidationError")


def test_final_component_swapped_for_symlink_is_refused(cfg, tmp_path, workspace, monkeypatch):
    import valet.files as files
    (tmp_path / "host.txt").write_text("host data\n")
    (workspace / "f.txt").write_text("fine\n")
    real_check = files.TransferGuard.check_common

    def swap_then_check(self, lexical, real):
        real_check(self, lexical, real)
        (workspace / "f.txt").unlink()
        (workspace / "f.txt").symlink_to(tmp_path / "host.txt")

    monkeypatch.setattr(files.TransferGuard, "check_common", swap_then_check)
    _refused(_pull(Broker(_enabled(cfg)), "f.txt"))


def test_parent_swapped_for_symlink_is_refused(cfg, tmp_path, workspace, monkeypatch):
    import valet.files as files
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "f.txt").write_text("host data\n")
    (workspace / "d").mkdir()
    (workspace / "d" / "f.txt").write_text("fine\n")
    real_check = files.TransferGuard.check_common

    def swap_then_check(self, lexical, real):
        real_check(self, lexical, real)
        (workspace / "d" / "f.txt").unlink()
        (workspace / "d").rmdir()
        (workspace / "d").symlink_to(outside)

    monkeypatch.setattr(files.TransferGuard, "check_common", swap_then_check)
    _refused(_pull(Broker(_enabled(cfg)), "d/f.txt"))


# -- content ------------------------------------------------------------------------

def test_verbatim_copy_of_a_secret_file_is_refused(cfg, secret_file, workspace):
    (workspace / "copy.txt").write_bytes(secret_file.read_bytes())
    _refused(_pull(Broker(_enabled(cfg)), "copy.txt"))


def test_text_containing_a_known_secret_value_is_refused(cfg, workspace):
    (workspace / "log.txt").write_text("connecting with sup3r-s3cret-value-do-not-leak\n")
    resp = _refused(_pull(Broker(_enabled(cfg)), "log.txt"))
    assert "secret" in resp["detail"]
    assert "sup3r" not in resp["detail"]


def test_suspected_secret_is_refused(cfg, workspace):
    (workspace / "creds.json").write_text('{"api_key": "q8Zr2LmN4vT7xY1pK9sD"}\n')
    resp = _refused(_pull(Broker(_enabled(cfg)), "creds.json"))
    assert "q8Zr2" not in resp["detail"]


@pytest.mark.parametrize("text", [
    "owner: someone@example.com\n",
    "role: arn:aws:iam::123456789012:role/deploy\n",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n",
])
def test_identifiers_valet_redacts_are_refused(cfg, workspace, text):
    (workspace / "x.txt").write_text(text)
    _refused(_pull(Broker(_enabled(cfg)), "x.txt"))


def test_real_host_path_in_text_is_refused(cfg, workspace):
    (workspace / "activate").write_text(f"VIRTUAL_ENV='{os.path.realpath(workspace)}/.venv'\n")
    resp = _refused(_pull(Broker(_enabled(cfg)), "activate"))
    assert "host path" in resp["detail"]


def test_binary_is_refused_unless_enabled(cfg, workspace):
    png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + bytes(range(256))
    (workspace / "chart.png").write_bytes(png)
    _refused(_pull(Broker(_enabled(cfg)), "chart.png"))
    ok = _pull(Broker(_enabled(cfg, allow_pull_binary=True)), "chart.png")
    assert ok["ok"] is True
    assert base64.b64decode(ok["content_b64"]) == png


def test_invalid_utf8_counts_as_binary(cfg, workspace):
    (workspace / "latin1.txt").write_bytes(b"caf\xe9\n")
    _refused(_pull(Broker(_enabled(cfg)), "latin1.txt"))


@pytest.mark.parametrize("payload", [
    b"\x00\x00junk sup3r-s3cret-value-do-not-leak junk",
    b"\x00\x00junk AKIAABCDEFGHIJKLMNOP junk",
    b"\x00\x00-----BEGIN OPENSSH PRIVATE KEY-----\x00",
])
def test_enabled_binary_is_still_scanned(cfg, workspace, payload):
    (workspace / "blob.bin").write_bytes(payload)
    _refused(_pull(Broker(_enabled(cfg, allow_pull_binary=True)), "blob.bin"))


# -- audit ----------------------------------------------------------------------------

def test_pull_is_audited_without_content(cfg, tmp_path, workspace):
    log = tmp_path / "audit.jsonl"
    c = dataclasses.replace(_enabled(cfg), audit=AuditConfig(log_path=str(log)))
    (workspace / "r.txt").write_text("result-body-marker\n")
    broker = Broker(c)
    ok = _pull(broker, "r.txt")
    _pull(broker, "secret_values_test")
    events = [json.loads(line) for line in log.read_text().splitlines()]
    assert "result-body-marker" not in log.read_text()
    assert events[0]["op"] == "files.pull"
    assert events[0]["decision"] == "allowed"
    assert events[0]["path"] == "./r.txt"
    assert events[0]["bytes_read"] == ok["bytes_read"]
    assert events[0]["sha256"] == ok["sha256"]
    assert events[1]["decision"] != "allowed"
    assert events[1]["path"] == "secret_values_test"


# -- client -----------------------------------------------------------------------------

class _Conn:
    def __init__(self, response):
        self.response = response
        self.requests = []

    def request(self, req):
        self.requests.append(req)
        return self.response

    def close(self):
        pass


def _ok_response(data: bytes, mode=0o644):
    return {"op": "files.pull", "ok": True, "path": "./out/r.txt",
            "bytes_read": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "mode": mode, "content_b64": base64.b64encode(data).decode()}


def test_cli_pull_writes_file_and_verifies_sha(monkeypatch, tmp_path):
    from valet.cli import main
    conn = _Conn(_ok_response(b"payload", mode=0o755))
    monkeypatch.setattr("valet.cli._connect", lambda _a: (conn, object(), None))
    dest = tmp_path / "local"
    dest.mkdir()
    assert main(["files", "pull", "out/r.txt", str(dest)]) == 0
    assert (dest / "r.txt").read_bytes() == b"payload"
    assert (os.stat(dest / "r.txt").st_mode & 0o777) == 0o755
    assert conn.requests[0]["op"] == "files.pull"


def test_cli_pull_rejects_sha_mismatch(monkeypatch, tmp_path):
    from valet.cli import main
    resp = _ok_response(b"payload")
    resp["sha256"] = "0" * 64
    monkeypatch.setattr("valet.cli._connect", lambda _a: (_Conn(resp), object(), None))
    dest = tmp_path / "r.txt"
    assert main(["files", "pull", "out/r.txt", str(dest)]) == 1
    assert not dest.exists()


def test_cli_pull_no_clobber(monkeypatch, tmp_path):
    from valet.cli import main
    dest = tmp_path / "r.txt"
    dest.write_text("keep")
    monkeypatch.setattr("valet.cli._connect",
                        lambda _a: (_Conn(_ok_response(b"new")), object(), None))
    assert main(["files", "pull", "--no-clobber", "out/r.txt", str(dest)]) == 2
    assert dest.read_text() == "keep"
