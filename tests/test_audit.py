import dataclasses
import json

from valet.broker import Broker
from valet.config import AuditConfig, load_config


def test_audit_config_loads_json_log_path(tmp_path):
    path = tmp_path / "config.toml"
    audit_log = tmp_path / "audit.jsonl"
    path.write_text(
        "[broker]\nfingerprint_salt = 'fixed-test-salt'\n\n"
        "[audit]\nlog_path = '" + str(audit_log) + "'\nconsole = false\n"
    )

    cfg = load_config(path)

    assert cfg.audit.log_path == str(audit_log)
    assert cfg.audit.console is False


def test_audit_log_writes_metadata_without_raw_output_or_secret(cfg, tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    secret = "audit-secret-value-do-not-leak"
    c = dataclasses.replace(
        cfg,
        audit=AuditConfig(log_path=str(audit_log)),
        redaction=dataclasses.replace(cfg.redaction, extra_values=(secret,)),
    )

    resp = Broker(c).handle(
        {
            "op": "exec",
            "cmd": f"echo leaking {secret} now",
        },
        audit_context={"transport": "uds", "caller": "codex"},
    )

    assert resp["ok"] is True
    event = json.loads(audit_log.read_text().strip())
    serialized = json.dumps(event)
    assert event["caller"] == "codex"
    assert event["transport"] == "uds"
    assert event["decision"] == "allowed"
    assert event["op"] == "exec"
    assert "REDACTED:secret:" in event["command"]
    assert secret not in serialized
    assert "stdout" not in event
    assert "stderr" not in event
    assert event["returned_stdout_bytes"] > 0


def test_audit_log_records_policy_denial(cfg, tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    c = dataclasses.replace(
        cfg,
        audit=AuditConfig(log_path=str(audit_log)),
        policy=dataclasses.replace(cfg.policy, deny=("curl",)),
    )

    resp = Broker(c).handle(
        {"op": "exec", "cmd": "curl https://example.com"},
        audit_context={"transport": "http", "caller": "127.0.0.1"},
    )

    assert resp["ok"] is False
    event = json.loads(audit_log.read_text().strip())
    assert event["decision"] == "denied"
    assert event["error_class"] == "PolicyDenied"
    assert event["exit_code"] is None
    assert event["command"] == "curl https://example.com"


def test_audit_flags_reference_to_path_outside_workspace(cfg, tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    outside = tmp_path / "outside_dir"
    outside.mkdir()
    c = dataclasses.replace(cfg, audit=AuditConfig(log_path=str(audit_log)))

    # The command is denied by the (default) read jail, but the audit event
    # still records that it reached for a path outside the workspace.
    resp = Broker(c).handle({"op": "exec", "cmd": ["ls", "-la", str(outside)]})

    assert resp["ok"] is False
    event = json.loads(audit_log.read_text().strip())
    assert event["referenced_outside_workspace"] is True


def test_audit_does_not_flag_workspace_local_command(cfg, tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    c = dataclasses.replace(cfg, audit=AuditConfig(log_path=str(audit_log)))

    Broker(c).handle({"op": "exec", "cmd": "pwd", "shell": True})

    event = json.loads(audit_log.read_text().strip())
    assert event["referenced_outside_workspace"] is False


def test_audit_records_rejected_handshake(cfg, tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    c = dataclasses.replace(cfg, audit=AuditConfig(log_path=str(audit_log)))

    Broker(c).audit_security_rejection(
        op="auth",
        caller="client_x",
        transport="websocket",
        detail="signature verification failed",
        peer="192.168.1.9:54321",
    )

    event = json.loads(audit_log.read_text().strip())
    assert event["op"] == "auth"
    assert event["phase"] == "handshake"
    assert event["decision"] == "denied"
    assert event["ok"] is False
    assert event["error_class"] == "authentication_failed"
    assert event["caller"] == "client_x"
    assert event["transport"] == "websocket"
    assert event["detail"] == "signature verification failed"
    assert event["peer"] == "192.168.1.9:54321"


def test_audit_rejected_handshake_defaults_caller(cfg, tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    c = dataclasses.replace(cfg, audit=AuditConfig(log_path=str(audit_log)))

    Broker(c).audit_security_rejection(
        op="auth",
        caller="",
        transport="websocket",
        detail="client identity is not approved",
    )

    event = json.loads(audit_log.read_text().strip())
    assert event["caller"] == "unknown"
    assert event["peer"] is None


def test_audit_console_prints_summary_and_pretty_json(cfg, capsys):
    c = dataclasses.replace(cfg, audit=AuditConfig())

    Broker(c, audit_to_console=True).handle(
        {"op": "ping"},
        audit_context={"transport": "uds", "caller": "codex"},
    )

    out = capsys.readouterr().out
    assert " INFO: codex uds allowed ping" in out
    assert '\n   {\n' in out
    assert '     "caller": "codex"' in out


def test_stream_audit_console_prints_started_before_completion(cfg, capsys):
    c = dataclasses.replace(cfg, audit=AuditConfig())
    events = Broker(c, audit_to_console=True).handle_stream(
        {"op": "exec", "cmd": "printf 'first\\nsecond\\n'"},
        audit_context={"transport": "uds", "caller": "codex"},
    )

    first = next(events)
    assert first["op"] == "exec_chunk"
    out = capsys.readouterr().out
    assert " INFO: codex uds allowed started printf 'first\\nsecond\\n'" in out

    list(events)
    out = capsys.readouterr().out
    assert " INFO: codex uds allowed printf 'first\\nsecond\\n'" in out
    assert "allowed None" not in out
