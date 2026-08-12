"""Auditing a read-only op (e.g. a REPL Tab-completion) must not build a full
redactor. Doing so rebuilt the whole-workspace secret index on every request,
which made completion slow. Only `exec` has an echoed command and output to
scrub; other ops get a path-only redactor that loads no secret values.
"""
from valet.broker import Broker


def _spy_scans(monkeypatch, ws):
    calls = {"n": 0}
    real = ws._secret_index.values_for

    def spy(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(ws._secret_index, "values_for", spy)
    return calls


def test_complete_audit_does_not_scan_secrets(cfg, monkeypatch):
    broker = Broker(cfg)
    ws = broker.workspaces[broker.default_workspace]
    calls = _spy_scans(monkeypatch, ws)

    resp = broker.handle({"op": "complete", "line": "ec", "cwd": ""})
    assert resp["ok"] is True
    assert calls["n"] == 0, "completion audit must not build the secret index"


def test_exec_audit_still_scans(cfg, monkeypatch):
    broker = Broker(cfg)
    ws = broker.workspaces[broker.default_workspace]
    calls = _spy_scans(monkeypatch, ws)

    broker.handle({"op": "exec", "cmd": ["echo", "ok"], "shell": False})
    assert calls["n"] >= 1, "exec redacts its output, so it must scan"


def test_complete_audit_still_virtualizes_cwd(cfg, monkeypatch):
    broker = Broker(cfg)
    events = []
    monkeypatch.setattr(broker.audit, "record", lambda e: events.append(e))

    broker.handle({"op": "complete", "line": "x", "cwd": ""})
    assert events, "complete should still be audited"
    assert events[-1]["cwd"] == "./"   # workspace root still shown virtualized
