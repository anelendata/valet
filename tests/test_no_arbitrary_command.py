"""Arbitrary / mutating commands cannot be run."""
import valet.operations as operations
from valet.broker import Broker
from valet.operations import READ_ONLY_OPS


def test_only_one_read_only_op_registered():
    assert READ_ONLY_OPS == ("schedule_list",)


def test_no_mutating_op_in_registry():
    for banned in ("schedule_create", "schedule_delete", "run", "deploy"):
        assert banned not in READ_ONLY_OPS


def test_mutating_op_rejected_and_not_executed(cfg, monkeypatch):
    called = {"ran": False}

    def _boom(*a, **k):
        called["ran"] = True
        raise AssertionError("executor must not run for a rejected op")

    monkeypatch.setattr(operations, "run", _boom)

    for op in ("schedule_create", "schedule_delete", "run", "arbitrary; rm -rf /"):
        resp = Broker(cfg).handle({"op": op, "project_alias": "demo_billing"})
        assert resp["ok"] is False
        assert resp["error_class"] == "ValidationError"
    assert called["ran"] is False


def test_shell_injection_in_alias_is_rejected_not_executed(cfg, monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("must not execute")

    monkeypatch.setattr(operations, "run", _boom)
    resp = Broker(cfg).handle({
        "op": "schedule_list",
        "project_alias": "demo_billing; rm -rf ~",
    })
    assert resp["ok"] is False
    assert resp["error_class"] == "ValidationError"
