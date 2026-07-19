"""Allowlists: unknown alias, invalid scope, invalid stage are all rejected."""
import pytest

from valet.broker import Broker
from valet.config import BrokerConfig
from valet.errors import ValidationError


def test_unknown_alias_rejected(cfg):
    with pytest.raises(ValidationError):
        cfg.project("no_such_project")


def test_unknown_alias_via_broker(cfg):
    resp = Broker(cfg).handle(
        {"op": "schedule_list", "project_alias": "no_such_project"}
    )
    assert resp["ok"] is False
    assert resp["error_class"] == "ValidationError"


def test_invalid_scope_rejected(cfg):
    with pytest.raises(ValidationError):
        BrokerConfig.check_scope("everything")


def test_invalid_scope_via_broker(cfg):
    resp = Broker(cfg).handle({
        "op": "schedule_list",
        "project_alias": "demo_billing",
        "scope": "everything",
    })
    assert resp["ok"] is False
    assert resp["error_class"] == "ValidationError"


def test_invalid_stage_rejected(cfg, project):
    with pytest.raises(ValidationError):
        project.check_stage("production-oops")


@pytest.mark.parametrize("scope", ["declared", "prefix", "all"])
def test_valid_scopes_accepted(scope):
    assert BrokerConfig.check_scope(scope) == scope
