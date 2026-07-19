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
