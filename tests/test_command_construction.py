"""The handoff command is constructed with the expected read-only arguments,
and the summary is derived + redacted (never raw)."""
import valet.operations as operations
from valet.broker import Broker
from valet.executor import RunResult
from valet.operations import build_schedule_list_argv


def test_argv_is_read_only_and_fixed(cfg, project):
    argv = build_schedule_list_argv(cfg, project, "prod", "declared")
    assert argv[:4] == ["handoff", "cloud", "schedule", "list"]
    # read-only flags only; no create/delete/deploy/mutate token anywhere
    assert "-p" in argv and project.project_dir in argv
    assert "-w" in argv and project.workspace_dir in argv
    assert "-s" in argv and "prod" in argv
    assert "-v" in argv and "scope=declared" in argv
    for banned in ("create", "delete", "deploy", "run", "push", "--yes", "-y"):
        assert banned not in argv


FAKE_YAML = """\
handoff_version: 0.1.0
schedules:
- rule:
    Name: demo_billing-daily
    Arn: arn:aws:events:us-east-1:123456789012:rule/demo_billing-daily
  target_id: daily
  status: scheduled
- rule:
    Name: demo_billing-hourly
    Arn: arn:aws:events:us-east-1:123456789012:rule/demo_billing-hourly
  target_id: hourly
  status: scheduled
"""


def test_schedule_list_summary_is_derived_and_redacted(cfg, monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = list(argv)
        captured["aws_profile"] = kwargs.get("aws_profile")
        return RunResult(argv=tuple(argv), exit_code=0, stdout=FAKE_YAML, stderr="")

    monkeypatch.setattr(operations, "run", fake_run)

    resp = Broker(cfg).handle({
        "op": "schedule_list", "project_alias": "demo_billing",
        "stage": "prod", "scope": "declared",
    })

    # correct read-only argv actually used, with the mapped AWS profile
    assert captured["argv"][:4] == ["handoff", "cloud", "schedule", "list"]
    assert captured["aws_profile"] == "demo-billing-prod"

    # derived facts, not raw output
    assert resp["ok"] is True
    assert resp["count"] == 2
    assert resp["by_scope"] == {"declared": 2}
    assert len(resp["rule_fingerprints"]) == 2
    assert all(fp.startswith("h:") for fp in resp["rule_fingerprints"])

    # no raw identifiers or account id anywhere in the response
    blob = repr(resp)
    assert "demo_billing-daily" not in blob
    assert "123456789012" not in blob
    assert "arn:aws" not in blob
    assert "redacted_output" not in resp  # structured path → no output text


def test_over_match_compare(cfg, monkeypatch):
    def fake_run(argv, **kwargs):
        scope = next(a.split("=", 1)[1] for a in argv if a.startswith("scope="))
        n = {"declared": 1, "prefix": 3, "all": 5}[scope]
        items = "\n".join(
            f"- rule: {{Name: r{i}}}\n  target_id: t{i}" for i in range(n)
        )
        return RunResult(tuple(argv), 0, f"schedules:\n{items}\n", "")

    monkeypatch.setattr(operations, "run", fake_run)
    resp = Broker(cfg).handle({
        "op": "schedule_list", "project_alias": "demo_billing",
        "scope": "prefix", "compare": True,
    })
    assert resp["by_scope"]["declared"] == 1
    assert resp["by_scope"]["prefix"] == 3
    assert resp["prefix_over_match"]["over_matches"] is True
    assert resp["prefix_over_match"]["extra_beyond_declared"] == 2
