"""Server-startup warmup of the redaction index."""
from valet.broker import Broker


def test_warm_redaction_prebuilds_the_index(cfg):
    broker = Broker(cfg)
    ws = broker.workspaces[broker.default_workspace]

    assert not ws._secret_index._entries  # cold before warmup

    warmed = broker.warm_redaction()

    assert warmed == 1
    assert ws._secret_index._entries      # warmup populated the scan cache
    # And the warmed index actually masks the fixture secret.
    out = ws.redactor_for(ws.root()).redact("x sup3r-s3cret-value-do-not-leak y")
    assert "sup3r-s3cret-value-do-not-leak" not in out


def test_warm_redaction_is_best_effort(cfg):
    # A workspace whose root does not exist is skipped, not fatal.
    import dataclasses

    bad = dataclasses.replace(cfg, exec=dataclasses.replace(cfg.exec, workspace="/no/such/dir"))
    broker = Broker(bad)
    # Root resolves (realpath of a missing path) but the scan finds nothing;
    # warmup must still complete without raising.
    assert broker.warm_redaction() in (0, 1)
