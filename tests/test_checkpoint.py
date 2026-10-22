"""The checkpoint.* ops: a hand-off note between agent sessions, in the workspace."""
from datetime import datetime

import pytest

from valet.broker import Broker
from valet.checkpoint import CheckpointStore, slugify, title_from_content
from valet.cli import main
from valet.config import DEFAULT_WORKSPACE_ID
from valet.files import TransferGuard


def _current(workspace):
    d = workspace / "checkpoint"
    return sorted(p.name for p in d.glob("*.md")) if d.is_dir() else []


def _archived(workspace):
    d = workspace / "checkpoint" / "archive"
    return sorted(p.name for p in d.glob("*.md")) if d.is_dir() else []


def test_slugify_is_brief_and_filename_safe():
    assert slugify("Fix the login bug!") == "fix-the-login-bug"
    assert slugify("one two three four five six seven eight") == \
        "one-two-three-four-five-six"
    assert slugify("../../etc/passwd") == "etc-passwd"
    assert slugify("!!!") == "checkpoint"
    assert title_from_content("\n\n## Migrate the DB\nbody") == "Migrate the DB"


def test_create_writes_timestamped_markdown(cfg, workspace):
    resp = Broker(cfg).handle({"op": "checkpoint.create",
                               "content": "# Migrate the DB\n\nNext: step 3\n"})
    assert resp["ok"] is True, resp
    assert resp["archived"] == []
    [name] = _current(workspace)
    assert name.endswith("-migrate-the-db.md")
    assert resp["path"] == f"./checkpoint/{name}"
    assert (workspace / "checkpoint" / name).read_text() == \
        "# Migrate the DB\n\nNext: step 3\n"


def test_create_archives_the_existing_checkpoint(cfg, workspace):
    broker = Broker(cfg)
    first = broker.handle({"op": "checkpoint.create", "content": "first",
                           "title": "First pass"})
    second = broker.handle({"op": "checkpoint.create", "content": "second",
                            "title": "Second pass"})
    assert second["ok"] is True
    old_name = first["path"].rsplit("/", 1)[1]
    assert second["archived"] == [f"./checkpoint/archive/{old_name}"]
    assert _archived(workspace) == [old_name]
    [current] = _current(workspace)
    assert current.endswith("-second-pass.md")


def test_resume_returns_latest_and_archives_it(cfg, workspace):
    broker = Broker(cfg)
    broker.handle({"op": "checkpoint.create", "content": "# Task\nkeep going\n"})
    resp = broker.handle({"op": "checkpoint.resume"})
    assert resp["ok"] is True, resp
    assert resp["content"] == "# Task\nkeep going\n"
    assert resp["archived_to"] == f"./checkpoint/archive/{resp['name']}"
    assert _current(workspace) == []
    assert _archived(workspace) == [resp["name"]]

    again = broker.handle({"op": "checkpoint.resume"})
    assert again["ok"] is False
    assert "no checkpoint" in again["detail"]


def test_resume_redacts_secret_values(cfg, workspace):
    broker = Broker(cfg)
    broker.handle({"op": "checkpoint.create",
                   "content": "db pw is sup3r-s3cret-value-do-not-leak\n"})
    resp = broker.handle({"op": "checkpoint.resume"})
    assert resp["ok"] is True
    assert "sup3r-s3cret-value-do-not-leak" not in resp["content"]


def test_archive_empties_current(cfg, workspace):
    broker = Broker(cfg)
    broker.handle({"op": "checkpoint.create", "content": "x"})
    resp = broker.handle({"op": "checkpoint.archive"})
    assert resp["ok"] is True
    assert len(resp["archived"]) == 1
    assert _current(workspace) == []
    assert broker.handle({"op": "checkpoint.archive"})["archived"] == []


def test_archive_name_collision_gets_a_suffix(cfg, workspace):
    store = CheckpointStore(TransferGuard.for_workspace(
        Broker(cfg).workspaces[DEFAULT_WORKSPACE_ID], cfg))
    now = datetime(2026, 10, 21, 22, 0, 1)
    store.create("a", "same", now=now)
    store.create("b", "same", now=now)
    store.archive()
    assert _archived(workspace) == ["2026-10-21-22-00-01-same-2.md",
                                    "2026-10-21-22-00-01-same.md"]


def test_empty_and_oversize_content_refused(cfg, workspace):
    broker = Broker(cfg)
    assert broker.handle({"op": "checkpoint.create", "content": "  \n"})["ok"] is False
    big = broker.handle({"op": "checkpoint.create", "content": "x" * (1024 * 1024 + 1)})
    assert big["ok"] is False
    assert _current(workspace) == []


def test_symlinked_checkpoint_dir_cannot_escape(cfg, tmp_path, workspace):
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace / "checkpoint").symlink_to(outside)
    resp = Broker(cfg).handle({"op": "checkpoint.create", "content": "x"})
    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"
    assert list(outside.iterdir()) == []


def test_info_and_ping_report_a_pending_checkpoint(cfg, workspace):
    broker = Broker(cfg)
    assert broker.handle({"op": "workspace_info"})["checkpoint"] is None
    assert broker.handle({"op": "ping"})["checkpoints"] == []
    created = broker.handle({"op": "checkpoint.create", "content": "x"})
    info = broker.handle({"op": "workspace_info"})
    assert info["checkpoint"]["path"] == created["path"]
    assert "content" not in info["checkpoint"]
    assert broker.handle({"op": "ping"})["checkpoints"] == [DEFAULT_WORKSPACE_ID]


# -- CLI, end to end against a real broker -------------------------------------

class _BrokerConn:
    def __init__(self, broker):
        self.broker = broker

    def request(self, req):
        return self.broker.handle(req)

    def close(self):
        pass


@pytest.fixture
def cli_broker(monkeypatch, cfg):
    broker = Broker(cfg)
    monkeypatch.setattr("valet.cli._connect",
                        lambda _args: (_BrokerConn(broker), object(), None))
    return broker


def test_cli_create_resume_archive_roundtrip(cli_broker, workspace, tmp_path, capsys):
    ws = DEFAULT_WORKSPACE_ID
    notes = tmp_path / "notes.md"
    notes.write_text("# Ship checkpoints\n- done: broker\n- next: docs\n")

    assert main(["-w", ws, "checkpoint", "create", str(notes)]) == 0
    out = capsys.readouterr().out
    assert "saved checkpoint ./checkpoint/" in out
    assert f"valet -w {ws} checkpoint resume" in out

    assert main(["-w", ws, "info"]) == 0
    out = capsys.readouterr().out
    assert "Checkpoint available" in out
    assert out.rstrip().endswith(f"valet -w {ws} checkpoint archive")

    assert main(["-w", ws, "checkpoint", "resume"]) == 0
    out = capsys.readouterr().out
    assert "- next: docs" in out
    assert "archived to ./checkpoint/archive/" in out
    assert _current(workspace) == []

    assert main(["-w", ws, "checkpoint", "resume"]) == 1
    assert "no checkpoint" in capsys.readouterr().err

    assert main(["-w", ws, "checkpoint", "create", "--text", "quick note"]) == 0
    assert main(["-w", ws, "checkpoint", "archive"]) == 0
    assert "archived ->" in capsys.readouterr().out
    assert _current(workspace) == []
    assert len(_archived(workspace)) == 2


def test_cli_create_needs_exactly_one_source(cli_broker, capsys):
    assert main(["-w", DEFAULT_WORKSPACE_ID, "checkpoint", "create"]) == 2
    assert main(["-w", DEFAULT_WORKSPACE_ID, "checkpoint", "create", "f.md",
                 "--text", "x"]) == 2


def test_status_and_help_mention_checkpoints(cli_broker, monkeypatch, capsys):
    class _Target:
        name = "local"
        is_remote = False

    monkeypatch.setattr("valet.cli.resolve_target", lambda **_kw: (_Target(), None))
    cli_broker.handle({"op": "checkpoint.create", "content": "x"})
    assert main(["status"]) == 0
    out = capsys.readouterr().out
    assert "checkpoint create" in out
    assert f"Checkpoint waiting to be resumed in: {DEFAULT_WORKSPACE_ID}" in out

    with pytest.raises(SystemExit):
        main(["--help"])
    assert "checkpoint resume" in capsys.readouterr().out
