"""The interactive REPL's line handler builds correct requests and is safe."""
import json

from valet.repl import interact, run_command


def _recorder():
    sent = []

    def send(req):
        sent.append(req)
        return {"ok": True, "echo": req}

    return send, sent


def test_schedule_list_builds_request():
    send, sent = _recorder()
    keep, out = run_command("schedule-list demo_billing --scope prefix --compare", send)
    assert keep is True
    assert sent[0] == {
        "op": "schedule_list", "project_alias": "demo_billing",
        "stage": "prod", "scope": "prefix", "compare": True,
    }
    assert json.loads(out)["ok"] is True


def test_sl_alias_and_defaults():
    send, sent = _recorder()
    run_command("sl demo_billing", send)
    assert sent[0]["scope"] == "declared"
    assert sent[0]["stage"] == "prod"
    assert sent[0]["compare"] is False


def test_quit_stops_loop():
    send, _ = _recorder()
    assert run_command("quit", send) == (False, None)
    assert run_command("exit", send) == (False, None)


def test_help_and_ops_do_not_send():
    send, sent = _recorder()
    _, help_out = run_command("help", send)
    _, ops_out = run_command("ops", send)
    assert "schedule-list" in help_out
    assert "schedule_list" in ops_out
    assert sent == []  # neither hit the daemon


def test_bad_scope_does_not_crash_or_send():
    send, sent = _recorder()
    keep, out = run_command("sl demo_billing --scope everything", send)
    assert keep is True          # REPL survives a bad line
    assert sent == []            # nothing sent to the daemon
    assert "everything" in out or "invalid choice" in out


def test_unknown_command_is_reported_not_sent():
    send, sent = _recorder()
    keep, out = run_command("rm -rf /", send)
    assert keep is True
    assert sent == []
    assert "unknown command" in out


def test_raw_call_passes_json_through():
    send, sent = _recorder()
    run_command('call {"op":"schedule_list","project_alias":"x"}', send)
    assert sent[0] == {"op": "schedule_list", "project_alias": "x"}


def test_interact_loop_with_scripted_input():
    send, sent = _recorder()
    lines = iter(["sl demo_billing", "quit"])

    def fake_input(prompt):
        return next(lines)

    rc = interact(send, input_fn=fake_input)
    assert rc == 0
    assert len(sent) == 1
